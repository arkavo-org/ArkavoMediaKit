import AVFoundation
import Foundation

/// Decodes AAC packets to mono PCM, to check what a protected track sounds like once decrypted.
enum AACDecoder {
    enum Failure: Error { case format, converter, decode(String) }

    /// The packets' sound, the channels averaged. `magicCookie` is the track's `esds` ES_Descriptor.
    static func decode(_ packets: [Data], magicCookie: Data, sampleRate: Double, channels: UInt32) throws -> [Float] {
        var description = AudioStreamBasicDescription(
            mSampleRate: sampleRate, mFormatID: kAudioFormatMPEG4AAC, mFormatFlags: 0, mBytesPerPacket: 0,
            mFramesPerPacket: 1_024, mBytesPerFrame: 0, mChannelsPerFrame: channels, mBitsPerChannel: 0, mReserved: 0)
        guard let input = AVAudioFormat(streamDescription: &description),
              let output = AVAudioFormat(commonFormat: .pcmFormatFloat32, sampleRate: sampleRate,
                                         channels: AVAudioChannelCount(channels), interleaved: false)
        else { throw Failure.format }
        input.magicCookie = magicCookie
        guard let converter = AVAudioConverter(from: input, to: output) else { throw Failure.converter }
        converter.magicCookie = magicCookie

        var next = 0
        var mono: [Float] = []
        while true {
            guard let pcm = AVAudioPCMBuffer(pcmFormat: output, frameCapacity: 4_096) else { throw Failure.format }
            var error: NSError?
            let status = converter.convert(to: pcm, error: &error) { _, inputStatus in
                guard next < packets.count else {
                    inputStatus.pointee = .endOfStream
                    return nil
                }
                let packet = packets[next]
                next += 1
                let buffer = AVAudioCompressedBuffer(format: input, packetCapacity: 1,
                                                     maximumPacketSize: packet.count)
                packet.withUnsafeBytes { buffer.data.copyMemory(from: $0.baseAddress!, byteCount: packet.count) }
                buffer.packetDescriptions?.pointee = AudioStreamPacketDescription(
                    mStartOffset: 0, mVariableFramesInPacket: 0, mDataByteSize: UInt32(packet.count))
                buffer.packetCount = 1
                buffer.byteLength = UInt32(packet.count)
                inputStatus.pointee = .haveData
                return buffer
            }
            if let error { throw Failure.decode(error.localizedDescription) }
            if let data = pcm.floatChannelData, pcm.frameLength > 0 {
                for frame in 0 ..< Int(pcm.frameLength) {
                    mono.append((0 ..< Int(channels)).reduce(Float(0)) { $0 + data[$1][frame] } / Float(channels))
                }
            }
            if status == .endOfStream || status == .error || pcm.frameLength == 0 { break }
        }
        return mono
    }

    /// The power of `frequency` in `samples` (Goertzel), per sample: a pure tone of amplitude A gives about A²/4.
    static func power(of frequency: Double, in samples: [Float], sampleRate: Double) -> Double {
        let coefficient = 2 * cos(2 * Double.pi * frequency / sampleRate)
        var previous = 0.0, beforePrevious = 0.0
        for sample in samples {
            let current = Double(sample) + coefficient * previous - beforePrevious
            beforePrevious = previous
            previous = current
        }
        let power = previous * previous + beforePrevious * beforePrevious - coefficient * previous * beforePrevious
        return power / Double(samples.count * samples.count)
    }
}
