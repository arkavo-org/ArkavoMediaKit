import Foundation

/// Runs `body` with the process's stdout redirected to a temporary file and
/// returns what was written. The capture is replayed to the real stdout
/// afterwards, so output from tests running in parallel is not lost. A file,
/// not a pipe, so a chatty body cannot fill the pipe buffer and block.
enum StdoutCapture {
    static func capture<T>(_ body: () async throws -> T) async throws -> (value: T, output: String) {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("stdout-\(UUID().uuidString).log")
        guard FileManager.default.createFile(atPath: url.path, contents: nil) else {
            throw CocoaError(.fileWriteUnknown)
        }
        defer { try? FileManager.default.removeItem(at: url) }
        let file = try FileHandle(forWritingTo: url)
        defer { try? file.close() }

        fflush(nil)
        let saved = dup(STDOUT_FILENO)
        guard saved >= 0, dup2(file.fileDescriptor, STDOUT_FILENO) >= 0 else {
            throw POSIXError(.EBADF)
        }
        let result: Result<T, Error>
        do { result = .success(try await body()) } catch { result = .failure(error) }
        fflush(nil)
        dup2(saved, STDOUT_FILENO)
        close(saved)

        let captured = try Data(contentsOf: url)
        FileHandle.standardOutput.write(captured)
        return (try result.get(), String(decoding: captured, as: UTF8.self))
    }
}
