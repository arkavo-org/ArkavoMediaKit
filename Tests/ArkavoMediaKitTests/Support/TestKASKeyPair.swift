import Foundation
import Security
import Testing

/// A per-test 2048-bit RSA keypair standing in for the KAS key. Packagers
/// RSA-wrap the DEK with `publicKeyPEM` (OAEP-SHA1, as the KAS does); tests
/// unwrap it from `privateKeyPEM` with OpenTDFKit's
/// `TDFCrypto.unwrapSymmetricKeyWithRSA` so a manifest binding can be verified
/// against the real DEK exactly the way KAS rewrap and the arks license service do.
///
/// Generated at runtime with `SecKeyCreateRandomKey` so no key material
/// lives in source. `SecKeyCopyExternalRepresentation` yields PKCS#1 DER for
/// RSA keys, which is what OpenTDFKit's `loadRSAPublicKey` /
/// `loadRSAPrivateKey` hand to `SecKeyCreateWithData` after stripping the
/// `PUBLIC KEY` / `RSA PRIVATE KEY` PEM armor.
struct TestKASKeyPair {
    let publicKeyPEM: String
    let privateKeyPEM: String
    /// The same public key as a SubjectPublicKeyInfo PEM — the form a real KAS serves.
    let spkiPublicKeyPEM: String

    init(bits: Int = 2048) throws {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: bits,
            kSecAttrIsPermanent as String: false,
        ]
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        let publicKey = try #require(SecKeyCopyPublicKey(privateKey))
        privateKeyPEM = try Self.pem(privateKey, label: "RSA PRIVATE KEY")
        publicKeyPEM = try Self.pem(publicKey, label: "PUBLIC KEY")
        guard let pkcs1 = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw error!.takeRetainedValue() as Error
        }
        // SEQUENCE { SEQUENCE { OID rsaEncryption, NULL }, BIT STRING { 0x00, PKCS#1 } }
        let algorithm = Data([0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00])
        let bitString = Self.der(tag: 0x03, Data([0x00]) + pkcs1)
        let spki = Self.der(tag: 0x30, algorithm + bitString)
        spkiPublicKeyPEM = "-----BEGIN PUBLIC KEY-----\n\(spki.base64EncodedString(options: [.lineLength64Characters]))\n-----END PUBLIC KEY-----"
    }

    private static func pem(_ key: SecKey, label: String) throws -> String {
        var error: Unmanaged<CFError>?
        guard let der = SecKeyCopyExternalRepresentation(key, &error) as Data? else {
            throw error!.takeRetainedValue() as Error
        }
        let body = der.base64EncodedString(options: [.lineLength64Characters])
        return "-----BEGIN \(label)-----\n\(body)\n-----END \(label)-----"
    }

    private static func der(tag: UInt8, _ body: Data) -> Data {
        var out = Data([tag])
        if body.count < 0x80 {
            out.append(UInt8(body.count))
        } else {
            var length = body.count
            var bytes: [UInt8] = []
            while length > 0 {
                bytes.insert(UInt8(length & 0xFF), at: 0)
                length >>= 8
            }
            out.append(0x80 | UInt8(bytes.count))
            out.append(contentsOf: bytes)
        }
        return out + body
    }
}
