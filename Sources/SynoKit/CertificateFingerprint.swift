import Foundation
import CryptoKit
import Security

public enum CertificateFingerprint {
    public static func sha256(of certificate: SecCertificate) -> String {
        let data = SecCertificateCopyData(certificate) as Data
        return sha256(of: data)
    }

    public static func sha256(of data: Data) -> String {
        let digest = SHA256.hash(data: data)
        return digest.map { String(format: "%02X", $0) }.joined(separator: ":")
    }

    public static func displayString(_ fingerprint: String) -> String {
        "SHA256:\(fingerprint)"
    }
}
