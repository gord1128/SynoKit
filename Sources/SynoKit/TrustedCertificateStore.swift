import Foundation
import Security

/// Persists trust-on-first-use (TOFU) certificate pins, one per exact host:port,
/// in a `SecureLocalStore` namespace distinct from credentials. Pinning is never
/// global — a pin for one host never affects trust decisions for another.
public enum TrustedCertificateStore {
    private static var service: String { "\(SecureLocalStore.serviceNamespace).pinned-certificates" }

    private static func account(host: String, port: Int) -> String {
        "\(host):\(port)"
    }

    public static func pinnedCertificateData(for host: String, port: Int) -> Data? {
        SecureLocalStore.read(service: service, account: account(host: host, port: port))
    }

    public static func fingerprint(for host: String, port: Int) -> String? {
        guard let data = pinnedCertificateData(for: host, port: port) else { return nil }
        return CertificateFingerprint.sha256(of: data)
    }

    @discardableResult
    public static func pin(certificateData: Data, for host: String, port: Int) -> Bool {
        SecureLocalStore.save(service: service, account: account(host: host, port: port), data: certificateData)
    }

    public static func matches(certificateData: Data, for host: String, port: Int) -> Bool {
        guard let pinned = pinnedCertificateData(for: host, port: port) else { return false }
        return pinned == certificateData
    }

    public static func removePin(for host: String, port: Int) {
        SecureLocalStore.delete(service: service, account: account(host: host, port: port))
    }
}
