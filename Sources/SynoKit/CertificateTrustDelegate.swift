import Foundation
import Security

public enum CertificateTrustEvent {
    case untrusted(fingerprint: String, certificateData: Data)
    case changed(oldFingerprint: String, newFingerprint: String, newCertificateData: Data)
}

/// Handles TLS trust evaluation for exactly one host:port. Never relaxes trust
/// globally: a session using this delegate only ever pins/trusts certificates
/// for the specific `host`/`port` it was constructed with.
///
/// `@unchecked Sendable`: this delegate is shared by one session that runs many
/// requests concurrently (e.g. a photo grid loading thumbnails in parallel), so
/// every `pendingTrustEvent` access — the challenge-queue writes, the per-request
/// `clearPendingEvent()`, and the client's read — goes through `lock`. (An earlier
/// version assumed a single sequential owner; ThreadSanitizer showed concurrent
/// `clearPendingEvent()` calls racing on the property.) The event is host-level
/// (this delegate is per host:port) and only set when trust fails, which happens
/// during the sequential connect handshake, so a single slot is still correct.
public final class CertificateTrustDelegate: NSObject, URLSessionDelegate, @unchecked Sendable {
    public let host: String
    public let port: Int

    private let lock = NSLock()
    /// Set when standard trust evaluation fails and a user decision is needed.
    private var _pendingTrustEvent: CertificateTrustEvent?
    public var pendingTrustEvent: CertificateTrustEvent? {
        lock.lock(); defer { lock.unlock() }
        return _pendingTrustEvent
    }

    public init(host: String, port: Int) {
        self.host = host
        self.port = port
    }

    public func clearPendingEvent() {
        lock.lock(); defer { lock.unlock() }
        _pendingTrustEvent = nil
    }

    private func setPendingEvent(_ event: CertificateTrustEvent) {
        lock.lock(); defer { lock.unlock() }
        _pendingTrustEvent = event
    }

    public func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        // 1. Standard system trust evaluation (valid CA-issued cert path).
        if SecTrustEvaluateWithError(serverTrust, nil) {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        // 2. Standard trust failed (self-signed, unknown CA, or host/IP mismatch).
        guard let certChain = SecTrustCopyCertificateChain(serverTrust) as? [SecCertificate],
              let leafCertificate = certChain.first else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        let certificateData = SecCertificateCopyData(leafCertificate) as Data
        let fingerprint = CertificateFingerprint.sha256(of: certificateData)

        if let pinnedData = TrustedCertificateStore.pinnedCertificateData(for: host, port: port) {
            if pinnedData == certificateData {
                completionHandler(.useCredential, URLCredential(trust: serverTrust))
            } else {
                let oldFingerprint = CertificateFingerprint.sha256(of: pinnedData)
                setPendingEvent(.changed(oldFingerprint: oldFingerprint, newFingerprint: fingerprint, newCertificateData: certificateData))
                completionHandler(.cancelAuthenticationChallenge, nil)
            }
        } else {
            setPendingEvent(.untrusted(fingerprint: fingerprint, certificateData: certificateData))
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}
