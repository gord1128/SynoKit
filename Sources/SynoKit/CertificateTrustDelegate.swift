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
/// `@unchecked Sendable`: the mutable `pendingTrustEvent` is written on the
/// URLSession delegate queue during a challenge and read by the client only
/// after the request's continuation resumes (a happens-after relationship),
/// so there is no real concurrent access.
public final class CertificateTrustDelegate: NSObject, URLSessionDelegate, @unchecked Sendable {
    public let host: String
    public let port: Int

    /// Set when standard trust evaluation fails and a user decision is needed.
    public private(set) var pendingTrustEvent: CertificateTrustEvent?

    public init(host: String, port: Int) {
        self.host = host
        self.port = port
    }

    public func clearPendingEvent() {
        pendingTrustEvent = nil
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
                pendingTrustEvent = .changed(oldFingerprint: oldFingerprint, newFingerprint: fingerprint, newCertificateData: certificateData)
                completionHandler(.cancelAuthenticationChallenge, nil)
            }
        } else {
            pendingTrustEvent = .untrusted(fingerprint: fingerprint, certificateData: certificateData)
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}
