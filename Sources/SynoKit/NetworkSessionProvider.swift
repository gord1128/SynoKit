import Foundation

/// Builds a `URLSession` scoped to exactly one NAS host:port, with its own
/// `CertificateTrustDelegate` and no cookie persistence (the DSM session id is
/// passed explicitly as a query parameter, never relied on as a cookie).
public enum NetworkSessionProvider {
    public static func makeSession(
        host: String,
        port: Int,
        requestTimeout: TimeInterval = 15,
        resourceTimeout: TimeInterval = 30
    ) -> (session: URLSession, trustDelegate: CertificateTrustDelegate) {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = requestTimeout
        configuration.timeoutIntervalForResource = resourceTimeout
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false

        let trustDelegate = CertificateTrustDelegate(host: host, port: port)
        let session = URLSession(configuration: configuration, delegate: trustDelegate, delegateQueue: nil)
        return (session, trustDelegate)
    }
}
