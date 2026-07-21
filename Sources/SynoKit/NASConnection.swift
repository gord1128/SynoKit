import Foundation

/// A single DSM host the app can connect to. Identified by `host:port`, the
/// same natural key `SecureLocalStore` and `TrustedCertificateStore` use to
/// namespace per-NAS data.
public struct NASConnection: Codable, Equatable, Identifiable, Sendable {
    public var host: String
    public var port: Int
    public var username: String
    /// DSM API calls are HTTPS-only; kept as a field for URL construction clarity.
    public var useHTTPS: Bool
    /// Optional user-chosen display name. When set it wins over the NAS's own
    /// reported server name and the raw host in every surface.
    public var nickname: String?
    /// Learned automatically from the local ARP table after a successful
    /// connection (not user-entered). Enables Wake-on-LAN when the NAS is off.
    /// `nil` until a lookup succeeds, or on non-broadcast links (e.g. Tailscale).
    public var macAddress: String?

    public init(host: String, port: Int, username: String, useHTTPS: Bool = true, nickname: String? = nil, macAddress: String? = nil) {
        self.host = host
        self.port = port
        self.username = username
        self.useHTTPS = useHTTPS
        self.nickname = nickname
        self.macAddress = macAddress
    }

    public var id: String { "\(host):\(port)" }

    public var baseURL: URL? {
        var components = URLComponents()
        components.scheme = useHTTPS ? "https" : "http"
        components.host = host
        components.port = port
        return components.url
    }
}
