import Foundation

/// Describes where a single DSM Web API lives and which versions it supports,
/// as reported by `SYNO.API.Info`. DSM API paths/versions vary across firmware
/// versions, so this must be discovered at runtime rather than hardcoded.
public struct APIEndpointInfo: Codable, Sendable {
    public let path: String
    public let minVersion: Int
    public let maxVersion: Int

    public init(path: String, minVersion: Int, maxVersion: Int) {
        self.path = path
        self.minVersion = minVersion
        self.maxVersion = maxVersion
    }
}

public struct APIInfoResponse: Codable, Sendable {
    public let success: Bool
    public let data: [String: APIEndpointInfo]?
}

public typealias APIInfoMap = [String: APIEndpointInfo]

/// Generic envelope every DSM webapi response follows.
public struct DSMEnvelope<T: Decodable>: Decodable {
    public let success: Bool
    public let data: T?
    public let error: DSMErrorPayload?
}

public struct DSMErrorPayload: Decodable, Sendable {
    public let code: Int
}

/// Used when only success/error matters and there is no payload to decode.
public struct DSMEmptyData: Decodable, Sendable {
    public init() {}
    public init(from decoder: Decoder) throws {}
}
