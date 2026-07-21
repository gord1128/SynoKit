import Foundation
import CryptoKit

/// Generic transport for one Synology DSM Web API host: runtime API discovery
/// (`SYNO.API.Info`), authentication (incl. 2FA/OTP), and authenticated
/// request execution. Host apps build their feature APIs (SYNO.Foto.*, …) on
/// top of `requestData`/`perform` rather than subclassing.
///
/// `@unchecked Sendable`: each instance is driven sequentially by its single
/// owner; `sid`/`apiInfoMap` are never mutated concurrently.
public final class SynologyClient: @unchecked Sendable {
    private let connection: NASConnection
    private let session: URLSession
    private let trustDelegate: CertificateTrustDelegate
    // Separate session for large transfers (originals, zips, video range
    // streaming). The API `session` caps every resource at 30s, which kills any
    // download longer than that; this one uses a long resource timeout while the
    // 30s idle/request timeout still catches dead connections.
    private let downloadSession: URLSession
    private let downloadTrustDelegate: CertificateTrustDelegate
    private let sessionName: String
    private let apiInfoCache: APIInfoCache

    private var apiInfoMap: APIInfoMap = [:]
    private var sid: String?

    // Session auto-recovery: the last successful credentials (kept in memory
    // only — they already live in the app's encrypted store) let an expired sid
    // be renewed transparently mid-session. `reloginTask` serializes concurrent
    // expiry so a burst of failing requests triggers exactly one re-login.
    private var lastCredentials: (username: String, password: String)?
    private let reloginLock = NSLock()
    private var reloginTask: Task<Void, Error>?

    private var hostKey: String { connection.id }

    /// Production initializer: builds a per-host pinned session.
    public convenience init(connection: NASConnection, sessionName: String = "SynoKit", apiInfoCache: APIInfoCache = .shared) {
        let (session, trustDelegate) = NetworkSessionProvider.makeSession(host: connection.host, port: connection.port)
        // Same host:port cert pinning, but a 1h resource cap so big files finish.
        let (downloadSession, downloadTrustDelegate) = NetworkSessionProvider.makeSession(
            host: connection.host, port: connection.port, requestTimeout: 30, resourceTimeout: 3600)
        self.init(connection: connection, session: session, trustDelegate: trustDelegate,
                  downloadSession: downloadSession, downloadTrustDelegate: downloadTrustDelegate,
                  sessionName: sessionName, apiInfoCache: apiInfoCache)
    }

    /// Injectable initializer (tests pass a stubbed `URLSession`). `downloadSession`
    /// defaults to `session` so existing stubs drive both paths.
    public init(connection: NASConnection, session: URLSession, trustDelegate: CertificateTrustDelegate,
                downloadSession: URLSession? = nil, downloadTrustDelegate: CertificateTrustDelegate? = nil,
                sessionName: String = "SynoKit", apiInfoCache: APIInfoCache = .shared) {
        self.connection = connection
        self.session = session
        self.trustDelegate = trustDelegate
        self.downloadSession = downloadSession ?? session
        self.downloadTrustDelegate = downloadTrustDelegate ?? trustDelegate
        self.sessionName = sessionName
        self.apiInfoCache = apiInfoCache
    }

    public var isAuthenticated: Bool { sid != nil }

    /// The host's base URL string (scheme://host:port), for building non-API URLs
    /// like public share links.
    public var hostBaseURL: String? {
        connection.baseURL.map { $0.absoluteString.hasSuffix("/") ? String($0.absoluteString.dropLast()) : $0.absoluteString }
    }

    public func endpoint(for apiName: String) -> APIEndpointInfo? { apiInfoMap[apiName] }

    // MARK: - Discovery

    /// Resolves paths/versions for `apiNames`. `required` (defaulting to all of
    /// `apiNames`) are the ones that must resolve: if any is still missing after
    /// the targeted query, a full `query=all` sweep is done. Optional APIs that
    /// simply don't exist on this NAS won't force the extra sweep.
    @discardableResult
    public func discoverAPIs(_ apiNames: [String], required: Set<String>? = nil, forceRefresh: Bool = false) async throws -> APIInfoMap {
        // The cache key includes a signature of the requested API list AND the
        // required set, so changing either (e.g. requiring an API the targeted
        // query dropped, which the sweep then resolves) busts the cache instead
        // of returning a stale map missing that API.
        let key = cacheKey(for: apiNames, required: required)
        if !forceRefresh, let cached = await apiInfoCache.map(for: key) {
            apiInfoMap = cached
            return cached
        }
        let mustResolve = required ?? Set(apiNames)
        guard let baseURL = connection.baseURL else { throw SynologyAPIError.invalidResponse }

        var map = try await queryAPIInfo(baseURL: baseURL, query: apiNames.joined(separator: ","))
        let missing = mustResolve.subtracting(map.keys)
        if !missing.isEmpty {
            let all = try await queryAPIInfo(baseURL: baseURL, query: "all")
            map = all.merging(map) { current, _ in current }
        }
        // SYNO.API.Auth is always at a known path even if Info omits it.
        if map["SYNO.API.Auth"] == nil {
            map["SYNO.API.Auth"] = APIEndpointInfo(path: "auth.cgi", minVersion: 1, maxVersion: 6)
        }

        apiInfoMap = map
        await apiInfoCache.store(map, for: key)
        return map
    }

    private func cacheKey(for apiNames: [String], required: Set<String>?) -> String {
        let joined = apiNames.sorted().joined(separator: ",")
        let req = (required ?? []).sorted().joined(separator: ",")
        let hash = SHA256.hash(data: Data("\(joined)|\(req)".utf8)).prefix(8).map { String(format: "%02x", $0) }.joined()
        return "\(hostKey)#\(hash)"
    }

    private func queryAPIInfo(baseURL: URL, query: String) async throws -> APIInfoMap {
        var components = URLComponents(url: baseURL.appendingPathComponent("webapi/query.cgi"), resolvingAgainstBaseURL: false)!
        components.queryItems = [
            URLQueryItem(name: "api", value: "SYNO.API.Info"),
            URLQueryItem(name: "method", value: "query"),
            URLQueryItem(name: "version", value: "1"),
            URLQueryItem(name: "query", value: query),
        ]
        guard let url = components.url else { throw SynologyAPIError.invalidResponse }
        let data = try await send(URLRequest(url: url))
        let decoded = try decodeJSON(APIInfoResponse.self, from: data)
        guard decoded.success, let map = decoded.data else {
            throw SynologyAPIError.apiUnavailable(apiName: "SYNO.API.Info")
        }
        return map
    }

    // MARK: - Auth

    /// Logs in via `SYNO.API.Auth`. Pass `otpCode` for accounts with 2FA.
    /// Credentials go in a POST body (form-urlencoded), never the URL query,
    /// so the password never lands in proxy/server access logs.
    public func login(username: String, password: String, otpCode: String? = nil) async throws {
        guard let endpoint = apiInfoMap["SYNO.API.Auth"] else {
            throw SynologyAPIError.apiUnavailable(apiName: "SYNO.API.Auth")
        }
        guard let baseURL = connection.baseURL else { throw SynologyAPIError.invalidResponse }

        var form = URLComponents()
        var items = [
            URLQueryItem(name: "api", value: "SYNO.API.Auth"),
            URLQueryItem(name: "method", value: "login"),
            URLQueryItem(name: "version", value: String(endpoint.maxVersion)),
            URLQueryItem(name: "account", value: username),
            URLQueryItem(name: "passwd", value: password),
            URLQueryItem(name: "session", value: sessionName),
            URLQueryItem(name: "format", value: "sid"),
        ]
        if let otpCode, !otpCode.isEmpty {
            items.append(URLQueryItem(name: "otp_code", value: otpCode))
        }
        form.queryItems = items

        let url = baseURL.appendingPathComponent("webapi/\(endpoint.path)")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded; charset=utf-8", forHTTPHeaderField: "Content-Type")
        request.httpBody = form.percentEncodedQuery?.data(using: .utf8)

        let data = try await send(request)
        let decoded = try decodeJSON(DSMEnvelope<LoginData>.self, from: data)
        guard decoded.success, let loginData = decoded.data else {
            throw SynologyAPIError.fromAuthErrorCode(decoded.error?.code ?? -1)
        }
        sid = loginData.sid
        // OTP codes are one-time, so silent re-login stores only user/password.
        // 2FA accounts will surface an auth error instead of renewing silently.
        lastCredentials = (username, password)
    }

    // MARK: - Session auto-recovery

    /// The DSM error code when `data` is a small session-expired envelope, else
    /// nil. Real payloads (images, item lists) are large and/or not JSON, so the
    /// cheap size+prefix gate avoids decoding them.
    private func sessionErrorCode(in data: Data) -> Int? {
        guard data.count < 512, data.first == UInt8(ascii: "{"),
              let envelope = try? decodeJSON(DSMEnvelope<DSMEmptyData>.self, from: data),
              !envelope.success, let code = envelope.error?.code,
              SynologyAPIError.sessionErrorCodes.contains(code) else { return nil }
        return code
    }

    /// Sync-scoped lock helper (safe to call from async code — the lock never
    /// spans a suspension point).
    private func withReloginLock<T>(_ body: () -> T) -> T {
        reloginLock.lock()
        defer { reloginLock.unlock() }
        return body()
    }

    /// Re-logs-in with the stored credentials, coalescing concurrent callers
    /// into a single in-flight login.
    private func reloginWithStoredCredentials() async throws {
        let task: Task<Void, Error> = withReloginLock {
            if let existing = reloginTask { return existing }
            let credentials = lastCredentials
            let t = Task {
                defer { self.withReloginLock { self.reloginTask = nil } }
                guard let credentials else { throw SynologyAPIError.sessionExpired }
                try await self.login(username: credentials.username, password: credentials.password)
            }
            reloginTask = t
            return t
        }
        try await task.value
    }

    private struct LoginData: Decodable {
        let sid: String
    }

    public func logout() async throws {
        guard let endpoint = apiInfoMap["SYNO.API.Auth"], let baseURL = connection.baseURL, let sid else {
            sid = nil
            return
        }
        var components = URLComponents(url: baseURL.appendingPathComponent("webapi/\(endpoint.path)"), resolvingAgainstBaseURL: false)!
        components.queryItems = [
            URLQueryItem(name: "api", value: "SYNO.API.Auth"),
            URLQueryItem(name: "method", value: "logout"),
            URLQueryItem(name: "version", value: String(endpoint.maxVersion)),
            URLQueryItem(name: "session", value: sessionName),
            URLQueryItem(name: "_sid", value: sid),
        ]
        if let url = components.url {
            _ = try? await send(URLRequest(url: url))
        }
        self.sid = nil
    }

    // MARK: - Authenticated requests

    /// Executes an authenticated GET against a discovered API and returns raw
    /// response bytes. `version` defaults to the endpoint's max supported.
    /// If the response is a session-expired envelope, silently re-logs-in with
    /// the stored credentials and retries once (with the fresh sid).
    public func requestData(api: String, method: String, version: Int? = nil, queryItems: [URLQueryItem] = []) async throws -> Data {
        let data = try await requestDataOnce(api: api, method: method, version: version, queryItems: queryItems)
        guard sessionErrorCode(in: data) != nil else { return data }
        try await reloginWithStoredCredentials()
        return try await requestDataOnce(api: api, method: method, version: version, queryItems: queryItems)
    }

    private func requestDataOnce(api: String, method: String, version: Int?, queryItems: [URLQueryItem]) async throws -> Data {
        guard let sid else { throw SynologyAPIError.sessionExpired }
        guard let endpoint = apiInfoMap[api] else { throw SynologyAPIError.apiUnavailable(apiName: api) }
        guard let baseURL = connection.baseURL else { throw SynologyAPIError.invalidResponse }

        var components = URLComponents(url: baseURL.appendingPathComponent("webapi/\(endpoint.path)"), resolvingAgainstBaseURL: false)!
        components.queryItems = [
            URLQueryItem(name: "api", value: api),
            URLQueryItem(name: "method", value: method),
            URLQueryItem(name: "version", value: String(version ?? endpoint.maxVersion)),
            URLQueryItem(name: "_sid", value: sid),
        ] + queryItems
        guard let url = components.url else { throw SynologyAPIError.invalidResponse }
        return try await send(URLRequest(url: url))
    }

    /// Builds the authenticated URL for a discovered API — for media that must be
    /// loaded *outside* `requestData` (e.g. AVFoundation progressive streaming via
    /// an `AVAssetResourceLoaderDelegate`). Returns nil if not logged in or the
    /// API isn't discovered.
    public func authenticatedURL(api: String, method: String, version: Int? = nil, queryItems: [URLQueryItem] = []) -> URL? {
        guard let sid, let endpoint = apiInfoMap[api], let baseURL = connection.baseURL else { return nil }
        var components = URLComponents(url: baseURL.appendingPathComponent("webapi/\(endpoint.path)"), resolvingAgainstBaseURL: false)!
        components.queryItems = [
            URLQueryItem(name: "api", value: api),
            URLQueryItem(name: "method", value: method),
            URLQueryItem(name: "version", value: String(version ?? endpoint.maxVersion)),
            URLQueryItem(name: "_sid", value: sid),
        ] + queryItems
        return components.url
    }

    /// Runs a request on this host's pinned (cert-trusted) session and returns the
    /// raw bytes + HTTP response. For range/streaming loaders that need the status
    /// code and headers (Content-Range, Content-Type). Reuses the same TLS trust
    /// as every other call, so AVFoundation streaming works with a self-signed NAS.
    public func rawData(for request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        // Video range streaming: long-transfer session so a big range isn't
        // guillotined by the API session's 30s resource cap.
        let (data, response) = try await downloadSession.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw SynologyAPIError.invalidResponse }
        return (data, http)
    }

    /// POSTs a multipart/form-data body to a discovered API (file uploads:
    /// torrents, photos). The `build` closure receives the live session id and
    /// the endpoint's max version so it can assemble the exact form fields DSM
    /// expects; `_sid` is also appended to the URL query.
    public func requestMultipart(
        api: String,
        extraQuery: [URLQueryItem] = [],
        pathSuffix: String? = nil,
        build: (_ sid: String, _ maxVersion: Int) -> (contentType: String, body: Data)
    ) async throws -> Data {
        let data = try await requestMultipartOnce(api: api, extraQuery: extraQuery, pathSuffix: pathSuffix, build: build)
        guard sessionErrorCode(in: data) != nil else { return data }
        try await reloginWithStoredCredentials()
        // Rebuild with the fresh sid (it's baked into both the URL and the form).
        return try await requestMultipartOnce(api: api, extraQuery: extraQuery, pathSuffix: pathSuffix, build: build)
    }

    private func requestMultipartOnce(
        api: String,
        extraQuery: [URLQueryItem],
        pathSuffix: String?,
        build: (_ sid: String, _ maxVersion: Int) -> (contentType: String, body: Data)
    ) async throws -> Data {
        guard let sid else { throw SynologyAPIError.sessionExpired }
        guard let endpoint = apiInfoMap[api] else { throw SynologyAPIError.apiUnavailable(apiName: api) }
        guard let baseURL = connection.baseURL else { throw SynologyAPIError.invalidResponse }

        // Some DSM upload APIs put the filename in the URL path (entry.cgi/<name>).
        var path = "webapi/\(endpoint.path)"
        if let pathSuffix { path += "/\(pathSuffix)" }
        var components = URLComponents(url: baseURL.appendingPathComponent(path), resolvingAgainstBaseURL: false)!
        components.queryItems = [URLQueryItem(name: "_sid", value: sid)] + extraQuery
        guard let url = components.url else { throw SynologyAPIError.invalidResponse }

        let (contentType, body) = build(sid, endpoint.maxVersion)
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue(contentType, forHTTPHeaderField: "Content-Type")
        request.httpBody = body
        return try await send(request)
    }

    /// Executes a request and decodes `DSMEnvelope<T>`, throwing a typed error
    /// (via `errorMapper`, default `fromDataErrorCode`) when the envelope fails.
    public func perform<T: Decodable>(
        _ type: T.Type,
        api: String,
        method: String,
        version: Int? = nil,
        queryItems: [URLQueryItem] = [],
        errorMapper: (Int) -> SynologyAPIError = SynologyAPIError.fromDataErrorCode
    ) async throws -> T {
        let data = try await requestData(api: api, method: method, version: version, queryItems: queryItems)
        let decoded = try decodeJSON(DSMEnvelope<T>.self, from: data)
        guard decoded.success, let payload = decoded.data else {
            throw errorMapper(decoded.error?.code ?? -1)
        }
        return payload
    }

    /// Executes a write action and checks only the envelope's `success` flag
    /// (DSM write responses often carry no `data`). Throws via `errorMapper`.
    public func performSuccess(
        api: String,
        method: String,
        version: Int? = nil,
        queryItems: [URLQueryItem] = [],
        errorMapper: (Int) -> SynologyAPIError = SynologyAPIError.fromDataErrorCode
    ) async throws {
        let data = try await requestData(api: api, method: method, version: version, queryItems: queryItems)
        let decoded = try decodeJSON(DSMEnvelope<DSMEmptyData>.self, from: data)
        guard decoded.success else { throw errorMapper(decoded.error?.code ?? -1) }
    }

    /// Decodes a `DSMEnvelope` from raw bytes (for callers of `requestMultipart`
    /// that need to interpret the response themselves).
    public func decodeEnvelope<T: Decodable>(_ type: T.Type, from data: Data) throws -> DSMEnvelope<T> {
        try decodeJSON(DSMEnvelope<T>.self, from: data)
    }

    /// Streams an authenticated GET to `destination` (no in-memory buffering —
    /// safe for large originals/zips). Overwrites any existing file. If the
    /// "file" turns out to be a session-expired envelope, re-logs-in and
    /// retries once.
    public func downloadToFile(api: String, method: String, version: Int? = nil, queryItems: [URLQueryItem] = [], to destination: URL) async throws {
        try await downloadToFileOnce(api: api, method: method, version: version, queryItems: queryItems, to: destination)
        // A session-expired "download" is a tiny JSON envelope, not the file.
        if let size = try? FileManager.default.attributesOfItem(atPath: destination.path)[.size] as? Int,
           size < 512,
           let data = try? Data(contentsOf: destination),
           sessionErrorCode(in: data) != nil {
            try await reloginWithStoredCredentials()
            try await downloadToFileOnce(api: api, method: method, version: version, queryItems: queryItems, to: destination)
        }
    }

    private func downloadToFileOnce(api: String, method: String, version: Int?, queryItems: [URLQueryItem], to destination: URL) async throws {
        guard let sid else { throw SynologyAPIError.sessionExpired }
        guard let endpoint = apiInfoMap[api] else { throw SynologyAPIError.apiUnavailable(apiName: api) }
        guard let baseURL = connection.baseURL else { throw SynologyAPIError.invalidResponse }

        var components = URLComponents(url: baseURL.appendingPathComponent("webapi/\(endpoint.path)"), resolvingAgainstBaseURL: false)!
        components.queryItems = [
            URLQueryItem(name: "api", value: api),
            URLQueryItem(name: "method", value: method),
            URLQueryItem(name: "version", value: String(version ?? endpoint.maxVersion)),
            URLQueryItem(name: "_sid", value: sid),
        ] + queryItems
        guard let url = components.url else { throw SynologyAPIError.invalidResponse }

        downloadTrustDelegate.clearPendingEvent()
        do {
            let (tempURL, _) = try await downloadSession.download(for: URLRequest(url: url))
            try? FileManager.default.removeItem(at: destination)
            try FileManager.default.moveItem(at: tempURL, to: destination)
        } catch {
            if let event = downloadTrustDelegate.pendingTrustEvent {
                downloadTrustDelegate.clearPendingEvent()
                switch event {
                case .untrusted(let fingerprint, let certificateData):
                    throw SynologyAPIError.certificateUntrusted(host: connection.host, port: connection.port, fingerprint: fingerprint, leafCertData: certificateData)
                case .changed(let old, let new, let newCertificateData):
                    throw SynologyAPIError.certificateChanged(host: connection.host, port: connection.port, oldFingerprint: old, newFingerprint: new, newCertificateData: newCertificateData)
                }
            }
            throw SynologyAPIError.hostUnreachable(underlying: error)
        }
    }

    // MARK: - Transport

    private func send(_ request: URLRequest) async throws -> Data {
        trustDelegate.clearPendingEvent()
        do {
            let (data, _) = try await session.data(for: request)
            return data
        } catch {
            if let event = trustDelegate.pendingTrustEvent {
                trustDelegate.clearPendingEvent()
                switch event {
                case .untrusted(let fingerprint, let certificateData):
                    throw SynologyAPIError.certificateUntrusted(host: connection.host, port: connection.port, fingerprint: fingerprint, leafCertData: certificateData)
                case .changed(let old, let new, let newCertificateData):
                    throw SynologyAPIError.certificateChanged(host: connection.host, port: connection.port, oldFingerprint: old, newFingerprint: new, newCertificateData: newCertificateData)
                }
            }
            throw SynologyAPIError.hostUnreachable(underlying: error)
        }
    }

    private func decodeJSON<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        do {
            return try JSONDecoder().decode(type, from: data)
        } catch {
            throw SynologyAPIError.decodingError(error)
        }
    }
}
