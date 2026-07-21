import Foundation
import CryptoKit
import SynoKit

let checks = Checks()
let connection = NASConnection(host: "nas.test", port: 5001, username: "me")

func isCase(_ error: Error?, _ matcher: (SynologyAPIError) -> Bool) -> Bool {
    guard let e = error as? SynologyAPIError else { return false }
    return matcher(e)
}

// MARK: - Core types

checks.section("Core types")

let conn = NASConnection(host: "nas.local", port: 5001, username: "u")
checks.expectEqual(conn.baseURL?.absoluteString, "https://nas.local:5001", "baseURL builds https URL")
checks.expectEqual(conn.id, "nas.local:5001", "id is host:port")

checks.expectEqual(
    CertificateFingerprint.sha256(of: Data()),
    "E3:B0:C4:42:98:FC:1C:14:9A:FB:F4:C8:99:6F:B9:24:27:AE:41:E4:64:9B:93:4C:A4:95:99:1B:78:52:B8:55",
    "SHA-256 of empty data matches known vector"
)

checks.expect(isCase(SynologyAPIError.fromAuthErrorCode(400)) { if case .invalidCredentials = $0 { return true }; return false }, "auth 400 → invalidCredentials")
checks.expect(isCase(SynologyAPIError.fromAuthErrorCode(403)) { if case .otpRequired = $0 { return true }; return false }, "auth 403 → otpRequired")
checks.expect(isCase(SynologyAPIError.fromAuthErrorCode(406)) { if case .otpRequired = $0 { return true }; return false }, "auth 406 → otpRequired")
checks.expect(isCase(SynologyAPIError.fromAuthErrorCode(404)) { if case .otpIncorrect = $0 { return true }; return false }, "auth 404 → otpIncorrect")
checks.expect(isCase(SynologyAPIError.fromAuthErrorCode(106)) { if case .sessionExpired = $0 { return true }; return false }, "auth 106 → sessionExpired")
checks.expect(isCase(SynologyAPIError.fromAuthErrorCode(500)) { if case .dsmError(let c) = $0 { return c == 500 }; return false }, "auth 500 → dsmError(500)")

// A non-auth API reusing code 404 must NOT be read as "OTP incorrect".
checks.expect(isCase(SynologyAPIError.fromDataErrorCode(404)) { if case .dsmError(let c) = $0 { return c == 404 }; return false }, "data 404 → raw dsmError(404), not OTP")
checks.expect(isCase(SynologyAPIError.fromDataErrorCode(107)) { if case .sessionExpired = $0 { return true }; return false }, "data 107 → sessionExpired")

do {
    struct S: Decodable { let sid: String }
    let ok = #"{"success":true,"data":{"sid":"ABC"}}"#.data(using: .utf8)!
    let env = try JSONDecoder().decode(DSMEnvelope<S>.self, from: ok)
    checks.expect(env.success && env.data?.sid == "ABC", "envelope decodes success payload")
    let err = #"{"success":false,"error":{"code":403}}"#.data(using: .utf8)!
    let errEnv = try JSONDecoder().decode(DSMEnvelope<S>.self, from: err)
    checks.expect(!errEnv.success && errEnv.error?.code == 403, "envelope decodes error code")
} catch {
    checks.expect(false, "envelope decoding threw: \(error)")
}

// MARK: - Secure local store (isolated temp dir)

checks.section("Secure local store")

let storeDir = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("SynoKitChecks-store-\(UUID().uuidString)")
SecureLocalStore.directoryOverride = storeDir

let secret = "hunter2".data(using: .utf8)!
checks.expect(SecureLocalStore.save(service: "svc", account: "acct", data: secret), "save returns true")
checks.expectEqual(SecureLocalStore.read(service: "svc", account: "acct"), secret, "read returns saved bytes")
checks.expect(SecureLocalStore.read(service: "svc", account: "missing") == nil, "unknown account → nil")

SecureLocalStore.save(service: "svc", account: "plain", data: "plaintext-secret".data(using: .utf8)!)
let onDisk = (try? Data(contentsOf: storeDir.appendingPathComponent("secure_store.json"))).flatMap { String(data: $0, encoding: .utf8) } ?? ""
checks.expect(!onDisk.contains("plaintext-secret"), "secret is encrypted on disk (no cleartext)")

checks.expect(SecureLocalStore.delete(service: "svc", account: "acct"), "delete returns true")
checks.expect(SecureLocalStore.read(service: "svc", account: "acct") == nil, "read after delete → nil")

// BUG-6 regression: many concurrent saves of distinct keys must ALL survive
// (an unlocked read-modify-write loses updates; under TSan this also flags the
// data race). Fails loudly if the store's ioLock ever regresses.
let concN = 50
DispatchQueue.concurrentPerform(iterations: concN) { i in
    _ = SecureLocalStore.save(service: "conc", account: "k\(i)", data: "v\(i)".data(using: .utf8)!)
}
let allSurvived = (0..<concN).allSatisfy {
    SecureLocalStore.read(service: "conc", account: "k\($0)") == "v\($0)".data(using: .utf8)!
}
checks.expect(allSurvived, "concurrent saves all persist (no lost update)")

let credConn = NASConnection(host: "192.168.0.9", port: 5001, username: "me")
checks.expect(CredentialStore.addOrUpdate(connection: credConn, password: "pw"), "credential addOrUpdate")
checks.expectEqual(CredentialStore.savedConnections().map(\.id), [credConn.id], "saved connections list")
checks.expectEqual(CredentialStore.password(for: credConn), "pw", "password round-trips")
CredentialStore.remove(connection: credConn)
checks.expect(CredentialStore.savedConnections().isEmpty, "connections empty after remove")
checks.expect(CredentialStore.password(for: credConn) == nil, "password gone after remove")

SecureLocalStore.directoryOverride = nil
try? FileManager.default.removeItem(at: storeDir)

// MARK: - SynologyClient (stubbed transport)

checks.section("SynologyClient")

// Route the client's on-disk API-info cache into a throwaway dir too.
let clientDir = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("SynoKitChecks-client-\(UUID().uuidString)")
SecureLocalStore.directoryOverride = clientDir

let authInfo = #"{"success":true,"data":{"SYNO.API.Auth":{"path":"auth.cgi","minVersion":1,"maxVersion":6}}}"#

func makeClient() -> SynologyClient {
    let session = StubURLProtocol.makeSession()
    let delegate = CertificateTrustDelegate(host: connection.host, port: connection.port)
    return SynologyClient(connection: connection, session: session, trustDelegate: delegate, apiInfoCache: APIInfoCache())
}

// discover + login success
StubURLProtocol.setHandler { request in
    if request.url!.absoluteString.contains("SYNO.API.Info") { return (200, authInfo.data(using: .utf8)!) }
    checks.expect(request.httpMethod == "POST", "login uses POST (password not in URL)")
    return (200, #"{"success":true,"data":{"sid":"SID-123"}}"#.data(using: .utf8)!)
}
do {
    let client = makeClient()
    try await client.discoverAPIs(["SYNO.API.Auth"])
    checks.expect(client.endpoint(for: "SYNO.API.Auth") != nil, "discovery resolves SYNO.API.Auth")
    try await client.login(username: "me", password: "pw")
    checks.expect(client.isAuthenticated, "login sets authenticated session")
} catch {
    checks.expect(false, "discover+login threw: \(error)")
}

// bad credentials
StubURLProtocol.setHandler { request in
    if request.url!.absoluteString.contains("SYNO.API.Info") { return (200, authInfo.data(using: .utf8)!) }
    return (200, #"{"success":false,"error":{"code":400}}"#.data(using: .utf8)!)
}
do {
    let client = makeClient()
    try await client.discoverAPIs(["SYNO.API.Auth"])
    let err = await checks.captureError { try await client.login(username: "me", password: "wrong") }
    checks.expect(isCase(err) { if case .invalidCredentials = $0 { return true }; return false }, "bad password → invalidCredentials")
    checks.expect(!client.isAuthenticated, "failed login leaves session unauthenticated")
}

// OTP required
StubURLProtocol.setHandler { request in
    if request.url!.absoluteString.contains("SYNO.API.Info") { return (200, authInfo.data(using: .utf8)!) }
    return (200, #"{"success":false,"error":{"code":403}}"#.data(using: .utf8)!)
}
do {
    let client = makeClient()
    try await client.discoverAPIs(["SYNO.API.Auth"])
    let err = await checks.captureError { try await client.login(username: "me", password: "pw") }
    checks.expect(isCase(err) { if case .otpRequired = $0 { return true }; return false }, "2FA account → otpRequired")
}

// request without login
do {
    let client = makeClient()
    let err = await checks.captureError { _ = try await client.requestData(api: "SYNO.Foto.Browse.Item", method: "list") }
    checks.expect(isCase(err) { if case .sessionExpired = $0 { return true }; return false }, "request before login → sessionExpired")
}

// perform decodes payload after login
do {
    struct Album: Decodable, Equatable { let id: Int; let name: String }
    StubURLProtocol.setHandler { request in
        let url = request.url!.absoluteString
        if url.contains("SYNO.API.Info") {
            return (200, #"{"success":true,"data":{"SYNO.API.Auth":{"path":"auth.cgi","minVersion":1,"maxVersion":6},"SYNO.Foto.Browse.Album":{"path":"entry.cgi","minVersion":1,"maxVersion":2}}}"#.data(using: .utf8)!)
        }
        if request.httpMethod == "POST" { return (200, #"{"success":true,"data":{"sid":"SID"}}"#.data(using: .utf8)!) }
        return (200, #"{"success":true,"data":{"id":7,"name":"Trip"}}"#.data(using: .utf8)!)
    }
    do {
        let client = makeClient()
        try await client.discoverAPIs(["SYNO.API.Auth", "SYNO.Foto.Browse.Album"])
        try await client.login(username: "me", password: "pw")
        let album = try await client.perform(Album.self, api: "SYNO.Foto.Browse.Album", method: "get")
        checks.expect(album == Album(id: 7, name: "Trip"), "perform decodes typed payload")
    } catch {
        checks.expect(false, "perform flow threw: \(error)")
    }
}

// session auto-recovery: expired sid → silent re-login → request retried with fresh sid
do {
    struct Album: Decodable, Equatable { let id: Int; let name: String }
    final class Counter: @unchecked Sendable { var logins = 0; var dataCalls = 0 }
    let counter = Counter()
    StubURLProtocol.setHandler { request in
        let url = request.url!.absoluteString
        if url.contains("SYNO.API.Info") {
            return (200, #"{"success":true,"data":{"SYNO.API.Auth":{"path":"auth.cgi","minVersion":1,"maxVersion":6},"SYNO.Foto.Browse.Album":{"path":"entry.cgi","minVersion":1,"maxVersion":2}}}"#.data(using: .utf8)!)
        }
        if request.httpMethod == "POST" {   // login
            counter.logins += 1
            return (200, #"{"success":true,"data":{"sid":"SID-\#(counter.logins)"}}"#.data(using: .utf8)!)
        }
        counter.dataCalls += 1
        if counter.dataCalls == 1 {   // first data request: session expired
            return (200, #"{"success":false,"error":{"code":119}}"#.data(using: .utf8)!)
        }
        checks.expect(url.contains("_sid=SID-2"), "retried request carries the fresh sid")
        return (200, #"{"success":true,"data":{"id":9,"name":"Recovered"}}"#.data(using: .utf8)!)
    }
    do {
        let client = makeClient()
        try await client.discoverAPIs(["SYNO.API.Auth", "SYNO.Foto.Browse.Album"])
        try await client.login(username: "me", password: "pw")
        let album = try await client.perform(Album.self, api: "SYNO.Foto.Browse.Album", method: "get")
        checks.expect(album == Album(id: 9, name: "Recovered"), "session expiry → silent re-login → request succeeds")
        checks.expect(counter.logins == 2, "exactly one re-login happened")
    } catch {
        checks.expect(false, "auto-relogin flow threw: \(error)")
    }
}

StubURLProtocol.setHandler(nil)
SecureLocalStore.directoryOverride = nil
try? FileManager.default.removeItem(at: clientDir)

// MARK: - Migration compat (namespace + legacy key)

checks.section("Migration compat")

let compatDir = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("SynoKitChecks-compat-\(UUID().uuidString)")
SecureLocalStore.directoryOverride = compatDir

// serviceNamespace must flow into the on-disk key so a host app can point at
// its pre-existing entries (SynologyMonitor: "com.synologymonitor").
SecureLocalStore.serviceNamespace = "com.example.app"
let nsConn = NASConnection(host: "n", port: 5001, username: "u", macAddress: "AA:BB:CC:DD:EE:FF")
CredentialStore.addOrUpdate(connection: nsConn, password: "pw")
checks.expect(CredentialStore.password(for: nsConn) == "pw", "namespaced credential round-trips")
checks.expect(nsConn.macAddress == "AA:BB:CC:DD:EE:FF", "NASConnection carries macAddress")
let rawJSON = (try? Data(contentsOf: compatDir.appendingPathComponent("secure_store.json"))).flatMap { String(data: $0, encoding: .utf8) } ?? ""
checks.expect(rawJSON.contains("com.example.app.credentials"), "on-disk key uses configured serviceNamespace")

// Legacy key fallback: seal a value under a host app's *old* key, then confirm
// SecureLocalStore reads it via legacyKeyProvider and re-seals under the master.
let legacyKey = SymmetricKey(data: SHA256.hash(data: Data("legacy-seed".utf8)))
let legacySecret = Data("legacy-value".utf8)
let sealed = try! AES.GCM.seal(legacySecret, using: legacyKey).combined!
// Write a raw entry the way SecureLocalStore stores them: base64 under "service|account".
let entryKey = "svc|legacy-acct"
var entries = (try? JSONDecoder().decode([String: String].self, from: Data(contentsOf: compatDir.appendingPathComponent("secure_store.json")))) ?? [:]
entries[entryKey] = sealed.base64EncodedString()
try! JSONEncoder().encode(entries).write(to: compatDir.appendingPathComponent("secure_store.json"))

checks.expect(SecureLocalStore.read(service: "svc", account: "legacy-acct") == nil, "legacy entry unreadable without provider")
SecureLocalStore.legacyKeyProvider = { legacyKey }
checks.expect(SecureLocalStore.read(service: "svc", account: "legacy-acct") == legacySecret, "legacy entry read via legacyKeyProvider")
SecureLocalStore.legacyKeyProvider = nil
checks.expect(SecureLocalStore.read(service: "svc", account: "legacy-acct") == legacySecret, "legacy entry re-sealed under master key (reads without provider)")

SecureLocalStore.serviceNamespace = "com.synokit"
SecureLocalStore.directoryOverride = nil
try? FileManager.default.removeItem(at: compatDir)

checks.finish()
