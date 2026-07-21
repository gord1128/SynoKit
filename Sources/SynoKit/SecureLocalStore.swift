import Foundation
import CryptoKit
import Security

/// Permanent local replacement for Keychain-backed storage — kept even once
/// packaged as a signed `.app`, since without a paid Developer ID the signing
/// identity isn't stable enough for Keychain's "Always Allow" ACL to stick.
/// Keeps an AES-GCM encrypted blob under Application Support, wrapped by a
/// random 256-bit master key generated once and persisted in its own file
/// (envelope encryption).
///
/// Configure `appDirectoryName` once at host-app launch so two apps sharing
/// SynoKit don't collide. Tests set `directoryOverride` to a temp path.
public enum SecureLocalStore {
    // These statics are configured once at host-app launch, before any
    // concurrent access, so they opt out of Swift 6 global-isolation checking.

    /// Sub-directory of Application Support the store lives in. Host apps set
    /// this at launch (e.g. "SynologyPhotosManager").
    nonisolated(unsafe) public static var appDirectoryName = "SynoKit"

    /// Reverse-DNS prefix that `CredentialStore` / `TrustedCertificateStore`
    /// derive their service names from. Host apps that carry pre-existing
    /// on-disk data must set this to the prefix those entries were written with
    /// (e.g. SynologyMonitor sets "com.synologymonitor") so the data stays
    /// readable after migrating onto SynoKit.
    nonisolated(unsafe) public static var serviceNamespace = "com.synokit"

    /// When set, wins over `appDirectoryName` (used by tests for isolation).
    nonisolated(unsafe) public static var directoryOverride: URL?

    /// Optional fallback key for reading entries sealed by a host app's prior
    /// (pre-SynoKit) scheme. On a read miss under the master key, the entry is
    /// decrypted with this key and transparently re-sealed under the master key.
    /// SynologyMonitor sets this to its legacy username-derived key.
    nonisolated(unsafe) public static var legacyKeyProvider: (@Sendable () -> SymmetricKey)?

    /// The on-disk directory all SynoKit local state lives in (secure store,
    /// master key, API-info cache). Honors `directoryOverride` so tests and
    /// other components share one redirectable location.
    public static var baseDirectory: URL {
        let dir: URL
        if let directoryOverride {
            dir = directoryOverride
        } else {
            let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            dir = base.appendingPathComponent(appDirectoryName, isDirectory: true)
        }
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    private static var fileURL: URL { baseDirectory.appendingPathComponent("secure_store.json") }
    private static var masterKeyURL: URL { baseDirectory.appendingPathComponent("secure_store.key") }

    // Serializes the entries-file read-modify-write (save/delete) so concurrent
    // writes — e.g. saving a password and pinning a cert during one connect —
    // don't lose each other's update. `keyLock` guards the one-time master-key
    // create so two concurrent first writes can't generate two keys. The two are
    // never held nested (encryptionKey is resolved before ioLock is taken).
    private static let ioLock = NSLock()
    private static let keyLock = NSLock()

    /// A random 256-bit key read-or-created from `masterKeyURL`. Computed per
    /// call (not cached) so that switching `directoryOverride` in tests always
    /// pairs the key with the matching data blob.
    private static var encryptionKey: SymmetricKey {
        keyLock.lock(); defer { keyLock.unlock() }
        let url = masterKeyURL
        if let existing = try? Data(contentsOf: url), existing.count == 32 {
            return SymmetricKey(data: existing)
        }
        var randomBytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, randomBytes.count, &randomBytes)
        let key = Data(randomBytes)
        try? key.write(to: url, options: .atomic)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        return SymmetricKey(data: key)
    }

    private static func storageKey(service: String, account: String) -> String {
        "\(service)|\(account)"
    }

    private static func loadEntries() -> [String: String] {
        guard let data = try? Data(contentsOf: fileURL),
              let dict = try? JSONDecoder().decode([String: String].self, from: data) else {
            return [:]
        }
        return dict
    }

    private static func writeEntries(_ entries: [String: String]) {
        guard let data = try? JSONEncoder().encode(entries) else { return }
        try? data.write(to: fileURL, options: .atomic)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fileURL.path)
    }

    @discardableResult
    public static func save(service: String, account: String, data: Data) -> Bool {
        guard let sealed = try? AES.GCM.seal(data, using: encryptionKey),
              let combined = sealed.combined else { return false }
        ioLock.lock(); defer { ioLock.unlock() }
        var entries = loadEntries()
        entries[storageKey(service: service, account: account)] = combined.base64EncodedString()
        writeEntries(entries)
        return true
    }

    public static func read(service: String, account: String) -> Data? {
        guard let base64 = loadEntries()[storageKey(service: service, account: account)],
              let combined = Data(base64Encoded: base64),
              let sealedBox = try? AES.GCM.SealedBox(combined: combined) else {
            return nil
        }
        if let data = try? AES.GCM.open(sealedBox, using: encryptionKey) {
            return data
        }
        // Fall back to a host app's legacy key, then re-seal under the master
        // key so subsequent reads take the fast path above.
        guard let legacyKey = legacyKeyProvider?(),
              let legacyData = try? AES.GCM.open(sealedBox, using: legacyKey) else {
            return nil
        }
        save(service: service, account: account, data: legacyData)
        return legacyData
    }

    @discardableResult
    public static func delete(service: String, account: String) -> Bool {
        ioLock.lock(); defer { ioLock.unlock() }
        var entries = loadEntries()
        entries.removeValue(forKey: storageKey(service: service, account: account))
        writeEntries(entries)
        return true
    }
}
