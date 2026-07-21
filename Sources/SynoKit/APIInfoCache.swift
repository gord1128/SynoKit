import Foundation

/// Caches the discovered `SYNO.API.Info` map per host so it isn't re-queried on
/// every launch, while still allowing a forced re-discovery when a call fails
/// with an "API not found"/version error (e.g. after a DSM firmware upgrade
/// changed an API's path/version).
public actor APIInfoCache {
    public static let shared = APIInfoCache()

    private var memoryCache: [String: APIInfoMap] = [:]

    public init() {}

    private var diskCacheURL: URL? {
        SecureLocalStore.baseDirectory.appendingPathComponent("api-info-cache.json")
    }

    public func map(for hostKey: String) -> APIInfoMap? {
        if let cached = memoryCache[hostKey] {
            return cached
        }
        guard let url = diskCacheURL,
              let data = try? Data(contentsOf: url),
              let allEntries = try? JSONDecoder().decode([String: APIInfoMap].self, from: data) else {
            return nil
        }
        let entry = allEntries[hostKey]
        if let entry {
            memoryCache[hostKey] = entry
        }
        return entry
    }

    public func store(_ map: APIInfoMap, for hostKey: String) {
        memoryCache[hostKey] = map
        guard let url = diskCacheURL else { return }
        var allEntries: [String: APIInfoMap] = [:]
        if let data = try? Data(contentsOf: url),
           let existing = try? JSONDecoder().decode([String: APIInfoMap].self, from: data) {
            allEntries = existing
        }
        allEntries[hostKey] = map
        if let encoded = try? JSONEncoder().encode(allEntries) {
            try? encoded.write(to: url)
        }
    }

    public func invalidate(hostKey: String) {
        memoryCache.removeValue(forKey: hostKey)
    }
}
