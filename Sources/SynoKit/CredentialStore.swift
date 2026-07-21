import Foundation

/// Persists the list of registered NAS connections, one password per
/// connection, and which one was last selected. Connections and passwords are
/// stored as separate `SecureLocalStore` entries so the non-secret connection
/// list can be read without touching any password entry.
public enum CredentialStore {
    private static var service: String { "\(SecureLocalStore.serviceNamespace).credentials" }
    private static let connectionListAccount = "nas-connections"
    private static let selectedConnectionAccount = "selected-connection-id"
    private static let passwordAccountPrefix = "nas-password:"

    public static func savedConnections() -> [NASConnection] {
        guard let data = SecureLocalStore.read(service: service, account: connectionListAccount) else { return [] }
        return (try? JSONDecoder().decode([NASConnection].self, from: data)) ?? []
    }

    public static func password(for connection: NASConnection) -> String? {
        guard let data = SecureLocalStore.read(service: service, account: passwordAccountPrefix + connection.id) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    @discardableResult
    public static func addOrUpdate(connection: NASConnection, password: String) -> Bool {
        var connections = savedConnections()
        if let index = connections.firstIndex(where: { $0.id == connection.id }) {
            connections[index] = connection
        } else {
            connections.append(connection)
        }
        guard let listData = try? JSONEncoder().encode(connections),
              let passwordData = password.data(using: .utf8) else { return false }
        let savedList = SecureLocalStore.save(service: service, account: connectionListAccount, data: listData)
        let savedPassword = SecureLocalStore.save(service: service, account: passwordAccountPrefix + connection.id, data: passwordData)
        return savedList && savedPassword
    }

    /// Updates a connection's stored metadata without touching its password.
    public static func updateConnection(_ connection: NASConnection) {
        var connections = savedConnections()
        guard let index = connections.firstIndex(where: { $0.id == connection.id }) else { return }
        connections[index] = connection
        if let listData = try? JSONEncoder().encode(connections) {
            SecureLocalStore.save(service: service, account: connectionListAccount, data: listData)
        }
    }

    /// Persists a reordered connection list without touching any password entry.
    public static func saveConnectionOrder(_ connections: [NASConnection]) {
        guard let listData = try? JSONEncoder().encode(connections) else { return }
        SecureLocalStore.save(service: service, account: connectionListAccount, data: listData)
    }

    public static func remove(connection: NASConnection) {
        var connections = savedConnections()
        connections.removeAll { $0.id == connection.id }
        if let listData = try? JSONEncoder().encode(connections) {
            SecureLocalStore.save(service: service, account: connectionListAccount, data: listData)
        }
        SecureLocalStore.delete(service: service, account: passwordAccountPrefix + connection.id)
    }

    public static func selectedConnectionID() -> String? {
        guard let data = SecureLocalStore.read(service: service, account: selectedConnectionAccount) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    public static func setSelectedConnectionID(_ id: String?) {
        guard let id, let data = id.data(using: .utf8) else {
            SecureLocalStore.delete(service: service, account: selectedConnectionAccount)
            return
        }
        SecureLocalStore.save(service: service, account: selectedConnectionAccount, data: data)
    }
}
