import Foundation

enum CatalogStorage {
    static let key = "ryu.node.catalog.v1"
    static func load() throws -> NodeCatalog {
        guard let data = UserDefaults.standard.data(forKey: key) else { return NodeCatalog() }
        return try JSONDecoder().decode(NodeCatalog.self, from: data)
    }
    static func save(_ catalog: NodeCatalog) throws {
        UserDefaults.standard.set(try JSONEncoder().encode(catalog), forKey: key)
    }
}
