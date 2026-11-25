import Foundation

// References only. Raw profiles remain in Keychain. IDs and names are local aliases.
struct NodeRecord: Codable, Equatable, Identifiable {
    let id: UUID
    let name: String
    let ref: Data
    var mtu: Int
    var selectiveCount: Int? = nil
    var kind: VPNKind? = nil
    var protocolKind: VPNKind { kind ?? .wireguard }
}
struct NodeCatalog: Codable {
    private(set) var nodes: [NodeRecord] = []
    static let limit = 6
    mutating func adopt(_ ref: Data, mtu: Int, selectiveCount: Int? = nil, kind: VPNKind = .wireguard) throws -> NodeRecord {
        if let n = nodes.first(where: { $0.ref == ref }) { return n }
        guard nodes.count < Self.limit else { throw ProfileError("Tối đa 6 profile. Xóa một profile không dùng trước.") }
        let index = (1...Self.limit).first { i in !nodes.contains { $0.name == "Node \(i)" } }!
        let n = NodeRecord(id: UUID(), name: "Node \(index)", ref: ref, mtu: mtu, selectiveCount: selectiveCount, kind: kind == .wireguard ? nil : kind)
        nodes.append(n)
        return n
    }
    mutating func setMTU(_ mtu: Int, for ref: Data) {
        guard [0,1420,1380,1280].contains(mtu), let i = nodes.firstIndex(where: {$0.ref == ref}) else { return }
        if nodes[i].protocolKind == .wireguard { nodes[i].mtu = mtu }
    }
    mutating func remove(_ id: UUID, current: Data?) -> NodeRecord? {
        guard let i = nodes.firstIndex(where: {$0.id == id}), nodes[i].ref != current else { return nil }
        return nodes.remove(at:i)
    }
}
struct NodeTrial: Equatable {
    let id: UUID
    let samples: [Double?]
    var score: RouteScore { RouteScore(mtu: 0, samples: samples) }
    var eligible: Bool { samples.count == 8 && score.successes == 8 }
}
enum NodeRanker {
    // Four fresh HTTPS samples in each of two passes, with reversed order in pass 2.
    // No recommendation unless all candidates have completed their trials.
    static func recommend(_ trials: [NodeTrial], baseline: UUID, expected: Set<UUID>) -> UUID? {
        guard Set(trials.map(\.id)) == expected, trials.count == expected.count, trials.allSatisfy({$0.samples.count == 8}),
              let b = trials.first(where: {$0.id == baseline}), b.eligible,
              let bp = b.score.p95, let bm = b.score.median else { return nil }
        return trials.filter { t in
            guard t.id != baseline, t.eligible, let p = t.score.p95, let m = t.score.median else {return false}
            return bp - p >= max(10, bp * 0.15) && m <= bm
        }.sorted { a,b in
            if a.score.p95! == b.score.p95! { return a.id.uuidString < b.id.uuidString }
            return a.score.p95! < b.score.p95!
        }.first?.id
    }
}
