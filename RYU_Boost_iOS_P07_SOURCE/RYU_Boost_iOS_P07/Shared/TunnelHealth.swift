import Foundation

// Only these three numeric fields may leave the VPN extension. Never expose UAPI raw text.
struct TunnelHealth: Codable, Equatable {
    let rx: UInt64
    let tx: UInt64
    let handshake: UInt64
    static func parse(_ raw: String) -> TunnelHealth? {
        var values = [String: UInt64]()
        let allowed: Set<String> = ["rx_bytes", "tx_bytes", "last_handshake_time_sec"]
        for line in raw.split(whereSeparator: \.isNewline) {
            let pair = line.split(separator: "=", maxSplits: 1)
            guard pair.count == 2 else { continue }
            let key = String(pair[0])
            guard allowed.contains(key) else { continue }
            guard values[key] == nil, let number = UInt64(pair[1]) else { return nil }
            values[key] = number
        }
        guard let rx = values["rx_bytes"], let tx = values["tx_bytes"], let hs = values["last_handshake_time_sec"] else { return nil }
        return TunnelHealth(rx: rx, tx: tx, handshake: hs)
    }
    func recent(now: Double, maxAge: Double = 180) -> Bool {
        let age = now - Double(handshake)
        return handshake > 0 && age >= -5 && age <= maxAge
    }
    func exchanged(since old: TunnelHealth) -> Bool { rx > old.rx && tx > old.tx }
    func status(now: Double) -> String {
        if handshake == 0 { return "Chưa có handshake — chưa xác minh tunnel" }
        if !recent(now: now) { return "Handshake cũ / đồng hồ lệch — không kết luận mất kết nối" }
        return "Handshake gần đây — chưa xác minh ping game"
    }
}
