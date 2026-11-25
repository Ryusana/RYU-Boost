import Foundation

struct ProfileError: LocalizedError {
    let reason: String
    var errorDescription: String? { reason }
    init(_ reason: String) { self.reason = reason }
}

// A restricted, single-peer standard WireGuard profile. No executable hooks.
struct WGProfile {
    var interface: [String:String]
    var peer: [String:String]
    static func parse(_ text: String) throws -> WGProfile {
        guard text.utf8.count <= 65536 else { throw ProfileError("Profile quá lớn") }
        var section = "", seen = Set<String>(), a = [String:String](), b = [String:String]()
        let ia: Set<String> = ["privatekey", "address", "dns", "mtu", "listenport"]
        let pa: Set<String> = ["publickey", "presharedkey", "allowedips", "endpoint", "persistentkeepalive"]
        for raw in text.components(separatedBy: .newlines) {
            let line = raw.components(separatedBy: "#")[0].trimmingCharacters(in: .whitespacesAndNewlines)
            if line.isEmpty { continue }
            if line.hasPrefix("[") {
                section = line.lowercased()
                guard ["[interface]", "[peer]"].contains(section), seen.insert(section).inserted else { throw ProfileError("Chỉ hỗ trợ một Interface và một Peer WireGuard chuẩn") }
                continue
            }
            let parts = line.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard parts.count == 2 else { throw ProfileError("Dòng cấu hình không hợp lệ") }
            let key = parts[0].trimmingCharacters(in: .whitespaces).lowercased()
            let val = parts[1].trimmingCharacters(in: .whitespaces)
            guard !val.isEmpty else { throw ProfileError("Giá trị trống") }
            if section == "[interface]", ia.contains(key), a[key] == nil { a[key] = val }
            else if section == "[peer]", pa.contains(key), b[key] == nil { b[key] = val }
            else { throw ProfileError("Trường không hỗ trợ hoặc bị lặp; không dùng cấu hình AWG hay script") }
        }
        for k in ["privatekey", "address"] where a[k] == nil { throw ProfileError("Thiếu trường Interface bắt buộc") }
        for k in ["publickey", "allowedips", "endpoint"] where b[k] == nil { throw ProfileError("Thiếu trường Peer bắt buộc") }
        for v in [a["privatekey"], b["publickey"], b["presharedkey"]].compactMap({ $0 }) {
            guard Data(base64Encoded: v)?.count == 32 else { throw ProfileError("Khóa WireGuard không hợp lệ") }
        }
        if let mtu = a["mtu"] { guard let n = Int(mtu), (1280...1500).contains(n) else { throw ProfileError("MTU ngoài phạm vi P0: 1280–1500") } }
        for val in [a["listenport"], b["persistentkeepalive"]].compactMap({$0}) { guard UInt16(val) != nil else { throw ProfileError("Giá trị số không hợp lệ") } }
        return WGProfile(interface: a, peer: b)
    }
    func list(_ value: String?) -> [String] { (value ?? "").split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter {!$0.isEmpty} }
}
