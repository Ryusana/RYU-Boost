import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

// Canonical binary prefix; supports both address families, no hostname resolution.
struct RoutePrefix: Hashable {
    let bytes: [UInt8]
    let length: Int
    init(_ raw: String) throws {
        let parts = raw.split(separator: "/", omittingEmptySubsequences: false)
        guard (1...2).contains(parts.count) else { throw ProfileError("IP/CIDR không hợp lệ") }
        let ip = String(parts[0]); let family = ip.contains(":") ? AF_INET6 : AF_INET
        let size = family == AF_INET ? 4 : 16
        var data = [UInt8](repeating: 0, count: size)
        let result = data.withUnsafeMutableBytes { buf in ip.withCString { inet_pton(family, $0, buf.baseAddress!) } }
        guard result == 1 else { throw ProfileError("Chỉ chấp nhận IP hoặc CIDR hợp lệ, không dùng tên miền") }
        let prefix = parts.count == 1 ? size * 8 : Int(parts[1]) ?? -1
        guard (0...size*8).contains(prefix) else { throw ProfileError("Độ dài CIDR không hợp lệ") }
        for index in 0..<size {
            let bits = max(0, min(8, prefix - index*8))
            let mask = UInt8(truncatingIfNeeded: 0xff << (8-bits))
            data[index] &= mask
        }
        bytes = data; length = prefix
    }
    func contains(_ other: RoutePrefix) -> Bool {
        guard bytes.count == other.bytes.count, length <= other.length else { return false }
        for index in bytes.indices {
            let bits = max(0, min(8, length-index*8))
            let mask = UInt8(truncatingIfNeeded: 0xff << (8-bits))
            if bytes[index] & mask != other.bytes[index] & mask { return false }
        }
        return true
    }
    var canonical: String {
        var out = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        _ = bytes.withUnsafeBytes { buf in out.withUnsafeMutableBufferPointer { dest in inet_ntop(bytes.count == 4 ? AF_INET : AF_INET6, buf.baseAddress!, dest.baseAddress!, socklen_t(dest.count)) } }
        return String(cString: out) + "/\(length)"
    }
}

struct SelectiveRoutes {
    let routes: [RoutePrefix]
    let gameCount: Int
    static func plan(_ profile: WGProfile, input: String) throws -> SelectiveRoutes {
        guard input.utf8.count <= 4096 else { throw ProfileError("Danh sách IP quá dài") }
        let tokens = input.split(whereSeparator: { $0 == "," || $0.isWhitespace }).map(String.init)
        guard (1...64).contains(tokens.count) else { throw ProfileError("Nhập 1–64 IP/CIDR game đã xác minh") }
        let permitted = try profile.list(profile.peer["allowedips"]).map(RoutePrefix.init)
        let families = Set(try profile.list(profile.interface["address"]).map { try RoutePrefix($0).bytes.count })
        var result: [RoutePrefix] = []
        func add(_ r: RoutePrefix) throws {
            guard families.contains(r.bytes.count), permitted.contains(where: {$0.contains(r)}) else {
                throw ProfileError("Tuyến không nằm trong AllowedIPs gốc hoặc thiếu địa chỉ cùng họ IP")
            }
            if !result.contains(r) { result.append(r) }
        }
        for item in tokens {
            let r = try RoutePrefix(item)
            // Narrow prefixes only: prevent accidental near-full tunnel.
            guard r.length >= (r.bytes.count == 4 ? 24 : 48) else { throw ProfileError("Tuyến game quá rộng; dùng IPv4 /24–/32 hoặc IPv6 /48–/128") }
            try add(r)
        }
        let gameCount = result.count
        // Preserve provider DNS reachability, but DNS may still be global on iOS.
        for item in profile.list(profile.interface["dns"]) {
            let r = try RoutePrefix(item)
            guard !item.contains("/") else { throw ProfileError("DNS phải là IP đơn") }
            try add(r)
        }
        return SelectiveRoutes(routes: result, gameCount: gameCount)
    }
    func derivedProfile(_ profile: WGProfile) throws -> Data {
        var peer = profile.peer
        peer["allowedips"] = routes.map(\.canonical).joined(separator: ", ")
        let a = profile.interface.keys.sorted().map { "\($0) = \(profile.interface[$0]!)" }
        let b = peer.keys.sorted().map { "\($0) = \(peer[$0]!)" }
        let text = (["[Interface]"] + a + ["", "[Peer]"] + b).joined(separator: "\n") + "\n"
        _ = try WGProfile.parse(text)
        return Data(text.utf8)
    }
}
