import Foundation

enum VPNKind: String, Codable { case wireguard, openvpn }

// Deliberately small, self-contained UDP profile subset.
// Preserve original bytes for OpenVPN3's own parser; this is not a general parser.
struct OVPNProfile {
    let text: String
    let requiresCredentials: Bool
    let hasClientCertificate: Bool
    static func parse(_ text: String) throws -> OVPNProfile {
        guard !text.isEmpty, text.utf8.count <= 65536, !text.contains("\0") else { throw ProfileError("Profile OVPN không hợp lệ hoặc quá lớn") }
        var block: String?; var blocks = Set<String>(); var nonempty = false
        var directives = [String: [String]]()
        let tags: Set<String> = ["ca", "cert", "key", "tls-auth", "tls-crypt"]
        let allowed: Set<String> = ["client", "dev", "proto", "remote", "remote-cert-tls", "verify-x509-name", "resolv-retry", "nobind", "persist-key", "persist-tun", "verb", "cipher", "data-ciphers", "auth", "auth-nocache", "auth-user-pass", "key-direction", "tls-version-min", "reneg-sec", "connect-retry", "connect-timeout", "explicit-exit-notify", "tun-mtu", "mssfix", "remote-random", "pull", "redirect-gateway", "route", "route-ipv6", "dhcp-option", "ping", "ping-restart"]
        for raw in text.components(separatedBy: .newlines) {
            let line = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            if let current = block {
                if line == "</\(current)>" {
                    guard nonempty else { throw ProfileError("Khối chứng chỉ trống") }
                    block = nil; nonempty = false
                } else {
                    guard !line.contains("<"), !line.contains(">") else { throw ProfileError("Khối inline không hợp lệ") }
                    if !line.isEmpty { nonempty = true }
                }
                continue
            }
            if line.isEmpty || line.hasPrefix("#") || line.hasPrefix(";") { continue }
            if line.hasPrefix("<") && line.hasSuffix(">") {
                let tag = String(line.dropFirst().dropLast())
                guard tags.contains(tag), blocks.insert(tag).inserted else { throw ProfileError("Khối inline không hỗ trợ hoặc lặp") }
                block = tag; continue
            }
            // Reject quoting/escaping and continuation rather than interpreting them differently from OpenVPN.
            guard !line.contains("\\"), !line.contains("\""), !line.contains("'"), !line.contains("#"), !line.contains(";") else { throw ProfileError("Cú pháp OVPN chưa hỗ trợ") }
            let parts = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
            guard let name = parts.first, allowed.contains(name), directives[name] == nil else { throw ProfileError("Directive không hỗ trợ hoặc lặp; Chỉ nhận profile UDP với dữ liệu xác thực được hỗ trợ") }
            directives[name] = Array(parts.dropFirst())
        }
        guard block == nil, blocks.contains("ca"), blocks.contains("cert") == blocks.contains("key"), !(blocks.contains("tls-auth") && blocks.contains("tls-crypt")), directives["client"] == [], directives["dev"] == ["tun"], directives["remote-cert-tls"] == ["server"] else { throw ProfileError("Cần client TUN, xác minh server, CA inline và cặp cert/key nếu dùng") }
        let auth = directives["auth-user-pass"]
        guard auth == nil || auth == [], auth != nil || blocks.contains("cert") else { throw ProfileError("Cần chứng chỉ client hoặc auth-user-pass không có tên file") }
        guard let proto = directives["proto"], proto.count == 1, ["udp", "udp4", "udp6"].contains(proto[0]), let remote = directives["remote"], remote.count == 2, !remote[0].isEmpty, let port = UInt16(remote[1]), port > 0 else { throw ProfileError("Chỉ hỗ trợ một remote UDP với cổng hợp lệ") }
        guard !remote[0].contains("/") else { throw ProfileError("Remote không hợp lệ") }
        if let mtu = directives["tun-mtu"] { guard mtu.count == 1, let n = Int(mtu[0]), (1280...1500).contains(n) else { throw ProfileError("MTU không hợp lệ") } }
        return OVPNProfile(text: text, requiresCredentials: auth != nil, hasClientCertificate: blocks.contains("cert"))
    }
}

enum ProfileKind {
    static func inspect(_ text: String) throws -> VPNKind {
        if (try? WGProfile.parse(text)) != nil { return .wireguard }
        _ = try OVPNProfile.parse(text)
        return .openvpn
    }
}
