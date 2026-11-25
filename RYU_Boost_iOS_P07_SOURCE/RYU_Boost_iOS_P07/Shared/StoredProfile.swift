import Foundation

// Only stored in shared Keychain. Never serialize into preferences or reports.
struct VPNCredentials: Codable, Equatable {
    let username: String
    let password: String
    func validate() throws {
        for value in [username, password] {
            guard !value.isEmpty, value.utf8.count <= 1024,
                  !value.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
                throw ProfileError("Thông tin xác thực VPN không hợp lệ")
            }
        }
    }
}
struct StoredProfile: Codable {
    private static let prefix = Data("RYU-PROFILE-V1\n".utf8)
    let text: String
    let credentials: VPNCredentials?
    func kind() throws -> VPNKind {
        let kind = try ProfileKind.inspect(text)
        if kind == .openvpn {
            let p = try OVPNProfile.parse(text)
            guard p.requiresCredentials == (credentials != nil) else { throw ProfileError("Thiếu hoặc thừa thông tin xác thực OpenVPN") }
            try credentials?.validate()
        } else if credentials != nil { throw ProfileError("WireGuard không dùng username/password") }
        return kind
    }
    func encodeForKeychain() throws -> Data {
        _ = try kind()
        // Preserve legacy plain UTF-8 for WG and certificate-only OVPN.
        guard credentials != nil else { return Data(text.utf8) }
        return Self.prefix + (try JSONEncoder().encode(self))
    }
    static func decode(_ data: Data) throws -> StoredProfile {
        guard data.count <= 150000 else { throw ProfileError("Profile lưu trữ quá lớn") }
        let result: StoredProfile
        if data.starts(with: prefix) {
            do { result = try JSONDecoder().decode(Self.self, from: Data(data.dropFirst(prefix.count))) }
            catch { throw ProfileError("Dữ liệu profile lưu trữ không hợp lệ") }
        } else {
            guard let text = String(data: data, encoding: .utf8) else { throw ProfileError("Profile không đọc được") }
            result = StoredProfile(text: text, credentials: nil)
        }
        _ = try result.kind()
        return result
    }
}
