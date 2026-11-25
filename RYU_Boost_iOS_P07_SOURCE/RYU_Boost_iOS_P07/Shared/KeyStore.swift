import Foundation
import Security

enum KeyStore {
    private static func group() throws -> String {
        guard let value = Bundle.main.object(forInfoDictionaryKey: "RYUKeychainGroup") as? String, !value.isEmpty, !value.contains("$(") else { throw ProfileError("Thiếu nhóm Keychain đã ký") }
        return value
    }
    static func add(_ data: Data) throws -> Data {
        let q: [String:Any] = [kSecClass as String:kSecClassGenericPassword, kSecAttrAccessGroup as String:try group(), kSecAttrService as String:"RYU.Boost.Profile", kSecAttrAccount as String:UUID().uuidString, kSecAttrAccessible as String:kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, kSecValueData as String:data, kSecReturnPersistentRef as String:true]
        var result: CFTypeRef?
        let status = SecItemAdd(q as CFDictionary, &result)
        guard status == errSecSuccess, let ref = result as? Data else { throw ProfileError("Không lưu được Keychain (\(status))") }
        return ref
    }
    static func read(_ ref: Data) throws -> Data {
        let q: [String:Any] = [kSecClass as String:kSecClassGenericPassword, kSecValuePersistentRef as String:ref, kSecReturnData as String:true, kSecMatchLimit as String:kSecMatchLimitOne]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else { throw ProfileError("Không đọc được Keychain (\(status))") }
        return data
    }
    static func remove(_ ref: Data) { SecItemDelete([kSecClass as String:kSecClassGenericPassword, kSecValuePersistentRef as String:ref] as CFDictionary) }
}
