// Keychain-backed KeyStore (design §6.5, §9.2, §9.3).
//
// Every item is a kSecClassGenericPassword under this service, marked
// kSecAttrAccessibleWhenUnlockedThisDeviceOnly (ThisDeviceOnly: nothing
// migrates to other devices through backups) with kSecAttrSynchronizable
// false. The `.biometryCurrentSet` access policy additionally attaches a
// SecAccessControl with kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
// and the .biometryCurrentSet flag — re-enrolling Face ID invalidates the
// item by definition, which is the documented §9.5 "本机包裹已失效" state.
import Foundation
import Security

public struct KeychainKeyStore: KeyStore {
    /// Keychain service namespace; one app normally uses one service.
    public let service: String

    public init(service: String = "app.keyref.core") {
        self.service = service
    }

    private func baseQuery(_ slot: KeyStoreSlot) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: slot.rawValue,
            kSecAttrSynchronizable as String: false,
        ]
    }

    private func accessControl(_ access: KeyStoreAccess) throws -> SecAccessControl? {
        switch access {
        case .whenUnlockedThisDeviceOnly:
            return nil
        case .biometryCurrentSet:
            var error: Unmanaged<CFError>?
            guard let ac = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                .biometryCurrentSet,
                &error) else {
                throw KeyStoreError.unavailable("SecAccessControlCreateWithFlags failed: \(error.map { String(describing: $0.takeRetainedValue()) } ?? "")")
            }
            return ac
        }
    }

    private func accessibility(_ access: KeyStoreAccess) -> CFString {
        switch access {
        case .whenUnlockedThisDeviceOnly:
            return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        case .biometryCurrentSet:
            return kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        }
    }

    public func store(_ slot: KeyStoreSlot, _ data: Data, access: KeyStoreAccess) throws {
        // Replace semantics: remove first so an access-policy change
        // (e.g. re-enroll after biometry invalidation) cannot collide.
        try? remove(slot)
        var attrs = baseQuery(slot)
        attrs[kSecValueData as String] = data
        attrs[kSecAttrAccessible as String] = accessibility(access)
        if let ac = try accessControl(access) {
            attrs[kSecAttrAccessControl as String] = ac
        }
        let status = SecItemAdd(attrs as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeyStoreError.unavailable("SecItemAdd failed: \(status)")
        }
    }

    public func retrieve(_ slot: KeyStoreSlot) throws -> Data? {
        var query = baseQuery(slot)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            return result as? Data
        case errSecItemNotFound:
            return nil
        case -25306:  // errSecItemInvalidKey: e.g. biometric set changed →
                      // the §9.5 invalid-local-wrap state.
            throw KeyStoreError.unavailable("keychain item unusable: \(status)")
        default:
            throw KeyStoreError.unavailable("SecItemCopyMatching failed: \(status)")
        }
    }

    public func remove(_ slot: KeyStoreSlot) throws {
        let status = SecItemDelete(baseQuery(slot) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeyStoreError.unavailable("SecItemDelete failed: \(status)")
        }
    }

    public func removeAll() throws {
        for slot in KeyStoreSlot.allCases {
            try remove(slot)
        }
    }
}
