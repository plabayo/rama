import Foundation
import Security

extension ContainerController {
    /// Delete MITM CA secrets from the System Keychain.
    ///
    /// The sysext owns the CA material in the System Keychain. The container app
    /// can only remove it (e.g. on uninstall or rotation). The sysext will create
    /// a fresh CA the next time it starts.
    func cleanSecrets() {
        var keychainRef: SecKeychain?
        let openStatus = SecKeychainOpen("/Library/Keychains/System.keychain", &keychainRef)
        guard openStatus == errSecSuccess, let keychain = keychainRef else {
            log("cleanSecrets: SecKeychainOpen failed (OSStatus \(openStatus))")
            return
        }

        for service in Self.secretServiceKeys {
            var item: SecKeychainItem?
            let findStatus = service.withCString { serviceCStr in
                Self.secretAccount.withCString { accountCStr in
                    SecKeychainFindGenericPassword(
                        keychain,
                        UInt32(service.utf8.count), serviceCStr,
                        UInt32(Self.secretAccount.utf8.count), accountCStr,
                        nil, nil, &item
                    )
                }
            }
            if findStatus == errSecItemNotFound { continue }
            guard findStatus == errSecSuccess, let keychainItem = item else {
                log(
                    "cleanSecrets: find failed for \(service) (OSStatus \(findStatus))"
                )
                continue
            }
            let deleteStatus = SecKeychainItemDelete(keychainItem)
            if deleteStatus != errSecSuccess {
                log(
                    "cleanSecrets: delete failed for \(service) (OSStatus \(deleteStatus))"
                )
            }
        }
    }
}
