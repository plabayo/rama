import Foundation
import Security

private let kTrustDomain: SecTrustSettingsDomain = SecTrustSettingsDomain.system

extension ContainerController {
    /// Remove the MITM CA completely:
    ///   1. Remove trust settings (so the CA is no longer trusted for TLS).
    ///   2. Delete the certificate item from the System Keychain.
    ///   3. Delete the PEM generic-password secrets used by the sysext.
    ///
    /// All three steps are best-effort and idempotent — it is not an error if any
    /// item does not exist. Trust is removed first while the cert is still readable.
    /// The sysext will generate a fresh CA the next time it starts.
    func clearCA() {
        // 1. Remove trust settings (need the cert to identify the trust entry).
        if let cert = loadMITMCACertificate() {
            let trustStatus = SecTrustSettingsRemoveTrustSettings(cert, kTrustDomain)
            if trustStatus != errSecSuccess && trustStatus != errSecItemNotFound {
                log("clearCA: SecTrustSettingsRemoveTrustSettings failed (OSStatus \(trustStatus))")
            } else {
                log("clearCA: trust settings removed (or were not present)")
            }

            // 2. Delete the certificate item from the keychain.
            let deleteQuery: [CFString: Any] = [
                kSecClass: kSecClassCertificate,
                kSecValueRef: cert,
            ]
            let deleteCertStatus = SecItemDelete(deleteQuery as CFDictionary)
            if deleteCertStatus != errSecSuccess && deleteCertStatus != errSecItemNotFound {
                log("clearCA: certificate item delete failed (OSStatus \(deleteCertStatus))")
            } else {
                log("clearCA: certificate item deleted (or was not present)")
            }
        }

        // 3. Delete the PEM generic-password secrets from the System Keychain.
        var keychainRef: SecKeychain?
        let openStatus = SecKeychainOpen("/Library/Keychains/System.keychain", &keychainRef)
        guard openStatus == errSecSuccess, let keychain = keychainRef else {
            log("clearCA: SecKeychainOpen failed (OSStatus \(openStatus))")
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
                log("clearCA: find failed for \(service) (OSStatus \(findStatus))")
                continue
            }
            let deleteStatus = SecKeychainItemDelete(keychainItem)
            if deleteStatus != errSecSuccess {
                log("clearCA: delete failed for \(service) (OSStatus \(deleteStatus))")
            }
        }
    }

    /// Install the MITM CA as a trusted certificate:
    ///   1. Add the certificate item to the System Keychain (visible in Keychain Access).
    ///   2. Set trust settings in the system domain (system-wide trust for TLS).
    ///
    /// The CA must already exist as a PEM generic-password in the System Keychain —
    /// start the proxy at least once first so the sysext can create it.
    /// macOS will prompt for administrator credentials.
    func installMITMCA() {
        guard let cert = loadMITMCACertificate() else { return }

        // 1. Add the certificate item to the user's login keychain. The System Keychain at
        // /Library/Keychains/System.keychain requires root to write certificate items,
        // so we store it in the login keychain where the app has write access. Trust
        // settings are indexed by certificate hash, not by which keychain holds the item.
        let addStatus = SecCertificateAddToKeychain(cert, nil)
        if addStatus != errSecSuccess && addStatus != errSecDuplicateItem {
            log("installMITMCA: SecCertificateAddToKeychain failed (OSStatus \(addStatus))")
            return
        }

        // 2. Set trust settings so the CA is trusted for TLS system-wide.
        let trustStatus = SecTrustSettingsSetTrustSettings(cert, kTrustDomain, nil)
        if trustStatus != errSecSuccess {
            log("installMITMCA: SecTrustSettingsSetTrustSettings failed (OSStatus \(trustStatus))")
            return
        }

        log("installMITMCA: CA certificate added to login keychain and marked trusted")
    }

    /// Read the CA certificate PEM from the System Keychain generic-password and
    /// return a SecCertificate. Returns nil (with a log entry) if absent or unparseable.
    private func loadMITMCACertificate() -> SecCertificate? {
        var keychainRef: SecKeychain?
        let openStatus = SecKeychainOpen("/Library/Keychains/System.keychain", &keychainRef)
        guard openStatus == errSecSuccess, let keychain = keychainRef else {
            log("loadMITMCACertificate: SecKeychainOpen failed (OSStatus \(openStatus))")
            return nil
        }

        var passwordLength: UInt32 = 0
        var passwordData: UnsafeMutableRawPointer?
        let findStatus = Self.secretServiceCertPEM.withCString { serviceCStr in
            Self.secretAccount.withCString { accountCStr in
                SecKeychainFindGenericPassword(
                    keychain,
                    UInt32(Self.secretServiceCertPEM.utf8.count), serviceCStr,
                    UInt32(Self.secretAccount.utf8.count), accountCStr,
                    &passwordLength, &passwordData,
                    nil
                )
            }
        }

        if findStatus == errSecItemNotFound {
            log("loadMITMCACertificate: CA cert not found — start the proxy first")
            return nil
        }
        guard findStatus == errSecSuccess, let rawData = passwordData, passwordLength > 0 else {
            log("loadMITMCACertificate: find failed (OSStatus \(findStatus))")
            return nil
        }

        let pemData = Data(bytes: rawData, count: Int(passwordLength))
        SecKeychainItemFreeContent(nil, rawData)

        guard let pemString = String(data: pemData, encoding: .utf8) else {
            log("loadMITMCACertificate: cert PEM is not valid UTF-8")
            return nil
        }

        // Strip PEM header/footer lines and base64-decode the body to get DER bytes.
        let b64 = pemString
            .components(separatedBy: "\n")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty && !$0.hasPrefix("-----") }
            .joined()
        guard let derData = Data(base64Encoded: b64) else {
            log("loadMITMCACertificate: failed to base64-decode cert body")
            return nil
        }

        guard let cert = SecCertificateCreateWithData(nil, derData as CFData) else {
            log("loadMITMCACertificate: SecCertificateCreateWithData failed — invalid DER")
            return nil
        }
        return cert
    }
}
