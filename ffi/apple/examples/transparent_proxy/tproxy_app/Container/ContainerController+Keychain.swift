import AppKit
import Foundation
import RamaAppleNetworkExtensionAsync
import RamaAppleXpcClient
import Security

/// MITM CA management. Split between sysext (cert add/delete in System
/// Keychain — runs as root, no prompt) and container (admin trust
/// add/remove — needs the auth dialog only a UI process can show).
/// PEMs are SE-encrypted, so the sysext does the keychain side and
/// returns the DER for the container to act on.
extension ContainerController {
    private static let trustDomain: SecTrustSettingsDomain = .admin

    /// Send `installRootCA` to the sysext (auto-starting if needed),
    /// then add admin trust locally to the returned cert.
    func installMITMCA() {
        log("installMITMCA: dispatching installRootCA over XPC")
        let client = RamaXpcClient(serviceName: xpcServiceName)
        let lifecycle = ensureProviderActive
        Task { [weak self] in
            guard let self else { return }
            do {
                let reply = try await client.call(
                    RamaTproxyInstallRootCA.self, ensuringActive: lifecycle)
                self.applyInstallReply(reply)
            } catch {
                self.logError("installMITMCA: xpc command failed", error)
                self.showCommandErrorAlert(
                    title: "Install Root CA",
                    message: error.localizedDescription
                )
            }
        }
    }

    /// Send `uninstallRootCA` to the sysext (auto-starting if needed),
    /// drop admin trust on the returned cert, then wipe the SE-encrypted
    /// PEM blobs so the next provider start regenerates.
    func clearCA() {
        log("clearCA: dispatching uninstallRootCA over XPC")
        let client = RamaXpcClient(serviceName: xpcServiceName)
        let lifecycle = ensureProviderActive
        Task { [weak self] in
            guard let self else { return }
            do {
                let reply = try await client.call(
                    RamaTproxyUninstallRootCA.self, ensuringActive: lifecycle)
                self.applyUninstallReply(reply)
            } catch {
                self.logError("clearCA: xpc command failed; continuing with local wipe", error)
            }
            self.wipeStoredCASecretsLocally()
        }
    }

    private func applyInstallReply(_ reply: RamaTproxyRootCaReply) {
        guard let cert = certificateFromReply(reply, op: "installRootCA") else { return }
        let status = SecTrustSettingsSetTrustSettings(cert, Self.trustDomain, nil)
        if status == errSecSuccess {
            log("installMITMCA: admin trust granted to MITM CA")
        } else {
            logErrorText(
                "installMITMCA: SecTrustSettingsSetTrustSettings failed (OSStatus \(status))"
            )
            showCommandErrorAlert(
                title: "Install Root CA",
                message: "macOS rejected the trust update (OSStatus \(status))."
            )
        }
    }

    private func applyUninstallReply(_ reply: RamaTproxyRootCaReply) {
        guard reply.ok else {
            let message = reply.error ?? "unknown sysext error"
            logErrorText("uninstallRootCA: sysext reported failure: \(message)")
            showCommandErrorAlert(title: "Clear Root CA", message: message)
            return
        }
        guard let cert = certificateFromReply(reply, op: "uninstallRootCA") else {
            log("clearCA: sysext reported no stored CA; skipping local trust removal")
            return
        }
        let status = SecTrustSettingsRemoveTrustSettings(cert, Self.trustDomain)
        if status == errSecSuccess {
            log("clearCA: admin trust removed from MITM CA")
        } else if status == errSecItemNotFound {
            log("clearCA: no admin trust setting was present (already clean)")
        } else {
            logErrorText(
                "clearCA: SecTrustSettingsRemoveTrustSettings failed (OSStatus \(status))"
            )
        }
    }

    /// Decode `cert_der_b64` to `SecCertificate`, surfacing sysext-side
    /// errors via an alert. Returns nil when the sysext returned no
    /// cert (e.g. uninstall with nothing stored) or DER is unparseable.
    private func certificateFromReply(
        _ reply: RamaTproxyRootCaReply,
        op: String
    ) -> SecCertificate? {
        guard reply.ok else {
            let message = reply.error ?? "unknown sysext error"
            logErrorText("\(op): sysext reported failure: \(message)")
            showCommandErrorAlert(title: op, message: message)
            return nil
        }
        guard let b64 = reply.cert_der_b64,
            let derData = Data(base64Encoded: b64)
        else {
            return nil
        }
        guard let cert = SecCertificateCreateWithData(nil, derData as CFData) else {
            logErrorText("\(op): SecCertificateCreateWithData failed for reply DER")
            return nil
        }
        return cert
    }

    /// Delete the CA-related generic-password entries (SE-encrypted PEMs
    /// + SE key blob) from the System Keychain. Deletion doesn't need
    /// decryption; macOS prompts for admin credentials.
    private func wipeStoredCASecretsLocally() {
        var keychainRef: SecKeychain?
        let openStatus = SecKeychainOpen("/Library/Keychains/System.keychain", &keychainRef)
        guard openStatus == errSecSuccess, let keychain = keychainRef else {
            log("wipeStoredCASecretsLocally: SecKeychainOpen failed (OSStatus \(openStatus))")
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
                    "wipeStoredCASecretsLocally: find failed for \(service) (OSStatus \(findStatus))"
                )
                continue
            }
            let deleteStatus = SecKeychainItemDelete(keychainItem)
            if deleteStatus != errSecSuccess {
                log(
                    "wipeStoredCASecretsLocally: delete failed for \(service) (OSStatus \(deleteStatus))"
                )
            } else {
                log("wipeStoredCASecretsLocally: deleted \(service)")
            }
        }
    }

    private func showCommandErrorAlert(title: String, message: String) {
        DispatchQueue.main.async {
            let alert = NSAlert()
            alert.messageText = title
            alert.informativeText = message
            alert.alertStyle = .critical
            alert.addButton(withTitle: "OK")
            alert.runModal()
        }
    }
}
