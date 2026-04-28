import AppKit
import Foundation
import RamaAppleNetworkExtension
import RamaAppleXpcClient
import Security

/// MITM CA management split across the container app and the system extension.
///
/// The CA cert and private key PEM live in the System Keychain encrypted by
/// a Secure-Enclave-bound key (see `tls/secure_enclave.rs` in the Rust
/// example). The container app cannot decrypt those PEMs, so the cert
/// keychain item add/delete is performed by the sysext (running as root, no
/// auth prompt) over the typed XPC routes
/// `RamaTproxyInstallRootCA` / `RamaTproxyUninstallRootCA`.
///
/// The sysext returns the DER-encoded cert in its reply, and the container
/// then sets or removes the **admin** trust setting locally — trust changes
/// go through Authorization Services and need an interactive admin auth
/// dialog, which only a UI process can present.
extension ContainerController {
    private static let trustDomain: SecTrustSettingsDomain = .admin

    /// Install root CA flow: send the typed XPC request (auto-starts the
    /// provider if needed), then locally apply admin trust to the
    /// returned cert.
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

    /// Uninstall root CA flow: send the typed XPC request (auto-starts if
    /// needed), drop admin trust on the returned cert, then locally wipe
    /// the SE-encrypted PEM blobs so the next provider start regenerates.
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

    // MARK: - Reply handling

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

    /// Decode the optional `cert_der_b64` field into a `SecCertificate`.
    /// Returns `nil` if the sysext reported failure, the field is absent,
    /// or the DER fails to parse.
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

    // MARK: - Local secret wipe (no decryption needed)

    /// Delete the CA-related generic-password entries from the System
    /// Keychain. These store the SE-encrypted (or plaintext-fallback)
    /// PEMs and the SE key blob; deleting them does not require
    /// decryption. macOS may prompt for administrator credentials.
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
