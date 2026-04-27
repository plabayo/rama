import AppKit
import Foundation
import Security
import XPC

/// MITM CA management split across the container app and the system extension.
///
/// The CA cert and private key PEM live in the System Keychain, encrypted by
/// a Secure-Enclave-bound key (see `tls/secure_enclave.rs` in the Rust
/// example). The container app cannot decrypt those PEMs, so the cert
/// keychain item add/delete is performed by the sysext (running as root, no
/// auth prompt) over a **typed XPC route** — see
/// `installRootCA:withReply:` and `uninstallRootCA:withReply:` in
/// `demo_xpc_server.rs`.
///
/// The sysext returns the DER-encoded cert in its reply, and the container
/// then sets or removes the **admin** trust setting locally — trust
/// changes go through Authorization Services and require the interactive
/// admin auth dialog, which only a UI process can present.
extension ContainerController {
    private static let trustDomain: SecTrustSettingsDomain = .admin

    /// Install root CA flow:
    ///   1. Send the `installRootCA:withReply:` typed XPC request
    ///      (auto-starts the provider if needed). The sysext adds the cert
    ///      to `/Library/Keychains/System.keychain` and returns the DER.
    ///   2. Locally call `SecTrustSettingsSetTrustSettings(.admin, NULL)`
    ///      on that cert. macOS will prompt for administrator credentials.
    func installMITMCA() {
        log("installMITMCA: dispatching installRootCA:withReply: over XPC")
        sendXpcRequestEnsuringActive(selector: "installRootCA:withReply:") { [weak self] result in
            guard let self else { return }
            switch result {
            case .success(let reply):
                self.handleInstallReply(reply)
            case .failure(let error):
                self.logError("installMITMCA: xpc command failed", error)
                self.showCommandErrorAlert(
                    title: "Install Root CA", message: error.localizedDescription)
            }
        }
    }

    /// Uninstall root CA flow:
    ///   1. Send the `uninstallRootCA:withReply:` typed XPC request
    ///      (auto-starts if needed). The sysext removes the cert from the
    ///      System Keychain and returns the DER for any cert it actually
    ///      deleted (or `null` when no CA is stored).
    ///   2. Locally call `SecTrustSettingsRemoveTrustSettings(.admin)` on
    ///      that cert (admin prompt) — best-effort, as the trust setting
    ///      may not exist if the user never installed it.
    ///   3. Wipe the SE-encrypted PEM blobs from the System Keychain
    ///      regardless of the remote outcome, so the next provider start
    ///      regenerates a fresh CA.
    func clearCA() {
        log("clearCA: dispatching uninstallRootCA:withReply: over XPC")
        sendXpcRequestEnsuringActive(selector: "uninstallRootCA:withReply:") { [weak self] result in
            guard let self else { return }
            switch result {
            case .success(let reply):
                self.handleUninstallReply(reply)
            case .failure(let error):
                self.logError("clearCA: xpc command failed; continuing with local wipe", error)
            }
            self.wipeStoredCASecretsLocally()
        }
    }

    // MARK: - Reply handling

    private func handleInstallReply(_ reply: xpc_object_t) {
        let parsed = parseRootCaReply(reply, op: "installRootCA", title: "Install Root CA")
        guard parsed.ok, let cert = parsed.certificate else {
            return
        }
        let trustStatus = SecTrustSettingsSetTrustSettings(cert, Self.trustDomain, nil)
        if trustStatus == errSecSuccess {
            log("installMITMCA: admin trust granted to MITM CA")
        } else {
            logErrorText(
                "installMITMCA: SecTrustSettingsSetTrustSettings failed (OSStatus \(trustStatus))"
            )
            showCommandErrorAlert(
                title: "Install Root CA",
                message: "macOS rejected the trust update (OSStatus \(trustStatus))."
            )
        }
    }

    private func handleUninstallReply(_ reply: xpc_object_t) {
        let parsed = parseRootCaReply(reply, op: "uninstallRootCA", title: "Clear Root CA")
        guard parsed.ok else { return }
        guard let cert = parsed.certificate else {
            // Sysext reported success but had no cert to return — nothing
            // was installed to begin with, so there's no admin-domain
            // trust to remove either.
            log("clearCA: sysext reported no stored CA; skipping local trust removal")
            return
        }
        let trustStatus = SecTrustSettingsRemoveTrustSettings(cert, Self.trustDomain)
        if trustStatus == errSecSuccess {
            log("clearCA: admin trust removed from MITM CA")
        } else if trustStatus == errSecItemNotFound {
            log("clearCA: no admin trust setting was present (already clean)")
        } else {
            logErrorText(
                "clearCA: SecTrustSettingsRemoveTrustSettings failed (OSStatus \(trustStatus))"
            )
        }
    }

    // MARK: - Reply parsing

    private struct ParsedRootCaReply {
        let ok: Bool
        let certificate: SecCertificate?
    }

    /// Parse the `$result` dictionary returned by the typed XPC router,
    /// expressing `RootCaCommandReply { ok, error, cert_der_b64 }`.
    private func parseRootCaReply(
        _ reply: xpc_object_t,
        op: String,
        title: String
    ) -> ParsedRootCaReply {
        guard xpc_get_type(reply) == XPC_TYPE_DICTIONARY else {
            logErrorText("\(op): xpc reply is not a dictionary")
            return ParsedRootCaReply(ok: false, certificate: nil)
        }
        guard let resultDict = xpc_dictionary_get_dictionary(reply, "$result") else {
            logErrorText("\(op): xpc reply missing $result")
            return ParsedRootCaReply(ok: false, certificate: nil)
        }

        let ok = xpc_dictionary_get_bool(resultDict, "ok")
        guard ok else {
            let message = xpcDictionaryString(resultDict, "error") ?? "unknown sysext error"
            logErrorText("\(op): sysext reported failure: \(message)")
            showCommandErrorAlert(title: title, message: message)
            return ParsedRootCaReply(ok: false, certificate: nil)
        }

        let certificate: SecCertificate? = {
            guard let b64 = xpcDictionaryString(resultDict, "cert_der_b64"),
                let derData = Data(base64Encoded: b64)
            else {
                return nil
            }
            guard let cert = SecCertificateCreateWithData(nil, derData as CFData) else {
                self.logErrorText("\(op): SecCertificateCreateWithData failed for reply DER")
                return nil
            }
            return cert
        }()

        log("\(op): success; cert_der_present=\(certificate != nil)")
        return ParsedRootCaReply(ok: true, certificate: certificate)
    }

    private func xpcDictionaryString(_ dict: xpc_object_t, _ key: String) -> String? {
        guard let cstr = xpc_dictionary_get_string(dict, key) else { return nil }
        let str = String(cString: cstr)
        return str.isEmpty ? nil : str
    }

    // MARK: - Local secret wipe (no decryption needed)

    /// Delete the CA-related generic-password entries from the System
    /// Keychain. These store the SE-encrypted (or plaintext-fallback) PEMs
    /// and the SE key blob; deleting them does not require decryption.
    /// macOS may prompt for administrator credentials.
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
