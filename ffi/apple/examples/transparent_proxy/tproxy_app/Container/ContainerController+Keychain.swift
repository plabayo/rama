import AppKit
import Darwin
import Foundation
import RamaAppleXpcClient
import Security

/// MITM CA install / uninstall / rotate, routed through the sysext via
/// typed XPC so the sysext (which holds the SE-encrypted keychain
/// material) does the keychain item add/remove and we set or remove
/// admin trust locally — only a UI process can present the auth dialog
/// for trust changes.
///
/// Note: in real production code you wouldn't manage CA lifecycle from
/// a sysext over XPC at all — an admin / installer running in user
/// space (or MDM) would do it. This indirection is here purely as a
/// demo of the typed XPC route surface.
extension ContainerController {
    private static let trustDomain: SecTrustSettingsDomain = .admin

    /// Send `installRootCA` and apply admin trust to the returned cert.
    /// Requires the proxy to be running.
    func installMITMCA() {
        guard isProviderActive() else {
            log("installMITMCA: proxy not active; skipping")
            showProviderInactiveAlert(action: "Install Root CA")
            return
        }
        log("installMITMCA: dispatching installRootCA over XPC")
        let client = ramaXpcClient
        Task { @MainActor [weak self] in
            guard let self else { return }
            do {
                let reply = try await client.call(RamaTproxyInstallRootCA.self)
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

    /// Send `uninstallRootCA`, drop admin trust on the returned cert,
    /// then wipe the SE-encrypted PEM blobs so the next provider start
    /// regenerates a fresh CA. Requires the proxy to be running.
    func clearCA() {
        guard isProviderActive() else {
            log("clearCA: proxy not active; skipping")
            showProviderInactiveAlert(action: "Clear Root CA")
            return
        }
        log("clearCA: dispatching uninstallRootCA over XPC")
        let client = ramaXpcClient
        Task { @MainActor [weak self] in
            guard let self else { return }
            do {
                let reply = try await client.call(RamaTproxyUninstallRootCA.self)
                self.applyUninstallReply(reply)
                self.wipeStoredCASecretsLocally()
            } catch {
                self.logError("clearCA: xpc command failed; continuing with local wipe", error)
                self.wipeStoredCASecretsLocally()
            }
        }
    }

    /// Launch-time `--clean-secrets`. The provider isn't active yet, so
    /// `clearCA()`'s XPC path would no-op; wipe locally and let the sysext
    /// regenerate on start.
    func clearStoredCAForLaunch() {
        log("clean-secrets: wiping stored MITM CA material before start")
        wipeStoredCASecretsLocally()
    }

    /// Rotate the MITM CA. When the proxy is active, swap the live CA
    /// via XPC and update admin trust to match. When inactive, fall
    /// back to a plain wipe — the next start regenerates.
    func rotateMITMCAAndApply() {
        guard isProviderActive() else {
            log("rotateMITMCA: proxy not active; falling back to local wipe")
            wipeStoredCASecretsLocally()
            return
        }
        log("rotateMITMCA: dispatching rotateRootCA over XPC")
        let client = ramaXpcClient
        Task { @MainActor [weak self] in
            guard let self else { return }
            do {
                let reply = try await client.call(RamaTproxyRotateRootCA.self)
                self.applyRotateReply(reply)
            } catch {
                self.logError("rotateMITMCA: xpc command failed", error)
                self.showCommandErrorAlert(
                    title: "Rotate Root CA",
                    message: error.localizedDescription
                )
            }
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
        removeAdminTrust(on: cert, op: "clearCA")
    }

    private func applyRotateReply(_ reply: RamaTproxyRotateRootCA.Reply) {
        guard reply.ok else {
            let message = reply.error ?? "unknown sysext error"
            logErrorText("rotateRootCA: sysext reported failure: \(message)")
            showCommandErrorAlert(title: "Rotate Root CA", message: message)
            return
        }

        if let prevB64 = reply.previous_cert_der_b64,
            let cert = certificate(fromBase64: prevB64, op: "rotateRootCA (previous)")
        {
            removeAdminTrust(on: cert, op: "rotateRootCA")
        }

        guard let newB64 = reply.new_cert_der_b64,
            let newCert = certificate(fromBase64: newB64, op: "rotateRootCA (new)")
        else {
            logErrorText("rotateRootCA: reply missing new cert DER")
            return
        }
        let status = SecTrustSettingsSetTrustSettings(newCert, Self.trustDomain, nil)
        if status == errSecSuccess {
            log("rotateRootCA: admin trust granted to rotated MITM CA")
        } else {
            logErrorText(
                "rotateRootCA: SecTrustSettingsSetTrustSettings failed (OSStatus \(status))"
            )
            showCommandErrorAlert(
                title: "Rotate Root CA",
                message: "macOS rejected the trust update (OSStatus \(status))."
            )
        }
    }

    /// Drop admin trust on `cert`. `errSecItemNotFound` is treated as
    /// "already clean" — common when the user never installed it.
    private func removeAdminTrust(on cert: SecCertificate, op: String) {
        let status = SecTrustSettingsRemoveTrustSettings(cert, Self.trustDomain)
        if status == errSecSuccess {
            log("\(op): admin trust removed from MITM CA")
        } else if status == errSecItemNotFound {
            log("\(op): no admin trust setting was present (already clean)")
        } else {
            logErrorText(
                "\(op): SecTrustSettingsRemoveTrustSettings failed (OSStatus \(status))"
            )
        }
    }

    /// Decode `cert_der_b64` to `SecCertificate`. Surfaces sysext-side
    /// errors via an alert; returns nil when no cert is present.
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
        guard let b64 = reply.cert_der_b64 else { return nil }
        return certificate(fromBase64: b64, op: op)
    }

    private func certificate(fromBase64 b64: String, op: String) -> SecCertificate? {
        guard let derData = Data(base64Encoded: b64) else { return nil }
        guard let cert = SecCertificateCreateWithData(nil, derData as CFData) else {
            logErrorText("\(op): SecCertificateCreateWithData failed for reply DER")
            return nil
        }
        return cert
    }

    /// Delete the CA-related generic-password entries (SE-encrypted
    /// PEMs + SE key blob) from the System Keychain. macOS prompts for
    /// admin credentials.
    private func wipeStoredCASecretsLocally() {
        typealias OpenFn = @convention(c) (
            UnsafePointer<CChar>, UnsafeMutablePointer<Unmanaged<SecKeychain>?>
        ) -> OSStatus

        // Security has no nondeprecated API for opening a named legacy keychain.
        guard let processHandle = dlopen(nil, RTLD_LAZY) else {
            log("wipeStoredCASecretsLocally: process symbol table unavailable")
            return
        }
        defer { dlclose(processHandle) }
        guard let openSymbol = dlsym(processHandle, "SecKeychainOpen") else {
            log("wipeStoredCASecretsLocally: legacy keychain symbols unavailable")
            return
        }
        let open = unsafeBitCast(openSymbol, to: OpenFn.self)

        var retainedKeychain: Unmanaged<SecKeychain>?
        let openStatus = "/Library/Keychains/System.keychain".withCString {
            open($0, &retainedKeychain)
        }
        guard openStatus == errSecSuccess, let keychain = retainedKeychain?.takeRetainedValue()
        else {
            log("wipeStoredCASecretsLocally: SecKeychainOpen failed (OSStatus \(openStatus))")
            return
        }

        for service in Self.secretServiceKeys {
            let query: [CFString: Any] = [
                kSecClass: kSecClassGenericPassword,
                kSecAttrService: service,
                kSecAttrAccount: Self.secretAccount,
                kSecMatchSearchList: [keychain],
            ]
            let deleteStatus = SecItemDelete(query as CFDictionary)
            if deleteStatus == errSecItemNotFound { continue }
            if deleteStatus != errSecSuccess {
                log(
                    "wipeStoredCASecretsLocally: delete failed for \(service) (OSStatus \(deleteStatus))"
                )
            } else {
                log("wipeStoredCASecretsLocally: deleted \(service)")
            }
        }
    }
}
