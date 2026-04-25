import CryptoKit
import Foundation
import Security
import X509

extension ContainerController {
    func loadOrCreateMITMCA() throws -> MITMCASecrets {
        let existingKey = try loadSecret(service: Self.secretServiceKeyPEM)
        let existingCert = try loadSecret(service: Self.secretServiceCertPEM)

        if let keyPEM = existingKey, let certPEM = existingCert {
            return MITMCASecrets(certPEM: certPEM, keyPEM: keyPEM)
        }

        if existingKey != nil || existingCert != nil {
            log("MITM CA keychain state incomplete; deleting partial CA material and regenerating")
            cleanSecrets()
        }

        let generated = try generateSelfSignedCAPEM()
        try storeSecret(service: Self.secretServiceKeyPEM, value: generated.keyPEM)
        try storeSecret(service: Self.secretServiceCertPEM, value: generated.certPEM)
        log("generated and stored new MITM CA PEM in user keychain")
        return generated
    }

    func cleanSecrets() {
        for service in Self.secretServiceKeys {
            let query: [CFString: Any] = [
                kSecClass: kSecClassGenericPassword,
                kSecAttrService: service,
                kSecAttrAccount: Self.secretAccount,
                kSecUseDataProtectionKeychain: true,
            ]
            SecItemDelete(query as CFDictionary)
        }
    }

    func generateSelfSignedCAPEM() throws -> MITMCASecrets {
        let signingKey = P256.Signing.PrivateKey()
        let now = Date()
        let calendar = Calendar(identifier: .gregorian)
        guard let notValidAfter = calendar.date(byAdding: .day, value: 3650, to: now) else {
            throw NSError(
                domain: "RamaTransparentProxyExampleContainer",
                code: 5,
                userInfo: [
                    NSLocalizedDescriptionKey: "failed to compute CA certificate expiry date"
                ]
            )
        }

        let subject = try DistinguishedName {
            CommonName("Rama Transparent Proxy Example Root CA")
            OrganizationName("Rama")
            OrganizationalUnitName("Transparent Proxy")
        }

        let certificate = try Certificate(
            version: .v3,
            serialNumber: .init(),
            publicKey: .init(signingKey.publicKey),
            notValidBefore: now,
            notValidAfter: notValidAfter,
            issuer: subject,
            subject: subject,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try Certificate.Extensions {
                Critical(BasicConstraints.isCertificateAuthority(maxPathLength: 0))
                Critical(
                    KeyUsage(
                        digitalSignature: true,
                        nonRepudiation: false,
                        keyEncipherment: false,
                        dataEncipherment: false,
                        keyAgreement: false,
                        keyCertSign: true,
                        cRLSign: true,
                        encipherOnly: false,
                        decipherOnly: false
                    )
                )
            },
            issuerPrivateKey: .init(signingKey)
        )

        let certPEM = try certificate.serializeAsPEM().pemString
        let keyPEM = try Certificate.PrivateKey(signingKey).serializeAsPEM().pemString
        return MITMCASecrets(certPEM: certPEM, keyPEM: keyPEM)
    }

    func loadSecret(service: String) throws -> String? {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: Self.secretAccount,
            kSecUseDataProtectionKeychain: true,
            kSecReturnData: true,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else {
            throw keychainError(status, "SecItemCopyMatching failed for \(service)")
        }
        guard let data = result as? Data else { return "" }
        guard let str = String(data: data, encoding: .utf8) else {
            throw NSError(
                domain: "RamaTransparentProxyExampleContainer",
                code: 3,
                userInfo: [
                    NSLocalizedDescriptionKey:
                        "keychain item for \(service) was not valid UTF-8"
                ]
            )
        }
        return str
    }

    func storeSecret(service: String, value: String) throws {
        guard let data = value.data(using: .utf8) else {
            throw NSError(
                domain: "RamaTransparentProxyExampleContainer",
                code: 4,
                userInfo: [
                    NSLocalizedDescriptionKey:
                        "failed to encode keychain secret \(service) as UTF-8"
                ]
            )
        }

        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: Self.secretAccount,
            kSecUseDataProtectionKeychain: true,
        ]

        let updateAttributes: [CFString: Any] = [kSecValueData: data]
        let updateStatus = SecItemUpdate(query as CFDictionary, updateAttributes as CFDictionary)
        if updateStatus == errSecSuccess { return }

        if updateStatus != errSecItemNotFound {
            throw keychainError(updateStatus, "SecItemUpdate failed for \(service)")
        }

        var addQuery = query
        addQuery[kSecValueData] = data
        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            throw keychainError(addStatus, "SecItemAdd failed for \(service)")
        }
    }

    private func keychainError(_ status: OSStatus, _ message: String) -> NSError {
        NSError(
            domain: "RamaTransparentProxyExampleContainer",
            code: Int(status),
            userInfo: [NSLocalizedDescriptionKey: "\(message) (OSStatus \(status))"]
        )
    }
}
