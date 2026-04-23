import CryptoKit
import Foundation
import OSLog
import Security
import XPC

private let secretAccount = "org.ramaproxy.example.tproxy.host"
private let secretServiceKeyPEM = "tls-root-selfsigned-ca-key"
private let secretServiceCertPEM = "tls-root-selfsigned-ca-crt"
private let sharedKeychainAccessGroupSuffix = "org.ramaproxy.example.tproxy.shared"
private let operationGetCAKeyPEM = "get_ca_key_pem"

private struct CodeSigningIdentity {
    let identifier: String
    let teamIdentifier: String?
}

private enum XpcServiceError: LocalizedError {
    case message(String)

    var errorDescription: String? {
        switch self {
        case let .message(value):
            value
        }
    }
}

private func expectedExtensionBundleIdentifier(for serviceBundleIdentifier: String) -> String {
    if serviceBundleIdentifier.hasSuffix(".xpc") {
        return String(serviceBundleIdentifier.dropLast(".xpc".count)) + ".provider"
    }
    return serviceBundleIdentifier + ".provider"
}

private func baseSecretQuery(service: String, accessGroup: String?) -> [String: Any] {
    var query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: secretAccount,
        kSecUseDataProtectionKeychain as String: true,
    ]
    if let accessGroup, !accessGroup.isEmpty {
        query[kSecAttrAccessGroup as String] = accessGroup
    }
    return query
}

private func resolveCodeSigningIdentity(_ codeRef: SecStaticCode) throws -> CodeSigningIdentity {
    var signingInfoRef: CFDictionary?
    let status = SecCodeCopySigningInformation(codeRef, SecCSFlags(rawValue: kSecCSSigningInformation), &signingInfoRef)
    guard status == errSecSuccess, let signingInfo = signingInfoRef as? [String: Any] else {
        throw XpcServiceError.message("SecCodeCopySigningInformation failed: OSStatus \(status)")
    }
    guard let identifier = signingInfo[kSecCodeInfoIdentifier as String] as? String, !identifier.isEmpty else {
        throw XpcServiceError.message("signing information missing code identifier")
    }
    return CodeSigningIdentity(
        identifier: identifier,
        teamIdentifier: signingInfo[kSecCodeInfoTeamIdentifier as String] as? String
    )
}

private func resolveCurrentCodeSigningIdentity() throws -> CodeSigningIdentity {
    guard let executableURL = Bundle.main.executableURL else {
        throw XpcServiceError.message("bundle executable URL not found")
    }
    var staticCodeRef: SecStaticCode?
    let status = SecStaticCodeCreateWithPath(executableURL as CFURL, SecCSFlags(), &staticCodeRef)
    guard status == errSecSuccess, let staticCodeRef else {
        throw XpcServiceError.message("SecStaticCodeCreateWithPath failed: OSStatus \(status)")
    }
    return try resolveCodeSigningIdentity(staticCodeRef)
}

private func sharedKeychainAccessGroup(hostIdentity: CodeSigningIdentity?) -> String? {
    guard let teamIdentifier = hostIdentity?.teamIdentifier, !teamIdentifier.isEmpty else {
        return nil
    }
    return "\(teamIdentifier).\(sharedKeychainAccessGroupSuffix)"
}

private func codeSigningRequirementString(bundleIdentifier: String, hostIdentity: CodeSigningIdentity?) -> String {
    guard let teamIdentifier = hostIdentity?.teamIdentifier, !teamIdentifier.isEmpty else {
        return "identifier \"\(bundleIdentifier)\""
    }
    return "identifier \"\(bundleIdentifier)\" and anchor apple generic and certificate leaf[subject.OU] = \"\(teamIdentifier)\""
}

private func loadSecret(service: String, accessGroup: String?) throws -> String? {
    var queries = [[String: Any]]()

    var sharedQuery = baseSecretQuery(service: service, accessGroup: accessGroup)
    sharedQuery[kSecReturnData as String] = true
    sharedQuery[kSecMatchLimit as String] = kSecMatchLimitOne
    queries.append(sharedQuery)

    var legacyQuery = baseSecretQuery(service: service, accessGroup: nil)
    legacyQuery[kSecReturnData as String] = true
    legacyQuery[kSecMatchLimit as String] = kSecMatchLimitOne
    queries.append(legacyQuery)

    for query in queries {
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecItemNotFound:
            continue
        case errSecSuccess:
            guard let data = item as? Data else {
                throw XpcServiceError.message("keychain item for \(service) did not return data")
            }
            guard let value = String(data: data, encoding: .utf8) else {
                throw XpcServiceError.message("keychain item for \(service) was not valid UTF-8")
            }
            return value
        default:
            throw XpcServiceError.message("failed to load keychain secret \(service): OSStatus \(status)")
        }
    }

    return nil
}

private func decodePEMBody(_ pem: String) throws -> Data {
    let base64 = pem
        .split(whereSeparator: \.isNewline)
        .map(String.init)
        .filter { !$0.hasPrefix("-----BEGIN") && !$0.hasPrefix("-----END") }
        .joined()

    guard let data = Data(base64Encoded: base64) else {
        throw XpcServiceError.message("failed to decode PEM body as base64")
    }
    return data
}

private func certificateFingerprintHex(_ pem: String) throws -> String {
    let certificateData = try decodePEMBody(pem)
    guard let certificate = SecCertificateCreateWithData(nil, certificateData as CFData) else {
        throw XpcServiceError.message("CA certificate PEM did not decode to a certificate")
    }
    let derData = SecCertificateCopyData(certificate) as Data
    return SHA256.hash(data: derData).map { String(format: "%02x", $0) }.joined()
}

private func loadCASecrets(accessGroup: String?) throws -> (keyPEM: String, certPEM: String) {
    guard let keyPEM = try loadSecret(service: secretServiceKeyPEM, accessGroup: accessGroup) else {
        throw XpcServiceError.message("CA key PEM not found in keychain")
    }
    guard let certPEM = try loadSecret(service: secretServiceCertPEM, accessGroup: accessGroup) else {
        throw XpcServiceError.message("CA certificate PEM not found in keychain")
    }
    return (keyPEM, certPEM)
}

private func sendErrorReply(peer: xpc_connection_t, request: xpc_object_t, message: String) {
    guard let reply = xpc_dictionary_create_reply(request) else {
        return
    }
    xpc_dictionary_set_string(reply, "error", message)
    xpc_connection_send_message(peer, reply)
}

private func handleRequest(
    peer: xpc_connection_t,
    request: xpc_object_t,
    accessGroup: String?,
    logger: Logger
) {
    guard let operationCString = xpc_dictionary_get_string(request, "op") else {
        sendErrorReply(peer: peer, request: request, message: "missing operation")
        return
    }

    let operation = String(cString: operationCString)
    guard operation == operationGetCAKeyPEM else {
        sendErrorReply(peer: peer, request: request, message: "unsupported request")
        return
    }

    guard let fingerprintCString = xpc_dictionary_get_string(request, "ca_cert_sha256_hex") else {
        sendErrorReply(peer: peer, request: request, message: "missing certificate fingerprint")
        return
    }
    let requestedFingerprint = String(cString: fingerprintCString).lowercased()
    guard !requestedFingerprint.isEmpty else {
        sendErrorReply(peer: peer, request: request, message: "missing certificate fingerprint")
        return
    }

    do {
        let secrets = try loadCASecrets(accessGroup: accessGroup)
        let currentFingerprint = try certificateFingerprintHex(secrets.certPEM)
        guard currentFingerprint == requestedFingerprint else {
            throw XpcServiceError.message("host CA fingerprint mismatch; refusing to release CA key")
        }

        guard let reply = xpc_dictionary_create_reply(request) else {
            logger.error("failed to allocate XPC reply dictionary")
            return
        }
        xpc_dictionary_set_string(reply, "ca_key_pem", secrets.keyPEM)
        xpc_connection_send_message(peer, reply)
        logger.info("served CA key to authorized extension peer pid \(xpc_connection_get_pid(peer), privacy: .public)")
    } catch {
        sendErrorReply(peer: peer, request: request, message: error.localizedDescription)
    }
}

private func isPeerCodeSigningRequirementError(_ event: xpc_object_t) -> Bool {
    if #available(macOS 15.0, *) {
        return xpc_equal(event, XPC_ERROR_PEER_CODE_SIGNING_REQUIREMENT)
    }
    return false
}

private func run() throws -> Never {
    let serviceName: String
    if let launchJobLabel = ProcessInfo.processInfo.environment["LAUNCH_JOB_LABEL"],
        !launchJobLabel.isEmpty
    {
        serviceName = launchJobLabel
    } else if let bundleIdentifier = Bundle.main.bundleIdentifier, !bundleIdentifier.isEmpty {
        serviceName = bundleIdentifier
    } else {
        throw XpcServiceError.message("XPC service label missing from launch environment")
    }
    let extensionBundleIdentifier = expectedExtensionBundleIdentifier(for: serviceName)
    let logger = Logger(subsystem: serviceName, category: "ca-xpc-service")

    let hostIdentity = try? resolveCurrentCodeSigningIdentity()
    let accessGroup = sharedKeychainAccessGroup(hostIdentity: hostIdentity)
    let peerRequirement = codeSigningRequirementString(
        bundleIdentifier: extensionBundleIdentifier,
        hostIdentity: hostIdentity
    )

    let listener = xpc_connection_create_mach_service(
        serviceName,
        DispatchQueue.main,
        UInt64(XPC_CONNECTION_MACH_SERVICE_LISTENER)
    )

    let requirementStatus = xpc_connection_set_peer_code_signing_requirement(listener, peerRequirement)
    guard requirementStatus == 0 else {
        throw XpcServiceError.message("failed to apply peer code-signing requirement: \(requirementStatus)")
    }

    xpc_connection_set_event_handler(listener) { event in
        let eventType = xpc_get_type(event)
        if eventType == XPC_TYPE_ERROR {
            if xpc_equal(event, XPC_ERROR_CONNECTION_INVALID) {
                logger.info("CA key XPC listener invalidated")
            } else if xpc_equal(event, XPC_ERROR_CONNECTION_INTERRUPTED) {
                logger.info("CA key XPC listener interrupted")
            } else {
                logger.error("CA key XPC listener received unexpected error event")
            }
            return
        }

        let peer = event
        xpc_connection_set_event_handler(peer) { peerEvent in
            let peerEventType = xpc_get_type(peerEvent)
            if peerEventType == XPC_TYPE_DICTIONARY {
                handleRequest(peer: peer, request: peerEvent, accessGroup: accessGroup, logger: logger)
                return
            }

            guard peerEventType == XPC_TYPE_ERROR else {
                logger.error("peer connection received unexpected XPC event type")
                return
            }

            if xpc_equal(peerEvent, XPC_ERROR_CONNECTION_INVALID) {
                logger.info("peer connection invalidated")
            } else if xpc_equal(peerEvent, XPC_ERROR_CONNECTION_INTERRUPTED) {
                logger.info("peer connection interrupted")
            } else if isPeerCodeSigningRequirementError(peerEvent) {
                logger.error("peer failed code-signing requirement")
            } else {
                logger.error("peer connection received unexpected error event")
            }
        }
        xpc_connection_activate(peer)
    }

    xpc_connection_activate(listener)
    logger.info("CA key XPC service ready: mach service=\(serviceName, privacy: .public) extension=\(extensionBundleIdentifier, privacy: .public)")
    dispatchMain()
}

do {
    try run()
} catch {
    let subsystem =
        ProcessInfo.processInfo.environment["LAUNCH_JOB_LABEL"]
        ?? Bundle.main.bundleIdentifier
        ?? "RamaTransparentProxyExampleXpcService"
    let logger = Logger(subsystem: subsystem, category: "ca-xpc-service")
    logger.error("failed to start XPC service: \(error.localizedDescription, privacy: .public)")
    exit(EXIT_FAILURE)
}
