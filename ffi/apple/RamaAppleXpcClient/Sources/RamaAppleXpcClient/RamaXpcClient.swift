import Foundation
import Security
@preconcurrency import XPC

/// Typed client for an `XpcMessageRouter`-shaped XPC service.
/// Each call opens a one-shot mach-service connection, sends
/// `{ "$selector": …, "$arguments": [<request>] }`, and decodes the
/// reply's `$result`.
public struct RamaXpcClient: Sendable {
    public let serviceName: String
    public let expectedPeerSigningIdentifier: String

    public init(serviceName: String, expectedPeerSigningIdentifier: String) {
        self.serviceName = serviceName
        self.expectedPeerSigningIdentifier = expectedPeerSigningIdentifier
    }

    /// Send a typed request and await its typed reply.
    public func call<R: RamaXpcRoute>(
        _ route: R.Type,
        _ request: R.Request
    ) async throws -> R.Reply {
        guard !serviceName.isEmpty else {
            throw RamaXpcError.emptyServiceName
        }
        guard Self.isValidSigningComponent(expectedPeerSigningIdentifier) else {
            throw RamaXpcError.invalidPeerSigningIdentifier
        }

        let payload = try RamaXpcCoder.encode(request)

        let arguments = xpc_array_create(nil, 0)
        xpc_array_append_value(arguments, payload)

        let message = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_string(message, "$selector", R.selector)
        xpc_dictionary_set_value(message, "$arguments", arguments)

        let reply = try await sendRaw(message: message)

        guard xpc_get_type(reply) == XPC_TYPE_DICTIONARY else {
            throw RamaXpcError.malformedReply("reply is not a dictionary")
        }
        guard let resultValue = xpc_dictionary_get_value(reply, "$result") else {
            throw RamaXpcError.malformedReply("reply missing `$result` field")
        }

        return try RamaXpcCoder.decode(R.Reply.self, from: resultValue)
    }

    private func sendRaw(message: xpc_object_t) async throws -> xpc_object_t {
        let serviceName = self.serviceName
        let requirement = try Self.peerCodeSigningRequirement(
            signingIdentifier: expectedPeerSigningIdentifier,
            teamIdentifier: Self.currentTeamIdentifier()
        )
        return try await withCheckedThrowingContinuation { continuation in
            let connection = xpc_connection_create_mach_service(
                serviceName,
                nil,
                Self.machServiceFlags
            )
            let requirementStatus = requirement.withCString {
                xpc_connection_set_peer_code_signing_requirement(connection, $0)
            }
            guard requirementStatus == 0 else {
                xpc_connection_cancel(connection)
                continuation.resume(
                    throwing: RamaXpcError.peerRequirement(requirementStatus))
                return
            }
            xpc_connection_set_event_handler(connection) { _ in }
            xpc_connection_activate(connection)

            xpc_connection_send_message_with_reply(connection, message, nil) { reply in
                xpc_connection_cancel(connection)
                if xpc_get_type(reply) == XPC_TYPE_ERROR {
                    let detail = Self.xpcDescription(reply)
                    continuation.resume(throwing: RamaXpcError.connection(detail))
                } else {
                    continuation.resume(returning: reply)
                }
            }
        }
    }

    private static func xpcDescription(_ object: xpc_object_t) -> String {
        let cstr = xpc_copy_description(object)
        defer { free(cstr) }
        return String(cString: cstr)
    }

    static let machServiceFlags = UInt64(XPC_CONNECTION_MACH_SERVICE_PRIVILEGED)

    static func peerCodeSigningRequirement(
        signingIdentifier: String,
        teamIdentifier: String
    ) throws -> String {
        guard isValidSigningComponent(signingIdentifier),
              isValidSigningComponent(teamIdentifier)
        else {
            throw RamaXpcError.invalidPeerSigningIdentifier
        }
        return "anchor apple generic and identifier \"\(signingIdentifier)\" "
            + "and certificate leaf[subject.OU] = \"\(teamIdentifier)\""
    }

    private static func isValidSigningComponent(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.allSatisfy {
            ($0 >= 48 && $0 <= 57)
                || ($0 >= 65 && $0 <= 90)
                || ($0 >= 97 && $0 <= 122)
                || $0 == 45 || $0 == 46 || $0 == 95
        }
    }

    private static func currentTeamIdentifier() throws -> String {
        var code: SecCode?
        var status = SecCodeCopySelf([], &code)
        guard status == errSecSuccess, let code else {
            throw RamaXpcError.codeSigning(status)
        }

        var staticCode: SecStaticCode?
        status = SecCodeCopyStaticCode(code, [], &staticCode)
        guard status == errSecSuccess, let staticCode else {
            throw RamaXpcError.codeSigning(status)
        }

        var information: CFDictionary?
        status = SecCodeCopySigningInformation(
            staticCode,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &information
        )
        guard status == errSecSuccess,
              let values = information as? [CFString: Any],
              let teamIdentifier = values[kSecCodeInfoTeamIdentifier] as? String,
              isValidSigningComponent(teamIdentifier)
        else {
            throw RamaXpcError.codeSigning(status == errSecSuccess ? errSecCSUnsigned : status)
        }
        return teamIdentifier
    }
}

extension RamaXpcClient {
    /// Convenience overload for routes whose `Request` is ``RamaXpcEmpty``.
    public func call<R: RamaXpcRoute>(_ route: R.Type) async throws -> R.Reply
    where R.Request == RamaXpcEmpty {
        try await call(route, RamaXpcEmpty())
    }
}
