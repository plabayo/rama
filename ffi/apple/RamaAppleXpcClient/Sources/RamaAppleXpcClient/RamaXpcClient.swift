import Foundation
@preconcurrency import XPC

/// Typed client for an `XpcMessageRouter`-shaped XPC service.
/// Each call opens a one-shot mach-service connection, sends
/// `{ "$selector": …, "$arguments": [<request>] }`, and decodes the
/// reply's `$result`.
public struct RamaXpcClient: Sendable {
    public let serviceName: String

    public init(serviceName: String) {
        self.serviceName = serviceName
    }

    /// Send a typed request and await its typed reply.
    public func call<R: RamaXpcRoute>(
        _ route: R.Type,
        _ request: R.Request
    ) async throws -> R.Reply {
        guard !serviceName.isEmpty else {
            throw RamaXpcError.emptyServiceName
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
        return try await withCheckedThrowingContinuation { continuation in
            let connection = xpc_connection_create_mach_service(serviceName, nil, 0)
            // Stream events surface via the reply handler for our
            // one-shot request shape, so this is a no-op.
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
        // `xpc_copy_description` always returns a non-null malloc'd C string.
        let cstr = xpc_copy_description(object)
        defer { free(cstr) }
        return String(cString: cstr)
    }
}

extension RamaXpcClient {
    /// Convenience overload for routes whose `Request` is ``RamaXpcEmpty``.
    public func call<R: RamaXpcRoute>(_ route: R.Type) async throws -> R.Reply
    where R.Request == RamaXpcEmpty {
        try await call(route, RamaXpcEmpty())
    }
}
