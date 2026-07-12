import Foundation

/// Errors thrown by ``RamaXpcClient`` and related APIs.
///
/// Conforms to `LocalizedError` so `error.localizedDescription` —
/// which AppKit alert handlers reach for — surfaces the same text
/// as `description`. Without that conformance the Swift-→-NSError
/// bridge collapses every case to a useless
/// `"DomainName error <case-index>"` string.
public enum RamaXpcError: Error, CustomStringConvertible, LocalizedError {
    /// `serviceName` was empty.
    case emptyServiceName
    /// The expected peer signing identifier was empty or malformed.
    case invalidPeerSigningIdentifier
    /// The current process's signing team could not be determined.
    case codeSigning(OSStatus)
    /// XPC rejected the peer code-signing requirement.
    case peerRequirement(Int32)
    /// The XPC connection delivered an error event before or instead of a reply.
    case connection(String)
    /// The remote replied with something that doesn't match the expected
    /// `{ "$result": <reply> }` envelope produced by `XpcMessageRouter`.
    case malformedReply(String)
    /// A value type was encountered that the XPC coder cannot serialize.
    case unsupportedValueType(String)
    /// Encoding the typed `Request` to the on-the-wire XPC representation failed.
    case encodingFailed(Error)
    /// Decoding the typed `Reply` from the on-the-wire XPC representation failed.
    case decodingFailed(Error)

    public var description: String {
        switch self {
        case .emptyServiceName:
            return "RamaXpcError: empty service name"
        case .invalidPeerSigningIdentifier:
            return "RamaXpcError: invalid peer signing identifier"
        case .codeSigning(let status):
            return "RamaXpcError: code-signing information unavailable: \(status)"
        case .peerRequirement(let code):
            return "RamaXpcError: peer requirement rejected: \(code)"
        case .connection(let detail):
            return "RamaXpcError: connection error: \(detail)"
        case .malformedReply(let detail):
            return "RamaXpcError: malformed reply: \(detail)"
        case .unsupportedValueType(let detail):
            return "RamaXpcError: unsupported value type: \(detail)"
        case .encodingFailed(let error):
            return "RamaXpcError: encoding failed: \(error)"
        case .decodingFailed(let error):
            return "RamaXpcError: decoding failed: \(error)"
        }
    }

    public var errorDescription: String? { description }
}
