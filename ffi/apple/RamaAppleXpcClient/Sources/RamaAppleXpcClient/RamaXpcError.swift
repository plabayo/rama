import Foundation

/// Errors thrown by ``RamaXpcClient`` and related APIs.
public enum RamaXpcError: Error, CustomStringConvertible {
    /// `serviceName` was empty.
    case emptyServiceName
    /// The XPC connection delivered an error event before or instead of a reply.
    case connection(String)
    /// The remote replied with something that doesn't match the expected
    /// `{ "$result": <reply> }` envelope produced by `XpcMessageRouter`.
    case malformedReply(String)
    /// A value type was encountered that the JSON ↔ XPC bridge does not
    /// know how to serialize. Should not happen for any standard `Codable`
    /// payload — file a bug if it does.
    case unsupportedValueType(String)
    /// Encoding the typed `Request` to the on-the-wire XPC representation failed.
    case encodingFailed(Error)
    /// Decoding the typed `Reply` from the on-the-wire XPC representation failed.
    case decodingFailed(Error)

    public var description: String {
        switch self {
        case .emptyServiceName:
            return "RamaXpcError: empty service name"
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
}
