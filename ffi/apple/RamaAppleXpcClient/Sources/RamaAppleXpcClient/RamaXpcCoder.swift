import Foundation
@preconcurrency import XPC

// MARK: - Codable ↔ xpc_object_t bridge
//
// The `XpcMessageRouter` on the Rust side exchanges values using the
// XPC-native types (`xpc_dictionary`, `xpc_array`, strings, integers,
// doubles, bools, data, null) via `xpc_serde`. Swift's `Codable` and
// Foundation's JSON layer share the same data model — JSON object →
// dictionary, JSON array → array, primitives → primitives — so we round
// `Encodable` / `Decodable` values through `JSONEncoder` /
// `JSONSerialization` and translate the resulting `Foundation` graph to
// and from `xpc_object_t`. This avoids hand-rolling a Codable-aware
// `Encoder` / `Decoder` while staying wire-compatible with the existing
// Rust router.

enum RamaXpcCoder {
    static func encode<T: Encodable>(_ value: T) throws -> xpc_object_t {
        let data: Data
        do {
            data = try JSONEncoder().encode(value)
        } catch {
            throw RamaXpcError.encodingFailed(error)
        }
        let foundation: Any
        do {
            foundation = try JSONSerialization.jsonObject(
                with: data, options: [.fragmentsAllowed])
        } catch {
            throw RamaXpcError.encodingFailed(error)
        }
        return try foundationToXpc(foundation)
    }

    static func decode<T: Decodable>(_ type: T.Type, from object: xpc_object_t) throws -> T {
        let foundation = xpcToFoundation(object)
        let data: Data
        do {
            data = try JSONSerialization.data(
                withJSONObject: foundation, options: [.fragmentsAllowed])
        } catch {
            throw RamaXpcError.decodingFailed(error)
        }
        do {
            return try JSONDecoder().decode(T.self, from: data)
        } catch {
            throw RamaXpcError.decodingFailed(error)
        }
    }
}

private func foundationToXpc(_ value: Any) throws -> xpc_object_t {
    if let dict = value as? [String: Any] {
        let xpc = xpc_dictionary_create(nil, nil, 0)
        for (key, child) in dict {
            xpc_dictionary_set_value(xpc, key, try foundationToXpc(child))
        }
        return xpc
    }
    if let array = value as? [Any] {
        let xpc = xpc_array_create(nil, 0)
        for child in array {
            xpc_array_append_value(xpc, try foundationToXpc(child))
        }
        return xpc
    }
    if let string = value as? String {
        return xpc_string_create(string)
    }
    if let number = value as? NSNumber {
        // CFBoolean (which is what JSON parses true/false to) is bridged
        // to NSNumber, so distinguish bools from numerics first.
        if CFGetTypeID(number) == CFBooleanGetTypeID() {
            return xpc_bool_create(number.boolValue)
        }
        switch CFNumberGetType(number) {
        case .doubleType, .floatType, .float32Type, .float64Type, .cgFloatType:
            return xpc_double_create(number.doubleValue)
        default:
            return xpc_int64_create(number.int64Value)
        }
    }
    if let data = value as? Data {
        return data.withUnsafeBytes { raw in
            xpc_data_create(raw.baseAddress, raw.count)
        }
    }
    if value is NSNull {
        return xpc_null_create()
    }
    throw RamaXpcError.unsupportedValueType(String(describing: type(of: value)))
}

private func xpcToFoundation(_ object: xpc_object_t) -> Any {
    let type = xpc_get_type(object)

    if type == XPC_TYPE_DICTIONARY {
        var result: [String: Any] = [:]
        xpc_dictionary_apply(object) { key, child in
            result[String(cString: key)] = xpcToFoundation(child)
            return true
        }
        return result
    }
    if type == XPC_TYPE_ARRAY {
        var result: [Any] = []
        xpc_array_apply(object) { _, child in
            result.append(xpcToFoundation(child))
            return true
        }
        return result
    }
    if type == XPC_TYPE_STRING {
        if let cstr = xpc_string_get_string_ptr(object) {
            return String(cString: cstr)
        }
        return ""
    }
    if type == XPC_TYPE_BOOL {
        return xpc_bool_get_value(object)
    }
    if type == XPC_TYPE_INT64 {
        return xpc_int64_get_value(object)
    }
    if type == XPC_TYPE_UINT64 {
        return xpc_uint64_get_value(object)
    }
    if type == XPC_TYPE_DOUBLE {
        return xpc_double_get_value(object)
    }
    if type == XPC_TYPE_DATA {
        let length = xpc_data_get_length(object)
        guard let ptr = xpc_data_get_bytes_ptr(object), length > 0 else {
            return Data()
        }
        return Data(bytes: ptr, count: length)
    }
    if type == XPC_TYPE_NULL {
        return NSNull()
    }
    // Unknown / unsupported leaf type — fall back to NSNull so JSON
    // serialization can at least proceed; it'll surface as a decode
    // error if the consumer expected a meaningful value here.
    return NSNull()
}
