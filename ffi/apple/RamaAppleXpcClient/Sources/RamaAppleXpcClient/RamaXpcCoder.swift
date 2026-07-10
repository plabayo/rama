import Foundation
@preconcurrency import XPC

enum RamaXpcCoder {
    static func encode<T: Encodable>(_ value: T) throws -> xpc_object_t {
        do {
            return try xpcObject(from: try encodeValue(value, codingPath: []))
        } catch {
            throw RamaXpcError.encodingFailed(error)
        }
    }

    static func decode<T: Decodable>(_ type: T.Type, from object: xpc_object_t) throws -> T {
        do {
            let value = try value(from: object)
            return try decodeXpcValue(type, from: value, codingPath: [])
        } catch {
            throw RamaXpcError.decodingFailed(error)
        }
    }
}

private indirect enum RamaXpcValue {
    case dictionary([String: RamaXpcValue])
    case array([RamaXpcValue])
    case string(String)
    case bool(Bool)
    case int(Int64)
    case uint(UInt64)
    case double(Double)
    case data(Data)
    case uuid(UUID)
    case date(Date)
    case null
}

private final class RamaXpcNode {
    enum Storage {
        case unset
        case dictionary([String: RamaXpcNode])
        case array([RamaXpcNode])
        case value(RamaXpcValue)
    }

    var storage: Storage = .unset

    func materialize(codingPath: [CodingKey]) throws -> RamaXpcValue {
        switch storage {
        case .unset:
            throw EncodingError.invalidValue(
                self,
                .init(codingPath: codingPath, debugDescription: "value encoded no content")
            )
        case .dictionary(let values):
            return .dictionary(
                try values.mapValues { try $0.materialize(codingPath: codingPath) })
        case .array(let values):
            return .array(try values.map { try $0.materialize(codingPath: codingPath) })
        case .value(let value):
            return value
        }
    }
}

private final class RamaXpcValueEncoder: Encoder {
    let node: RamaXpcNode
    let codingPath: [CodingKey]
    let userInfo: [CodingUserInfoKey: Any] = [:]

    init(node: RamaXpcNode, codingPath: [CodingKey]) {
        self.node = node
        self.codingPath = codingPath
    }

    func container<Key: CodingKey>(
        keyedBy type: Key.Type
    ) -> KeyedEncodingContainer<Key> {
        if case .unset = node.storage {
            node.storage = .dictionary([:])
        }
        guard case .dictionary = node.storage else {
            preconditionFailure("multiple incompatible encoding containers")
        }
        return KeyedEncodingContainer(
            RamaXpcKeyedEncodingContainer<Key>(node: node, codingPath: codingPath))
    }

    func unkeyedContainer() -> UnkeyedEncodingContainer {
        if case .unset = node.storage {
            node.storage = .array([])
        }
        guard case .array = node.storage else {
            preconditionFailure("multiple incompatible encoding containers")
        }
        return RamaXpcUnkeyedEncodingContainer(node: node, codingPath: codingPath)
    }

    func singleValueContainer() -> SingleValueEncodingContainer {
        RamaXpcSingleValueEncodingContainer(node: node, codingPath: codingPath)
    }
}

private struct RamaXpcKeyedEncodingContainer<Key: CodingKey>:
    KeyedEncodingContainerProtocol
{
    let node: RamaXpcNode
    let codingPath: [CodingKey]

    mutating func encodeNil(forKey key: Key) throws {
        insert(valueNode(.null), forKey: key)
    }

    mutating func encode(_ value: Bool, forKey key: Key) throws { try insert(value, key) }
    mutating func encode(_ value: String, forKey key: Key) throws { try insert(value, key) }
    mutating func encode(_ value: Double, forKey key: Key) throws { try insert(value, key) }
    mutating func encode(_ value: Float, forKey key: Key) throws { try insert(value, key) }
    mutating func encode(_ value: Int, forKey key: Key) throws { try insert(value, key) }
    mutating func encode(_ value: Int8, forKey key: Key) throws { try insert(value, key) }
    mutating func encode(_ value: Int16, forKey key: Key) throws { try insert(value, key) }
    mutating func encode(_ value: Int32, forKey key: Key) throws { try insert(value, key) }
    mutating func encode(_ value: Int64, forKey key: Key) throws { try insert(value, key) }
    mutating func encode(_ value: UInt, forKey key: Key) throws { try insert(value, key) }
    mutating func encode(_ value: UInt8, forKey key: Key) throws { try insert(value, key) }
    mutating func encode(_ value: UInt16, forKey key: Key) throws { try insert(value, key) }
    mutating func encode(_ value: UInt32, forKey key: Key) throws { try insert(value, key) }
    mutating func encode(_ value: UInt64, forKey key: Key) throws { try insert(value, key) }

    mutating func encode<T: Encodable>(_ value: T, forKey key: Key) throws {
        try insert(value, key)
    }

    mutating func nestedContainer<NestedKey: CodingKey>(
        keyedBy keyType: NestedKey.Type,
        forKey key: Key
    ) -> KeyedEncodingContainer<NestedKey> {
        let child = RamaXpcNode()
        child.storage = .dictionary([:])
        insert(child, forKey: key)
        return KeyedEncodingContainer(
            RamaXpcKeyedEncodingContainer<NestedKey>(
                node: child, codingPath: codingPath + [key]))
    }

    mutating func nestedUnkeyedContainer(forKey key: Key) -> UnkeyedEncodingContainer {
        let child = RamaXpcNode()
        child.storage = .array([])
        insert(child, forKey: key)
        return RamaXpcUnkeyedEncodingContainer(
            node: child, codingPath: codingPath + [key])
    }

    mutating func superEncoder() -> Encoder {
        let key = RamaXpcCodingKey(stringValue: "super")
        let child = RamaXpcNode()
        insert(child, forStringKey: key.stringValue)
        return RamaXpcValueEncoder(node: child, codingPath: codingPath + [key])
    }

    mutating func superEncoder(forKey key: Key) -> Encoder {
        let child = RamaXpcNode()
        insert(child, forKey: key)
        return RamaXpcValueEncoder(node: child, codingPath: codingPath + [key])
    }

    private func insert<T: Encodable>(_ value: T, _ key: Key) throws {
        insert(try encodeNode(value, codingPath: codingPath + [key]), forKey: key)
    }

    private func insert(_ child: RamaXpcNode, forKey key: Key) {
        insert(child, forStringKey: key.stringValue)
    }

    private func insert(_ child: RamaXpcNode, forStringKey key: String) {
        guard case .dictionary(var values) = node.storage else {
            preconditionFailure("keyed container changed storage")
        }
        values[key] = child
        node.storage = .dictionary(values)
    }
}

private struct RamaXpcUnkeyedEncodingContainer: UnkeyedEncodingContainer {
    let node: RamaXpcNode
    let codingPath: [CodingKey]

    var count: Int {
        guard case .array(let values) = node.storage else { return 0 }
        return values.count
    }

    mutating func encodeNil() throws { append(valueNode(.null)) }
    mutating func encode(_ value: Bool) throws { try append(value) }
    mutating func encode(_ value: String) throws { try append(value) }
    mutating func encode(_ value: Double) throws { try append(value) }
    mutating func encode(_ value: Float) throws { try append(value) }
    mutating func encode(_ value: Int) throws { try append(value) }
    mutating func encode(_ value: Int8) throws { try append(value) }
    mutating func encode(_ value: Int16) throws { try append(value) }
    mutating func encode(_ value: Int32) throws { try append(value) }
    mutating func encode(_ value: Int64) throws { try append(value) }
    mutating func encode(_ value: UInt) throws { try append(value) }
    mutating func encode(_ value: UInt8) throws { try append(value) }
    mutating func encode(_ value: UInt16) throws { try append(value) }
    mutating func encode(_ value: UInt32) throws { try append(value) }
    mutating func encode(_ value: UInt64) throws { try append(value) }
    mutating func encode<T: Encodable>(_ value: T) throws { try append(value) }

    mutating func nestedContainer<NestedKey: CodingKey>(
        keyedBy keyType: NestedKey.Type
    ) -> KeyedEncodingContainer<NestedKey> {
        let child = RamaXpcNode()
        child.storage = .dictionary([:])
        append(child)
        let key = RamaXpcCodingKey(intValue: count - 1)
        return KeyedEncodingContainer(
            RamaXpcKeyedEncodingContainer<NestedKey>(
                node: child, codingPath: codingPath + [key]))
    }

    mutating func nestedUnkeyedContainer() -> UnkeyedEncodingContainer {
        let child = RamaXpcNode()
        child.storage = .array([])
        append(child)
        let key = RamaXpcCodingKey(intValue: count - 1)
        return RamaXpcUnkeyedEncodingContainer(
            node: child, codingPath: codingPath + [key])
    }

    mutating func superEncoder() -> Encoder {
        let child = RamaXpcNode()
        append(child)
        let key = RamaXpcCodingKey(intValue: count - 1)
        return RamaXpcValueEncoder(node: child, codingPath: codingPath + [key])
    }

    private func append<T: Encodable>(_ value: T) throws {
        try append(encodeNode(value, codingPath: codingPath + [RamaXpcCodingKey(intValue: count)]))
    }

    private func append(_ child: RamaXpcNode) {
        guard case .array(var values) = node.storage else {
            preconditionFailure("unkeyed container changed storage")
        }
        values.append(child)
        node.storage = .array(values)
    }
}

private struct RamaXpcSingleValueEncodingContainer: SingleValueEncodingContainer {
    let node: RamaXpcNode
    let codingPath: [CodingKey]

    mutating func encodeNil() throws { node.storage = .value(.null) }
    mutating func encode(_ value: Bool) throws { try assign(value) }
    mutating func encode(_ value: String) throws { try assign(value) }
    mutating func encode(_ value: Double) throws { try assign(value) }
    mutating func encode(_ value: Float) throws { try assign(value) }
    mutating func encode(_ value: Int) throws { try assign(value) }
    mutating func encode(_ value: Int8) throws { try assign(value) }
    mutating func encode(_ value: Int16) throws { try assign(value) }
    mutating func encode(_ value: Int32) throws { try assign(value) }
    mutating func encode(_ value: Int64) throws { try assign(value) }
    mutating func encode(_ value: UInt) throws { try assign(value) }
    mutating func encode(_ value: UInt8) throws { try assign(value) }
    mutating func encode(_ value: UInt16) throws { try assign(value) }
    mutating func encode(_ value: UInt32) throws { try assign(value) }
    mutating func encode(_ value: UInt64) throws { try assign(value) }
    mutating func encode<T: Encodable>(_ value: T) throws { try assign(value) }

    private func assign<T: Encodable>(_ value: T) throws {
        node.storage = try encodeNode(value, codingPath: codingPath).storage
    }
}

private func encodeValue<T: Encodable>(
    _ value: T,
    codingPath: [CodingKey]
) throws -> RamaXpcValue {
    try encodeNode(value, codingPath: codingPath).materialize(codingPath: codingPath)
}

private func encodeNode<T: Encodable>(
    _ value: T,
    codingPath: [CodingKey]
) throws -> RamaXpcNode {
    let node = RamaXpcNode()
    switch value {
    case let value as Bool: node.storage = .value(.bool(value))
    case let value as String: node.storage = .value(.string(value))
    case let value as Double: node.storage = .value(.double(value))
    case let value as Float: node.storage = .value(.double(Double(value)))
    case let value as Int: node.storage = .value(.int(Int64(value)))
    case let value as Int8: node.storage = .value(.int(Int64(value)))
    case let value as Int16: node.storage = .value(.int(Int64(value)))
    case let value as Int32: node.storage = .value(.int(Int64(value)))
    case let value as Int64: node.storage = .value(.int(value))
    case let value as UInt: node.storage = .value(.uint(UInt64(value)))
    case let value as UInt8: node.storage = .value(.uint(UInt64(value)))
    case let value as UInt16: node.storage = .value(.uint(UInt64(value)))
    case let value as UInt32: node.storage = .value(.uint(UInt64(value)))
    case let value as UInt64: node.storage = .value(.uint(value))
    case let value as Data: node.storage = .value(.data(value))
    case let value as UUID: node.storage = .value(.uuid(value))
    case let value as Date: node.storage = .value(.date(value))
    case let value as URL: node.storage = .value(.string(value.absoluteString))
    default:
        try value.encode(to: RamaXpcValueEncoder(node: node, codingPath: codingPath))
    }
    return node
}

private func valueNode(_ value: RamaXpcValue) -> RamaXpcNode {
    let node = RamaXpcNode()
    node.storage = .value(value)
    return node
}

private final class RamaXpcValueDecoder: Decoder {
    let value: RamaXpcValue
    let codingPath: [CodingKey]
    let userInfo: [CodingUserInfoKey: Any] = [:]

    init(value: RamaXpcValue, codingPath: [CodingKey]) {
        self.value = value
        self.codingPath = codingPath
    }

    func container<Key: CodingKey>(
        keyedBy type: Key.Type
    ) throws -> KeyedDecodingContainer<Key> {
        guard case .dictionary(let values) = value else {
            throw mismatch([String: RamaXpcValue].self, value, codingPath)
        }
        return KeyedDecodingContainer(
            RamaXpcKeyedDecodingContainer<Key>(values: values, codingPath: codingPath))
    }

    func unkeyedContainer() throws -> UnkeyedDecodingContainer {
        guard case .array(let values) = value else {
            throw mismatch([RamaXpcValue].self, value, codingPath)
        }
        return RamaXpcUnkeyedDecodingContainer(values: values, codingPath: codingPath)
    }

    func singleValueContainer() throws -> SingleValueDecodingContainer {
        RamaXpcSingleValueDecodingContainer(value: value, codingPath: codingPath)
    }
}

private struct RamaXpcKeyedDecodingContainer<Key: CodingKey>:
    KeyedDecodingContainerProtocol
{
    let values: [String: RamaXpcValue]
    let codingPath: [CodingKey]
    var allKeys: [Key] { values.keys.compactMap(Key.init(stringValue:)) }

    func contains(_ key: Key) -> Bool { values[key.stringValue] != nil }

    func decodeNil(forKey key: Key) throws -> Bool {
        guard let value = values[key.stringValue] else { return false }
        if case .null = value { return true }
        return false
    }

    func decode(_ type: Bool.Type, forKey key: Key) throws -> Bool { try decodeValue(type, key) }
    func decode(_ type: String.Type, forKey key: Key) throws -> String { try decodeValue(type, key) }
    func decode(_ type: Double.Type, forKey key: Key) throws -> Double { try decodeValue(type, key) }
    func decode(_ type: Float.Type, forKey key: Key) throws -> Float { try decodeValue(type, key) }
    func decode(_ type: Int.Type, forKey key: Key) throws -> Int { try decodeValue(type, key) }
    func decode(_ type: Int8.Type, forKey key: Key) throws -> Int8 { try decodeValue(type, key) }
    func decode(_ type: Int16.Type, forKey key: Key) throws -> Int16 { try decodeValue(type, key) }
    func decode(_ type: Int32.Type, forKey key: Key) throws -> Int32 { try decodeValue(type, key) }
    func decode(_ type: Int64.Type, forKey key: Key) throws -> Int64 { try decodeValue(type, key) }
    func decode(_ type: UInt.Type, forKey key: Key) throws -> UInt { try decodeValue(type, key) }
    func decode(_ type: UInt8.Type, forKey key: Key) throws -> UInt8 { try decodeValue(type, key) }
    func decode(_ type: UInt16.Type, forKey key: Key) throws -> UInt16 { try decodeValue(type, key) }
    func decode(_ type: UInt32.Type, forKey key: Key) throws -> UInt32 { try decodeValue(type, key) }
    func decode(_ type: UInt64.Type, forKey key: Key) throws -> UInt64 { try decodeValue(type, key) }

    func decode<T: Decodable>(_ type: T.Type, forKey key: Key) throws -> T {
        try decodeValue(type, key)
    }

    func nestedContainer<NestedKey: CodingKey>(
        keyedBy type: NestedKey.Type,
        forKey key: Key
    ) throws -> KeyedDecodingContainer<NestedKey> {
        try decoder(forKey: key).container(keyedBy: type)
    }

    func nestedUnkeyedContainer(forKey key: Key) throws -> UnkeyedDecodingContainer {
        try decoder(forKey: key).unkeyedContainer()
    }

    func superDecoder() throws -> Decoder {
        let key = RamaXpcCodingKey(stringValue: "super")
        guard let value = values[key.stringValue] else {
            throw missing(key, codingPath)
        }
        return RamaXpcValueDecoder(value: value, codingPath: codingPath + [key])
    }

    func superDecoder(forKey key: Key) throws -> Decoder { try decoder(forKey: key) }

    private func decodeValue<T: Decodable>(_ type: T.Type, _ key: Key) throws -> T {
        let decoder = try decoder(forKey: key)
        return try decodeXpcValue(type, from: decoder.value, codingPath: decoder.codingPath)
    }

    private func decoder(forKey key: Key) throws -> RamaXpcValueDecoder {
        guard let value = values[key.stringValue] else {
            throw missing(key, codingPath)
        }
        return RamaXpcValueDecoder(value: value, codingPath: codingPath + [key])
    }
}

private struct RamaXpcUnkeyedDecodingContainer: UnkeyedDecodingContainer {
    let values: [RamaXpcValue]
    let codingPath: [CodingKey]
    var currentIndex = 0
    var count: Int? { values.count }
    var isAtEnd: Bool { currentIndex >= values.count }

    mutating func decodeNil() throws -> Bool {
        guard !isAtEnd else { throw endOfArray(codingPath, currentIndex) }
        if case .null = values[currentIndex] {
            currentIndex += 1
            return true
        }
        return false
    }

    mutating func decode(_ type: Bool.Type) throws -> Bool { try decodeNext(type) }
    mutating func decode(_ type: String.Type) throws -> String { try decodeNext(type) }
    mutating func decode(_ type: Double.Type) throws -> Double { try decodeNext(type) }
    mutating func decode(_ type: Float.Type) throws -> Float { try decodeNext(type) }
    mutating func decode(_ type: Int.Type) throws -> Int { try decodeNext(type) }
    mutating func decode(_ type: Int8.Type) throws -> Int8 { try decodeNext(type) }
    mutating func decode(_ type: Int16.Type) throws -> Int16 { try decodeNext(type) }
    mutating func decode(_ type: Int32.Type) throws -> Int32 { try decodeNext(type) }
    mutating func decode(_ type: Int64.Type) throws -> Int64 { try decodeNext(type) }
    mutating func decode(_ type: UInt.Type) throws -> UInt { try decodeNext(type) }
    mutating func decode(_ type: UInt8.Type) throws -> UInt8 { try decodeNext(type) }
    mutating func decode(_ type: UInt16.Type) throws -> UInt16 { try decodeNext(type) }
    mutating func decode(_ type: UInt32.Type) throws -> UInt32 { try decodeNext(type) }
    mutating func decode(_ type: UInt64.Type) throws -> UInt64 { try decodeNext(type) }
    mutating func decode<T: Decodable>(_ type: T.Type) throws -> T { try decodeNext(type) }

    mutating func nestedContainer<NestedKey: CodingKey>(
        keyedBy type: NestedKey.Type
    ) throws -> KeyedDecodingContainer<NestedKey> {
        try nextDecoder().container(keyedBy: type)
    }

    mutating func nestedUnkeyedContainer() throws -> UnkeyedDecodingContainer {
        try nextDecoder().unkeyedContainer()
    }

    mutating func superDecoder() throws -> Decoder { try nextDecoder() }

    private mutating func decodeNext<T: Decodable>(_ type: T.Type) throws -> T {
        let decoder = try nextDecoder()
        return try decodeXpcValue(type, from: decoder.value, codingPath: decoder.codingPath)
    }

    private mutating func nextDecoder() throws -> RamaXpcValueDecoder {
        guard !isAtEnd else { throw endOfArray(codingPath, currentIndex) }
        let key = RamaXpcCodingKey(intValue: currentIndex)
        let value = values[currentIndex]
        currentIndex += 1
        return RamaXpcValueDecoder(value: value, codingPath: codingPath + [key])
    }
}

private struct RamaXpcSingleValueDecodingContainer: SingleValueDecodingContainer {
    let value: RamaXpcValue
    let codingPath: [CodingKey]

    func decodeNil() -> Bool {
        if case .null = value { return true }
        return false
    }

    func decode(_ type: Bool.Type) throws -> Bool {
        guard case .bool(let value) = value else { throw mismatch(type, value, codingPath) }
        return value
    }

    func decode(_ type: String.Type) throws -> String {
        guard case .string(let value) = value else { throw mismatch(type, value, codingPath) }
        return value
    }

    func decode(_ type: Double.Type) throws -> Double {
        switch value {
        case .double(let value): return value
        case .int(let value): return Double(value)
        case .uint(let value): return Double(value)
        default: throw mismatch(type, value, codingPath)
        }
    }

    func decode(_ type: Float.Type) throws -> Float {
        let value = try decode(Double.self)
        let result = Float(value)
        guard !value.isFinite || result.isFinite else {
            throw mismatch(type, self.value, codingPath)
        }
        return result
    }

    func decode(_ type: Int.Type) throws -> Int { try signed(type) }
    func decode(_ type: Int8.Type) throws -> Int8 { try signed(type) }
    func decode(_ type: Int16.Type) throws -> Int16 { try signed(type) }
    func decode(_ type: Int32.Type) throws -> Int32 { try signed(type) }
    func decode(_ type: Int64.Type) throws -> Int64 { try signed(type) }
    func decode(_ type: UInt.Type) throws -> UInt { try unsigned(type) }
    func decode(_ type: UInt8.Type) throws -> UInt8 { try unsigned(type) }
    func decode(_ type: UInt16.Type) throws -> UInt16 { try unsigned(type) }
    func decode(_ type: UInt32.Type) throws -> UInt32 { try unsigned(type) }
    func decode(_ type: UInt64.Type) throws -> UInt64 { try unsigned(type) }

    func decode<T: Decodable>(_ type: T.Type) throws -> T {
        if type == Data.self, case .data(let value) = value { return value as! T }
        if type == UUID.self {
            switch value {
            case .uuid(let value): return value as! T
            case .string(let value):
                guard let uuid = UUID(uuidString: value) else {
                    throw mismatch(type, self.value, codingPath)
                }
                return uuid as! T
            default: break
            }
        }
        if type == Date.self {
            switch value {
            case .date(let value): return value as! T
            case .double(let value): return Date(timeIntervalSinceReferenceDate: value) as! T
            default: break
            }
        }
        if type == URL.self, case .string(let value) = value, let url = URL(string: value) {
            return url as! T
        }
        return try T(from: RamaXpcValueDecoder(value: value, codingPath: codingPath))
    }

    private func signed<T: FixedWidthInteger & SignedInteger>(_ type: T.Type) throws -> T {
        let result: T?
        switch value {
        case .int(let value): result = T(exactly: value)
        case .uint(let value): result = T(exactly: value)
        default: result = nil
        }
        guard let result else { throw mismatch(type, value, codingPath) }
        return result
    }

    private func unsigned<T: FixedWidthInteger & UnsignedInteger>(_ type: T.Type) throws -> T {
        let result: T?
        switch value {
        case .uint(let value): result = T(exactly: value)
        case .int(let value): result = T(exactly: value)
        default: result = nil
        }
        guard let result else { throw mismatch(type, value, codingPath) }
        return result
    }
}

private func decodeXpcValue<T: Decodable>(
    _ type: T.Type,
    from value: RamaXpcValue,
    codingPath: [CodingKey]
) throws -> T {
    try RamaXpcSingleValueDecodingContainer(
        value: value, codingPath: codingPath
    ).decode(type)
}

private struct RamaXpcCodingKey: CodingKey {
    let stringValue: String
    let intValue: Int?

    init(stringValue: String) {
        self.stringValue = stringValue
        self.intValue = nil
    }

    init(intValue: Int) {
        self.stringValue = "Index \(intValue)"
        self.intValue = intValue
    }
}

private func missing(_ key: CodingKey, _ codingPath: [CodingKey]) -> DecodingError {
    .keyNotFound(
        key,
        .init(codingPath: codingPath, debugDescription: "missing key \(key.stringValue)"))
}

private func mismatch<T>(
    _ type: T.Type,
    _ value: RamaXpcValue,
    _ codingPath: [CodingKey]
) -> DecodingError {
    .typeMismatch(
        type,
        .init(
            codingPath: codingPath,
            debugDescription: "cannot decode \(type) from \(value.kind)"))
}

private func endOfArray(_ codingPath: [CodingKey], _ index: Int) -> DecodingError {
    .valueNotFound(
        RamaXpcValue.self,
        .init(codingPath: codingPath, debugDescription: "no value at index \(index)"))
}

private extension RamaXpcValue {
    var kind: String {
        switch self {
        case .dictionary: return "dictionary"
        case .array: return "array"
        case .string: return "string"
        case .bool: return "bool"
        case .int: return "int64"
        case .uint: return "uint64"
        case .double: return "double"
        case .data: return "data"
        case .uuid: return "uuid"
        case .date: return "date"
        case .null: return "null"
        }
    }
}

private func xpcObject(from value: RamaXpcValue) throws -> xpc_object_t {
    switch value {
    case .dictionary(let values):
        let object = xpc_dictionary_create(nil, nil, 0)
        for (key, value) in values {
            try validateXpcString(key)
            xpc_dictionary_set_value(object, key, try xpcObject(from: value))
        }
        return object
    case .array(let values):
        let object = xpc_array_create(nil, 0)
        for value in values {
            xpc_array_append_value(object, try xpcObject(from: value))
        }
        return object
    case .string(let value):
        try validateXpcString(value)
        return xpc_string_create(value)
    case .bool(let value): return xpc_bool_create(value)
    case .int(let value): return xpc_int64_create(value)
    case .uint(let value): return xpc_uint64_create(value)
    case .double(let value): return xpc_double_create(value)
    case .data(let value):
        return value.withUnsafeBytes { xpc_data_create($0.baseAddress, $0.count) }
    case .uuid(let value):
        var bytes = value.uuid
        return withUnsafeBytes(of: &bytes) {
            xpc_uuid_create($0.bindMemory(to: UInt8.self).baseAddress!)
        }
    case .date(let value):
        let valueNanos = value.timeIntervalSince1970 * 1_000_000_000
        guard let nanos = Int64(exactly: valueNanos.rounded()) else {
            throw EncodingError.invalidValue(
                value,
                .init(codingPath: [], debugDescription: "date is outside the XPC range"))
        }
        return xpc_date_create(nanos)
    case .null: return xpc_null_create()
    }
}

private func value(from object: xpc_object_t) throws -> RamaXpcValue {
    let type = xpc_get_type(object)
    if type == XPC_TYPE_DICTIONARY {
        var values: [String: RamaXpcValue] = [:]
        var failure: Error?
        xpc_dictionary_apply(object) { key, child in
            do {
                values[String(cString: key)] = try value(from: child)
                return true
            } catch {
                failure = error
                return false
            }
        }
        if let failure { throw failure }
        return .dictionary(values)
    }
    if type == XPC_TYPE_ARRAY {
        var values: [RamaXpcValue] = []
        var failure: Error?
        xpc_array_apply(object) { _, child in
            do {
                values.append(try value(from: child))
                return true
            } catch {
                failure = error
                return false
            }
        }
        if let failure { throw failure }
        return .array(values)
    }
    if type == XPC_TYPE_STRING {
        guard let string = xpc_string_get_string_ptr(object) else {
            throw RamaXpcError.unsupportedValueType("invalid XPC string")
        }
        return .string(String(cString: string))
    }
    if type == XPC_TYPE_BOOL { return .bool(xpc_bool_get_value(object)) }
    if type == XPC_TYPE_INT64 { return .int(xpc_int64_get_value(object)) }
    if type == XPC_TYPE_UINT64 { return .uint(xpc_uint64_get_value(object)) }
    if type == XPC_TYPE_DOUBLE { return .double(xpc_double_get_value(object)) }
    if type == XPC_TYPE_DATA {
        let length = xpc_data_get_length(object)
        guard length > 0 else { return .data(Data()) }
        guard let bytes = xpc_data_get_bytes_ptr(object) else {
            throw RamaXpcError.unsupportedValueType("invalid XPC data")
        }
        return .data(Data(bytes: bytes, count: length))
    }
    if type == XPC_TYPE_UUID {
        guard let source = xpc_uuid_get_bytes(object) else {
            throw RamaXpcError.unsupportedValueType("invalid XPC UUID")
        }
        var bytes: uuid_t = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        withUnsafeMutableBytes(of: &bytes) {
            $0.copyBytes(from: UnsafeRawBufferPointer(start: source, count: 16))
        }
        return .uuid(UUID(uuid: bytes))
    }
    if type == XPC_TYPE_DATE {
        let seconds = Double(xpc_date_get_value(object)) / 1_000_000_000
        return .date(Date(timeIntervalSince1970: seconds))
    }
    if type == XPC_TYPE_NULL { return .null }
    throw RamaXpcError.unsupportedValueType("unsupported XPC object type")
}

private func validateXpcString(_ value: String) throws {
    guard !value.utf8.contains(0) else {
        throw RamaXpcError.unsupportedValueType("XPC strings cannot contain NUL")
    }
}
