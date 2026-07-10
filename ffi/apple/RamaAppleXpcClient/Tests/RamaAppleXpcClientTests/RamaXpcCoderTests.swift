import Foundation
import XCTest
@preconcurrency import XPC

@testable import RamaAppleXpcClient

final class RamaXpcCoderTests: XCTestCase {
    private enum Mode: String, Codable {
        case direct
    }

    private struct NestedPayload: Codable, Equatable {
        let signed: Int64
        let unsigned: [UInt16]
        let blobs: [String: Data]
        let optional: String?
        let mode: Mode
    }

    private struct Payload: Codable, Equatable {
        let smallUnsigned: UInt8
        let largeUnsigned: UInt64
        let data: Data
        let uuid: UUID
        let date: Date
    }

    func testNativeTypesAndRoundTrip() throws {
        let payload = Payload(
            smallUnsigned: 7,
            largeUnsigned: .max,
            data: Data([0x01, 0x02, 0xFE]),
            uuid: UUID(uuidString: "3E51D81C-766D-4A40-9FEE-D6B7647D62B6")!,
            date: Date(timeIntervalSince1970: 123.25)
        )
        let object = try RamaXpcCoder.encode(payload)

        XCTAssertEqual(type(of: object, key: "smallUnsigned"), XPC_TYPE_UINT64)
        XCTAssertEqual(type(of: object, key: "largeUnsigned"), XPC_TYPE_UINT64)
        XCTAssertEqual(type(of: object, key: "data"), XPC_TYPE_DATA)
        XCTAssertEqual(type(of: object, key: "uuid"), XPC_TYPE_UUID)
        XCTAssertEqual(type(of: object, key: "date"), XPC_TYPE_DATE)
        XCTAssertEqual(
            xpc_date_get_value(xpc_dictionary_get_value(object, "date")!),
            123_250_000_000
        )
        XCTAssertEqual(try RamaXpcCoder.decode(Payload.self, from: object), payload)
    }

    func testNestedContainersAndNullRoundTrip() throws {
        let payload = NestedPayload(
            signed: .min,
            unsigned: [0, 1, .max],
            blobs: ["empty": Data(), "value": Data([0xAA])],
            optional: nil,
            mode: .direct
        )

        let object = try RamaXpcCoder.encode(payload)

        XCTAssertEqual(try RamaXpcCoder.decode(NestedPayload.self, from: object), payload)
    }

    func testNarrowIntegerOverflowIsRejected() {
        let value = xpc_uint64_create(256)

        XCTAssertThrowsError(try RamaXpcCoder.decode(UInt8.self, from: value))
    }

    func testFloatAcceptsRepresentableXpcDouble() throws {
        let value = xpc_double_create(0.1)

        XCTAssertEqual(try RamaXpcCoder.decode(Float.self, from: value), 0.1)
    }

    func testDateOutsideNativeRangeIsRejected() {
        let value = Date(timeIntervalSince1970: Double(Int64.max) / 1_000_000_000)

        XCTAssertThrowsError(try RamaXpcCoder.encode(value))
    }

    private func type(of object: xpc_object_t, key: String) -> xpc_type_t? {
        guard let value = xpc_dictionary_get_value(object, key) else { return nil }
        return xpc_get_type(value)
    }
}
