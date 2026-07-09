import RamaAppleNEFFI
import XCTest

/// Tripwires for the C ABI Swift consumes. The C header and Rust
/// tests pin the same numbers, so accidental field drift fails close
/// to the boundary where it was introduced.
final class FFIAbiLayoutTests: XCTestCase {
    func testCoreByteStructLayouts() {
        XCTAssertEqual(MemoryLayout<RamaBytesView>.size, 16)
        XCTAssertEqual(MemoryLayout<RamaBytesView>.alignment, 8)
        XCTAssertEqual(MemoryLayout<RamaBytesOwned>.size, 24)
        XCTAssertEqual(MemoryLayout<RamaBytesOwned>.alignment, 8)
        XCTAssertEqual(MemoryLayout<RamaBytesOwnedView>.size, 32)
        XCTAssertEqual(MemoryLayout<RamaBytesOwnedView>.alignment, 8)
    }

    func testTransparentProxyMetadataLayouts() {
        XCTAssertEqual(MemoryLayout<RamaTransparentProxyFlowEndpoint>.size, 24)
        XCTAssertEqual(MemoryLayout<RamaTransparentProxyFlowEndpoint>.alignment, 8)
        XCTAssertEqual(MemoryLayout<RamaTransparentProxyFlowMeta>.size, 160)
        XCTAssertEqual(MemoryLayout<RamaTransparentProxyFlowMeta>.alignment, 8)
        XCTAssertEqual(MemoryLayout<RamaTransparentProxyNetworkRule>.size, 56)
        XCTAssertEqual(MemoryLayout<RamaTransparentProxyNetworkRule>.alignment, 8)
        XCTAssertEqual(MemoryLayout<RamaTransparentProxyConfig>.size, 80)
        XCTAssertEqual(MemoryLayout<RamaTransparentProxyConfig>.alignment, 8)
        XCTAssertEqual(MemoryLayout<RamaTransparentProxyInitConfig>.size, 32)
        XCTAssertEqual(MemoryLayout<RamaTransparentProxyInitConfig>.alignment, 8)
    }

    func testFixedWidthStatusEnumLayout() {
        XCTAssertEqual(MemoryLayout<RamaTcpDeliverStatus>.size, 1)
        XCTAssertEqual(MemoryLayout<RamaPromoteConfirmStatus>.size, 1)
    }

    func testEgressAndPeerStructLayouts() {
        XCTAssertEqual(MemoryLayout<RamaUdpPeerView>.size, 32)
        XCTAssertEqual(MemoryLayout<RamaUdpPeerView>.alignment, 8)
        XCTAssertEqual(MemoryLayout<RamaNwEgressParameters>.size, 11)
        XCTAssertEqual(MemoryLayout<RamaNwEgressParameters>.alignment, 1)
        XCTAssertEqual(MemoryLayout<RamaTcpEgressConnectOptions>.size, 56)
        XCTAssertEqual(MemoryLayout<RamaTcpEgressConnectOptions>.alignment, 4)
    }
}
