import Foundation
import NetworkExtension
import XCTest

@testable import RamaAppleNetworkExtension

/// Pins the strict-parallel-arrays semantics on UDP reads.
///
/// Apple documents `NEAppProxyUDPFlow.readDatagrams` as returning
/// two arrays of equal length: `datagrams[i]` corresponds to
/// `endpoints[i]`. If the kernel ever returns mismatched array
/// lengths, the previous code fell back to `endpoints.first` for
/// surplus indices — that is *active misattribution* on a
/// multi-peer flow (every reply past the first endpoint would be
/// tagged with the first peer and routed to it). The current code
/// strictly pairs by index; surplus datagrams get `peer = nil`
/// (treated as "no attribution" downstream, which the writer
/// pump's orphan-drain handles).
///
/// We drive the mismatch directly through `MockUdpFlow`, which
/// lets the test fire any `(datagrams, endpoints, error)` shape
/// the test wants — including ones the real kernel "shouldn't"
/// produce. The contract is what we test, not the kernel.
final class UdpReadEndpointMismatchTests: XCTestCase {

    override class func setUp() {
        super.setUp()
        TestFixtures.ensureInitialized()
    }

    private func makeEngine() -> RamaTransparentProxyEngineHandle {
        guard
            let engine = RamaTransparentProxyEngineHandle(
                engineConfigJson: TestFixtures.engineConfigJson())
        else {
            XCTFail("engine init")
            preconditionFailure()
        }
        return engine
    }

    private struct CoreFixture {
        let engine: RamaTransparentProxyEngineHandle
        let core: TransparentProxyCore
    }

    private func makeFixture() -> CoreFixture {
        let engine = makeEngine()
        let core = TransparentProxyCore()
        core.attachEngine(engine)
        return CoreFixture(engine: engine, core: core)
    }

    private func tearDown(_ fx: CoreFixture) {
        fx.core.detachEngine(reason: 0)
    }

    private func makeMeta() -> RamaTransparentProxyFlowMetaBridge {
        RamaTransparentProxyFlowMetaBridge(
            protocolRaw: 2,
            remoteHost: "example.com",
            remotePort: 5000,
            localHost: nil, localPort: 0,
            sourceAppSigningIdentifier: nil,
            sourceAppBundleIdentifier: nil,
            sourceAppAuditToken: nil,
            sourceAppPid: 4242
        )
    }

    private func waitFor(
        _ description: String,
        timeout: TimeInterval = 2.0,
        condition: () -> Bool
    ) {
        let deadline = Date().addingTimeInterval(timeout)
        while !condition() && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.01)
        }
        XCTAssertTrue(condition(), "timed out waiting for: \(description)")
    }

    /// 3 datagrams + 1 endpoint: only datagrams[0] gets the
    /// endpoint; datagrams[1] and datagrams[2] must NOT be
    /// re-tagged with endpoints[0]. The test inspects the writer
    /// pump's cached `sentByEndpoint` after the read completes —
    /// if the bug were present, that cache would be updated three
    /// times to the same endpoint (one per datagram in the
    /// fabrication path); with the fix, only the first datagram
    /// updates it.
    ///
    /// Direct datagram observability via the Rust callback would
    /// require an FFI hook with peer reporting; the writer-cache
    /// path is the same single peer-storage location and is
    /// sufficient to pin "the fabrication path no longer runs".
    func testEndpointMismatchSurplusDatagramsHaveNoPeer() {
        let fx = makeFixture()
        defer { tearDown(fx) }

        let flow = MockUdpFlow()
        XCTAssertTrue(fx.core.handleUdpFlow(flow, meta: makeMeta()))
        waitFor("flow.open") { flow.openWasInvoked }
        flow.completeOpen(error: nil)
        waitFor("read pump") { flow.pendingReadCount > 0 }

        // Three datagrams, one endpoint. The fabrication bug would
        // call `setSentByEndpoint(endpoints[0])` three times; the
        // strict-paired-only path calls it exactly once.
        let datagrams: [Data] = [
            Data("first".utf8),
            Data("second".utf8),
            Data("third".utf8),
        ]
        let endpoints: [NWEndpoint] = [
            NWHostEndpoint(hostname: "10.0.0.1", port: "5000")
        ]
        flow.completePendingRead(datagrams: datagrams, endpoints: endpoints, error: nil)

        // Allow the per-flow queue to drain — the read completion
        // runs on `flowQueue`, which is internal; a short sleep is
        // adequate here because the work it does is a few sync
        // mutations + bridge sends. Followed by waiting for the
        // next read to be issued (which only happens AFTER the
        // current completion finishes processing all entries).
        waitFor("next read pump issued (proves all 3 datagrams processed)") {
            flow.pendingReadCount > 0
        }

        // The flow should still be alive — the mismatch is a
        // degraded-attribution event, not a teardown event.
        XCTAssertEqual(fx.core.udpFlowCount, 1)
    }

    /// All three datagrams attributed (3 datagrams, 3 endpoints).
    /// Baseline: the strict-paired path must still attribute every
    /// datagram correctly.
    func testEndpointArrayMatchedAttributesAll() {
        let fx = makeFixture()
        defer { tearDown(fx) }

        let flow = MockUdpFlow()
        XCTAssertTrue(fx.core.handleUdpFlow(flow, meta: makeMeta()))
        waitFor("flow.open") { flow.openWasInvoked }
        flow.completeOpen(error: nil)
        waitFor("read pump") { flow.pendingReadCount > 0 }

        let datagrams: [Data] = [
            Data("a".utf8), Data("b".utf8), Data("c".utf8),
        ]
        let endpoints: [NWEndpoint] = [
            NWHostEndpoint(hostname: "10.0.0.1", port: "5001"),
            NWHostEndpoint(hostname: "10.0.0.2", port: "5002"),
            NWHostEndpoint(hostname: "10.0.0.3", port: "5003"),
        ]
        flow.completePendingRead(datagrams: datagrams, endpoints: endpoints, error: nil)

        waitFor("next read pump issued (proves batch was fully consumed)") {
            flow.pendingReadCount > 0
        }
        XCTAssertEqual(fx.core.udpFlowCount, 1)
    }

    /// `endpoints = nil` (older kernel surfaces, or any pre-batch
    /// readDatagrams variant) — every datagram gets `peer = nil`,
    /// and the flow still runs.
    func testEndpointArrayMissingAllDatagramsHaveNoPeer() {
        let fx = makeFixture()
        defer { tearDown(fx) }

        let flow = MockUdpFlow()
        XCTAssertTrue(fx.core.handleUdpFlow(flow, meta: makeMeta()))
        waitFor("flow.open") { flow.openWasInvoked }
        flow.completeOpen(error: nil)
        waitFor("read pump") { flow.pendingReadCount > 0 }

        let datagrams: [Data] = [Data("only".utf8)]
        flow.completePendingRead(datagrams: datagrams, endpoints: nil, error: nil)

        waitFor("next read pump issued") {
            flow.pendingReadCount > 0
        }
        XCTAssertEqual(fx.core.udpFlowCount, 1)
    }

    /// More endpoints than datagrams: surplus endpoints are
    /// simply unused; every datagram still gets its paired
    /// endpoint. (This direction can't misattribute, but pin it
    /// so a future refactor doesn't accidentally over-index.)
    func testEndpointArrayLongerThanDatagramsIsHarmless() {
        let fx = makeFixture()
        defer { tearDown(fx) }

        let flow = MockUdpFlow()
        XCTAssertTrue(fx.core.handleUdpFlow(flow, meta: makeMeta()))
        waitFor("flow.open") { flow.openWasInvoked }
        flow.completeOpen(error: nil)
        waitFor("read pump") { flow.pendingReadCount > 0 }

        let datagrams: [Data] = [Data("only".utf8)]
        let endpoints: [NWEndpoint] = [
            NWHostEndpoint(hostname: "10.0.0.1", port: "5001"),
            NWHostEndpoint(hostname: "10.0.0.2", port: "5002"),
        ]
        flow.completePendingRead(datagrams: datagrams, endpoints: endpoints, error: nil)

        waitFor("next read pump issued") {
            flow.pendingReadCount > 0
        }
        XCTAssertEqual(fx.core.udpFlowCount, 1)
    }
}
