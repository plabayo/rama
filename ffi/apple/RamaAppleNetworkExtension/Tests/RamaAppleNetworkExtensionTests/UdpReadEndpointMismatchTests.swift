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
/// strictly pairs by index; surplus datagrams get `peer = nil`.
///
/// Assertion strategy: the read loop calls
/// `writer.setSentByEndpoint(...)` exactly once per matched
/// (datagram, endpoint) pair; the writer pump exposes a
/// test-only invocation counter (`testSentByEndpointSetCount`)
/// and the last value (`testLastSentByEndpoint`). A regression
/// of the `eps.first` fabrication path would bump the counter
/// once per *datagram* (including unmatched ones), so the
/// counter is a direct disambiguator.
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

    /// 3 datagrams + 1 endpoint: exactly one cache update. The
    /// fabrication bug would update the cache 3 times.
    func testEndpointMismatch3Datagrams1EndpointTouchesCacheOnce() {
        let fx = makeFixture()
        defer { tearDown(fx) }

        let flow = MockUdpFlow()
        XCTAssertTrue(fx.core.handleUdpFlow(flow, meta: makeMeta()))
        waitFor("flow.open") { flow.openWasInvoked }
        flow.completeOpen(error: nil)
        waitFor("read pump") { flow.pendingReadCount > 0 }
        guard let writer = fx.core.testInspectUdpWriter(for: flow) else {
            XCTFail("writer not registered for flow")
            return
        }
        XCTAssertEqual(writer.testSentByEndpointSetCount, 0, "baseline")

        let datagrams: [Data] = [
            Data("first".utf8),
            Data("second".utf8),
            Data("third".utf8),
        ]
        let firstEndpoint = NWHostEndpoint(hostname: "10.0.0.1", port: "5001")
        flow.completePendingRead(datagrams: datagrams, endpoints: [firstEndpoint], error: nil)
        waitFor("next read pump issued (proves loop completed)") { flow.pendingReadCount > 0 }

        XCTAssertEqual(
            writer.testSentByEndpointSetCount, 1,
            "exactly one attribution: only datagrams[0] is paired with endpoints[0]"
        )
        XCTAssertEqual(
            (writer.testLastSentByEndpoint as? NWHostEndpoint)?.hostname, "10.0.0.1",
            "the one cached endpoint must be endpoints[0], not a fabrication"
        )
    }

    /// 3 datagrams + 3 endpoints: cache updated 3 times (once per
    /// matched pair), final value is endpoints.last.
    func testEndpointArrayMatched3DatagramsTouchesCacheThrice() {
        let fx = makeFixture()
        defer { tearDown(fx) }

        let flow = MockUdpFlow()
        XCTAssertTrue(fx.core.handleUdpFlow(flow, meta: makeMeta()))
        waitFor("flow.open") { flow.openWasInvoked }
        flow.completeOpen(error: nil)
        waitFor("read pump") { flow.pendingReadCount > 0 }
        guard let writer = fx.core.testInspectUdpWriter(for: flow) else {
            XCTFail("writer not registered for flow")
            return
        }

        let datagrams: [Data] = [
            Data("a".utf8), Data("b".utf8), Data("c".utf8),
        ]
        let endpoints: [NWEndpoint] = [
            NWHostEndpoint(hostname: "10.0.0.1", port: "5001"),
            NWHostEndpoint(hostname: "10.0.0.2", port: "5002"),
            NWHostEndpoint(hostname: "10.0.0.3", port: "5003"),
        ]
        flow.completePendingRead(datagrams: datagrams, endpoints: endpoints, error: nil)
        waitFor("next read pump issued") { flow.pendingReadCount > 0 }

        XCTAssertEqual(
            writer.testSentByEndpointSetCount, 3,
            "every datagram has a paired endpoint, so cache is updated 3 times"
        )
        XCTAssertEqual(
            (writer.testLastSentByEndpoint as? NWHostEndpoint)?.hostname, "10.0.0.3",
            "FIFO ordering: the last update must be the last endpoint"
        )
    }

    /// `endpoints = nil`: no cache updates at all, even though
    /// datagrams are present and the flow keeps running.
    func testEndpointArrayMissingTouchesCacheZeroTimes() {
        let fx = makeFixture()
        defer { tearDown(fx) }

        let flow = MockUdpFlow()
        XCTAssertTrue(fx.core.handleUdpFlow(flow, meta: makeMeta()))
        waitFor("flow.open") { flow.openWasInvoked }
        flow.completeOpen(error: nil)
        waitFor("read pump") { flow.pendingReadCount > 0 }
        guard let writer = fx.core.testInspectUdpWriter(for: flow) else {
            XCTFail("writer not registered for flow")
            return
        }

        flow.completePendingRead(datagrams: [Data("only".utf8)], endpoints: nil, error: nil)
        waitFor("next read pump issued") { flow.pendingReadCount > 0 }

        XCTAssertEqual(
            writer.testSentByEndpointSetCount, 0,
            "no endpoint array means no attribution and no cache touch"
        )
        XCTAssertNil(writer.testLastSentByEndpoint)
    }

    /// 1 datagram + 2 endpoints: surplus endpoints are ignored;
    /// cache touched exactly once with endpoints[0].
    func testEndpointArrayLongerThanDatagramsAttributesOnlyMatched() {
        let fx = makeFixture()
        defer { tearDown(fx) }

        let flow = MockUdpFlow()
        XCTAssertTrue(fx.core.handleUdpFlow(flow, meta: makeMeta()))
        waitFor("flow.open") { flow.openWasInvoked }
        flow.completeOpen(error: nil)
        waitFor("read pump") { flow.pendingReadCount > 0 }
        guard let writer = fx.core.testInspectUdpWriter(for: flow) else {
            XCTFail("writer not registered for flow")
            return
        }

        let datagrams: [Data] = [Data("only".utf8)]
        let endpoints: [NWEndpoint] = [
            NWHostEndpoint(hostname: "10.0.0.1", port: "5001"),
            NWHostEndpoint(hostname: "10.0.0.2", port: "5002"),
        ]
        flow.completePendingRead(datagrams: datagrams, endpoints: endpoints, error: nil)
        waitFor("next read pump issued") { flow.pendingReadCount > 0 }

        XCTAssertEqual(
            writer.testSentByEndpointSetCount, 1,
            "only datagrams[0] is paired; surplus endpoints contribute nothing"
        )
        XCTAssertEqual(
            (writer.testLastSentByEndpoint as? NWHostEndpoint)?.hostname, "10.0.0.1"
        )
    }
}
