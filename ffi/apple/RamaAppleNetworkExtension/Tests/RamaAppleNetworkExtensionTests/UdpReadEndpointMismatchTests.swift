// This file relies on the explicitly test-enabled read-loop observation seam
// fields on `UdpClientWritePump` (`testSentByEndpointSetCount` /
// `testLastSentByEndpoint`). Release-mode builds compile out those
// fields and corresponding `UdpFlowSession` calls entirely (zero fallback
// mutation or endpoint ARC churn on the production hot path), and
// ordinary Release products omit this file's required instrumentation. Debug
// tests and optimized tests built with RAMA_TESTING enable it explicitly.
#if DEBUG || RAMA_TESTING

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
/// Assertion strategy: the Debug-only read seam calls
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

    /// `completePendingRead` invokes the Apple callback inline, and that
    /// callback queues all Swift-side forwarding on this flow's serial queue.
    /// A synchronous snapshot therefore observes the completed forwarding
    /// turn without assuming that Rust has requested another kernel read.
    private func writerSnapshot(
        core: TransparentProxyCore,
        flow: MockUdpFlow,
        writer: UdpClientWritePump
    ) -> (setCount: Int, lastEndpoint: NWEndpoint?) {
        guard let flowQueue = core.testInspectUdpFlowQueue(for: flow) else {
            XCTFail("flow queue not registered for flow")
            return (writer.testSentByEndpointSetCount, writer.testLastSentByEndpoint)
        }
        return flowQueue.sync {
            (writer.testSentByEndpointSetCount, writer.testLastSentByEndpoint)
        }
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
        let snapshot = writerSnapshot(core: fx.core, flow: flow, writer: writer)

        XCTAssertEqual(
            snapshot.setCount, 1,
            "exactly one attribution: only datagrams[0] is paired with endpoints[0]"
        )
        XCTAssertEqual(
            (snapshot.lastEndpoint as? NWHostEndpoint)?.hostname, "10.0.0.1",
            "the one Debug observation endpoint must be endpoints[0], not a fabrication"
        )
        XCTAssertTrue(
            snapshot.lastEndpoint === firstEndpoint,
            "the hot path must cache Apple's original endpoint object instead of reconstructing it"
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
        let snapshot = writerSnapshot(core: fx.core, flow: flow, writer: writer)

        XCTAssertEqual(
            snapshot.setCount, 3,
            "every datagram has a paired endpoint, so cache is updated 3 times"
        )
        XCTAssertEqual(
            (snapshot.lastEndpoint as? NWHostEndpoint)?.hostname, "10.0.0.3",
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
        let snapshot = writerSnapshot(core: fx.core, flow: flow, writer: writer)

        XCTAssertEqual(
            snapshot.setCount, 0,
            "no endpoint array means no attribution and no cache touch"
        )
        XCTAssertNil(snapshot.lastEndpoint)
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
        let snapshot = writerSnapshot(core: fx.core, flow: flow, writer: writer)

        XCTAssertEqual(
            snapshot.setCount, 1,
            "only datagrams[0] is paired; surplus endpoints contribute nothing"
        )
        XCTAssertEqual(
            (snapshot.lastEndpoint as? NWHostEndpoint)?.hostname, "10.0.0.1"
        )
    }

    /// Activation itself must not prefetch. Rust's service supplies read
    /// credits one at a time, and each forwarded credit must map to exactly
    /// one Apple read. Capturing the real Rust callbacks before forwarding
    /// them makes every phase observable without scheduler-delay assertions.
    func testActivationAndServiceDemandIssueExactlyOneAppleReadPerCredit() {
        let fx = makeFixture()
        defer { tearDown(fx) }

        let flow = MockUdpFlow()
        let session = UdpFlowSession(core: fx.core, flow: flow, meta: makeMeta())
        session.idleTimeoutMs = 0
        session.buildClientWritePump()
        session.installRequestRead()

        let serviceDemands = Locked<[UInt64]>([])
        let decision = fx.engine.newUdpSession(
            meta: makeMeta(),
            onServerDatagram: { _, _ in },
            onClientReadDemand: { probeId in
                serviceDemands.withLock { $0.append(probeId) }
            },
            onServerClosed: {}
        )
        guard case .intercept(let handle) = decision else {
            return XCTFail("expected UDP interception")
        }
        defer { handle.onClientClose() }
        session.sessionHandle = handle
        session.ctx.session = handle

        session.openKernelFlow()
        waitFor("flow.open") { flow.openWasInvoked }
        XCTAssertEqual(flow.pendingReadCount, 0, "opening must not prefetch")
        XCTAssertEqual(serviceDemands.withLock { $0.count }, 0)

        XCTAssertTrue(flow.completeOpen(error: nil))
        waitFor("first real Rust service demand") {
            serviceDemands.withLock { $0.count } == 1
        }
        session.flowQueue.sync {}
        XCTAssertEqual(
            flow.pendingReadCount, 0,
            "activation must not issue an Apple read before its service demand is forwarded")

        guard let firstProbeId = serviceDemands.withLock({ $0.first }) else {
            return XCTFail("first Rust service demand missing")
        }
        session.ctx.requestReadWithProbe?(firstProbeId)
        session.flowQueue.sync {}
        XCTAssertEqual(flow.pendingReadCount, 1, "one service demand must issue one Apple read")
        XCTAssertEqual(
            serviceDemands.withLock { $0.count }, 1,
            "a blocked service receive must not create a second demand")

        XCTAssertTrue(
            flow.completePendingRead(
                datagrams: [Data("unattributed".utf8)], endpoints: nil, error: nil))
        waitFor("second real Rust service demand") {
            serviceDemands.withLock { $0.count } == 2
        }
        session.flowQueue.sync {}
        XCTAssertEqual(
            flow.pendingReadCount, 0,
            "the next Apple read must remain gated until the second demand is forwarded")

        guard
            let secondProbeId = serviceDemands.withLock({
                $0.count > 1 ? $0[1] : nil
            })
        else {
            return XCTFail("second Rust service demand missing")
        }
        session.ctx.requestReadWithProbe?(secondProbeId)
        session.flowQueue.sync {}
        XCTAssertEqual(
            flow.pendingReadCount, 1,
            "the second service demand must issue exactly one additional Apple read")
        XCTAssertEqual(
            serviceDemands.withLock { $0.count }, 2,
            "the second service receive must remain blocked without another datagram")
    }
}

#endif  // DEBUG
