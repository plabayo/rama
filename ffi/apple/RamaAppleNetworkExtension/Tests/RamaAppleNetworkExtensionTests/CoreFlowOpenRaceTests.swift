import Foundation
import Network
import XCTest

@testable import RamaAppleNetworkExtension

/// Tests the race where a post-ready egress failure is observed
/// *after* the per-flow state machine has already issued `flow.open`
/// but *before* the `flow.open` completion fires.
///
/// The teardown path (TCP: `tearDownPostReady`; UDP: `terminate`) is
/// already in place, but each of its cleanup entrypoints is
/// asynchronous (`connection.cancel()` schedules a state transition,
/// pump `.cancel()` posts to a queue, `removeTcpFlow` mutates the
/// shared map). That makes "removed" not the same as "no completions
/// can still see this flow alive". The pending `flow.open` completion
/// still runs serially on `flowQueue` after teardown — and at that
/// point the success branch must NOT spawn fresh pumps, rearm the
/// egress connection, or wire client-side reads against a connection
/// the teardown already cancelled.
///
/// The audit found this exact ordering uncovered: every other
/// lifecycle test completes `flow.open` before injecting post-ready
/// failure, so the post-completion-success path is never exercised
/// against a torn-down context. These tests fill that gap.
final class CoreFlowOpenRaceTests: XCTestCase {

    override class func setUp() {
        super.setUp()
        TestFixtures.ensureInitialized()
    }

    // MARK: - Test scaffolding (mirrors CoreTcpLifecycleTests)

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
        let capture: NwConnectionCapture
    }

    private func makeFixture() -> CoreFixture {
        let engine = makeEngine()
        let core = TransparentProxyCore()
        core.attachEngine(engine)
        let capture = NwConnectionCapture()
        core.nwConnectionFactory = capture.factory
        return CoreFixture(engine: engine, core: core, capture: capture)
    }

    private func tearDownFixture(_ fx: CoreFixture) {
        fx.core.detachEngine(reason: 0)
    }

    private func makeTcpMeta() -> RamaTransparentProxyFlowMetaBridge {
        RamaTransparentProxyFlowMetaBridge(
            protocolRaw: 1,
            remoteHost: "example.com",
            remotePort: 443,
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
        _ predicate: () -> Bool
    ) {
        let deadline = Date().addingTimeInterval(timeout)
        while !predicate() && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.005)
        }
        XCTAssertTrue(predicate(), "timed out waiting for: \(description)")
    }

    // MARK: - TCP: post-ready failure while flow.open is pending

    /// Drives the race: egress reaches `.ready` (which schedules
    /// `flow.open` and arms the egress read pump), the egress then
    /// fails post-ready, and only *after* teardown does the kernel
    /// finally signal `flow.open` success. The flow.open completion
    /// must observe the teardown and become a no-op — it must NOT
    /// start the client-side read pump, must NOT issue a fresh
    /// receive on the cancelled NWConnection, and must NOT leave a
    /// stale entry in `tcpFlowCount`.
    func testTcpFlowOpenCompletingAfterPostReadyFailureIsANoOp() {
        let fx = makeFixture()
        defer { tearDownFixture(fx) }

        let flow = MockTcpFlow()
        XCTAssertTrue(fx.core.handleTcpFlow(flow, meta: makeTcpMeta()))
        XCTAssertEqual(fx.core.tcpFlowCount, 1)

        let conn = fx.capture.waitForLastConnection()
        conn.transition(to: .ready)

        // .ready synchronously creates the pumps but does NOT issue
        // their first read — that's inside the flow.open completion.
        // So pending receive/read counts must both be 0 here.
        waitFor("flow.open called by .ready handler") { flow.openWasInvoked }
        XCTAssertEqual(
            conn.pendingReceiveCount, 0,
            "no egress receive must be in flight before flow.open completes"
        )
        XCTAssertEqual(
            flow.pendingReadCount, 0,
            "no client read must be in flight before flow.open completes"
        )

        // Inject post-ready failure. tearDownPostReady runs serially
        // on flowQueue, then dequeues; flow.open's pending completion
        // will run AFTER teardown on the same queue.
        conn.transition(to: .failed(.posix(.ECONNRESET)))
        waitFor("post-ready teardown removed the flow") {
            fx.core.tcpFlowCount == 0
        }

        // Now fire flow.open — this is the racy completion. It must
        // be a no-op for everything except logging.
        flow.completeOpen(error: nil)
        // Give the queue time to drain.
        Thread.sleep(forTimeInterval: 0.15)

        XCTAssertEqual(
            flow.pendingReadCount, 0,
            "racy flow.open completion must not start the client read pump after teardown"
        )
        XCTAssertEqual(
            fx.core.tcpFlowCount, 0,
            "racy flow.open completion must not resurrect the flow registration"
        )
        XCTAssertEqual(
            conn.pendingReceiveCount, 0,
            "racy flow.open completion must not arm a fresh receive against the cancelled NWConnection"
        )
    }

    // No UDP mirror of the post-ready failure race: the UDP path no
    // longer drives an `NWConnection` state machine — egress is a
    // Rust-owned BSD socket on the service side, opened after
    // `flow.open` succeeds. There is no pre-`flow.open` NWConnection
    // window in which a post-ready failure could race a pending
    // `flow.open` completion, so the bug class this guarded against
    // is structurally absent in the new UDP path.
}
