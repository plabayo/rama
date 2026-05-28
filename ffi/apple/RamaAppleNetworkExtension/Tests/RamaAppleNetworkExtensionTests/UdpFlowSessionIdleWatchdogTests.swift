import Foundation
import Network
import XCTest

@testable import RamaAppleNetworkExtension

/// Watchdog phase tests for `UdpFlowSession.armIdleTimer`.
///
/// `TransparentProxyCore` retains the per-flow session strongly
/// (via `UdpFlowSessionAnchor`); the watchdog is what tells the
/// core when to drop it for flows where Apple never delivers a
/// terminal datagram-read signal (DNS request/response, NAT
/// keepalives, mDNS jitter, …). These tests pin the contract
/// end-to-end.
final class UdpFlowSessionIdleWatchdogTests: XCTestCase {

    private final class Fixture {
        let core: TransparentProxyCore
        let flow: MockUdpFlow
        let session: UdpFlowSession<MockUdpFlow>

        init(idleTimeoutMs: UInt32) {
            self.core = TransparentProxyCore()
            self.flow = MockUdpFlow()
            let meta = RamaTransparentProxyFlowMetaBridge(
                protocolRaw: 2, remoteHost: "example.com", remotePort: 53,
                localHost: nil, localPort: 0,
                sourceAppSigningIdentifier: nil,
                sourceAppBundleIdentifier: nil,
                sourceAppAuditToken: nil, sourceAppPid: 4242)
            self.session = UdpFlowSession(core: core, flow: flow, meta: meta)
            self.session.idleTimeoutMs = idleTimeoutMs
        }

        /// Sync barrier: wait until any work already enqueued on
        /// `flowQueue` has run.
        func drainFlowQueue() {
            let drained = XCTestExpectation(description: "flow queue drained")
            session.flowQueue.async { drained.fulfill() }
            _ = XCTWaiter.wait(for: [drained], timeout: 2.0)
        }
    }

    /// With `idleTimeoutMs == 0` the watchdog is disabled: `armIdleTimer`
    /// schedules nothing. This is the explicit opt-out for tests that
    /// exercise other phase code.
    func testZeroTimeoutDisablesWatchdog() {
        let fx = Fixture(idleTimeoutMs: 0)
        fx.session.installTerminate()
        fx.session.flowQueue.async { fx.session.armIdleTimer() }
        fx.drainFlowQueue()
        XCTAssertNil(fx.session.idleWork, "zero timeout must leave idleWork nil")
    }

    /// `armIdleTimer` schedules a work item; calling it again before
    /// fire cancels the previous one. (Otherwise back-to-back datagrams
    /// would leave stale work queued and the watchdog would fire too
    /// early or duplicate.)
    func testArmIdleTimerCancelsPreviousWorkOnRearm() {
        let fx = Fixture(idleTimeoutMs: 10_000) // long enough not to fire mid-test
        fx.session.installTerminate()
        fx.session.flowQueue.async { fx.session.armIdleTimer() }
        fx.drainFlowQueue()
        let first = fx.session.idleWork
        XCTAssertNotNil(first)

        fx.session.flowQueue.async { fx.session.armIdleTimer() }
        fx.drainFlowQueue()
        let second = fx.session.idleWork
        XCTAssertNotNil(second)
        XCTAssertFalse(first === second, "rearm must replace the work item")
        XCTAssertTrue(first?.isCancelled ?? false, "the previous work item must be cancelled")
    }

    /// After `idleTimeoutMs` elapses with no activity, the watchdog
    /// fires `ctx.terminate(nil)` — readState becomes `.closed`, the
    /// flow's close-read/write hooks fire, and the core's session
    /// registry drops the anchor (verified via `udpFlowCount`).
    ///
    /// Uses a very short timeout (50 ms) to keep the test fast.
    func testIdleTimerFireTerminatesFlow() {
        let fx = Fixture(idleTimeoutMs: 50)
        fx.session.installTerminate()
        // Pretend `start()` succeeded — register the session anchor.
        fx.core.registerUdpFlow(fx.session.flowId, anchor: fx.session)
        XCTAssertEqual(fx.core.udpFlowCount, 1)
        fx.session.flowQueue.async { fx.session.armIdleTimer() }

        // Wait long enough for the 50 ms deadline + the cancellation
        // dispatch to settle on flowQueue.
        let exp = expectation(description: "idle terminate completes")
        fx.session.flowQueue.asyncAfter(deadline: .now() + .milliseconds(200)) {
            exp.fulfill()
        }
        wait(for: [exp], timeout: 2.0)

        XCTAssertEqual(fx.session.ctx.readState, .closed)
        XCTAssertEqual(fx.flow.closeReadCallCount, 1)
        XCTAssertEqual(fx.flow.closeWriteCallCount, 1)
        XCTAssertEqual(fx.core.udpFlowCount, 0,
                       "core must drop the session anchor so it can deallocate")
    }

    /// The terminate closure cancels the pending idle work item so a
    /// fire that lost the race after teardown can't double-close the
    /// flow.
    func testTerminateCancelsPendingIdleWork() {
        let fx = Fixture(idleTimeoutMs: 10_000)
        fx.session.installTerminate()
        fx.session.flowQueue.async { fx.session.armIdleTimer() }
        fx.drainFlowQueue()
        XCTAssertNotNil(fx.session.idleWork)

        let exp = expectation(description: "terminate clears idle work")
        fx.session.flowQueue.async {
            fx.session.ctx.terminate?(nil)
            fx.session.flowQueue.async { exp.fulfill() }
        }
        wait(for: [exp], timeout: 2.0)

        XCTAssertNil(fx.session.idleWork, "terminate must nil the idleWork reference")
    }

    /// Re-arming before the timer fires resets the deadline. Pin the
    /// observable: an arm at t=0 with a 100 ms timeout, plus a re-arm
    /// at t=70 ms, must not fire at t=100 ms — only at t=170 ms.
    func testRearmExtendsDeadline() {
        let fx = Fixture(idleTimeoutMs: 100)
        fx.session.installTerminate()
        fx.core.registerUdpFlow(fx.session.flowId, anchor: fx.session)
        fx.session.flowQueue.async { fx.session.armIdleTimer() }

        // Rearm at +70 ms.
        fx.session.flowQueue.asyncAfter(deadline: .now() + .milliseconds(70)) {
            fx.session.armIdleTimer()
        }

        // At +130 ms (past the original deadline, before the rearmed
        // one), the watchdog must NOT have fired yet.
        let midCheck = expectation(description: "still alive at +130ms")
        fx.session.flowQueue.asyncAfter(deadline: .now() + .milliseconds(130)) {
            XCTAssertNotEqual(fx.session.ctx.readState, .closed,
                              "rearm at +70ms must extend deadline past +100ms")
            midCheck.fulfill()
        }
        wait(for: [midCheck], timeout: 2.0)

        // At +250 ms (past the rearmed deadline), it should have fired.
        let lateCheck = expectation(description: "fired by +250ms")
        fx.session.flowQueue.asyncAfter(deadline: .now() + .milliseconds(150)) {
            lateCheck.fulfill()
        }
        wait(for: [lateCheck], timeout: 2.0)
        XCTAssertEqual(fx.session.ctx.readState, .closed)
        XCTAssertEqual(fx.core.udpFlowCount, 0)
    }

    /// Lifecycle invariant: when `start()` takes any non-intercept
    /// path (engine unavailable, `.passthrough`, `.blocked`), the
    /// session is never registered with the core, so the local
    /// variable going out of scope is the only ref and the
    /// session deallocates immediately. This is what made the
    /// previous `lifetimeAnchor` cycle leak the 131 bypassed flows
    /// observed in the 15-min stress bundle.
    func testEarlyReturnPathsDeallocateSession() {
        let core = TransparentProxyCore()
        let flow = MockUdpFlow()
        let meta = RamaTransparentProxyFlowMetaBridge(
            protocolRaw: 2, remoteHost: "example.com", remotePort: 53,
            localHost: nil, localPort: 0,
            sourceAppSigningIdentifier: nil,
            sourceAppBundleIdentifier: nil,
            sourceAppAuditToken: nil, sourceAppPid: 4242)
        weak var weakSession: UdpFlowSession<MockUdpFlow>?
        autoreleasepool {
            let session = UdpFlowSession(core: core, flow: flow, meta: meta)
            weakSession = session
            // No engine attached → `requestEngineSession()` returns
            // nil → `start()` falls through the bypass branch.
            XCTAssertFalse(session.start())
        }
        XCTAssertNil(weakSession,
                     "engine-unavailable path must not retain the session")
        XCTAssertEqual(core.udpFlowCount, 0)
    }
}
