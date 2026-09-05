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

        init(idleTimeoutMs: UInt64) {
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

    func testTimeoutConversionSaturatesInsteadOfWrapping() {
        XCTAssertEqual(udpIdleTimeoutNanoseconds(60_000), 60_000_000_000)
        XCTAssertEqual(
            udpIdleTimeoutNanoseconds(UInt64.max / 1_000_000),
            (UInt64.max / 1_000_000) * 1_000_000
        )
        XCTAssertEqual(
            udpIdleTimeoutNanoseconds(UInt64.max / 1_000_000 + 1),
            UInt64.max
        )
        XCTAssertEqual(udpIdleTimeoutNanoseconds(UInt64.max), UInt64.max)
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
        #if DEBUG || RAMA_TESTING
            XCTAssertEqual(fx.session.idleTimerScheduleCount, 0)
        #endif
    }

    /// A high-rate datagram burst changes only the activity timestamp.
    /// It must retain the original work item and perform exactly one
    /// queue schedule until that item fires.
    func testActivityBurstDoesNotRescheduleTimer() {
        let fx = Fixture(idleTimeoutMs: 10_000) // long enough not to fire mid-test
        fx.session.installTerminate()
        let base = DispatchTime.now().uptimeNanoseconds
        fx.session.flowQueue.async {
            fx.session.armIdleTimer(nowUptimeNs: base)
        }
        fx.drainFlowQueue()
        let first = fx.session.idleWork
        XCTAssertNotNil(first)
        #if DEBUG || RAMA_TESTING
            XCTAssertEqual(fx.session.idleTimerScheduleCount, 1)
        #endif

        fx.session.flowQueue.async {
            for offset in 1...50_000 {
                fx.session.recordIdleActivity(
                    nowUptimeNs: base + UInt64(offset)
                )
            }
        }
        fx.drainFlowQueue()

        XCTAssertTrue(first === fx.session.idleWork)
        XCTAssertFalse(first?.isCancelled ?? true)
        #if DEBUG || RAMA_TESTING
            XCTAssertEqual(fx.session.idleTimerScheduleCount, 1)
        #endif

        let terminated = expectation(description: "burst fixture terminated")
        fx.session.flowQueue.async {
            fx.session.ctx.terminate?(nil)
            fx.session.flowQueue.async { terminated.fulfill() }
        }
        wait(for: [terminated], timeout: 2.0)
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

    /// A timer firing at the original deadline observes activity at
    /// +70 ms and schedules exactly the remaining 70 ms. A fire at
    /// the extended deadline then terminates. Explicit monotonic times
    /// make this independent of wall-clock scheduling jitter.
    func testActivityExtendsDeadlineAtTimerFire() {
        let fx = Fixture(idleTimeoutMs: 100_000)
        fx.session.installTerminate()
        fx.core.registerUdpFlow(fx.session.flowId, anchor: fx.session)
        let base = DispatchTime.now().uptimeNanoseconds
        let timeoutNs = UInt64(fx.session.idleTimeoutMs) * 1_000_000
        let activityAt = base + 70_000_000

        let reconciled = expectation(description: "extended idle timer reconciled")
        fx.session.flowQueue.async {
            fx.session.armIdleTimer(nowUptimeNs: base)
            let first = fx.session.idleWork
            fx.session.recordIdleActivity(nowUptimeNs: activityAt)

            // Simulate the original item firing at its deadline. Cancel
            // its real delayed delivery because this test drives the
            // same state transition with an explicit monotonic time.
            first?.cancel()
            fx.session.handleIdleTimerFire(nowUptimeNs: base + timeoutNs)

            XCTAssertNotEqual(fx.session.ctx.readState, .closed)
            XCTAssertFalse(first === fx.session.idleWork)
            #if DEBUG || RAMA_TESTING
                XCTAssertEqual(fx.session.idleTimerScheduleCount, 2)
            #endif

            fx.session.idleWork?.cancel()
            fx.session.handleIdleTimerFire(
                nowUptimeNs: activityAt + timeoutNs
            )
            fx.session.flowQueue.async { reconciled.fulfill() }
        }
        wait(for: [reconciled], timeout: 2.0)

        XCTAssertEqual(fx.session.ctx.readState, .closed)
        XCTAssertEqual(fx.core.udpFlowCount, 0)
    }

    func testReadCallbackRecordsActivityBeforeFlowQueueDispatch() {
        let fx = Fixture(idleTimeoutMs: 100_000)
        let priorActivity = DispatchTime.now().uptimeNanoseconds
        fx.session.recordIdleActivity(nowUptimeNs: priorActivity)

        let blockerStarted = DispatchSemaphore(value: 0)
        let releaseBlocker = DispatchSemaphore(value: 0)
        fx.session.flowQueue.async {
            blockerStarted.signal()
            releaseBlocker.wait()
        }
        XCTAssertEqual(blockerStarted.wait(timeout: .now() + 1), .success)

        fx.session.handleReadCompletion(
            datagrams: [Data("activity".utf8)],
            endpoints: nil,
            error: nil)

        XCTAssertGreaterThan(
            fx.session.testIdleActivitySnapshot.lastUptimeNs ?? 0,
            priorActivity,
            "callback entry must publish activity while queue processing is still blocked")

        releaseBlocker.signal()
        fx.drainFlowQueue()
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
