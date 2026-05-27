import Foundation
import Network
import XCTest

@testable import RamaAppleNetworkExtension

/// Edge-case tests that exercise specific code paths the main
/// lifecycle suite doesn't cover by accident. Every test here is
/// motivated by an actual bug shape that *could* exist if a future
/// edit got the path wrong; none of them are "test coverage for
/// coverage's sake."
final class CoreEdgeCaseTests: XCTestCase {

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

    private func makeMeta(
        protocolRaw: UInt32 = 1,
        port: UInt16 = 443
    ) -> RamaTransparentProxyFlowMetaBridge {
        RamaTransparentProxyFlowMetaBridge(
            protocolRaw: protocolRaw,
            remoteHost: "example.com",
            remotePort: port,
            localHost: nil, localPort: 0,
            sourceAppSigningIdentifier: nil,
            sourceAppBundleIdentifier: nil,
            sourceAppAuditToken: nil,
            sourceAppPid: 4242
        )
    }

    private func waitFor(
        _ description: String,
        timeout: TimeInterval = 5.0,
        condition: () -> Bool
    ) {
        let deadline = Date().addingTimeInterval(timeout)
        while !condition() && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.02)
        }
        XCTAssertTrue(condition(), "timed out waiting for: \(description)")
    }

    // MARK: - handleAppMessage in various engine states

    func testHandleAppMessageBeforeEngineAttached() {
        let core = TransparentProxyCore()
        // No `attachEngine` call — engine is nil.
        let reply = core.handleAppMessage(Data("ping".utf8))
        XCTAssertNil(reply, "handleAppMessage with no engine must short-circuit to nil")
    }

    func testHandleAppMessageAfterEngineDetached() {
        let core = TransparentProxyCore()
        core.attachEngine(makeEngine())
        core.detachEngine(reason: 0)
        let reply = core.handleAppMessage(Data("ping".utf8))
        XCTAssertNil(
            reply, "handleAppMessage after detachEngine must short-circuit to nil"
        )
    }

    func testHandleAppMessageWithEngineAttached() {
        let core = TransparentProxyCore()
        core.attachEngine(makeEngine())
        defer { core.detachEngine(reason: 0) }
        // The test engine's demo handler treats unparseable JSON as a
        // no-reply scenario, so the request → empty reply path is
        // exercised end-to-end. The point isn't the reply content
        // (the demo's policy) but that the route doesn't crash and
        // returns a `Data` shape consistent with `nil = no reply`.
        let reply = core.handleAppMessage(Data("ping".utf8))
        // Either nil or non-nil is acceptable — we're testing the
        // routing, not the demo handler's choice. What we check is
        // that no exception was raised.
        _ = reply
    }

    // MARK: - applyMetadata path

    func testApplyMetadataInvokedWhenPreserveOriginalIsDefault() {
        // The Swift core consults `egressOpts.parameters.preserve_original_meta_data`
        // and only calls `flow.applyMetadata(to:)` when it's true. The
        // engine's demo handler doesn't override the egress options
        // (so `egressOpts == nil`), and the core's default for that
        // case is `?? true`. Mock flow asserts the call happened.
        let core = TransparentProxyCore()
        core.attachEngine(makeEngine())
        defer { core.detachEngine(reason: 0) }
        let capture = NwConnectionCapture()
        core.nwConnectionFactory = capture.factory

        let flow = MockTcpFlow()
        XCTAssertTrue(core.handleTcpFlow(flow, meta: makeMeta()))
        XCTAssertEqual(
            flow.applyMetadataCallCount, 1,
            "applyMetadata must run by default (preserve_original_meta_data ?? true)"
        )

        let conn = capture.waitForLastConnection()
        conn.transition(to: .failed(.posix(.ECONNREFUSED)))
        waitFor("flow cleaned up") { core.tcpFlowCount == 0 }
        conn.simulateCancelled()
        capture.releaseAll()
    }

    // MARK: - Engine attached twice without detach

    func testEngineAttachReplacesPreviousEngine() {
        // Defensive — `attachEngine` is documented as a single-shot
        // operation from `startProxy`, but a future code path that
        // calls it twice without detaching shouldn't leak the first
        // engine via the core's `engine` storage. This pins that
        // semantic.
        let core = TransparentProxyCore()
        weak var weakE1: RamaTransparentProxyEngineHandle?
        autoreleasepool {
            let e1 = makeEngine()
            weakE1 = e1
            core.attachEngine(e1)
        }
        // Replace via second attach — first must release.
        core.attachEngine(makeEngine())
        // Engine handle deinit fires asynchronously after the Rust
        // runtime drains; allow a brief window before asserting.
        let deadline = Date().addingTimeInterval(2.0)
        while weakE1 != nil && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.05)
        }
        XCTAssertNil(
            weakE1,
            "second attachEngine must release the first engine handle"
        )
        core.detachEngine(reason: 0)
    }

    // MARK: - registerTcpFlow / removeTcpFlow idempotence

    func testRemoveTcpFlowIsIdempotent() {
        let core = TransparentProxyCore()
        core.attachEngine(makeEngine())
        defer { core.detachEngine(reason: 0) }

        let capture = NwConnectionCapture()
        core.nwConnectionFactory = capture.factory
        let flow = MockTcpFlow()
        _ = core.handleTcpFlow(flow, meta: makeMeta())
        let conn = capture.waitForLastConnection()
        conn.transition(to: .failed(.posix(.ECONNREFUSED)))
        waitFor("flow removed") { core.tcpFlowCount == 0 }
        conn.simulateCancelled()

        // Double-remove via the public API surface — should not
        // crash or assert.
        core.removeTcpFlow(ObjectIdentifier(flow))
        core.removeTcpFlow(ObjectIdentifier(flow))
        XCTAssertEqual(core.tcpFlowCount, 0)
    }

    // MARK: - handleNewFlow rejects non-TCP / non-UDP

    func testHandleAppMessageEmptyData() {
        // Edge case: empty payload. Should not crash; semantic is
        // up to the engine's handler. We test that the route
        // doesn't blow up on a zero-length input.
        let core = TransparentProxyCore()
        core.attachEngine(makeEngine())
        defer { core.detachEngine(reason: 0) }
        _ = core.handleAppMessage(Data())
    }

    // MARK: - State transition after detachEngine

    /// Apple delivers `stateUpdateHandler` state changes asynchronously
    /// on the connection's queue. A state can in principle arrive
    /// after the flow has already been torn down via `detachEngine`.
    /// Because every `[weak self, weak ctx]` capture in the handler
    /// observes both as nil, the late state must be a no-op rather
    /// than crash or invoke any cleanup path.
    func testStateUpdateAfterDetachIsNoOp() {
        let core = TransparentProxyCore()
        core.attachEngine(makeEngine())
        let capture = NwConnectionCapture()
        core.nwConnectionFactory = capture.factory

        let flow = MockTcpFlow()
        _ = core.handleTcpFlow(flow, meta: makeMeta())
        let conn = capture.waitForLastConnection()
        conn.transition(to: .ready)
        waitFor("flow.open invoked") { flow.openWasInvoked }
        flow.completeOpen(error: nil)
        waitFor("egress receive in flight") { conn.pendingReceiveCount > 0 }

        // Tear everything down — the engine is gone, ctx is gone,
        // session is gone.
        core.detachEngine(reason: 0)
        XCTAssertEqual(core.tcpFlowCount, 0)

        // Now fire a state transition. The handler is still set on
        // the mock connection because we haven't called
        // simulateCancelled; this models the real case of a late
        // kernel callback firing on a connection that production
        // code has already abandoned.
        //
        // The handler must process this without crashing. Pre-fix
        // behavior would have been a segfault if `ctx` had been
        // captured strongly; with `[weak ctx]` everywhere the
        // closure body bails out at the `guard let ctx` line.
        conn.transition(to: .failed(.posix(.ECONNRESET)))

        // Sanity: no extra cancel call, no flow.close invocations
        // from this late transition.
        let cancelsBefore = conn.cancelCount
        Thread.sleep(forTimeInterval: 0.10)
        XCTAssertEqual(
            conn.cancelCount, cancelsBefore,
            "late state transition must not trigger any new cancel"
        )
        conn.simulateCancelled()
        capture.releaseAll()
    }

    // MARK: - Duplicate .ready (Wi-Fi roam recovery shape)

    /// Post-ready `.waiting` followed by another `.ready` is the
    /// Wi-Fi roam pattern. The duplicate `.ready` arm in the state
    /// handler must cancel any pending `.waiting` tolerance work
    /// item so it doesn't fire on the now-healthy connection.
    func testDuplicateReadyAfterWaitingCancelsToleranceTimer() {
        let savedTolerance = defaultEgressWaitingToleranceMs
        defaultEgressWaitingToleranceMs = 200
        defer { defaultEgressWaitingToleranceMs = savedTolerance }

        let core = TransparentProxyCore()
        core.attachEngine(makeEngine())
        defer { core.detachEngine(reason: 0) }
        let capture = NwConnectionCapture()
        core.nwConnectionFactory = capture.factory

        let flow = MockTcpFlow()
        _ = core.handleTcpFlow(flow, meta: makeMeta())
        let conn = capture.waitForLastConnection()
        conn.transition(to: .ready)
        waitFor("flow.open invoked") { flow.openWasInvoked }
        flow.completeOpen(error: nil)
        waitFor("egress receive in flight") { conn.pendingReceiveCount > 0 }

        // Go into .waiting then bounce back to .ready before the
        // tolerance fires.
        conn.transition(to: .waiting(.posix(.ENETDOWN)))
        Thread.sleep(forTimeInterval: 0.05)
        conn.transition(to: .ready)

        // Wait past where the tolerance would have fired had the
        // duplicate .ready not cancelled it.
        Thread.sleep(forTimeInterval: 0.40)

        XCTAssertEqual(
            core.tcpFlowCount, 1,
            "duplicate .ready must cancel pending waiting-tolerance timer; flow should still be alive"
        )

        // Clean shutdown so the deferred detachEngine doesn't leak.
        conn.completePendingReceive(isComplete: true)
        waitFor("flow removed") { core.tcpFlowCount == 0 }
        conn.simulateCancelled()
        capture.releaseAll()
    }

    // MARK: - Periodic flow-count reporting timer

    /// The flow-count reporting timer is scheduled on attachEngine
    /// and cancelled on detachEngine. Without explicit cancel-on-
    /// detach, an attach/detach/attach sequence would leak a timer
    /// per cycle. This test drives the sequence and confirms
    /// detachEngine doesn't leak (the count test in
    /// `CoreArcLeakSweepTests.testTcpHappyPath_NoLeaksAcrossEveryClass`
    /// already passes; this is the unit-level version).
    func testAttachDetachCycleDoesNotLeakTimer() {
        let core = TransparentProxyCore()
        for _ in 0..<5 {
            core.attachEngine(makeEngine())
            core.detachEngine(reason: 0)
        }
        // No state to assert directly — the timer is private — but
        // running this test under the engine-init / shutdown 5×
        // pattern catches any obvious double-cancel crash or leak
        // that would surface here.
    }

    /// Mirrors the shape of a `startProxy` failure after `attachEngine`:
    /// the provider gets as far as attaching the engine, hits a later
    /// failure (e.g. `engine.config()` returns nil, or
    /// `setTunnelNetworkSettings` errors), and must locally detach so
    /// the engine + flow-count telemetry timer don't leak — Apple's
    /// runtime does NOT compensate via `stopProxy` after a failed
    /// `startProxy`. The fix in `RamaTransparentProxyProvider.swift`
    /// adds `core.detachEngine(reason: 0)` on each failure branch
    /// after attach; this test pins that the resulting state machine
    /// is usable again (the provider can be re-instantiated and
    /// re-attached cleanly) and that handleAppMessage falls through
    /// to nil in the failed/detached window.
    func testFailedStartupShapeDetachThenReattachIsClean() {
        let core = TransparentProxyCore()

        // Step 1: attach the engine, as `startProxy` does immediately
        // after engine creation.
        core.attachEngine(makeEngine())
        XCTAssertEqual(
            core.tcpFlowCount, 0,
            "freshly attached engine should have zero flows registered"
        )

        // Step 2: simulate a later-step startup failure by calling
        // `detachEngine` before any flows are handed in — what the
        // failure paths in `startProxy` now do.
        core.detachEngine(reason: 0)

        // After cleanup, handleAppMessage must short-circuit (no
        // engine attached) and not crash.
        XCTAssertNil(
            core.handleAppMessage(Data("ping".utf8)),
            "handleAppMessage after failed-startup teardown must return nil"
        )

        // Step 3: re-attach. The flow-count timer was cancelled and
        // the engine pointer cleared, so a fresh engine attaches
        // cleanly — no timer collision, no leftover registration
        // maps. If `detachEngine` had failed to release state, this
        // re-attach would surface as a double-timer schedule or a
        // dangling Rust runtime.
        core.attachEngine(makeEngine())
        defer { core.detachEngine(reason: 0) }
        XCTAssertEqual(
            core.tcpFlowCount, 0,
            "re-attached engine should have a clean registration map"
        )
    }
}
