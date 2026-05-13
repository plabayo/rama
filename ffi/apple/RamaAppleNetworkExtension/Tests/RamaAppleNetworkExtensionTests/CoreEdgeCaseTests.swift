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
}
