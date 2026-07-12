import Foundation
import Network
import XCTest

@testable import RamaAppleNetworkExtension

/// Contract tests for the per-flow teardown methods (the `applyX`
/// family, now on `TcpFlowContext` — folded in from the former
/// `TcpFlowTeardown`).
///
/// These are the single source of truth for tearing down an
/// intercepted TCP flow — seven distinct terminal-state transitions
/// used to inline their own cleanup sequences, which drifted into the
/// 1,177 `is already cancelled` + 1,520 `flow is closed for writes`
/// log-quarantine pathology surfaced during stress testing.
/// Consolidating them behind a sticky `isDone` flag makes idempotency a
/// structural property instead of seven separate disciplines.
///
/// These tests pin:
///
///   * **Idempotency** — first variant wins; every subsequent
///     call (any variant) is a no-op.
///   * **Pre-open variants** (`applyPreReadyFailure`,
///     `applyConnectTimeout`) leave the kernel flow alone —
///     the flow was never opened, calling `closeReadWithError`
///     on an un-opened flow is a contract violation.
///   * **Drained-close variant** distinguishes
///     `wasOpened: true` (close with `nil`, a clean EOF) from
///     `wasOpened: false` (close with `upstreamUnavailable`).
///   * **Full-teardown variants** close the flow with the
///     provided error, cancel-and-detach the connection, and
///     leave `ctx.connection == nil` for racing teardowns.
final class TcpFlowTeardownTests: XCTestCase {

    // MARK: - Helpers

    /// Bag of mocks + the context under test. Holding the whole graph
    /// (`ctx`, `core`) on the fixture keeps it alive for the test — the
    /// context's `core` ref is weak (production has the registry as the
    /// strong holder; here the fixture plays that role).
    private final class Fixture {
        let flow: MockTcpFlow
        let conn: MockNwConnection
        let ctx: TcpFlowContext
        let core: TransparentProxyCore

        init() {
            self.flow = MockTcpFlow()
            self.conn = MockNwConnection()
            self.ctx = TcpFlowContext()
            self.ctx.connection = self.conn
            // Engine-less core — `removeTcpFlow` is just a dict
            // remove; our tests don't register the flow first,
            // so the call is a harmless no-op.
            self.core = TransparentProxyCore()
            // Wire what the teardown methods need (as `TcpFlowSession.init`
            // does in production).
            self.ctx.flow = flow
            self.ctx.core = core
            self.ctx.flowId = ObjectIdentifier(flow)
        }
    }

    // MARK: - Idempotency

    /// First terminal-state path wins. A second call on ANY
    /// variant must observably do nothing: no extra
    /// `closeReadWithError`, no extra `cancel`, `isDone` stays
    /// `true`.
    func testFirstVariantWinsSubsequentCallsAreNoops() {
        let fx = Fixture()
        let err = NSError(domain: "test", code: 1)

        fx.ctx.applyWriterTerminal(err)

        XCTAssertTrue(fx.ctx.isDone)
        XCTAssertEqual(fx.flow.closeReadCallCount, 1)
        XCTAssertEqual(fx.flow.closeWriteCallCount, 1)
        XCTAssertEqual(fx.conn.cancelCount, 1)

        // Second call — any variant.
        fx.ctx.applyReadHardError(err)
        fx.ctx.applyDrainedClose(wasOpened: true)
        fx.ctx.applyPreReadyFailure()

        XCTAssertEqual(
            fx.flow.closeReadCallCount, 1,
            "subsequent teardown variants must not re-close the flow")
        XCTAssertEqual(fx.flow.closeWriteCallCount, 1)
        XCTAssertEqual(
            fx.conn.cancelCount, 1, "subsequent teardowns must not re-cancel the connection")
    }

    // MARK: - Pre-open variants

    /// `applyPreReadyFailure` runs in the egress-connection-failed-
    /// before-`.ready` path. The kernel flow has not been opened, but we
    /// DID claim it (`handleNewFlow` returned `true`), so per Apple's
    /// `NEAppProxyFlow` contract it must be opened or closed — dropping it
    /// unopened strands the app's `connect()`. Reject it by closing with
    /// the `upstreamUnavailable` error (same mechanism as the `blocked`
    /// path) so the app fails fast and can retry.
    func testApplyPreReadyFailureRejectsUnopenedFlow() {
        let fx = Fixture()

        fx.ctx.applyPreReadyFailure()

        XCTAssertTrue(fx.ctx.isDone)
        XCTAssertEqual(fx.flow.closeReadCallCount, 1, "pre-ready failure rejects the claimed flow")
        XCTAssertEqual(fx.flow.closeWriteCallCount, 1)
        XCTAssertNotNil(
            fx.flow.lastCloseReadError,
            "rejecting an unopened flow closes with a non-nil error so the app sees a failure")
        XCTAssertEqual(fx.conn.cancelCount, 1, "the egress connection still gets cancelled")
        XCTAssertNil(fx.ctx.connection, "ctx.connection is nilled for racing teardown paths")
    }

    /// Symmetric of `applyPreReadyFailure` — connect-timeout fires
    /// in the same pre-ready window, same cleanup shape.
    func testApplyConnectTimeoutRejectsUnopenedFlow() {
        let fx = Fixture()

        fx.ctx.applyConnectTimeout()

        XCTAssertEqual(fx.flow.closeReadCallCount, 1)
        XCTAssertEqual(fx.flow.closeWriteCallCount, 1)
        XCTAssertEqual(fx.conn.cancelCount, 1)
    }

    // MARK: - Drained close

    /// `wasOpened: true` represents the natural-EOF path after a
    /// successful flow.open — close with `nil` so Apple's
    /// `NEAppProxyFlow` treats it as a clean EOF.
    func testApplyDrainedCloseWasOpenedTrueClosesWithNil() {
        let fx = Fixture()

        fx.ctx.applyDrainedClose(wasOpened: true)

        XCTAssertEqual(fx.flow.closeReadCallCount, 1)
        XCTAssertEqual(fx.flow.closeWriteCallCount, 1)
        // Convenience accessor for the most-recent close-read
        // error — should be nil for the clean-EOF path.
        XCTAssertNil(fx.flow.lastCloseReadError, "wasOpened=true must close with nil error")
    }

    /// `wasOpened: false` means we hit server EOF before the
    /// kernel flow ever opened — close with the
    /// `upstreamUnavailable` synthesised error so the
    /// originating app sees a reasonable failure rather than a
    /// silent close.
    func testApplyDrainedCloseWasOpenedFalseClosesWithUpstreamUnavailable() {
        let fx = Fixture()

        fx.ctx.applyDrainedClose(wasOpened: false)

        XCTAssertEqual(fx.flow.closeReadCallCount, 1)
        XCTAssertEqual(fx.flow.closeWriteCallCount, 1)
        XCTAssertNotNil(
            fx.flow.lastCloseReadError,
            "wasOpened=false must close with a non-nil error so the originating app sees a failure"
        )
    }

    func testApplyDrainedCloseForwardsReadError() {
        let fx = Fixture()
        let error = NSError(domain: "test.egress", code: 54)

        fx.ctx.applyDrainedClose(wasOpened: true, error: error)

        let observed = fx.flow.lastCloseReadError as NSError?
        XCTAssertEqual(observed?.domain, error.domain)
        XCTAssertEqual(observed?.code, error.code)
    }

    // MARK: - Full-teardown variants

    /// `applyPostReadyFailure(nil)` synthesises a descriptive
    /// `NSError` so the kernel flow's close carries some signal
    /// downstream. Pre-refactor every call site had its own
    /// `??` fallback for this — easy to forget. The class
    /// guarantees it.
    func testApplyPostReadyFailureSynthesisesErrorIfNilProvided() {
        let fx = Fixture()

        fx.ctx.applyPostReadyFailure(nil)

        XCTAssertEqual(fx.flow.closeReadCallCount, 1)
        XCTAssertEqual(fx.flow.closeWriteCallCount, 1)
        XCTAssertNotNil(
            fx.flow.lastCloseReadError, "applyPostReadyFailure(nil) must synthesise an error")
    }

    /// `applyPostReadyFailure` with an explicit error must
    /// forward THAT error to the flow's close, not the
    /// synthesised one.
    func testApplyPostReadyFailureForwardsExplicitError() {
        let fx = Fixture()
        let err = NSError(domain: "test.upstream", code: 42)

        fx.ctx.applyPostReadyFailure(err)

        XCTAssertEqual(fx.flow.closeReadCallCount, 1)
        let observed = fx.flow.lastCloseReadError as NSError?
        XCTAssertEqual(observed?.domain, "test.upstream")
        XCTAssertEqual(observed?.code, 42)
    }

    /// Full-teardown variants nil the connection slot so
    /// concurrent teardown paths see `ctx.connection == nil`
    /// and skip their own cancel — the
    /// "already cancelled, ignoring cancel" log-quarantine
    /// suppression.
    func testApplyReadHardErrorNilsConnection() {
        let fx = Fixture()
        let err = NSError(domain: "test", code: 1)

        fx.ctx.applyReadHardError(err)

        XCTAssertEqual(fx.conn.cancelCount, 1, "the cancel ran")
        XCTAssertNil(fx.ctx.connection, "ctx.connection is nilled for racing teardown paths")
    }

    func testFullTeardownReleasesAdmissionToken() {
        let fx = Fixture()
        let decision = fx.core.testAdmitTcpStart(
            flowId: ObjectIdentifier(fx.flow),
            meta: RamaTransparentProxyFlowMetaBridge(
                protocolRaw: 1,
                remoteHost: "example.com",
                remotePort: 443,
                localHost: nil,
                localPort: 0,
                sourceAppSigningIdentifier: nil,
                sourceAppBundleIdentifier: nil,
                sourceAppAuditToken: nil,
                sourceAppPid: 4242))
        guard case .admit(let token) = decision else {
            XCTFail("expected admission")
            return
        }
        fx.ctx.admissionToken = token

        fx.ctx.applyEngineDetached()

        let deadline = Date().addingTimeInterval(1)
        while fx.core.testTcpStartsInFlight != 0, Date() < deadline {
            Thread.sleep(forTimeInterval: 0.002)
        }
        XCTAssertEqual(fx.core.testTcpStartsInFlight, 0)
        XCTAssertNil(fx.ctx.admissionToken)
    }

    // MARK: - Cross-variant idempotency

    /// Idempotency holds even when the FIRST call is the
    /// minimal pre-ready variant and the SECOND call is a
    /// full-teardown variant. The first run already nilled
    /// `ctx.connection`, so the second run's `ctx?.connection?
    /// .cancelAndDetach()` is a no-op anyway — but the
    /// structural `done` flag means we never even reach those
    /// lines on the second call.
    func testIdempotencyAcrossDifferentVariants() {
        let fx = Fixture()

        fx.ctx.applyPreReadyFailure()
        XCTAssertEqual(fx.flow.closeReadCallCount, 1, "pre-ready failure rejects the claimed flow")
        XCTAssertEqual(fx.conn.cancelCount, 1)

        fx.ctx.applyPostReadyFailure(NSError(domain: "late", code: 1))

        XCTAssertEqual(
            fx.flow.closeReadCallCount, 1, "second variant must not run; flow not closed again")
        XCTAssertEqual(fx.conn.cancelCount, 1, "connection cancel does not double-fire")
    }
}
