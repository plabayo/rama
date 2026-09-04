import Foundation
import Network
import XCTest

@testable import RamaAppleNetworkExtension

/// Tests for terminal connection release in `NwTcpConnectionWritePump`.
///
/// A local FIN is only a half-close and must not impose a response deadline.
/// The bounded cancellation grace starts once the whole promoted flow reaches
/// terminal. Each test verifies:
///
/// 1. The FIN is actually sent on the wire (empty send with isComplete = true).
/// 2. A local FIN alone never cancels the connection.
/// 3. Terminal release eventually cancels the connection.
/// 4. External `pump.cancel()` invalidates the watchdog before it fires.
/// 5. A non-ready connection short-circuits the drain path — no FIN,
///    no watchdog.
///
/// All tests use a short `lingerCloseDeadline` (≤ 600ms) so the suite
/// stays fast even under CI noise. The lower bound on "watchdog fired"
/// is asserted by waiting past the deadline plus a slack margin.
final class NwTcpConnectionWritePumpLingerTests: XCTestCase {

    private func makeQueue() -> DispatchQueue {
        DispatchQueue(label: "rama.tproxy.test.tcp.write-pump.linger", qos: .utility)
    }

    /// Awaits a block on the test's serial queue. The pump's
    /// finishCloseIfDrained → delegate hop runs asynchronously on its
    /// own queue, so the test has to synchronise its inspection.
    private func waitForQueueDrain(_ queue: DispatchQueue, timeout: TimeInterval = 1.0) {
        let exp = expectation(description: "queue drained")
        queue.async { exp.fulfill() }
        wait(for: [exp], timeout: timeout)
    }

    func testDrainSendsFinWithoutStartingResponseDeadline() {
        let mock = MockNwConnection()
        mock.transition(to: .ready)
        let queue = makeQueue()
        let pump = NwTcpConnectionWritePump(
            connection: mock,
            queue: queue,
            lingerCloseDeadline: .milliseconds(300),
            onDrained: {}
        )

        pump.closeWhenDrained()
        waitForQueueDrain(queue)

        // Drain with no pending bytes emits exactly one FIN. A successful
        // local half-close must not start whole-connection cancellation.
        XCTAssertEqual(mock.sentChunks.count, 1, "expected exactly one send (the FIN)")
        XCTAssertNil(mock.sentChunks.first?.content, "FIN send should have nil content")
        XCTAssertEqual(mock.sentChunks.first?.isComplete, true, "FIN send should have isComplete=true")
        Thread.sleep(forTimeInterval: 0.45)
        waitForQueueDrain(queue)
        XCTAssertEqual(
            mock.cancelCount, 0,
            "a quiet response half must survive beyond the terminal grace")
    }

    func testExternalPumpCancelInvalidatesLingerWatchdog() {
        let mock = MockNwConnection()
        mock.transition(to: .ready)
        let queue = makeQueue()
        let pump = NwTcpConnectionWritePump(
            connection: mock,
            queue: queue,
            lingerCloseDeadline: .milliseconds(600),
            onDrained: {}
        )

        pump.closeWhenDrained()
        waitForQueueDrain(queue)
        XCTAssertEqual(mock.sentChunks.count, 1)
        XCTAssertEqual(mock.cancelCount, 0)

        pump.armTerminalLingerCancel()
        waitForQueueDrain(queue)

        // Cancel the pump while the watchdog is still pending. External
        // cancel is the path that the per-flow context's teardown
        // closures take after a hard error or natural close.
        pump.cancel()
        waitForQueueDrain(queue)

        // Wait well past the linger deadline.
        Thread.sleep(forTimeInterval: 0.90)
        waitForQueueDrain(queue)

        XCTAssertEqual(
            mock.cancelCount, 0,
            "external pump.cancel() must invalidate the watchdog; pump.cancel() itself does not call connection.cancel()"
        )
    }

    /// Regression: the linger watchdog must fire even when the
    /// pump itself is deallocated before the deadline. The
    /// promote-cutover teardown path drops the per-flow ctx
    /// (and the pump with it) right after the FIN send
    /// completes; without a strong capture of the connection,
    /// the watchdog `[weak self]` no-ops and the NWConnection
    /// registration leaks.
    func testLingerCancelsConnectionEvenAfterPumpDeallocated() {
        let mock = MockNwConnection()
        mock.transition(to: .ready)
        let queue = makeQueue()

        do {
            let pump = NwTcpConnectionWritePump(
                connection: mock,
                queue: queue,
                lingerCloseDeadline: .milliseconds(150),
                onDrained: {}
            )
            pump.closeWhenDrained()
            waitForQueueDrain(queue)
            XCTAssertEqual(mock.sentChunks.count, 1, "FIN was sent")
            pump.armTerminalLingerCancel()
            waitForQueueDrain(queue)
            // No `cancelCount == 0` assertion here: the watchdog fires
            // on a wall-clock deadline, so "not yet fired" races a
            // loaded CI runner that can stall past the deadline before
            // we reach this line. The regression (watchdog fires after
            // the pump is deallocated) is asserted below.
            // `pump` goes out of scope → deallocated.
        }

        // Poll for the watchdog to fire rather than asserting after a
        // fixed sleep — robust to a loaded runner delaying the timer.
        let firedBy = Date().addingTimeInterval(2.0)
        while mock.cancelCount == 0 && Date() < firedBy {
            Thread.sleep(forTimeInterval: 0.01)
        }
        waitForQueueDrain(queue)

        XCTAssertEqual(
            mock.cancelCount, 1,
            "linger watchdog must cancel the connection even after the pump is deallocated"
        )
    }

    /// Regression (broader self-scan, audit theme): a terminal write
    /// error DURING the drain closes the core via
    /// `pumpCore(_:didTerminateWith:)`, NOT via the FIN path
    /// (`pumpCoreDidFinishDraining`). That handler must STILL fire the
    /// pending `closeWhenDrained` callback and force-cancel the
    /// connection.
    ///
    /// Before the fix `didTerminateWith` was a silent no-op. In the
    /// promoted `TcpDirectForwarder` hot path the C→S
    /// `.finishing → .finished` transition is gated SOLELY on this
    /// callback, so it wedged forever: `onTerminal` never fired and the
    /// per-flow ctx (which strongly holds the pump) leaked in the
    /// registry — `deinit` can't rescue it because the ctx is pinned
    /// waiting for the `.finished` only this callback delivers. The
    /// NWConnection registration leaked too: the nastiest trigger is the
    /// transient-backpressure retry hard-deadline, which terminates while
    /// the connection is still `.ready`, so the egress state handler
    /// never observes `.failed`/`.cancelled` and there is no other
    /// teardown path. `TcpClientWritePump` already fired its drain
    /// completion on terminate — this restores the egress-side symmetry.
    func testTerminalWriteErrorDuringDrainFiresCallbackAndForceCancels() {
        let mock = MockNwConnection()
        mock.transition(to: .ready)
        let queue = makeQueue()
        let drained = expectation(description: "closeWhenDrained callback fired")
        let pump = NwTcpConnectionWritePump(
            connection: mock,
            queue: queue,
            lingerCloseDeadline: .milliseconds(300),
            onDrained: {}
        )

        // Queue a chunk so the drain has an in-flight send to fail.
        // With no pending bytes, `closeWhenDrained` would send the FIN
        // immediately and never reach the terminate path.
        pump.enqueue(Data([0x01, 0x02, 0x03]))
        waitForQueueDrain(queue)
        XCTAssertEqual(mock.sentChunks.count, 1, "the data chunk was sent")
        XCTAssertEqual(
            mock.pendingSendCount, 1, "its send completion is still outstanding")

        pump.closeWhenDrained { drained.fulfill() }
        waitForQueueDrain(queue)
        // Still draining — the in-flight send hasn't completed, so no
        // FIN and no terminal yet.
        XCTAssertEqual(mock.cancelCount, 0)

        // Fail the in-flight send with a NON-transient error
        // (ECONNRESET is not in the {ENOBUFS, EAGAIN} retry set) → the
        // core terminates instead of finishing the drain.
        mock.completePendingSend(error: .posix(.ECONNRESET))

        wait(for: [drained], timeout: 2.0)
        waitForQueueDrain(queue)
        XCTAssertEqual(
            mock.cancelCount, 1,
            "terminal write error must force-cancel the connection so it can't leak"
        )
        // No FIN was ever sent — the drain terminated on error before
        // the FIN send (a FIN is a send with nil content).
        XCTAssertNil(
            mock.sentChunks.first(where: { $0.content == nil }),
            "no FIN on the terminal-error path"
        )
    }

    /// Regression (promoted-teardown leak): `closeWhenDrained` on an
    /// already-closed core sends no FIN and arms no linger watchdog. Since
    /// `applyPromotedTerminal` delegates the connection cancel to that
    /// watchdog, the fast path must cancel itself or the connection (and
    /// the graph it anchors) leaks. It must still fire the callback.
    func testCloseWhenDrainedOnAlreadyClosedCoreForceCancels() {
        let mock = MockNwConnection()
        mock.transition(to: .ready)
        let queue = makeQueue()
        let drained = expectation(description: "closeWhenDrained callback fired")
        let pump = NwTcpConnectionWritePump(
            connection: mock,
            queue: queue,
            lingerCloseDeadline: .milliseconds(300),
            onDrained: {}
        )

        // Close the core WITHOUT cancelling the connection — exactly what
        // `pump.cancel()` does (the connection cancel is normally the
        // teardown caller's responsibility, but promoted teardown
        // delegates it to this pump).
        pump.cancel()
        waitForQueueDrain(queue)
        XCTAssertEqual(
            mock.cancelCount, 0,
            "precondition: pump.cancel() alone does not cancel the connection"
        )

        // The graceful close now arrives on an already-closed core → the
        // `isClosed()` fast path. It must force-cancel the connection AND
        // fire the callback.
        pump.closeWhenDrained { drained.fulfill() }
        wait(for: [drained], timeout: 2.0)
        waitForQueueDrain(queue)

        XCTAssertEqual(
            mock.cancelCount, 1,
            "closeWhenDrained on an already-closed core must force-cancel the connection so the promoted-teardown path can't leak it"
        )
        XCTAssertEqual(
            mock.sentChunks.count, 0,
            "no FIN is possible on an already-closed core"
        )
    }

    func testDrainOnNonReadyConnectionForceCancelsInsteadOfLeaking() {
        let mock = MockNwConnection()
        mock.transition(to: .preparing)
        let queue = makeQueue()
        let pump = NwTcpConnectionWritePump(
            connection: mock,
            queue: queue,
            lingerCloseDeadline: .milliseconds(300),
            onDrained: {}
        )

        pump.closeWhenDrained()
        waitForQueueDrain(queue)

        // No FIN can be sent on a non-`.ready` connection...
        XCTAssertEqual(
            mock.sentChunks.count, 0,
            "FIN must not be sent when the connection is not in .ready state"
        )
        // ...but the connection MUST be force-cancelled right away —
        // not left for a watchdog this branch never arms. The promoted
        // terminal path delegates connection cancel to this pump, so
        // bailing without cancelling leaks the NWConnection + its NECP
        // entry. Immediate, not deadline-gated.
        XCTAssertEqual(
            mock.cancelCount, 1,
            "non-ready drain must force-cancel the connection so it can't leak"
        )
    }

    /// The terminal release remains activity-aware as a defensive guard for
    /// late callbacks and cancels only after a full quiet window.
    func testTerminalLingerDefersWhileLateActivityMoves() {
        final class IdleClock: @unchecked Sendable {
            private let lock = NSLock()
            private var ms: UInt64 = 0
            var value: UInt64 {
                get { lock.lock(); defer { lock.unlock() }; return ms }
                set { lock.lock(); defer { lock.unlock() }; ms = newValue }
            }
        }
        let mock = MockNwConnection()
        mock.transition(to: .ready)
        let queue = makeQueue()
        let idle = IdleClock()  // starts at 0ms = actively moving bytes
        let pump = NwTcpConnectionWritePump(
            connection: mock,
            queue: queue,
            lingerCloseDeadline: .milliseconds(120),
            onDrained: {},
            readSideIdleMs: { idle.value }
        )

        pump.closeWhenDrained()
        waitForQueueDrain(queue)
        XCTAssertEqual(mock.sentChunks.count, 1, "the FIN itself is unaffected")
        pump.armTerminalLingerCancel()
        waitForQueueDrain(queue)

        // Well past the linger deadline the connection must still be alive:
        // every expiry observed recent activity and re-armed.
        Thread.sleep(forTimeInterval: 0.4)
        waitForQueueDrain(queue)
        XCTAssertEqual(
            mock.cancelCount, 0,
            "linger must defer while the read side is still streaming")

        // The flow goes quiet; the next re-armed check force-cancels.
        idle.value = 10_000
        pollUntil("linger watchdog cancels once the flow is quiet") { mock.cancelCount == 1 }
    }
}
