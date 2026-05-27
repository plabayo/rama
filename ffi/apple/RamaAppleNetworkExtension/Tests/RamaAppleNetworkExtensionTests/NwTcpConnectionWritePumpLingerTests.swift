import Foundation
import Network
import XCTest

@testable import RamaAppleNetworkExtension

/// Tests for the linger-cancel watchdog in `NwTcpConnectionWritePump`.
///
/// The watchdog exists so that a peer which never replies to our FIN
/// cannot pin the macOS NWConnection registration alive. Each test
/// drives the pump through a slightly different drain → wait → expect
/// sequence to verify:
///
/// 1. The FIN is actually sent on the wire (empty send with isComplete = true).
/// 2. `cancel()` fires after the linger deadline if nothing else closed
///    the connection first.
/// 3. External `pump.cancel()` invalidates the watchdog before it fires.
/// 4. A non-ready connection short-circuits the drain path — no FIN,
///    no watchdog.
///
/// All tests use a short `lingerCloseDeadline` (≤ 200ms) so the suite
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

    func testDrainSendsFinAndArmsLingerWatchdog() {
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

        // Drain with no pending bytes emits exactly one FIN — content
        // nil with isComplete = true. The watchdog has been scheduled
        // but has not yet fired.
        XCTAssertEqual(mock.sentChunks.count, 1, "expected exactly one send (the FIN)")
        XCTAssertNil(mock.sentChunks.first?.content, "FIN send should have nil content")
        XCTAssertEqual(mock.sentChunks.first?.isComplete, true, "FIN send should have isComplete=true")
        XCTAssertEqual(mock.cancelCount, 0, "linger watchdog must not fire before its deadline")

        // Wait past the linger deadline + slack. The watchdog fires on
        // `queue` so we also let the queue drain to make the
        // observation deterministic.
        Thread.sleep(forTimeInterval: 0.45)
        waitForQueueDrain(queue)

        XCTAssertEqual(
            mock.cancelCount, 1,
            "linger watchdog should have force-cancelled the connection exactly once"
        )
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

    func testDrainOnNonReadyConnectionDoesNotSendFinOrArmWatchdog() {
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

        // Past the linger deadline.
        Thread.sleep(forTimeInterval: 0.45)
        waitForQueueDrain(queue)

        XCTAssertEqual(
            mock.sentChunks.count, 0,
            "FIN must not be sent when the connection is not in .ready state"
        )
        XCTAssertEqual(
            mock.cancelCount, 0,
            "no watchdog should arm when the drain hook bailed before sending the FIN"
        )
    }
}
