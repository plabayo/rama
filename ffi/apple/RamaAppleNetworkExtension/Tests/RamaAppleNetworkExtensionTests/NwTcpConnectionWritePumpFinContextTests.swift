import Foundation
import Network
import XCTest

@testable import RamaAppleNetworkExtension

/// Pins the wire-level contract for the TCP write-close (FIN) emitted by
/// `NwTcpConnectionWritePump.closeWhenDrained()`.
///
/// Apple's `nw_connection_send` docs:
///
/// > To send a write-close (or shutdown a write side, in BSD sockets
/// > parlance) on a stream protocol like TCP, the application should
/// > pass `is_complete = true` along with
/// > `NW_CONNECTION_FINAL_MESSAGE_CONTEXT` (or
/// > `NW_CONNECTION_DEFAULT_STREAM_CONTEXT`).
///
/// See:
/// <https://developer.apple.com/documentation/network/nw_connection_send(_:_:_:_:_:)?language=objc>
/// <https://developer.apple.com/documentation/network/nwconnection/contentcontext/finalmessage>
/// <https://developer.apple.com/documentation/network/nwconnection/contentcontext/defaultstream>
///
/// The companion `NwTcpConnectionWritePumpLingerTests` exercises the
/// linger-cancel behavior. This file's narrow purpose is to lock in the
/// FIN's content-context — an isComplete = true with `.defaultMessage`
/// does not signal half-close on TCP and silently degrades the drain
/// path into "wait, then force-cancel".
final class NwTcpConnectionWritePumpFinContextTests: XCTestCase {

    private func makeQueue() -> DispatchQueue {
        DispatchQueue(label: "rama.tproxy.test.tcp.write-pump.fin", qos: .utility)
    }

    private func waitForQueueDrain(_ queue: DispatchQueue, timeout: TimeInterval = 1.0) {
        let exp = expectation(description: "queue drained")
        queue.async { exp.fulfill() }
        wait(for: [exp], timeout: timeout)
    }

    /// The FIN emitted on drain MUST use a content context that
    /// indicates a TCP write-close (`.finalMessage` or
    /// `.defaultStream`). Using `.defaultMessage` silently turns the
    /// "FIN" into a normal write whose `isComplete` flag has no
    /// meaning on a stream protocol — the peer never observes a
    /// half-close.
    func testDrainFinUsesStreamHalfCloseContentContext() {
        let mock = MockNwConnection()
        mock.transition(to: .ready)
        let queue = makeQueue()
        let pump = NwTcpConnectionWritePump(
            connection: mock,
            queue: queue,
            lingerCloseDeadline: .milliseconds(2_000),
            onDrained: {}
        )

        pump.closeWhenDrained()
        waitForQueueDrain(queue)

        XCTAssertEqual(mock.sentChunks.count, 1, "expected exactly one send (the FIN)")
        let chunk = mock.sentChunks.first
        XCTAssertNil(chunk?.content, "FIN send must carry no content")
        XCTAssertEqual(chunk?.isComplete, true, "FIN send must mark isComplete = true")

        // The actual contract under test: the content context must be
        // one that NWConnection interprets as a stream half-close.
        // Identity equality is the right check — these are class
        // singletons exposed by NWConnection.ContentContext.
        let isStreamHalfClose =
            chunk?.contentContext === NWConnection.ContentContext.finalMessage
            || chunk?.contentContext === NWConnection.ContentContext.defaultStream
        XCTAssertTrue(
            isStreamHalfClose,
            "FIN must use .finalMessage or .defaultStream content context "
                + "to signal TCP half-close; got "
                + String(describing: chunk?.contentContext)
        )
    }

    func testFinCompletionReturnsDrainCallbackToPumpQueue() {
        let mock = MockNwConnection()
        mock.transition(to: .ready)
        let queue = makeQueue()
        let queueKey = DispatchSpecificKey<UInt8>()
        queue.setSpecific(key: queueKey, value: 1)
        let callbackOnQueue = TestValue(false)
        let callback = expectation(description: "FIN drain callback")
        let pump = NwTcpConnectionWritePump(
            connection: mock,
            queue: queue,
            lingerCloseDeadline: .milliseconds(2_000),
            onDrained: {})

        pump.closeWhenDrained {
            callbackOnQueue.set(DispatchQueue.getSpecific(key: queueKey) == 1)
            callback.fulfill()
        }
        waitForQueueDrain(queue)
        XCTAssertTrue(mock.completePendingSend(error: nil))
        wait(for: [callback], timeout: 1.0)

        XCTAssertTrue(callbackOnQueue.get())
    }

    func testDataSendErrorReachesTerminalBeforeDrainWaiter() {
        let mock = MockNwConnection()
        mock.transition(to: .ready)
        let queue = makeQueue()
        let events = Locked([String]())
        let terminal = expectation(description: "terminal owner notified")
        let drained = expectation(description: "drain waiter released")
        let pump = NwTcpConnectionWritePump(
            connection: mock,
            queue: queue,
            lingerCloseDeadline: .milliseconds(2_000),
            onDrained: {},
            onTerminal: { _ in
                events.withLock { $0.append("terminal") }
                terminal.fulfill()
            })

        XCTAssertEqual(pump.enqueue(Data([0x01])), .accepted)
        waitForQueueDrain(queue)
        XCTAssertEqual(mock.pendingSendCount, 1)
        pump.closeWhenDrained {
            events.withLock { $0.append("drain") }
            drained.fulfill()
        }
        waitForQueueDrain(queue)

        XCTAssertTrue(mock.completePendingSend(error: .posix(.ECONNRESET)))
        wait(for: [terminal, drained], timeout: 1.0)
        XCTAssertEqual(events.withLock { $0 }, ["terminal", "drain"])
    }

    func testDeinitFallbackReturnsDrainCallbackToPumpQueue() {
        let mock = MockNwConnection()
        mock.transition(to: .ready)
        let queue = makeQueue()
        let queueKey = DispatchSpecificKey<UInt8>()
        queue.setSpecific(key: queueKey, value: 1)
        let callbackOnQueue = TestValue(false)
        let callback = expectation(description: "deinit drain callback")
        var pump: NwTcpConnectionWritePump? = NwTcpConnectionWritePump(
            connection: mock,
            queue: queue,
            lingerCloseDeadline: .milliseconds(2_000),
            onDrained: {})

        XCTAssertEqual(pump?.enqueue(Data([0x01])), .accepted)
        waitForQueueDrain(queue)
        XCTAssertEqual(mock.pendingSendCount, 1)
        pump?.closeWhenDrained {
            callbackOnQueue.set(DispatchQueue.getSpecific(key: queueKey) == 1)
            callback.fulfill()
        }
        waitForQueueDrain(queue)
        pump = nil
        wait(for: [callback], timeout: 1.0)

        XCTAssertTrue(callbackOnQueue.get())
    }
}
