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

    func testDataCompletionAlreadyOnConnectionQueueRunsInline() {
        let mock = MockNwConnection()
        mock.transition(to: .ready)
        let queue = makeQueue()
        let drained = TestValue(0)
        let pump = NwTcpConnectionWritePump(
            connection: mock,
            queue: queue,
            onDrained: { drained.update { $0 += 1 } }
        )

        XCTAssertEqual(
            pump.enqueue(Data(repeating: 0xA1, count: writePumpMaxPendingBytes)),
            .accepted)
        waitForQueueDrain(queue)
        XCTAssertEqual(pump.enqueue(Data([0xB1])), .paused)

        queue.sync {
            XCTAssertTrue(mock.completePendingSend(error: nil))
            XCTAssertEqual(
                drained.get(), 1,
                "NW completion already delivered on its queue must not add a hop")
        }
    }

    func testDataCompletionOffConnectionQueueIsNormalized() {
        let mock = MockNwConnection()
        mock.transition(to: .ready)
        let queue = makeQueue()
        let drained = TestValue(0)
        let pump = NwTcpConnectionWritePump(
            connection: mock,
            queue: queue,
            onDrained: { drained.update { $0 += 1 } }
        )

        XCTAssertEqual(
            pump.enqueue(Data(repeating: 0xA1, count: writePumpMaxPendingBytes)),
            .accepted)
        waitForQueueDrain(queue)
        XCTAssertEqual(pump.enqueue(Data([0xB1])), .paused)
        let blockerEntered = expectation(description: "queue blocker entered")
        let releaseBlocker = DispatchSemaphore(value: 0)
        queue.async {
            blockerEntered.fulfill()
            releaseBlocker.wait()
        }
        wait(for: [blockerEntered], timeout: 1.0)

        XCTAssertTrue(mock.completePendingSend(error: nil))
        XCTAssertEqual(drained.get(), 0, "off-queue completion must be dispatched")
        releaseBlocker.signal()
        waitForQueueDrain(queue)
        XCTAssertEqual(drained.get(), 1)
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

    func testFinSendErrorReachesTerminalBeforeDrainWaiter() {
        let mock = MockNwConnection()
        mock.transition(to: .ready)
        let queue = makeQueue()
        let events = Locked([String]())
        let observed = TestValue<Error?>(nil)
        let terminal = expectation(description: "terminal owner notified")
        let drained = expectation(description: "drain waiter released")
        let pump = NwTcpConnectionWritePump(
            connection: mock,
            queue: queue,
            onDrained: {},
            onTerminal: { error in
                observed.set(error)
                events.withLock { $0.append("terminal") }
                terminal.fulfill()
            })

        pump.closeWhenDrained {
            events.withLock { $0.append("drain") }
            drained.fulfill()
        }
        waitForQueueDrain(queue)
        XCTAssertEqual(mock.pendingSendCount, 1, "FIN completion is pending")

        XCTAssertTrue(mock.completePendingSend(error: .posix(.ECONNRESET)))
        wait(for: [terminal, drained], timeout: 1.0)
        XCTAssertEqual(events.withLock { $0 }, ["terminal", "drain"])
        guard case .posix(.ECONNRESET)? = observed.get() as? NWError else {
            return XCTFail("original FIN send error was not preserved")
        }
        XCTAssertEqual(mock.cancelCount, 1)
    }

    func testPendingFinCompletionDoesNotRetainPump() {
        let mock = MockNwConnection()
        mock.transition(to: .ready)
        let queue = makeQueue()
        weak var weakPump: NwTcpConnectionWritePump?

        autoreleasepool {
            let pump = NwTcpConnectionWritePump(
                connection: mock,
                queue: queue,
                onDrained: {})
            weakPump = pump
            pump.closeWhenDrained()
            waitForQueueDrain(queue)
            XCTAssertEqual(mock.pendingSendCount, 1)
        }

        waitForQueueDrain(queue)
        XCTAssertNil(
            weakPump,
            "NWConnection retaining its FIN completion must not retain the pump")
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
