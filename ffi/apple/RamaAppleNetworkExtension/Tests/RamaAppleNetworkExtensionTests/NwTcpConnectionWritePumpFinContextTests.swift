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
}
