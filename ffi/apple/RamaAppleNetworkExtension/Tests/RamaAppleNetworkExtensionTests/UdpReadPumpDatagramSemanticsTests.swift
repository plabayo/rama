import Foundation
import Network
import XCTest

@testable import RamaAppleNetworkExtension

/// Tests that pin the WHATWG-of-Apple contract for `NWConnection.receive`
/// on a UDP connection:
///
/// > For datagram-based protocols, `isComplete` is set to `true` once a
/// > fully-formed datagram has been received. It is therefore NOT an
/// > end-of-stream signal — every healthy datagram completion arrives
/// > with `isComplete = true`. Only `error != nil` (or, by convention
/// > here, a real cancel surfaced via `error: .posix(.ECANCELED)`)
/// > indicates the pump should terminate.
///
/// See `nw_connection_receive_completion_t`:
/// <https://developer.apple.com/documentation/network/nw_connection_receive_completion_t?language=objc>
///
/// These tests deliberately bypass the convenience defaults of the test
/// mock (`isComplete: Bool = false`) — that default is a lurking trap
/// because it hides exactly the bug shape we are guarding against.
final class UdpReadPumpDatagramSemanticsTests: XCTestCase {
    override class func setUp() {
        super.setUp()
        TestFixtures.ensureInitialized()
    }

    private func makeEngine() -> RamaTransparentProxyEngineHandle {
        guard
            let h = RamaTransparentProxyEngineHandle(
                engineConfigJson: TestFixtures.engineConfigJson())
        else {
            XCTFail("engine init")
            preconditionFailure()
        }
        return h
    }

    private func makeQueue() -> DispatchQueue {
        DispatchQueue(label: "rama.tproxy.test.udp.read.datagram", qos: .utility)
    }

    private func makeInterceptedSession(
        _ engine: RamaTransparentProxyEngineHandle,
        onServerDatagram: @escaping (Data) -> Void
    ) -> RamaUdpSessionHandle {
        let meta = RamaTransparentProxyFlowMetaBridge(
            protocolRaw: 2,
            remoteHost: "example.com",
            remotePort: 5000,
            localHost: nil, localPort: 0,
            sourceAppSigningIdentifier: nil,
            sourceAppBundleIdentifier: nil,
            sourceAppAuditToken: nil,
            sourceAppPid: 4242
        )
        let decision = engine.newUdpSession(
            meta: meta,
            onServerDatagram: onServerDatagram,
            onClientReadDemand: {},
            onServerClosed: {}
        )
        guard case .intercept(let session) = decision else {
            XCTFail("demo handler unexpectedly returned non-intercept")
            preconditionFailure()
        }
        session.activate(onSendToEgress: { _ in })
        return session
    }

    private func waitFor(
        _ description: String,
        timeout: TimeInterval = 1.0,
        _ predicate: () -> Bool
    ) {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if predicate() { return }
            Thread.sleep(forTimeInterval: 0.005)
        }
        XCTFail("timed out waiting for: \(description)")
    }

    /// A healthy UDP datagram completion (`isComplete: true`, no error)
    /// MUST NOT terminate the pump — Apple sets `isComplete` on every
    /// datagram boundary. The pump must deliver the datagram and arm a
    /// new receive so subsequent datagrams keep flowing.
    func testDatagramWithIsCompleteTrueDoesNotTerminate() {
        let engine = makeEngine()
        defer { engine.stop(reason: 0) }

        let firstDelivered = expectation(description: "first datagram delivered")
        let secondDelivered = expectation(description: "second datagram delivered")
        var deliveryCount = 0
        let session = makeInterceptedSession(engine, onServerDatagram: { data in
            deliveryCount += 1
            if data == Data("first".utf8) { firstDelivered.fulfill() }
            if data == Data("second".utf8) { secondDelivered.fulfill() }
        })

        let connection = MockUdpConnection()
        let terminated = XCTestExpectation(description: "terminate must NOT fire on healthy datagram")
        terminated.isInverted = true
        let pump = NwUdpConnectionReadPump(
            connection: connection,
            session: session,
            queue: makeQueue(),
            onTerminate: { _ in terminated.fulfill() }
        )

        pump.start()
        waitFor("first receive scheduled") { connection.pendingReceiveCount > 0 }

        // Deliver a fully-formed datagram with the same shape Apple's
        // Network framework would use: data present, isComplete = true.
        connection.completeReceive(data: Data("first".utf8), isComplete: true)
        wait(for: [firstDelivered], timeout: 1.0)

        // A second receive MUST be queued after the first completion.
        waitFor("pump rescheduled after first datagram") {
            connection.pendingReceiveCount > 0
        }
        connection.completeReceive(data: Data("second".utf8), isComplete: true)
        wait(for: [secondDelivered], timeout: 1.0)

        // 200ms of safety margin — terminate must not have fired.
        wait(for: [terminated], timeout: 0.2)
        XCTAssertEqual(deliveryCount, 2)
    }

    /// A long stream of datagrams must keep flowing — i.e. the pump
    /// always rearms after each `isComplete: true` completion. This is
    /// the property that the existing terminate-on-isComplete bug
    /// silently breaks for every real UDP session.
    func testManyDatagramsAllFlowThrough() {
        let engine = makeEngine()
        defer { engine.stop(reason: 0) }

        let total = 16
        let allDelivered = expectation(description: "all datagrams delivered")
        allDelivered.expectedFulfillmentCount = total
        let session = makeInterceptedSession(engine, onServerDatagram: { _ in
            allDelivered.fulfill()
        })

        let connection = MockUdpConnection()
        let pump = NwUdpConnectionReadPump(
            connection: connection,
            session: session,
            queue: makeQueue(),
            onTerminate: { error in XCTFail("unexpected terminate: \(String(describing: error))") }
        )
        pump.start()

        for i in 0..<total {
            waitFor("receive #\(i) scheduled") { connection.pendingReceiveCount > 0 }
            connection.completeReceive(data: Data("dgram-\(i)".utf8), isComplete: true)
        }
        wait(for: [allDelivered], timeout: 2.0)
    }

    /// Termination is gated on `error != nil`, not on `isComplete`.
    /// Apple surfaces a real socket failure (cancel, ECONNRESET, etc.)
    /// via the `error` argument; that is the only signal that should
    /// drive teardown for UDP.
    func testErrorTerminatesEvenWithIsCompleteFalse() {
        let engine = makeEngine()
        defer { engine.stop(reason: 0) }

        let session = makeInterceptedSession(engine, onServerDatagram: { _ in })
        let connection = MockUdpConnection()
        let terminated = expectation(description: "terminate on error")
        let pump = NwUdpConnectionReadPump(
            connection: connection,
            session: session,
            queue: makeQueue(),
            onTerminate: { error in
                XCTAssertNotNil(error)
                terminated.fulfill()
            }
        )

        pump.start()
        waitFor("receive scheduled") { connection.pendingReceiveCount > 0 }
        connection.completeReceive(data: nil, isComplete: false, error: .posix(.ECONNRESET))
        wait(for: [terminated], timeout: 1.0)
    }
}
