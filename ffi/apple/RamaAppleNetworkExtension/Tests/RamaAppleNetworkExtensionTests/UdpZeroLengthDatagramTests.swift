import Foundation
import Network
import NetworkExtension
import XCTest

@testable import RamaAppleNetworkExtension

/// RFC 768 §2: a UDP datagram with a zero-length payload is a valid
/// datagram. Real protocols (DTLS, QUIC connection migration probes,
/// some game-server keep-alives) rely on receiving them. A transparent
/// proxy MUST forward zero-length datagrams in both directions
/// unchanged. Silently dropping them — what the previous code did via
/// `data.isEmpty` early-returns at five distinct sites — is a
/// protocol-correctness bug, not an optimisation.
///
/// These tests exercise the boundaries the audit named:
/// 1. `UdpClientWritePump.enqueue(Data())` reaches `flow.writeDatagrams`
///    as a real datagram.
/// 2. `NwUdpConnectionReadPump` delivers a zero-length receive
///    completion to the session as a real datagram.
///
/// They are deliberately pump-level so they can catch the bug even
/// when the higher-level demo handler chooses to filter empties.
final class UdpZeroLengthDatagramTests: XCTestCase {
    override class func setUp() {
        super.setUp()
        TestFixtures.ensureInitialized()
    }

    // MARK: - Helpers

    private func makeQueue(_ label: String) -> DispatchQueue {
        DispatchQueue(label: "rama.tproxy.test.udp.zero-length.\(label)", qos: .utility)
    }

    private func waitForQueueDrain(_ queue: DispatchQueue, timeout: TimeInterval = 1.0) {
        let exp = expectation(description: "queue drained")
        queue.async { exp.fulfill() }
        wait(for: [exp], timeout: timeout)
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

    private func makeUdpSession(
        on engine: RamaTransparentProxyEngineHandle,
        onServerDatagram: @escaping (Data) -> Void = { _ in }
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
        guard case .intercept(let s) = decision else {
            XCTFail("demo handler unexpectedly returned non-intercept")
            preconditionFailure()
        }
        return s
    }

    // MARK: - Tests

    /// Egress write-pump (Rust → client kernel direction): an empty
    /// datagram enqueued by the Rust side must reach `writeDatagrams`
    /// as one batch of one zero-length `Data`. Previously the pump
    /// early-returned in `enqueue(_:)` and the datagram never made it
    /// to the flow at all.
    func testWritePumpForwardsZeroLengthDatagramToFlow() {
        let flow = MockUdpFlow()
        let queue = makeQueue("write-pump")
        let pump = UdpClientWritePump(
            flow: flow,
            queue: queue,
            logger: { _ in },
            onTerminalError: { _ in
                XCTFail("unexpected terminal error from write pump")
            }
        )
        pump.markOpened()
        // Pin an endpoint so `flushLocked` can issue the write.
        pump.setSentByEndpoint(NWHostEndpoint(hostname: "127.0.0.1", port: "5000"))

        pump.enqueue(Data())
        waitForQueueDrain(queue)

        XCTAssertEqual(flow.writtenBatches.count, 1, "empty datagram must reach writeDatagrams")
        XCTAssertEqual(flow.writtenBatches.first?.datagrams.count, 1)
        XCTAssertEqual(
            flow.writtenBatches.first?.datagrams.first?.count, 0,
            "the forwarded datagram must be byte-for-byte the zero-length one"
        )
    }

    /// Read pump (egress NWConnection → Rust session direction): a
    /// zero-length receive completion delivered by the (mock) egress
    /// `NWConnection` must surface as a `session.onEgressDatagram`
    /// call. Previously the pump dropped empties via
    /// `if let data, !data.isEmpty` and the receive was effectively
    /// ignored.
    ///
    /// Verified through the engine's end-to-end path: the session
    /// hands the datagram to the demo service, which routes it back
    /// out as an `onServerDatagram` callback. We pin the round-trip
    /// length so a future regression at any layer between the
    /// `connection.receive` and the `onServerDatagram` callback is
    /// visible.
    func testEgressReadPumpForwardsZeroLengthDatagramToSession() {
        let engine = makeEngine()
        defer { engine.stop(reason: 0) }

        let observed = expectation(description: "zero-length datagram observed by session callback")
        // expectedFulfillmentCount = 1 is the default — but we also
        // want to ensure we do NOT see a duplicate, so the inverted
        // sibling guards that.
        observed.assertForOverFulfill = true
        let session = makeUdpSession(on: engine, onServerDatagram: { data in
            XCTAssertEqual(data.count, 0, "session must receive the empty datagram unchanged")
            observed.fulfill()
        })
        // `activate` wires the egress send-callback that the bridge
        // service writes to via `egress.send(_:)`. Without it the
        // egress half is half-open and `on_egress_datagram` has no
        // tx to forward through. This is the same shape every other
        // pump-level test uses.
        session.activate(onSendToEgress: { _ in })
        let connection = MockUdpConnection()
        let pump = NwUdpConnectionReadPump(
            connection: connection,
            session: session,
            queue: makeQueue("read-pump"),
            onTerminate: { error in
                XCTFail("unexpected terminate: \(String(describing: error))")
            }
        )

        pump.start()
        // Wait for the first receive to be queued.
        let deadline = Date().addingTimeInterval(1.0)
        while Date() < deadline, connection.pendingReceiveCount == 0 {
            Thread.sleep(forTimeInterval: 0.005)
        }
        XCTAssertGreaterThan(
            connection.pendingReceiveCount, 0,
            "pump did not arm a receive — test setup is broken"
        )

        connection.completeReceive(data: Data(), isComplete: true)
        wait(for: [observed], timeout: 2.0)
    }
}
