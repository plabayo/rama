import Foundation
import Network
import XCTest

@testable import RamaAppleNetworkExtension

final class MockUdpConnection: UdpConnectionReadable {
    typealias Completion = @Sendable (Data?, NWConnection.ContentContext?, Bool, NWError?) -> Void

    private let lock = NSLock()
    private var completions: [Completion] = []

    func receive(
        minimumIncompleteLength: Int,
        maximumLength: Int,
        completion: @escaping Completion
    ) {
        lock.lock()
        completions.append(completion)
        lock.unlock()
    }

    var pendingReceiveCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return completions.count
    }

    /// `isComplete` is intentionally required (no default) because
    /// Apple's contract differs between stream and datagram protocols
    /// (per-datagram on UDP, end-of-stream on TCP). A permissive
    /// default of `false` is what hid the
    /// "first-datagram-tears-the-pump-down" bug; every caller must
    /// pass it explicitly so the contract under test is visible at
    /// the call site.
    func completeReceive(data: Data?, isComplete: Bool, error: NWError? = nil) {
        lock.lock()
        guard !completions.isEmpty else {
            lock.unlock()
            return
        }
        let completion = completions.removeFirst()
        lock.unlock()
        DispatchQueue.global().async {
            completion(data, nil, isComplete, error)
        }
    }
}

final class UdpReadPumpTests: XCTestCase {
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
        DispatchQueue(label: "rama.tproxy.test.udp.read", qos: .utility)
    }

    private func makeInterceptedSession(
        _ engine: RamaTransparentProxyEngineHandle,
        onServerDatagram: @escaping (Data, RamaUdpPeer?) -> Void = { _, _ in },
        onSendToEgress: @escaping (Data, RamaUdpPeer?) -> Void = { _, _ in }
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
        session.activate(onSendToEgress: onSendToEgress)
        return session
    }

    func testStartDeliversDatagramToSession() {
        let engine = makeEngine()
        defer { engine.stop(reason: 0) }

        let delivered = expectation(description: "server datagram delivered")
        let session = makeInterceptedSession(engine, onServerDatagram: { data, _ in
            if data == Data("udp-payload".utf8) {
                delivered.fulfill()
            }
        })
        let connection = MockUdpConnection()
        let pump = NwUdpConnectionReadPump(
            connection: connection,
            session: session,
            queue: makeQueue(),
            onTerminate: { _ in XCTFail("unexpected terminate") }
        )

        pump.start()
        for _ in 0..<100 where connection.pendingReceiveCount == 0 {
            Thread.sleep(forTimeInterval: 0.005)
        }
        XCTAssertGreaterThan(connection.pendingReceiveCount, 0)

        // Apple sets `isComplete = true` on every received datagram —
        // it's the datagram boundary, not an EOF — so the call has to
        // be explicit. `UdpReadPumpDatagramSemanticsTests` covers the
        // wider "many datagrams flow through" contract.
        connection.completeReceive(data: Data("udp-payload".utf8), isComplete: true)
        wait(for: [delivered], timeout: 1.0)
    }

    /// Termination is gated on `error != nil`, not on `isComplete`.
    /// Previously this test asserted the opposite — that an
    /// `isComplete: true` completion with no error terminates — which
    /// silently encoded the bug fixed in this PR. See
    /// `UdpReadPumpDatagramSemanticsTests` for the positive cases.
    func testReceiveErrorTriggersTerminate() {
        let engine = makeEngine()
        defer { engine.stop(reason: 0) }

        let session = makeInterceptedSession(engine)
        let connection = MockUdpConnection()
        let terminated = expectation(description: "terminate fired")
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
        for _ in 0..<100 where connection.pendingReceiveCount == 0 {
            Thread.sleep(forTimeInterval: 0.005)
        }
        connection.completeReceive(data: nil, isComplete: false, error: .posix(.ECANCELED))

        wait(for: [terminated], timeout: 1.0)
    }

    func testCancelSuppressesLateReceiveCallback() {
        let engine = makeEngine()
        defer { engine.stop(reason: 0) }

        let noDelivery = expectation(description: "datagram not delivered")
        noDelivery.isInverted = true
        let noTerminate = expectation(description: "terminate not called")
        noTerminate.isInverted = true

        let session = makeInterceptedSession(engine, onServerDatagram: { _, _ in
            noDelivery.fulfill()
        })
        let connection = MockUdpConnection()
        let pump = NwUdpConnectionReadPump(
            connection: connection,
            session: session,
            queue: makeQueue(),
            onTerminate: { _ in noTerminate.fulfill() }
        )

        pump.start()
        for _ in 0..<100 where connection.pendingReceiveCount == 0 {
            Thread.sleep(forTimeInterval: 0.005)
        }

        pump.cancel()
        connection.completeReceive(
            data: Data("late".utf8),
            isComplete: true,
            error: .posix(.ECANCELED)
        )

        wait(for: [noDelivery, noTerminate], timeout: 0.2)
    }
}
