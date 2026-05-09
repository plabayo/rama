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

    func completeReceive(data: Data?, isComplete: Bool = false, error: NWError? = nil) {
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
        onServerDatagram: @escaping (Data) -> Void = { _ in },
        onSendToEgress: @escaping (Data) -> Void = { _ in }
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
        let session = makeInterceptedSession(engine, onServerDatagram: { data in
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

        connection.completeReceive(data: Data("udp-payload".utf8))
        wait(for: [delivered], timeout: 1.0)
    }

    func testReceiveCompletionTriggersTerminate() {
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
                XCTAssertNil(error)
                terminated.fulfill()
            }
        )

        pump.start()
        for _ in 0..<100 where connection.pendingReceiveCount == 0 {
            Thread.sleep(forTimeInterval: 0.005)
        }
        connection.completeReceive(data: nil, isComplete: true)

        wait(for: [terminated], timeout: 1.0)
    }

    func testCancelSuppressesLateReceiveCallback() {
        let engine = makeEngine()
        defer { engine.stop(reason: 0) }

        let noDelivery = expectation(description: "datagram not delivered")
        noDelivery.isInverted = true
        let noTerminate = expectation(description: "terminate not called")
        noTerminate.isInverted = true

        let session = makeInterceptedSession(engine, onServerDatagram: { _ in
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
