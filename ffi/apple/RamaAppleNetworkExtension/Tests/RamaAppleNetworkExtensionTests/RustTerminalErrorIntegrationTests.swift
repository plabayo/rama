import Foundation
import Network
import XCTest

@testable import RamaAppleNetworkExtension

/// Uses the actual Rust FFI session and example routing service. Only Apple's
/// transport boundaries are faked; terminal errors are never injected into a
/// Swift replacement for the new getter.
final class RustTerminalErrorIntegrationTests: XCTestCase {
    override class func setUp() {
        super.setUp()
        TestFixtures.ensureInitialized()
    }

    private final class Harness {
        let engine: RamaTransparentProxyEngineHandle
        let core = TransparentProxyCore()
        let flow = MockTcpFlow()
        let connection = MockNwConnection()
        let session: TcpFlowSession<MockTcpFlow>
        let handle: RamaTcpSessionHandle
        let serverClosed = TestValue(0)
        let egressClosed = TestValue(0)
        let requestBytes = TestValue(Data())
        let acceptedResponse = TestValue(Data())
        let writer: TcpClientWritePump

        init() {
            engine = RamaTransparentProxyEngineHandle(
                engineConfigJson: TestFixtures.engineConfigJson())!
            let meta = RamaTransparentProxyFlowMetaBridge(
                protocolRaw: 1, remoteHost: "origin.test", remotePort: 22,
                localHost: nil, localPort: 0, sourceAppSigningIdentifier: nil,
                sourceAppBundleIdentifier: nil, sourceAppAuditToken: nil, sourceAppPid: 4242)
            session = TcpFlowSession(core: core, flow: flow, meta: meta)
            session.buildClientWritePump()
            writer = session.ctx.clientWritePump!
            let writer = writer
            let accepted = acceptedResponse
            let closed = serverClosed
            guard case .intercept(let handle) = engine.newTcpSession(
                meta: meta,
                onServerBytes: { data in
                    let status = writer.enqueue(data)
                    if status == .accepted { accepted.update { $0.append(data) } }
                    return status
                },
                onClientReadDemand: {},
                onServerClosed: { closed.update { $0 += 1 } }
            ) else { preconditionFailure("example service must intercept") }
            self.handle = handle
            let egressWriter = NwTcpConnectionWritePump(
                connection: connection, queue: session.flowQueue, onDrained: {})
            flow.captureWriteCompletions = true
            connection.transition(to: .ready)
            session.flowQueue.sync {
                session.sessionHandle = handle
                session.ctx.session = handle
                session.ctx.connection = connection
                session.ctx.egressWritePump = egressWriter
                session.ctx.egressReady = true
                session.egressReady = true
                session.configureDrainPolicy(nil)
            }
            writer.markOpened()
            let request = requestBytes
            let egressClosed = egressClosed
            // No promotion callback: the real non-HTTP service falls back to
            // Rust forwarding, so this exercises the additional FFI boundary.
            handle.activate(
                onWriteToEgress: { data in
                    request.update { $0.append(data) }
                    return .accepted
                },
                onEgressReadDemand: {},
                onCloseEgress: { egressClosed.update { $0 += 1 } })
        }

        func drain() { for _ in 0..<8 { session.flowQueue.sync {} } }

        deinit {
            session.flowQueue.sync { session.ctx.applyEngineDetached() }
            while flow.completeNextWrite() {}
            while connection.completePendingSend(error: nil) {}
            handle.cancel()
            engine.stop(reason: 0)
        }
    }

    private func waitFor(_ description: String, _ condition: () -> Bool) {
        let deadline = Date().addingTimeInterval(5)
        while !condition() && Date() < deadline { Thread.sleep(forTimeInterval: 0.001) }
        XCTAssertTrue(condition(), "timed out waiting for \(description)")
    }

    private func produceReadErrorAfterClientEOF(_ h: Harness, tail: Data) {
        let request = Data("SSH-2.0-rama-ffi-test\r\n".utf8)
        XCTAssertNil(h.handle.terminalError())
        XCTAssertEqual(h.handle.onClientBytes(request), .accepted)
        h.handle.onClientEof()
        waitFor("Rust forwards request and client half-close") {
            h.requestBytes.get() == request && h.egressClosed.get() == 1
        }
        XCTAssertNil(h.handle.terminalError(), "client EOF is not a stream error")
        XCTAssertEqual(h.handle.onEgressBytes(tail), .accepted)
        waitFor("all response bytes admitted to the Swift writer") {
            h.acceptedResponse.get() == tail && h.flow.pendingWriteCompletionCount == 1
        }
        h.handle.onEgressError()
        waitFor("actual Rust read-error publication and close callback") {
            (h.handle.terminalError() as NSError?)?.code == Int(ECONNRESET)
                && h.serverClosed.get() == 1
        }
        h.drain()
    }

    func testRustReadErrorDrainsAcceptedResponseBeforeErrorCloseInEitherCallbackOrder() {
        for clientCloseFirst in [false, true] {
            let h = Harness()
            let tail = Data((0..<(48 * 1024 + 17)).map { UInt8($0 % 251) })
            produceReadErrorAfterClientEOF(h, tail: tail)
            h.session.flowQueue.sync {
                if clientCloseFirst {
                    h.session.closeClientAfterRustDrain()
                    h.session.closeEgressAfterRustDrain()
                } else {
                    h.session.closeEgressAfterRustDrain()
                    h.session.closeClientAfterRustDrain()
                }
            }
            h.drain()
            // Completing the upload FIN must not discard the held response.
            while h.connection.completePendingSend(error: nil) { h.drain() }
            XCTAssertEqual(h.flow.closeWriteCallCount, 0)
            XCTAssertEqual(h.connection.cancelCount, 0)
            h.session.flowQueue.sync { XCTAssertFalse(h.session.ctx.isDone) }
            while h.flow.completeNextWrite() { h.drain() }
            waitFor("error-carrying close after the final response completion") {
                h.flow.closeWriteCallCount == 1
            }
            XCTAssertEqual(h.flow.writes.reduce(into: Data()) { $0.append($1) }, tail)
            XCTAssertEqual((h.flow.lastCloseWriteError as NSError?)?.domain, NSPOSIXErrorDomain)
            XCTAssertEqual((h.flow.lastCloseWriteError as NSError?)?.code, Int(ECONNRESET))
            XCTAssertEqual((h.flow.lastCloseReadError as NSError?)?.code, Int(ECONNRESET))
            XCTAssertEqual(h.flow.closeReadCallCount, 1)
            XCTAssertEqual(h.connection.cancelCount, 1)
            h.session.flowQueue.sync {
                h.session.closeClientAfterRustDrain()
                h.session.closeEgressAfterRustDrain()
                XCTAssertNil(h.session.ctx.connection)
            }
            h.drain()
            XCTAssertEqual(h.flow.closeWriteCallCount, 1)
            XCTAssertEqual(h.flow.closeReadCallCount, 1)
        }
    }

    func testRealHandleRetainsRecordedErrorAcrossCancellation() {
        let h = Harness()
        produceReadErrorAfterClientEOF(h, tail: Data([1, 2, 3, 4]))
        XCTAssertEqual((h.handle.terminalError() as NSError?)?.code, Int(ECONNRESET))
        h.handle.cancel()
        XCTAssertEqual((h.handle.terminalError() as NSError?)?.code, Int(ECONNRESET))
        h.handle.cancel()
        XCTAssertEqual((h.handle.terminalError() as NSError?)?.code, Int(ECONNRESET))
    }
}
