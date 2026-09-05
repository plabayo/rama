import Foundation
import Network
import XCTest

@testable import RamaAppleNetworkExtension

final class ExcludedSniPromotionTests: XCTestCase {

    private static let excludedPattern = "*.excluded.test"
    private static let serverName = "asset.excluded.test"
    private static let exactServerName = "exact-excluded.test"

    private struct Fixture {
        let engine: RamaTransparentProxyEngineHandle
        let core: TransparentProxyCore
        let capture: NwConnectionCapture
    }

    private struct ActiveFlow {
        let flow: MockTcpFlow
        let connection: MockNwConnection
        let context: TcpFlowContext
    }

    override class func setUp() {
        super.setUp()
        TestFixtures.ensureInitialized()
    }

    private func makeFixture(
        excludedPattern: String = ExcludedSniPromotionTests.excludedPattern,
        tcpWritePumpMaxPendingBytes: Int? = nil
    ) -> Fixture {
        guard let engine = RamaTransparentProxyEngineHandle(
            engineConfigJson: TestFixtures.engineConfigJson(
                excludeDomains: [excludedPattern],
                peekDurationSeconds: 10,
                tcpWritePumpMaxPendingBytes: tcpWritePumpMaxPendingBytes
            )
        ) else {
            XCTFail("engine init")
            preconditionFailure()
        }
        let core = TransparentProxyCore()
        core.attachEngine(engine)
        let capture = NwConnectionCapture()
        core.nwConnectionFactory = capture.factory
        return Fixture(engine: engine, core: core, capture: capture)
    }

    private func makeMeta(remotePort: UInt16 = 443) -> RamaTransparentProxyFlowMetaBridge {
        RamaTransparentProxyFlowMetaBridge(
            protocolRaw: 1,
            remoteHost: "origin.test",
            remotePort: remotePort,
            localHost: nil,
            localPort: 0,
            sourceAppSigningIdentifier: nil,
            sourceAppBundleIdentifier: nil,
            sourceAppAuditToken: nil,
            sourceAppPid: 4242
        )
    }

    private func waitFor(
        _ description: String,
        timeout: TimeInterval = 10,
        condition: () -> Bool
    ) {
        let deadline = Date(timeIntervalSinceNow: timeout)
        while !condition() && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.005)
        }
        XCTAssertTrue(condition(), "timed out waiting for: \(description)")
    }

    private func driveToActive(_ fixture: Fixture, flow: MockTcpFlow) -> ActiveFlow {
        XCTAssertTrue(fixture.core.handleTcpFlow(flow, meta: makeMeta()))
        let connection = fixture.capture.waitForLastConnection()
        connection.transition(to: .ready)
        waitFor("flow.open") { flow.openWasInvoked }
        XCTAssertTrue(flow.completeOpen(error: nil))
        waitFor("initial reads") {
            flow.pendingReadCount > 0 && connection.pendingReceiveCount > 0
        }
        guard let context = fixture.core.testInspectTcpContext(for: flow) else {
            XCTFail("missing flow context")
            preconditionFailure()
        }
        return ActiveFlow(flow: flow, connection: connection, context: context)
    }

    private func startSendCompleter(_ connections: [MockNwConnection]) -> AtomicFlag {
        let stopped = AtomicFlag()
        DispatchQueue.global().async {
            while !stopped.load() {
                for connection in connections {
                    _ = connection.completePendingSend(error: nil)
                }
                Thread.sleep(forTimeInterval: 0.001)
            }
        }
        return stopped
    }

    private func finish(
        _ fixture: Fixture,
        activeFlows: [ActiveFlow],
        timeout: TimeInterval = 30
    ) {
        let stopped = AtomicFlag()
        DispatchQueue.global().async {
            while !stopped.load() {
                for active in activeFlows {
                    active.flow.completeRead(data: nil, error: nil)
                    _ = active.connection.completePendingReceive(isComplete: true)
                    _ = active.connection.completePendingSend(error: nil)
                }
                Thread.sleep(forTimeInterval: 0.001)
            }
        }
        defer { stopped.store(true) }
        waitFor("all excluded flows removed", timeout: timeout) {
            fixture.core.tcpFlowCount == 0
        }
    }

    private func sentData(_ connection: MockNwConnection) -> Data {
        connection.sentChunks.reduce(into: Data()) { result, chunk in
            if let content = chunk.content {
                result.append(content)
            }
        }
    }

    private func writtenData(_ flow: MockTcpFlow) -> Data {
        flow.writes.reduce(into: Data()) { $0.append($1) }
    }

    private func payload(_ label: String, index: Int, size: Int) -> Data {
        var data = Data("\(label)-\(index)-".utf8)
        data.append(Data(repeating: UInt8(index & 0xff), count: size))
        return data
    }

    func testExcludedSniPromotionPreservesFragmentedHelloAndCutoverBytes() {
        let fixture = makeFixture()
        defer { fixture.core.detachEngine(reason: 0) }

        let active = driveToActive(fixture, flow: MockTcpFlow())
        let sendCompleter = startSendCompleter([active.connection])
        defer { sendCompleter.store(true) }

        let hello = TestFixtures.tlsClientHello(serverName: Self.serverName)
        let split = hello.count - 7
        active.flow.completeRead(data: Data(hello[..<split]), error: nil)
        waitFor("another read for fragmented ClientHello") {
            active.flow.pendingReadCount > 0
        }
        XCTAssertEqual(active.context.mode, .viaRust)

        let serverBytes = payload("server", index: 1, size: 4096)
        active.flow.completeRead(data: Data(hello[split...]), error: nil)
        XCTAssertTrue(
            active.connection.completePendingReceive(
                data: serverBytes,
                isComplete: false
            )
        )

        waitFor("excluded SNI promotion") { active.context.mode == .promoted }
        waitFor("direct client read") { active.flow.pendingReadCount > 0 }

        let clientBytes = payload("client", index: 1, size: 8192)
        active.flow.completeRead(data: clientBytes, error: nil)

        var expectedClientBytes = hello
        expectedClientBytes.append(clientBytes)
        waitFor("client bytes preserved across cutover") {
            self.sentData(active.connection) == expectedClientBytes
        }
        waitFor("server bytes preserved across cutover") {
            self.writtenData(active.flow) == serverBytes
        }

        finish(fixture, activeFlows: [active])
    }

    /// Full linked Rust/Swift drain replay. A plain HTTP response is produced
    /// by the real example service and crosses the real `RamaTcpSessionHandle`
    /// callback into the `TcpFlowSession` writer. With a 16 KiB exported pump
    /// cap and captured kernel write completions, Rust accepts one chunk then
    /// parks on `.paused`. Completing each Swift write must run the production
    /// `buildClientWritePump.onDrained -> session.signalServerDrain()` edge so
    /// Rust retries the rejected chunk and eventually delivers the exact body.
    func testRealRustServerBytesReplayAfterSwiftWriterDrain() {
        let writerCap = 16 * 1024
        let fixture = makeFixture(tcpWritePumpMaxPendingBytes: writerCap)
        defer { fixture.core.detachEngine(reason: 0) }

        XCTAssertEqual(
            fixture.engine.config()?.tcpWritePumpMaxPendingBytes,
            writerCap,
            "test requires the opaque JSON cap to reach Swift's generation policy")

        let flow = MockTcpFlow()
        flow.captureWriteCompletions = true
        XCTAssertTrue(fixture.core.handleTcpFlow(flow, meta: makeMeta(remotePort: 80)))
        let connection = fixture.capture.waitForLastConnection()
        connection.transition(to: .ready)
        waitFor("HTTP flow.open") { flow.openWasInvoked }
        XCTAssertTrue(flow.completeOpen(error: nil))
        waitFor("linked HTTP pumps") {
            flow.pendingReadCount > 0 && connection.pendingReceiveCount > 0
        }

        let sendCompleter = startSendCompleter([connection])
        defer { sendCompleter.store(true) }
        let request = Data("GET /drain HTTP/1.1\r\nHost: origin.test\r\nConnection: keep-alive\r\n\r\n".utf8)
        flow.completeRead(data: request, error: nil)
        waitFor("Rust service forwarded HTTP request") {
            self.sentData(connection).range(of: Data("GET /drain HTTP/1.1".utf8)) != nil
        }

        let body = Data(repeating: 0xD7, count: writerCap * 6 + 113)
        var response = Data(
            "HTTP/1.1 200 OK\r\nContent-Length: \(body.count)\r\nContent-Type: application/octet-stream\r\n\r\n".utf8)
        response.append(body)
        waitFor("Rust requested upstream response bytes") {
            connection.pendingReceiveCount > 0
        }
        XCTAssertTrue(
            connection.completePendingReceive(data: response, isComplete: false),
            "mock upstream must deliver the response through the real egress handle")

        waitFor("first Rust server chunk reached Swift writer") {
            flow.pendingWriteCompletionCount == 1
        }
        XCTAssertLessThanOrEqual(flow.writes[0].count, writerCap)
        XCTAssertLessThan(
            writtenData(flow).count,
            response.count,
            "fixture must actually enter paused replay, not accept the response in one callback")

        let replayDeadline = Date(timeIntervalSinceNow: 15)
        while Date() < replayDeadline {
            let received = writtenData(flow)
            if let separator = received.range(of: Data("\r\n\r\n".utf8)),
                Data(received[separator.upperBound...]) == body
            {
                break
            }
            if !flow.completeNextWrite() {
                Thread.sleep(forTimeInterval: 0.002)
            }
        }

        let received = writtenData(flow)
        guard let separator = received.range(of: Data("\r\n\r\n".utf8)) else {
            return XCTFail("linked Rust response never produced complete HTTP headers")
        }
        XCTAssertEqual(
            Data(received[separator.upperBound...]),
            body,
            "paused Rust chunk was not replayed exactly after Swift writer drain")
        XCTAssertGreaterThan(
            flow.writes.count, 1,
            "test did not exercise a real paused -> signalServerDrain -> retry cycle")
    }

    func testExactExcludedSniPromotesThroughFfi() {
        let fixture = makeFixture(excludedPattern: Self.exactServerName)
        defer { fixture.core.detachEngine(reason: 0) }

        let active = driveToActive(fixture, flow: MockTcpFlow())
        let sendCompleter = startSendCompleter([active.connection])
        defer { sendCompleter.store(true) }

        active.flow.completeRead(
            data: TestFixtures.tlsClientHello(serverName: Self.exactServerName),
            error: nil
        )
        waitFor("exact excluded SNI promotion") {
            active.context.mode == .promoted
        }

        finish(fixture, activeFlows: [active])
    }

    func testExcludedSniPromotionForwardsEgressResetToClient() {
        let fixture = makeFixture()
        defer { fixture.core.detachEngine(reason: 0) }

        let active = driveToActive(fixture, flow: MockTcpFlow())
        let sendCompleter = startSendCompleter([active.connection])
        defer { sendCompleter.store(true) }

        active.flow.completeRead(
            data: TestFixtures.tlsClientHello(serverName: Self.serverName),
            error: nil
        )
        waitFor("excluded SNI promotion") { active.context.mode == .promoted }
        waitFor("promoted server receive") { active.connection.pendingReceiveCount > 0 }

        XCTAssertTrue(
            active.connection.completePendingReceive(
                isComplete: false,
                error: NWError.posix(.ECONNRESET)
            )
        )
        waitFor("egress reset forwarded to client") {
            active.flow.closeWriteCallCount == 1
        }
        guard case .posix(.ECONNRESET)? = active.flow.lastCloseWriteError as? NWError else {
            return XCTFail("connection reset error was not forwarded")
        }

        finish(fixture, activeFlows: [active])
        XCTAssertEqual(active.flow.closeReadCallCount, 1)
        XCTAssertEqual(
            active.flow.closeWriteCallCount, 1,
            "final aggregation must not replace the reset close with clean EOF")
        guard case .posix(.ECONNRESET)? = active.flow.lastCloseWriteError as? NWError else {
            return XCTFail("final write close did not preserve connection reset")
        }
    }

    func testExcludedSniPromotionKeepsDownloadAliveAfterClientHalfClose() {
        let savedLingerCloseMs = defaultLingerCloseMs
        defaultLingerCloseMs = 75
        defer { defaultLingerCloseMs = savedLingerCloseMs }
        let fixture = makeFixture()
        defer { fixture.core.detachEngine(reason: 0) }

        let active = driveToActive(fixture, flow: MockTcpFlow())
        let sendCompleter = startSendCompleter([active.connection])
        defer { sendCompleter.store(true) }

        active.flow.completeRead(
            data: TestFixtures.tlsClientHello(serverName: Self.serverName),
            error: nil
        )
        waitFor("excluded SNI promotion") { active.context.mode == .promoted }
        waitFor("promoted client read") { active.flow.pendingReadCount > 0 }

        active.flow.completeRead(data: nil, error: nil)
        waitFor("client half-close finished") {
            active.context.flowQueue?.sync {
                active.context.directForwarder?.c2sPhase == .finished
            } ?? false
        }
        waitFor("server receive remains active") {
            active.connection.pendingReceiveCount > 0
        }

        Thread.sleep(forTimeInterval: 0.25)
        active.context.flowQueue?.sync {}
        XCTAssertEqual(
            active.connection.cancelCount, 0,
            "local FIN must not impose a deadline on a quiet response half")

        let download = payload("download", index: 1, size: 16 * 1024)
        XCTAssertTrue(
            active.connection.completePendingReceive(
                data: download,
                isComplete: false
            )
        )
        waitFor("download continues after client half-close") {
            self.writtenData(active.flow) == download
        }
        XCTAssertEqual(fixture.core.tcpFlowCount, 1)
        XCTAssertEqual(active.connection.cancelCount, 0)

        finish(fixture, activeFlows: [active])
        waitFor("terminal release cancels the promoted connection") {
            active.connection.cancelCount == 1
        }
    }

    func testConcurrentExcludedSniPromotionChurnPreservesBytesAndCleansUp() {
        let fixture = makeFixture()
        defer { fixture.core.detachEngine(reason: 0) }

        let flowCount = 16
        let flows = (0..<flowCount).map { _ in MockTcpFlow() }
        for flow in flows {
            XCTAssertTrue(fixture.core.handleTcpFlow(flow, meta: makeMeta()))
        }
        XCTAssertEqual(fixture.core.tcpFlowCount, flowCount)

        waitFor("all excluded-flow connections", timeout: 30) {
            flows.allSatisfy {
                fixture.core.testInspectTcpContext(for: $0)?.connection != nil
            }
        }
        let activeFlows: [ActiveFlow] = flows.map { flow in
            guard let context = fixture.core.testInspectTcpContext(for: flow),
                let connection = context.connection as? MockNwConnection
            else {
                XCTFail("missing flow state")
                preconditionFailure()
            }
            return ActiveFlow(flow: flow, connection: connection, context: context)
        }

        for active in activeFlows {
            active.connection.transition(to: .ready)
        }
        waitFor("all excluded flows reached flow.open", timeout: 30) {
            activeFlows.allSatisfy { $0.flow.openWasInvoked }
        }
        for active in activeFlows {
            XCTAssertTrue(active.flow.completeOpen(error: nil))
        }
        waitFor("all excluded flows started reads", timeout: 30) {
            activeFlows.allSatisfy {
                $0.flow.pendingReadCount > 0 && $0.connection.pendingReceiveCount > 0
            }
        }

        let connections = activeFlows.map(\.connection)
        let sendCompleter = startSendCompleter(connections)
        defer { sendCompleter.store(true) }

        let hello = TestFixtures.tlsClientHello(serverName: Self.serverName)
        let splits = activeFlows.indices.map { 5 + ($0 % (hello.count - 10)) }
        for (index, active) in activeFlows.enumerated() {
            active.flow.completeRead(data: Data(hello[..<splits[index]]), error: nil)
        }
        waitFor("all fragmented hellos request more bytes", timeout: 30) {
            activeFlows.allSatisfy { $0.flow.pendingReadCount > 0 }
        }
        XCTAssertTrue(activeFlows.allSatisfy { $0.context.mode == .viaRust })

        let serverPayloads = activeFlows.indices.map {
            payload("server", index: $0, size: 2048 + $0)
        }
        for (index, active) in activeFlows.enumerated() {
            active.flow.completeRead(data: Data(hello[splits[index]...]), error: nil)
            XCTAssertTrue(
                active.connection.completePendingReceive(
                    data: serverPayloads[index],
                    isComplete: false
                )
            )
        }

        waitFor("all excluded SNI flows promoted", timeout: 30) {
            activeFlows.allSatisfy { $0.context.mode == .promoted }
        }
        waitFor("all promoted flows resumed client reads", timeout: 30) {
            activeFlows.allSatisfy { $0.flow.pendingReadCount > 0 }
        }

        let clientPayloads = activeFlows.indices.map {
            payload("client", index: $0, size: 4096 + $0)
        }
        for (index, active) in activeFlows.enumerated() {
            active.flow.completeRead(data: clientPayloads[index], error: nil)
        }

        waitFor("all client payloads preserved", timeout: 30) {
            activeFlows.enumerated().allSatisfy { index, active in
                var expected = hello
                expected.append(clientPayloads[index])
                return self.sentData(active.connection) == expected
            }
        }
        waitFor("all server payloads preserved", timeout: 30) {
            activeFlows.enumerated().allSatisfy { index, active in
                self.writtenData(active.flow) == serverPayloads[index]
            }
        }

        finish(fixture, activeFlows: activeFlows, timeout: 60)
    }
}
