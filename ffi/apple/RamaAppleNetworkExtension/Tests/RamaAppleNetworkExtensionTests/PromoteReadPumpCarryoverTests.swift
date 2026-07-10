import Foundation
import Network
import XCTest

@testable import RamaAppleNetworkExtension

/// `cancelForPromote(onCarryover:)` is the load-bearing primitive
/// that turns the existing Rust-bound read pumps into a clean
/// hand-off point for a promote cutover. The contract is:
///
///   * Replay buffer (`pendingData`) is handed over immediately
///     in the `.some(data)` form, freeing the pump from any
///     `.paused`-tail it owns.
///   * If a `readData` / `receive` is in flight, the completion
///     handler is hijacked: data goes through the carryover sink
///     instead of `session.onClientBytes` / `session.onEgressBytes`.
///   * EOF (or error) on the in-flight read fires the sink with
///     `.none` — the direct forwarder treats these uniformly.
///   * Subsequent calls to `cancelForPromote` are no-ops (phase
///     is already `.closed`).
///   * Crucially: `onTerminal` is NEVER fired by the cutover
///     cancel path — that callback is for the engine's natural
///     teardown route, which the direct forwarder displaces.
final class PromoteReadPumpCarryoverTests: XCTestCase {
    override class func setUp() {
        super.setUp()
        TestFixtures.ensureInitialized()
    }

    // MARK: - Fixture helpers

    private func makeEngine() -> RamaTransparentProxyEngineHandle {
        guard let h = RamaTransparentProxyEngineHandle(
            engineConfigJson: TestFixtures.engineConfigJson())
        else {
            XCTFail("engine init"); preconditionFailure()
        }
        return h
    }

    private func makeQueue(_ tag: String) -> DispatchQueue {
        DispatchQueue(label: "rama.tproxy.test.\(tag)", qos: .utility)
    }

    private func tcpMeta() -> RamaTransparentProxyFlowMetaBridge {
        RamaTransparentProxyFlowMetaBridge(
            protocolRaw: 1, remoteHost: "example.com", remotePort: 443,
            localHost: nil, localPort: 0,
            sourceAppSigningIdentifier: nil,
            sourceAppBundleIdentifier: nil,
            sourceAppAuditToken: nil, sourceAppPid: 4242)
    }

    private func interceptSession(
        _ engine: RamaTransparentProxyEngineHandle
    ) -> RamaTcpSessionHandle {
        let decision = engine.newTcpSession(
            meta: tcpMeta(),
            onServerBytes: { _ in .accepted },
            onClientReadDemand: {},
            onServerClosed: {})
        guard case .intercept(let s) = decision else {
            XCTFail("non-intercept"); preconditionFailure()
        }
        return s
    }

    /// Wait for the pump to issue a `readData` against the mock.
    private func waitForReadDataIssued(
        _ flow: MockTcpFlow,
        timeout: TimeInterval = 1.0
    ) {
        let exp = expectation(description: "pump issued readData")
        DispatchQueue.global().async {
            let deadline = Date(timeIntervalSinceNow: timeout)
            while Date() < deadline {
                if !flow.pendingReadCompletions.isEmpty {
                    exp.fulfill(); return
                }
                Thread.sleep(forTimeInterval: 0.005)
            }
            XCTFail("pump never issued readData")
        }
        wait(for: [exp], timeout: timeout + 0.5)
    }

    // MARK: - TcpClientReadPump

    /// `cancelForPromote` on an idle pump (no in-flight read, no
    /// pending replay) is a clean no-op: no carryover fires, no
    /// terminal fires, phase becomes `.closed`.
    func testClientReadPumpCancelForPromoteOnIdlePumpIsNoOp() {
        let engine = makeEngine(); defer { engine.stop(reason: 0) }
        let session = interceptSession(engine)
        let flow = MockTcpFlow()
        let queue = makeQueue("client.idle")

        var terminalCount = 0
        let pump = TcpClientReadPump(
            flow: flow, session: session, queue: queue,
            logger: { _ in },
            onTerminal: { _ in terminalCount += 1 })

        var carryoverCount = 0
        pump.cancelForPromote(
            onCarryover: { _ in carryoverCount += 1 },
            onComplete: {})

        // Drain the queue.
        queue.sync {}

        XCTAssertEqual(carryoverCount, 0, "no carryover when idle")
        XCTAssertEqual(terminalCount, 0,
            "cancelForPromote MUST NOT fire onTerminal — the cutover owns teardown")
    }

    // NOTE: the held-`.paused`-replay-buffer hand-off is now covered
    // directly (with a scripted sink that can actually return `.paused`)
    // by `TcpReadPumpReplayTests.testClientReadPumpCancelForPromoteFlushesHeldReplayBuffer`.
    // The idle-pump no-op it used to stand in for is covered above by
    // `testClientReadPumpCancelForPromoteOnIdlePumpIsNoOp`.

    /// In-flight `readData` whose completion lands AFTER
    /// `cancelForPromote` must route the bytes through the
    /// carryover sink, not drop them, and not deliver them to
    /// Rust.
    func testClientReadPumpCarryoverFiresOnInFlightReadCompletion() {
        let engine = makeEngine(); defer { engine.stop(reason: 0) }
        let session = interceptSession(engine)
        let flow = MockTcpFlow()
        let queue = makeQueue("client.inflight")

        let pump = TcpClientReadPump(
            flow: flow, session: session, queue: queue,
            logger: { _ in },
            onTerminal: { _ in XCTFail("onTerminal must not fire") })

        pump.requestRead()
        waitForReadDataIssued(flow)

        // Cancel for promote; install carryover sink BEFORE
        // delivering bytes.
        let carryoverFired = expectation(description: "carryover fired")
        let completeFired = expectation(description: "onComplete fired")
        var captured: Data?
        pump.cancelForPromote(
            onCarryover: { data in
                captured = data
                carryoverFired.fulfill()
            },
            onComplete: { completeFired.fulfill() })

        // Deliver bytes on the in-flight read.
        let payload = Data([0x10, 0x20, 0x30, 0x40])
        flow.completeRead(data: payload, error: nil)

        wait(for: [carryoverFired, completeFired], timeout: 2.0,
             enforceOrder: true)
        XCTAssertEqual(captured, payload,
            "in-flight bytes must reach the carryover sink intact")
    }

    /// Same setup but the in-flight `readData` returns EOF
    /// `(nil, nil)`. The carryover sink fires with `.none`,
    /// signalling the direct forwarder to emit a FIN downstream.
    func testClientReadPumpCarryoverEofMapsToNone() {
        let engine = makeEngine(); defer { engine.stop(reason: 0) }
        let session = interceptSession(engine)
        let flow = MockTcpFlow()
        let queue = makeQueue("client.eof")

        let pump = TcpClientReadPump(
            flow: flow, session: session, queue: queue,
            logger: { _ in },
            onTerminal: { _ in XCTFail("onTerminal must not fire on promote-EOF") })

        pump.requestRead()
        waitForReadDataIssued(flow)

        let carryoverFired = expectation(description: "carryover fired")
        let completeFired = expectation(description: "onComplete fired")
        var sawNoneSentinel = false
        pump.cancelForPromote(
            onCarryover: { data in
                sawNoneSentinel = (data == nil)
                carryoverFired.fulfill()
            },
            onComplete: { completeFired.fulfill() })

        flow.completeRead(data: nil, error: nil)
        wait(for: [carryoverFired, completeFired], timeout: 2.0,
             enforceOrder: true)
        XCTAssertTrue(sawNoneSentinel,
            "EOF on in-flight read must surface as `nil` to the carryover sink")
    }

    /// Same shape but the in-flight `readData` returns an error.
    /// Mapped to `.none` per cutover-EOF semantics: the direct
    /// forwarder uses the FIN path either way.
    func testClientReadPumpCarryoverErrorMapsToNone() {
        let engine = makeEngine(); defer { engine.stop(reason: 0) }
        let session = interceptSession(engine)
        let flow = MockTcpFlow()
        let queue = makeQueue("client.err")

        let pump = TcpClientReadPump(
            flow: flow, session: session, queue: queue,
            logger: { _ in },
            onTerminal: { _ in XCTFail("onTerminal must not fire on promote-error") })

        pump.requestRead()
        waitForReadDataIssued(flow)

        let carryoverFired = expectation(description: "carryover fired")
        let completeFired = expectation(description: "onComplete fired")
        var captured: Data? = Data([0xAA])
        pump.cancelForPromote(
            onCarryover: { data in
                captured = data
                carryoverFired.fulfill()
            },
            onComplete: { completeFired.fulfill() })

        flow.completeRead(data: nil, error: NSError(domain: "test", code: 1))
        wait(for: [carryoverFired, completeFired], timeout: 2.0,
             enforceOrder: true)
        XCTAssertNil(captured,
            "error on in-flight read must surface as `nil` to the carryover sink")
    }

    /// `cancelForPromote` called twice is a no-op on the second
    /// call.
    func testClientReadPumpCancelForPromoteIsIdempotent() {
        let engine = makeEngine(); defer { engine.stop(reason: 0) }
        let session = interceptSession(engine)
        let flow = MockTcpFlow()
        let queue = makeQueue("client.idem")

        let pump = TcpClientReadPump(
            flow: flow, session: session, queue: queue,
            logger: { _ in }, onTerminal: { _ in })

        var carryoverCount = 0
        pump.cancelForPromote(
            onCarryover: { _ in carryoverCount += 1 },
            onComplete: {})
        pump.cancelForPromote(
            onCarryover: { _ in carryoverCount += 1 },
            onComplete: {})
        queue.sync {}

        XCTAssertEqual(carryoverCount, 0,
            "no carryover fires on idle pump regardless of cancel count")
    }

    // MARK: - NwTcpConnectionReadPump

    /// Symmetric to the client-read pump: an in-flight
    /// `connection.receive` that returns bytes must route them
    /// through the carryover sink, not the session.
    func testEgressReadPumpCarryoverFiresOnInFlightReceive() {
        let engine = makeEngine(); defer { engine.stop(reason: 0) }
        let session = interceptSession(engine)
        let conn = MockNwConnection()
        let queue = makeQueue("egress.inflight")

        let pump = NwTcpConnectionReadPump(
            connection: conn, session: session, queue: queue,
            eofGraceDeadline: .milliseconds(50))
        pump.start()

        // Wait for the first connection.receive to be issued.
        let issued = expectation(description: "pump issued receive")
        DispatchQueue.global().async {
            let deadline = Date(timeIntervalSinceNow: 1.0)
            while Date() < deadline {
                if conn.pendingReceiveCount > 0 {
                    issued.fulfill(); return
                }
                Thread.sleep(forTimeInterval: 0.005)
            }
            XCTFail("pump never issued connection.receive")
        }
        wait(for: [issued], timeout: 1.5)

        let carryoverFired = expectation(description: "carryover fired")
        let completeFired = expectation(description: "onComplete fired")
        var captured: Data?
        pump.cancelForPromote(
            onCarryover: { data in
                captured = data
                carryoverFired.fulfill()
            },
            onComplete: { completeFired.fulfill() })

        let payload = Data([0xCA, 0xFE, 0xBA, 0xBE])
        _ = conn.completePendingReceive(data: payload, isComplete: false, error: nil)
        wait(for: [carryoverFired, completeFired], timeout: 2.0,
             enforceOrder: true)
        XCTAssertEqual(captured, payload)
    }

    /// In-flight `connection.receive` returning `isComplete: true`
    /// (peer closed) maps to `.none`.
    func testEgressReadPumpCarryoverIsCompleteMapsToNone() {
        let engine = makeEngine(); defer { engine.stop(reason: 0) }
        let session = interceptSession(engine)
        let conn = MockNwConnection()
        let queue = makeQueue("egress.complete")

        let pump = NwTcpConnectionReadPump(
            connection: conn, session: session, queue: queue,
            eofGraceDeadline: .milliseconds(50))
        pump.start()

        let issued = expectation(description: "pump issued receive")
        DispatchQueue.global().async {
            let deadline = Date(timeIntervalSinceNow: 1.0)
            while Date() < deadline {
                if conn.pendingReceiveCount > 0 {
                    issued.fulfill(); return
                }
                Thread.sleep(forTimeInterval: 0.005)
            }
            XCTFail("pump never issued connection.receive")
        }
        wait(for: [issued], timeout: 1.5)

        let carryoverFired = expectation(description: "carryover fired")
        let completeFired = expectation(description: "onComplete fired")
        var sawNone = false
        pump.cancelForPromote(
            onCarryover: { data in
                sawNone = (data == nil)
                carryoverFired.fulfill()
            },
            onComplete: { completeFired.fulfill() })

        _ = conn.completePendingReceive(data: nil, isComplete: true, error: nil)
        wait(for: [carryoverFired, completeFired], timeout: 2.0,
             enforceOrder: true)
        XCTAssertTrue(sawNone,
            "isComplete on in-flight receive must surface as `nil`")
    }

    func testEgressReadPumpCarryoverPreservesReadError() {
        let engine = makeEngine(); defer { engine.stop(reason: 0) }
        let session = interceptSession(engine)
        let conn = MockNwConnection()
        let queue = makeQueue("egress.error")
        let pump = NwTcpConnectionReadPump(
            connection: conn, session: session, queue: queue,
            eofGraceDeadline: .seconds(2))
        pump.start()

        pollUntil("pump issued connection.receive") { conn.pendingReceiveCount > 0 }

        let completeFired = expectation(description: "onComplete fired")
        var events: [String] = []
        pump.cancelForPromote(
            onCarryover: { data in events.append(data == nil ? "terminal" : "data") },
            onError: { _ in events.append("error") },
            onComplete: {
                events.append("complete")
                completeFired.fulfill()
            })

        _ = conn.completePendingReceive(
            data: Data([0x11, 0x22]), isComplete: false,
            error: NWError.posix(.ECONNRESET))
        wait(for: [completeFired], timeout: 2.0)
        XCTAssertEqual(events, ["data", "error", "terminal", "complete"])
    }

    /// An empty non-terminal receive resolves the drain barrier without
    /// synthesizing an EOF carryover marker.
    func testEgressReadPumpCarryoverEmptyNonTerminalReceiveStillCompletes() {
        let engine = makeEngine(); defer { engine.stop(reason: 0) }
        let session = interceptSession(engine)
        let conn = MockNwConnection()
        let queue = makeQueue("egress.empty.nonterminal")

        let pump = NwTcpConnectionReadPump(
            connection: conn, session: session, queue: queue,
            eofGraceDeadline: .milliseconds(50))
        pump.start()

        let issued = expectation(description: "pump issued receive")
        DispatchQueue.global().async {
            let deadline = Date(timeIntervalSinceNow: 1.0)
            while Date() < deadline {
                if conn.pendingReceiveCount > 0 {
                    issued.fulfill(); return
                }
                Thread.sleep(forTimeInterval: 0.005)
            }
            XCTFail("pump never issued connection.receive")
        }
        wait(for: [issued], timeout: 1.5)

        let completeFired = expectation(description: "onComplete fired")
        var carryoverFires = 0
        pump.cancelForPromote(
            onCarryover: { _ in carryoverFires += 1 },
            onComplete: { completeFired.fulfill() })

        _ = conn.completePendingReceive(data: Data(), isComplete: false, error: nil)
        wait(for: [completeFired], timeout: 2.0)
        XCTAssertEqual(carryoverFires, 0)
    }

    /// External `cancel()` (the existing non-promote API) then
    /// `cancelForPromote(...)` — the second call must be a no-op,
    /// no carryover firing on the already-closed pump.
    func testEgressReadPumpCancelThenPromoteIsNoOp() {
        let engine = makeEngine(); defer { engine.stop(reason: 0) }
        let session = interceptSession(engine)
        let conn = MockNwConnection()
        let queue = makeQueue("egress.cancel.then.promote")

        let pump = NwTcpConnectionReadPump(
            connection: conn, session: session, queue: queue,
            eofGraceDeadline: .milliseconds(50))
        pump.start()
        pump.cancel()
        queue.sync {}

        var carryoverFires = 0
        var completeFires = 0
        pump.cancelForPromote(
            onCarryover: { _ in carryoverFires += 1 },
            onComplete: { completeFires += 1 })
        queue.sync {}

        XCTAssertEqual(carryoverFires, 0,
            "cancelForPromote on an already-closed pump must not produce carryover")
        XCTAssertEqual(completeFires, 1,
            "onComplete must fire even on an already-closed pump so the forwarder's drain barrier doesn't hang")
    }
}
