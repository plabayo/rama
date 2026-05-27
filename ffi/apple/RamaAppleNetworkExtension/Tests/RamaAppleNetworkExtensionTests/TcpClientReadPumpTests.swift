import Foundation
import XCTest

@testable import RamaAppleNetworkExtension

/// Pure routing-decision tests. The dispatcher's onTerminal closure
/// historically embedded an inline `if let` that decided cancel vs
/// onClientEof; a regression that swapped the branches surfaced
/// only as the close-reason histogram drifting in production. This
/// suite pins the routing as a directly assertable contract.
final class TcpReadTerminalRoutingTests: XCTestCase {
    func testNilErrorRoutesToNaturalEof() {
        var natural = 0
        var hard = 0
        let t = TcpReadTerminal(
            onNaturalEof: { natural += 1 },
            onHardError: { _ in hard += 1 }
        )
        t.dispatch(nil)
        XCTAssertEqual(natural, 1)
        XCTAssertEqual(hard, 0)
    }

    func testNonNilErrorRoutesToHardError() {
        var natural = 0
        var captured: Error?
        let t = TcpReadTerminal(
            onNaturalEof: { natural += 1 },
            onHardError: { captured = $0 }
        )
        let err = NSError(domain: "test", code: 42)
        t.dispatch(err)
        XCTAssertEqual(natural, 0)
        XCTAssertEqual((captured as? NSError)?.code, 42)
    }

    func testEachDispatchInvokesExactlyOnePath() {
        var natural = 0
        var hard = 0
        let t = TcpReadTerminal(
            onNaturalEof: { natural += 1 },
            onHardError: { _ in hard += 1 }
        )
        t.dispatch(nil)
        t.dispatch(NSError(domain: "x", code: 1))
        t.dispatch(nil)
        XCTAssertEqual(natural, 2)
        XCTAssertEqual(hard, 1)
    }
}

/// Read-pump terminate-trigger tests. The pump must surface
/// `terminate(with: nil)` for all natural-EOF inputs (nil/empty
/// data, `.closed` from session, missing session) and
/// `terminate(with: error)` for any kernel error. Combined with
/// `TcpReadTerminalRoutingTests` this pins both the input contract
/// (what the pump considers EOF) and the routing decision (what the
/// dispatcher does with each).
final class TcpClientReadPumpTests: XCTestCase {
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
        DispatchQueue(label: "rama.tproxy.test.reader", qos: .utility)
    }

    private func makeInterceptedSession(
        _ engine: RamaTransparentProxyEngineHandle
    ) -> RamaTcpSessionHandle {
        let meta = RamaTransparentProxyFlowMetaBridge(
            protocolRaw: 1,
            remoteHost: "example.com",
            remotePort: 443,
            localHost: nil, localPort: 0,
            sourceAppSigningIdentifier: nil,
            sourceAppBundleIdentifier: nil,
            sourceAppAuditToken: nil,
            sourceAppPid: 4242
        )
        let decision = engine.newTcpSession(
            meta: meta,
            onServerBytes: { _ in .accepted },
            onClientReadDemand: {},
            onServerClosed: {}
        )
        guard case .intercept(let s) = decision else {
            XCTFail("demo handler unexpectedly returned non-intercept")
            preconditionFailure()
        }
        return s
    }

    /// Apple's contract for `flow.readData` is that `(nil, nil)` is
    /// EOF — the originating app closed its write side. The pump
    /// must surface this as `terminate(with: nil)`, which the
    /// dispatcher then routes to `session.onClientEof()` so the
    /// bridge drains the response direction cleanly. A regression
    /// that maps `(nil, nil)` to `terminate(with: someError)` would
    /// flip the close-reason histogram back to mostly `shutdown`.
    func testReadDataNilDataTriggersNaturalEofTerminal() {
        let engine = makeEngine()
        defer { engine.stop(reason: 0) }
        let session = makeInterceptedSession(engine)

        let flow = MockTcpFlow()
        let terminalFired = expectation(description: "onTerminal fires")
        var sawError: Error?
        var sawNil = false
        let pump = TcpClientReadPump(
            flow: flow,
            session: session,
            queue: makeQueue(),
            logger: { _ in },
            onTerminal: { error in
                if let error {
                    sawError = error
                } else {
                    sawNil = true
                }
                terminalFired.fulfill()
            }
        )
        pump.requestRead()

        // Wait for pump to issue a readData, then deliver an EOF.
        let issued = expectation(description: "pump issued readData")
        DispatchQueue.global().async {
            for _ in 0..<100 {
                if !flow.pendingReadCompletions.isEmpty {
                    issued.fulfill()
                    return
                }
                Thread.sleep(forTimeInterval: 0.005)
            }
            XCTFail("pump never issued readData")
        }
        wait(for: [issued], timeout: 1.0)
        flow.completeRead(data: nil, error: nil)

        wait(for: [terminalFired], timeout: 1.0)
        XCTAssertTrue(sawNil, "(nil, nil) must surface as terminate(with: nil) — natural-EOF path")
        XCTAssertNil(sawError)
    }

    /// Empty-data response is the second flavour of EOF on the
    /// `NEAppProxyTCPFlow` API. Same routing requirement as the
    /// nil-data case.
    func testReadDataEmptyDataTriggersNaturalEofTerminal() {
        let engine = makeEngine()
        defer { engine.stop(reason: 0) }
        let session = makeInterceptedSession(engine)
        let flow = MockTcpFlow()
        let terminalFired = expectation(description: "onTerminal fires")
        var sawNil = false
        let pump = TcpClientReadPump(
            flow: flow,
            session: session,
            queue: makeQueue(),
            logger: { _ in },
            onTerminal: { error in
                if error == nil { sawNil = true }
                terminalFired.fulfill()
            }
        )
        pump.requestRead()

        // Spin until the pump issues a read.
        for _ in 0..<200 {
            if !flow.pendingReadCompletions.isEmpty { break }
            Thread.sleep(forTimeInterval: 0.005)
        }
        flow.completeRead(data: Data(), error: nil)

        wait(for: [terminalFired], timeout: 1.0)
        XCTAssertTrue(sawNil)
    }

    /// Kernel errors must surface with the original error preserved
    /// — the dispatcher relies on the error value to drive its
    /// close-reason classification path.
    func testReadDataErrorTriggersHardErrorTerminal() {
        let engine = makeEngine()
        defer { engine.stop(reason: 0) }
        let session = makeInterceptedSession(engine)
        let flow = MockTcpFlow()
        let terminalFired = expectation(description: "onTerminal fires")
        var sawError: NSError?
        let pump = TcpClientReadPump(
            flow: flow,
            session: session,
            queue: makeQueue(),
            logger: { _ in },
            onTerminal: { error in
                sawError = error as NSError?
                terminalFired.fulfill()
            }
        )
        pump.requestRead()

        for _ in 0..<200 {
            if !flow.pendingReadCompletions.isEmpty { break }
            Thread.sleep(forTimeInterval: 0.005)
        }
        flow.completeRead(
            data: nil,
            error: NSError(domain: NSPOSIXErrorDomain, code: Int(EPIPE))
        )

        wait(for: [terminalFired], timeout: 1.0)
        XCTAssertEqual(sawError?.code, Int(EPIPE))
    }

    /// Once `terminate` has fired, the pump must not fire it again
    /// even if a late `readData` callback lands. Required so the
    /// dispatcher's onTerminal closure runs exactly once per flow —
    /// double-firing would double-execute the hard-error or natural-
    /// EOF teardown.
    func testTerminateFiresAtMostOnce() {
        let engine = makeEngine()
        defer { engine.stop(reason: 0) }
        let session = makeInterceptedSession(engine)
        let flow = MockTcpFlow()
        var fireCount = 0
        let firedAtLeastOnce = expectation(description: "terminate fires once")
        let pump = TcpClientReadPump(
            flow: flow,
            session: session,
            queue: makeQueue(),
            logger: { _ in },
            onTerminal: { _ in
                fireCount += 1
                if fireCount == 1 { firedAtLeastOnce.fulfill() }
            }
        )
        pump.requestRead()
        for _ in 0..<200 {
            if !flow.pendingReadCompletions.isEmpty { break }
            Thread.sleep(forTimeInterval: 0.005)
        }
        // Deliver the first EOF.
        flow.completeRead(data: nil, error: nil)
        wait(for: [firedAtLeastOnce], timeout: 1.0)

        // Deliver another EOF on any pending callback (the pump
        // should already be closed and not have issued another
        // readData). Allow some time for any rogue late-fire.
        for _ in 0..<5 { flow.completeRead(data: nil, error: nil) }
        Thread.sleep(forTimeInterval: 0.1)
        XCTAssertEqual(fireCount, 1, "onTerminal fired \(fireCount) times — must be exactly one")
    }
}
