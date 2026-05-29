import Foundation
import Network
import XCTest

@testable import RamaAppleNetworkExtension

/// Tests for `TransparentProxyCore.handleSystemSleep` /
/// `handleSystemWake` and the underlying
/// `TcpFlowTeardown.applySystemSleep` variant.
final class SystemLifecycleTests: XCTestCase {

    private final class TcpFx {
        let core: TransparentProxyCore
        let flow: MockTcpFlow
        let conn: MockNwConnection
        let ctx: TcpFlowContext
        let teardown: TcpFlowTeardown

        init() {
            self.core = TransparentProxyCore()
            self.flow = MockTcpFlow()
            self.conn = MockNwConnection()
            self.ctx = TcpFlowContext()
            self.ctx.connection = conn
            let flowId = ObjectIdentifier(flow)
            self.teardown = TcpFlowTeardown(
                ctx: ctx, core: core, flow: flow, flowId: flowId)
            ctx.teardown = teardown
        }
    }

    // MARK: - applySystemSleep on a single flow

    /// `applySystemSleep` runs a full teardown (kernel flow closed,
    /// connection cancelled-and-detached, registry-removal called).
    func testApplySystemSleepRunsFullTeardown() {
        let fx = TcpFx()
        fx.teardown.applySystemSleep()
        XCTAssertEqual(fx.flow.closeReadCallCount, 1)
        XCTAssertEqual(fx.flow.closeWriteCallCount, 1)
        XCTAssertEqual(fx.conn.cancelCount, 1)
        XCTAssertNil(fx.ctx.connection)
        XCTAssertTrue(fx.teardown.isDone)
    }

    /// Sleep teardown is the same sticky one-shot as the other
    /// variants — a second sleep call is a no-op.
    func testApplySystemSleepIsIdempotent() {
        let fx = TcpFx()
        fx.teardown.applySystemSleep()
        fx.teardown.applySystemSleep()
        XCTAssertEqual(fx.conn.cancelCount, 1)
        XCTAssertEqual(fx.flow.closeReadCallCount, 1)
    }

    /// Sleep teardown does NOT race with a prior full teardown:
    /// if a hard error already tore the flow down, applySystemSleep
    /// is a no-op.
    func testApplySystemSleepAfterReadHardErrorIsNoop() {
        let fx = TcpFx()
        fx.teardown.applyReadHardError(NSError(domain: "test", code: 1))
        XCTAssertEqual(fx.conn.cancelCount, 1)

        fx.teardown.applySystemSleep()
        XCTAssertEqual(fx.conn.cancelCount, 1, "second teardown variant is a no-op")
    }

    // MARK: - core.handleSystemSleep

    /// `handleSystemSleep` walks the TCP registry and fires
    /// `applySystemSleep` on every context's teardown. Completion
    /// fires once we're done.
    func testHandleSystemSleepDrainsAllRegisteredTcpFlows() {
        let core = TransparentProxyCore()
        var teardowns: [TcpFlowTeardown] = []
        var flows: [MockTcpFlow] = []
        var conns: [MockNwConnection] = []
        // Build a few mock contexts and shove them straight into
        // the registry. Engine-less; we're only testing the
        // walk-and-drain path.
        for _ in 0..<5 {
            let f = MockTcpFlow()
            let c = MockNwConnection()
            let ctx = TcpFlowContext()
            ctx.connection = c
            let td = TcpFlowTeardown(
                ctx: ctx, core: core, flow: f, flowId: ObjectIdentifier(f))
            ctx.teardown = td
            // Use the registry directly — registerTcpFlow needs a
            // RamaTcpSessionHandle which we can't construct here.
            // Direct insertion is fine because we don't exercise
            // anything that touches the session map.
            core.testInsertTcpContext(ObjectIdentifier(f), ctx)
            flows.append(f)
            conns.append(c)
            teardowns.append(td)
        }

        let exp = expectation(description: "sleep completion")
        core.handleSystemSleep { exp.fulfill() }
        wait(for: [exp], timeout: 2.0)

        for (i, td) in teardowns.enumerated() {
            XCTAssertTrue(td.isDone, "teardown[\(i)] fired")
            XCTAssertEqual(conns[i].cancelCount, 1)
            XCTAssertEqual(flows[i].closeReadCallCount, 1)
        }
    }

    /// `handleSystemSleep` with NO registered flows fires its
    /// completion immediately and is a no-op otherwise.
    func testHandleSystemSleepOnEmptyRegistryFiresCompletion() {
        let core = TransparentProxyCore()
        let exp = expectation(description: "sleep completion")
        core.handleSystemSleep { exp.fulfill() }
        wait(for: [exp], timeout: 2.0)
    }

    /// `handleSystemWake` is a no-op when no engine attached;
    /// must not crash.
    func testHandleSystemWakeWithoutEngineIsHarmless() {
        let core = TransparentProxyCore()
        core.handleSystemWake()
    }
}
