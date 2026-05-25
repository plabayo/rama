import Foundation
import Network
import XCTest

@testable import RamaAppleNetworkExtension

/// Pins the registry-cleanup invariants for
/// `TransparentProxyCore.tcpContexts` / `udpContexts`.
///
/// These maps are the only persistent per-flow state on the core
/// side. Every entry MUST be removed exactly when the flow ends —
/// either via the teardown class's `removeXxxFlow(flowId)` call or
/// via `detachEngine`'s bulk reset. A regression here surfaces in
/// production as the 60s telemetry timer reporting climbing
/// `tcp_flows` / `udp_flows` counts; better to pin it in unit tests.
final class RegistryCleanupTests: XCTestCase {

    // MARK: - register / remove single flow

    /// register → remove is exactly idempotent at the registry level.
    func testRegisterThenRemoveReturnsCountToZero() {
        let core = TransparentProxyCore()
        let flow = MockTcpFlow()
        let ctx = TcpFlowContext()
        core.testInsertTcpContext(ObjectIdentifier(flow), ctx)
        XCTAssertEqual(core.tcpFlowCount, 1)

        core.removeTcpFlow(ObjectIdentifier(flow))
        XCTAssertEqual(core.tcpFlowCount, 0)
    }

    /// Removing an already-removed flow is harmless.
    func testRemoveIsIdempotent() {
        let core = TransparentProxyCore()
        let flow = MockTcpFlow()
        let ctx = TcpFlowContext()
        core.testInsertTcpContext(ObjectIdentifier(flow), ctx)
        core.removeTcpFlow(ObjectIdentifier(flow))
        core.removeTcpFlow(ObjectIdentifier(flow))
        XCTAssertEqual(core.tcpFlowCount, 0, "double-remove must not corrupt the count")
    }

    /// Removing an unknown flow id is harmless.
    func testRemoveUnknownIsNoop() {
        let core = TransparentProxyCore()
        let flow = MockTcpFlow()
        core.removeTcpFlow(ObjectIdentifier(flow))
        XCTAssertEqual(core.tcpFlowCount, 0)
    }

    // MARK: - many flows: teardown drains registry

    /// 100 contexts × 9 random teardown variants. Every one must
    /// call `removeTcpFlow`, leaving the registry empty.
    func testTeardownVariantsAlwaysRemoveFromRegistry() {
        let core = TransparentProxyCore()
        struct Bag {
            let flow: MockTcpFlow
            let conn: MockNwConnection
            let ctx: TcpFlowContext
            let td: TcpFlowTeardown
        }
        var bags: [Bag] = []
        for _ in 0..<100 {
            let flow = MockTcpFlow()
            let conn = MockNwConnection()
            let ctx = TcpFlowContext()
            ctx.connection = conn
            let td = TcpFlowTeardown(
                ctx: ctx, core: core, flow: flow, flowId: ObjectIdentifier(flow))
            ctx.teardown = td
            core.testInsertTcpContext(ObjectIdentifier(flow), ctx)
            bags.append(Bag(flow: flow, conn: conn, ctx: ctx, td: td))
        }
        XCTAssertEqual(core.tcpFlowCount, 100)

        var rng = SystemRandomNumberGenerator()
        for bag in bags {
            switch Int(rng.next() % 9) {
            case 0: bag.td.applyPreReadyFailure()
            case 1: bag.td.applyConnectTimeout()
            case 2: bag.td.applyWriterTerminal(NSError(domain: "x", code: 1))
            case 3: bag.td.applyDrainedClose(wasOpened: true)
            case 4: bag.td.applyDrainedClose(wasOpened: false)
            case 5: bag.td.applyPostReadyFailure(nil)
            case 6: bag.td.applyFlowOpenFailure(NSError(domain: "x", code: 2))
            case 7: bag.td.applyReadHardError(NSError(domain: "x", code: 3))
            default: bag.td.applySystemSleep()
            }
        }
        XCTAssertEqual(
            core.tcpFlowCount, 0,
            "every teardown variant must call removeTcpFlow")
    }

    // MARK: - detachEngine bulk clear

    /// `detachEngine` clears every registered flow even if the
    /// per-flow teardowns never ran (e.g. provider crash mid-flow).
    func testDetachEngineDrainsBothRegistries() {
        let core = TransparentProxyCore()
        // Keep strong refs so `ObjectIdentifier`s don't collide
        // via address reuse after each loop iteration's flow
        // deallocates.
        var tcpFlows: [MockTcpFlow] = []
        var udpFlows: [MockUdpFlow] = []
        for _ in 0..<10 {
            let flow = MockTcpFlow()
            core.testInsertTcpContext(ObjectIdentifier(flow), TcpFlowContext())
            tcpFlows.append(flow)
            let udp = MockUdpFlow()
            core.testInsertUdpContext(ObjectIdentifier(udp), UdpFlowContext())
            udpFlows.append(udp)
        }
        XCTAssertEqual(core.tcpFlowCount, 10)
        XCTAssertEqual(core.udpFlowCount, 10)
        _ = (tcpFlows, udpFlows)  // keep alive past the asserts

        core.detachEngine(reason: 0)

        XCTAssertEqual(core.tcpFlowCount, 0)
        XCTAssertEqual(core.udpFlowCount, 0)
    }

    /// `detachEngine` on an already-empty registry is a no-op.
    func testDetachEngineOnEmptyRegistryIsHarmless() {
        let core = TransparentProxyCore()
        core.detachEngine(reason: 0)
        XCTAssertEqual(core.tcpFlowCount, 0)
        XCTAssertEqual(core.udpFlowCount, 0)
    }

    /// Repeated `detachEngine` is idempotent (the production
    /// startProxy path can race against stopProxy; we must not
    /// crash on a duplicate detach).
    func testDetachEngineIsIdempotent() {
        let core = TransparentProxyCore()
        let flow = MockTcpFlow()
        core.testInsertTcpContext(ObjectIdentifier(flow), TcpFlowContext())
        core.detachEngine(reason: 0)
        core.detachEngine(reason: 0)
        XCTAssertEqual(core.tcpFlowCount, 0)
    }

    // MARK: - sleep walks every registered flow

    /// `handleSystemSleep` invokes teardown for every entry; the
    /// registry is empty when the completion fires.
    func testHandleSystemSleepDrainsRegistry() {
        let core = TransparentProxyCore()
        var keepAlive: [(MockTcpFlow, MockNwConnection, TcpFlowContext, TcpFlowTeardown)] = []
        for _ in 0..<50 {
            let flow = MockTcpFlow()
            let conn = MockNwConnection()
            let ctx = TcpFlowContext()
            ctx.connection = conn
            let td = TcpFlowTeardown(
                ctx: ctx, core: core, flow: flow, flowId: ObjectIdentifier(flow))
            ctx.teardown = td
            core.testInsertTcpContext(ObjectIdentifier(flow), ctx)
            keepAlive.append((flow, conn, ctx, td))
        }
        XCTAssertEqual(core.tcpFlowCount, 50)
        _ = keepAlive

        let exp = expectation(description: "sleep completion")
        core.handleSystemSleep { exp.fulfill() }
        wait(for: [exp], timeout: 2.0)

        XCTAssertEqual(core.tcpFlowCount, 0)
    }
}
