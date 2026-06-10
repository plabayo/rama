import Foundation
import Network
import XCTest

@testable import RamaAppleNetworkExtension

/// Layer-2 scenarios for `UdpFlowSession`: chain transitions of
/// the read-state machine, verify the writer and terminate paths
/// stay consistent across them.
final class UdpFlowSessionCompositionTests: XCTestCase {

    private final class Fixture {
        let core: TransparentProxyCore
        let flow: MockUdpFlow
        let session: UdpFlowSession<MockUdpFlow>

        init() {
            self.core = TransparentProxyCore()
            self.flow = MockUdpFlow()
            let meta = RamaTransparentProxyFlowMetaBridge(
                protocolRaw: 2, remoteHost: "example.com", remotePort: 53,
                localHost: nil, localPort: 0,
                sourceAppSigningIdentifier: nil,
                sourceAppBundleIdentifier: nil,
                sourceAppAuditToken: nil, sourceAppPid: 4242)
            self.session = UdpFlowSession(core: core, flow: flow, meta: meta)
            self.session.installTerminate()
            self.session.buildClientWritePump()
            self.session.installRequestRead()
        }

        /// Spin the flow queue once. Most session methods are
        /// queue-async; tests need a barrier to observe state.
        func barrier() {
            let exp = XCTestExpectation(description: "queue barrier")
            session.flowQueue.async { exp.fulfill() }
            XCTWaiter().wait(for: [exp], timeout: 2.0)
        }
    }

    /// Read-completion with an error terminates the flow.
    ///
    /// Teardown spans two `flowQueue` hops: `handleReadCompletion` runs on the
    /// first hop and *posts* `terminate`, whose body (`readState = .closed`,
    /// kernel-flow close) runs on the second. A single barrier lands between
    /// the two hops and would race the close, so flush twice before asserting.
    func testReadCompletionWithErrorTerminates() {
        let fx = Fixture()
        fx.session.handleReadCompletion(
            datagrams: nil, endpoints: nil,
            error: NSError(domain: "test", code: 1))
        fx.barrier()
        fx.barrier()
        XCTAssertEqual(fx.session.ctx.readState, .closed)
        XCTAssertEqual(fx.flow.closeReadCallCount, 1)
        XCTAssertEqual(fx.flow.closeWriteCallCount, 1)
    }

    /// Read-completion with empty datagrams = EOF = terminate.
    ///
    /// Two-hop teardown — see `testReadCompletionWithErrorTerminates` for why
    /// the assert needs two barriers.
    func testReadCompletionEmptyDatagramsTerminates() {
        let fx = Fixture()
        fx.session.handleReadCompletion(datagrams: [], endpoints: nil, error: nil)
        fx.barrier()
        fx.barrier()
        XCTAssertEqual(fx.session.ctx.readState, .closed)
        XCTAssertEqual(fx.flow.closeReadCallCount, 1)
    }

    /// terminate fired twice: only the first one closes the flow;
    /// the second observes `readState == .closed` and bails.
    func testTerminateIsIdempotent() {
        let fx = Fixture()
        let exp1 = expectation(description: "first terminate")
        fx.session.flowQueue.async {
            fx.session.ctx.terminate?(nil)
            fx.session.flowQueue.async { exp1.fulfill() }
        }
        wait(for: [exp1], timeout: 2.0)
        XCTAssertEqual(fx.flow.closeReadCallCount, 1)

        let exp2 = expectation(description: "second terminate")
        fx.session.flowQueue.async {
            fx.session.ctx.terminate?(nil)
            fx.session.flowQueue.async { exp2.fulfill() }
        }
        wait(for: [exp2], timeout: 2.0)
        XCTAssertEqual(fx.flow.closeReadCallCount, 1, "second terminate is a no-op")
    }

    /// `requestRead` after terminate is a no-op (readState is .closed).
    func testRequestReadAfterTerminateIsNoop() {
        let fx = Fixture()
        let term = expectation(description: "terminate")
        fx.session.flowQueue.async {
            fx.session.ctx.terminate?(nil)
            fx.session.flowQueue.async { term.fulfill() }
        }
        wait(for: [term], timeout: 2.0)
        XCTAssertEqual(fx.session.ctx.readState, .closed)

        let req = expectation(description: "request after close")
        fx.session.flowQueue.async {
            fx.session.ctx.requestRead?()
            fx.session.flowQueue.async { req.fulfill() }
        }
        wait(for: [req], timeout: 2.0)
        XCTAssertEqual(fx.flow.pendingReadCount, 0, "requestRead after close issues no readDatagrams")
    }
}
