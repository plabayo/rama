import Foundation
import Network
import XCTest

@testable import RamaAppleNetworkExtension

final class UdpFlowSessionTests: XCTestCase {

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
        }
    }

    /// init() leaves ctx in idle state — no writer / no terminate.
    func testInitContextIsIdleAndEmpty() {
        let fx = Fixture()
        XCTAssertEqual(fx.session.ctx.readState, .idle)
        XCTAssertNil(fx.session.ctx.writer)
        XCTAssertNil(fx.session.ctx.terminate)
        XCTAssertNil(fx.session.ctx.requestRead)
    }

    /// `buildClientWritePump()` attaches the writer.
    func testBuildClientWritePumpAttachesToContext() {
        let fx = Fixture()
        fx.session.buildClientWritePump()
        XCTAssertNotNil(fx.session.ctx.writer)
    }

    /// `installTerminate()` wires the terminate closure; calling it
    /// flips readState to .closed and closes the flow.
    func testInstallTerminateClosesFlowOnFire() {
        let fx = Fixture()
        fx.session.installTerminate()
        XCTAssertNotNil(fx.session.ctx.terminate)
        let exp = expectation(description: "terminate dispatches")
        fx.session.flowQueue.async {
            fx.session.ctx.terminate?(nil)
            fx.session.flowQueue.async { exp.fulfill() }
        }
        wait(for: [exp], timeout: 2.0)
        XCTAssertEqual(fx.session.ctx.readState, .closed)
        XCTAssertEqual(fx.flow.closeReadCallCount, 1)
        XCTAssertEqual(fx.flow.closeWriteCallCount, 1)
    }

    /// Without an engine attached, `requestEngineSession()` returns nil.
    func testRequestEngineSessionWithoutEngineReturnsNil() {
        let fx = Fixture()
        XCTAssertNil(fx.session.requestEngineSession())
    }

    /// `start()` without an engine returns false (= flow not claimed).
    func testStartWithoutEngineReturnsFalse() {
        let fx = Fixture()
        XCTAssertFalse(fx.session.start())
    }

    /// `installRequestRead()` wires the request-read closure; firing
    /// it kicks `flow.readDatagrams` exactly once.
    func testInstallRequestReadIssuesReadDatagrams() {
        let fx = Fixture()
        fx.session.installRequestRead()
        XCTAssertEqual(fx.flow.pendingReadCount, 0)
        let exp = expectation(description: "requestRead dispatches")
        fx.session.flowQueue.async {
            fx.session.ctx.requestRead?()
            fx.session.flowQueue.async { exp.fulfill() }
        }
        wait(for: [exp], timeout: 2.0)
        XCTAssertEqual(fx.flow.pendingReadCount, 1)
        XCTAssertEqual(fx.session.ctx.readState, .reading)
    }

    /// While a read is in flight, a second `requestRead` coalesces
    /// into the `readingWithDemand` state — does NOT issue a second
    /// concurrent `readDatagrams`.
    func testRequestReadCoalescesWhileReadInFlight() {
        let fx = Fixture()
        fx.session.installRequestRead()
        let exp = expectation(description: "two demands dispatched")
        fx.session.flowQueue.async {
            fx.session.ctx.requestRead?()
            fx.session.ctx.requestRead?()
            fx.session.flowQueue.async { exp.fulfill() }
        }
        wait(for: [exp], timeout: 2.0)
        XCTAssertEqual(fx.flow.pendingReadCount, 1, "second demand must not issue a second concurrent read")
        XCTAssertEqual(fx.session.ctx.readState, .readingWithDemand)
    }
}
