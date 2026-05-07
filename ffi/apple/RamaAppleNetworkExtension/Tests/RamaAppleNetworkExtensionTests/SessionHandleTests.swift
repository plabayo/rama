import Foundation
import XCTest

@testable import RamaAppleNetworkExtension

final class SessionHandleTests: XCTestCase {
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

    private func tcpMeta() -> RamaTransparentProxyFlowMetaBridge {
        RamaTransparentProxyFlowMetaBridge(
            protocolRaw: 1,  // tcp
            remoteHost: "example.com",
            remotePort: 443,
            localHost: nil,
            localPort: 0,
            sourceAppSigningIdentifier: nil,
            sourceAppBundleIdentifier: nil,
            sourceAppAuditToken: nil,
            sourceAppPid: 4242
        )
    }

    private func udpMeta() -> RamaTransparentProxyFlowMetaBridge {
        RamaTransparentProxyFlowMetaBridge(
            protocolRaw: 2,  // udp
            remoteHost: "example.com",
            remotePort: 53,
            localHost: nil,
            localPort: 0,
            sourceAppSigningIdentifier: nil,
            sourceAppBundleIdentifier: nil,
            sourceAppAuditToken: nil,
            sourceAppPid: 4242
        )
    }

    /// Post-cancel `onClientBytes` must return `.closed` instead of
    /// reaching the freed Rust session. Pinning the cancel-vs-callback
    /// invariant at the Swift layer (the Rust unit-test
    /// `tcp_cancel_serialises_against_inflight_user_callback` covers
    /// the engine side; this one covers the Swift wrapper).
    func testTcpCancelThenOnClientBytesReturnsClosed() {
        let engine = makeEngine()
        defer { engine.stop(reason: 0) }

        let decision = engine.newTcpSession(
            meta: tcpMeta(),
            onServerBytes: { _ in .accepted },
            onClientReadDemand: {},
            onServerClosed: {}
        )
        guard case .intercept(let session) = decision else {
            // Demo handler may decide passthrough/blocked depending on
            // its config; the FFI surface itself is what we test, so
            // skip if no session was returned.
            return
        }

        session.cancel()
        XCTAssertEqual(session.onClientBytes(Data("after-cancel".utf8)), .closed)
    }

    /// Tight-loop create + cancel + drop on a single engine. Catches
    /// cumulative leaks (LeakSanitizer) and any per-iteration UAF.
    func testTcpSessionChurnDoesNotLeak() {
        let engine = makeEngine()
        defer { engine.stop(reason: 0) }

        for _ in 0..<256 {
            let decision = engine.newTcpSession(
                meta: tcpMeta(),
                onServerBytes: { _ in .accepted },
                onClientReadDemand: {},
                onServerClosed: {}
            )
            if case .intercept(let session) = decision {
                session.cancel()
                // Session drops here; deinit calls _session_free.
            }
        }
    }

    /// Concurrent stress: workers that each spin up a session, push a
    /// few bytes, cancel, and drop. ASan/TSan-friendly target for the
    /// Swift wrapper's NSLock pattern + the engine's `callback_active`
    /// mutex.
    func testTcpSessionConcurrentChurnIsSafe() {
        let engine = makeEngine()
        defer { engine.stop(reason: 0) }

        let group = DispatchGroup()
        let workers = 4
        let perWorker = 64
        for _ in 0..<workers {
            DispatchQueue.global(qos: .userInitiated).async(group: group) {
                for _ in 0..<perWorker {
                    let decision = engine.newTcpSession(
                        meta: self.tcpMeta(),
                        onServerBytes: { _ in .accepted },
                        onClientReadDemand: {},
                        onServerClosed: {}
                    )
                    if case .intercept(let session) = decision {
                        _ = session.onClientBytes(Data("hello".utf8))
                        session.cancel()
                    }
                }
            }
        }
        XCTAssertEqual(group.wait(timeout: .now() + 30), .success)
    }

    /// UDP equivalent of the TCP session churn test. Exercises the
    /// `RamaUdpSessionHandle.onClientDatagram` path concurrently.
    func testUdpSessionConcurrentChurnIsSafe() {
        let engine = makeEngine()
        defer { engine.stop(reason: 0) }

        let group = DispatchGroup()
        let workers = 4
        let perWorker = 64
        for _ in 0..<workers {
            DispatchQueue.global(qos: .userInitiated).async(group: group) {
                for _ in 0..<perWorker {
                    let decision = engine.newUdpSession(
                        meta: self.udpMeta(),
                        onServerDatagram: { _ in },
                        onClientReadDemand: {},
                        onServerClosed: {}
                    )
                    if case .intercept(let session) = decision {
                        session.onClientDatagram(Data("dgram".utf8))
                        session.onClientClose()
                    }
                }
            }
        }
        XCTAssertEqual(group.wait(timeout: .now() + 30), .success)
    }
}
