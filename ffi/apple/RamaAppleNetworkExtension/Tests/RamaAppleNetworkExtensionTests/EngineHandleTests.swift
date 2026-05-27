// Swift FFI engine-handle integration tests. Drive these via
// `just test-e2e-ffi-swift` (or the asan/tsan variants). The Rust
// counterpart is the `tproxy_rs` demo staticlib — same build pipeline
// the cargo `tproxy_ffi_e2e` tests use.

import Foundation
import XCTest

@testable import RamaAppleNetworkExtension

final class EngineHandleTests: XCTestCase {
    override class func setUp() {
        super.setUp()
        TestFixtures.ensureInitialized()
    }

    /// Plain alloc → drop sanity. Catches a broken FFI link or a
    /// regressed `RamaTransparentProxyEngineHandle.deinit` (e.g. a
    /// double-free that ASan would surface here).
    func testInitAndDropDoesNotCrash() {
        let handle = RamaTransparentProxyEngineHandle(
            engineConfigJson: TestFixtures.engineConfigJson())
        XCTAssertNotNil(handle, "engine should construct with the test CA config")
    }

    /// `stop()` swaps `enginePtr` to nil under the lock. Subsequent
    /// methods short-circuit (return nil / passthrough), they do not
    /// dereference the freed pointer.
    func testStopMakesSubsequentMethodCallsSafe() {
        guard
            let handle = RamaTransparentProxyEngineHandle(
                engineConfigJson: TestFixtures.engineConfigJson())
        else {
            XCTFail("engine init")
            return
        }
        handle.stop(reason: 0)
        // After stop, every entry point is allowed and must be safe.
        XCTAssertNil(handle.config())
        XCTAssertNil(handle.handleAppMessage(Data("ping".utf8)))
    }

    /// Double-stop is idempotent: the second call sees `enginePtr =
    /// nil` and is a no-op. Future regression that omits the swap
    /// would re-enter `_engine_stop` and double-free.
    func testStopIsIdempotent() {
        guard
            let handle = RamaTransparentProxyEngineHandle(
                engineConfigJson: TestFixtures.engineConfigJson())
        else {
            XCTFail("engine init")
            return
        }
        handle.stop(reason: 0)
        handle.stop(reason: 0)
    }

    /// `handleAppMessage` holds the lock across the FFI call. While
    /// many threads spam messages and one stops the engine, every
    /// thread must return cleanly — no UAF on the freed engine, no
    /// deadlock.
    func testConcurrentHandleAppMessageWithStopIsSafe() {
        guard
            let handle = RamaTransparentProxyEngineHandle(
                engineConfigJson: TestFixtures.engineConfigJson())
        else {
            XCTFail("engine init")
            return
        }

        let group = DispatchGroup()
        let workers = 8
        let perWorker = 200
        for w in 0..<workers {
            DispatchQueue.global(qos: .userInitiated).async(group: group) {
                for i in 0..<perWorker {
                    let msg = Data("worker=\(w) seq=\(i)".utf8)
                    _ = handle.handleAppMessage(msg)
                }
            }
        }
        // Stop arrives mid-flight. The lock guarantees no in-flight
        // FFI call observes the engine being freed.
        DispatchQueue.global(qos: .userInitiated).async(group: group) {
            Thread.sleep(forTimeInterval: 0.001)
            handle.stop(reason: 0)
        }
        XCTAssertEqual(group.wait(timeout: .now() + 10), .success)
    }
}
