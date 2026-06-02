import Foundation
import XCTest

@testable import RamaAppleNetworkExtension

/// Tests for the lifecycle-event logging path.
///
/// Background: every Swift-side `core.logInfo(...)` call routes through
/// the Rust FFI, which forwards to `tracing::info!`. With the current
/// `tracing-oslog` mapping the events are supposed to land at
/// `OS_LOG_TYPE_DEFAULT` for our subsystem, but in practice
/// `log show` does NOT return them — see `LifecycleLog`'s file-level
/// doc for the post-incident analysis.
///
/// The fix is `logLifecycle(_:)` on `TransparentProxyCore`, which
/// emits the message through `LifecycleLog` (a direct `os.Logger`
/// wrapper) AND through the existing Rust path. The direct path is
/// the load-bearing one and is what these tests pin.
final class LifecycleLogTests: XCTestCase {

    override class func setUp() {
        super.setUp()
        TestFixtures.ensureInitialized()
    }

    override func tearDown() {
        // Always clear the test overrides + restore the default
        // subsystem; otherwise a failed assertion mid-test would
        // leak state into the next case in the run order and
        // produce confusing cascading failures.
        LifecycleLog.noticeOverride = nil
        LifecycleLog.errorOverride = nil
        LifecycleLog.subsystem = Bundle.main.bundleIdentifier ?? "org.plabayo.rama.ne"
        super.tearDown()
    }

    // MARK: - Configurable subsystem

    /// Default subsystem must be the host's bundle ID — the rama
    /// library is a shell, the host (Aikido, our example, …) owns
    /// the namespace.
    func testDefaultSubsystemIsHostBundleId() {
        // In the test binary, Bundle.main is the XCTest harness or
        // the package's `xctest`. Either way it has a bundle ID
        // distinct from the placeholder.
        let expected = Bundle.main.bundleIdentifier ?? "org.plabayo.rama.ne"
        XCTAssertEqual(LifecycleLog.subsystem, expected)
    }

    /// Host extensions can override the subsystem at startup. The
    /// next emission uses the new value. We can't observe the
    /// subsystem at the os_log layer without `OSLogStore`
    /// entitlements, but we CAN pin that the property assignment
    /// sticks — and the per-emit `Logger(subsystem:category:)`
    /// path documented in `LifecycleLog` then carries it through.
    func testSubsystemIsConfigurable() {
        LifecycleLog.subsystem = "com.example.host.custom"
        XCTAssertEqual(LifecycleLog.subsystem, "com.example.host.custom")
        // Sanity: emitting with the custom subsystem doesn't crash.
        LifecycleLog.notice("hello-from-custom-subsystem")
    }

    /// Concurrent reads and writes of `subsystem` must not race or
    /// crash. The implementation gates both behind an `NSLock`;
    /// this test hammers the read/write surface from many threads
    /// at once. With the lock the test passes deterministically;
    /// without it (an unsynchronized `nonisolated(unsafe) var`)
    /// `String` COW mutation under contention would corrupt or
    /// trip TSan.
    func testSubsystemReadWriteIsRaceFree() {
        let original = LifecycleLog.subsystem

        let writeCount = 200
        let readCount = 500
        let exp = expectation(description: "concurrent access done")
        exp.expectedFulfillmentCount = writeCount + readCount

        let writeQueue = DispatchQueue(
            label: "rama.test.subsystem.writes", attributes: .concurrent)
        let readQueue = DispatchQueue(
            label: "rama.test.subsystem.reads", attributes: .concurrent)

        for i in 0..<writeCount {
            writeQueue.async {
                LifecycleLog.subsystem = "com.example.race.\(i)"
                exp.fulfill()
            }
        }
        for _ in 0..<readCount {
            readQueue.async {
                // Read AND emit (which itself reads the subsystem).
                _ = LifecycleLog.subsystem
                LifecycleLog.notice("concurrent-emit")
                exp.fulfill()
            }
        }
        wait(for: [exp], timeout: 5.0)

        // After the dust settles, subsystem is some valid string —
        // the test isn't about which value wins, only that no
        // crash / data race occurred.
        XCTAssertFalse(LifecycleLog.subsystem.isEmpty)

        // Restore deterministically.
        LifecycleLog.subsystem = original
    }

    // MARK: - Direct `LifecycleLog` surface

    /// The override hook fires when set, and the `os.Logger` sink is
    /// bypassed. This is what tests rely on to observe lifecycle
    /// emissions without `OSLogStore` entitlements.
    func testNoticeOverrideIsInvokedAndShadowsOsLog() {
        let lock = NSLock()
        var captured: [String] = []
        LifecycleLog.noticeOverride = { msg in
            lock.lock()
            captured.append(msg)
            lock.unlock()
        }

        LifecycleLog.notice("hello-lifecycle")

        lock.lock()
        defer { lock.unlock() }
        XCTAssertEqual(captured, ["hello-lifecycle"])
    }

    /// The error override is independent of the notice override —
    /// installing one does not redirect the other.
    func testErrorOverrideIsIndependentOfNoticeOverride() {
        // Use `CapturedMessages` (already thread-safe via its
        // internal lock) so the `@Sendable` override closure isn't
        // capturing a `var` from outer scope — that's an error
        // under Swift-6 strict concurrency.
        let notices = CapturedMessages()
        let errors = CapturedMessages()
        LifecycleLog.noticeOverride = { notices.append($0) }
        LifecycleLog.errorOverride = { errors.append($0) }

        LifecycleLog.notice("a")
        LifecycleLog.error("b")
        LifecycleLog.notice("c")

        XCTAssertEqual(notices.values, ["a", "c"])
        XCTAssertEqual(errors.values, ["b"])
    }

    /// Without an override, the `os.Logger` path is used. The test
    /// just verifies no crash / no exception; we can't easily read
    /// back from `OSLogStore` in the unit-test harness.
    func testNoticeWithoutOverrideDoesNotCrash() {
        LifecycleLog.noticeOverride = nil
        LifecycleLog.error("fallback-path-error")
        LifecycleLog.notice("fallback-path-notice")
    }

    /// The hook tolerates being invoked from multiple threads at once.
    /// `nonisolated(unsafe)` is fine for tests that mutate the hook
    /// only in `setUp`/`tearDown`; this test exercises the read path
    /// under concurrent emit.
    func testNoticeOverrideIsThreadSafeForReads() {
        let counter = ConcurrentCounter()
        LifecycleLog.noticeOverride = { _ in counter.increment() }

        let exp = expectation(description: "all emits done")
        exp.expectedFulfillmentCount = 100
        for i in 0..<100 {
            DispatchQueue.global().async {
                LifecycleLog.notice("e\(i)")
                exp.fulfill()
            }
        }
        wait(for: [exp], timeout: 5.0)

        XCTAssertEqual(counter.value, 100)
    }

    // MARK: - `TransparentProxyCore` lifecycle methods

    /// `core.logLifecycle(_:)` routes through `LifecycleLog.notice(_:)`
    /// — verified through the test override. This is the load-bearing
    /// path: every lifecycle call site (`extension startProxy`,
    /// `engine created`, `system sleep:`, `system wake`,
    /// `extension stopProxy`) goes through here.
    func testCoreLogLifecycleReachesLifecycleLogNotice() {
        let core = makeCore()
        let captured = expectAndCapture(overrideField: .notice)

        core.logLifecycle("core-lifecycle-msg")

        XCTAssertEqual(captured.values, ["core-lifecycle-msg"])
    }

    /// `core.logLifecycleError(_:)` routes through `LifecycleLog.error(_:)`,
    /// not `.notice(_:)`. Easy to get wrong with a copy-paste — pin it.
    func testCoreLogLifecycleErrorReachesLifecycleLogError() {
        let core = makeCore()
        let notices = expectAndCapture(overrideField: .notice)
        let errors = expectAndCapture(overrideField: .error)

        core.logLifecycleError("core-lifecycle-error")

        XCTAssertEqual(notices.values, [] as [String])
        XCTAssertEqual(errors.values, ["core-lifecycle-error"])
    }

    /// `handleSystemSleep` must emit a `"system sleep"` lifecycle
    /// notice before invoking the completion. This is the load-bearing
    /// signal a post-incident `log show` needs to attribute the sleep
    /// to our extension.
    func testHandleSystemSleepEmitsLifecycleNotice() {
        let core = makeCore()
        let captured = expectAndCapture(overrideField: .notice)
        let exp = expectation(description: "sleep completion")
        core.handleSystemSleep { exp.fulfill() }
        wait(for: [exp], timeout: 1.0)

        XCTAssertTrue(
            captured.values.contains("system sleep"),
            "expected a 'system sleep' lifecycle notice; got \(captured.values)"
        )
    }

    /// `handleSystemWake` must emit `"system wake"` so the wake event
    /// shows up in `log show` regardless of the Rust tracing pipeline.
    func testHandleSystemWakeEmitsLifecycleNotice() {
        let core = makeCore()
        let captured = expectAndCapture(overrideField: .notice)

        core.handleSystemWake()

        XCTAssertTrue(
            captured.values.contains("system wake"),
            "expected 'system wake' lifecycle notice; got \(captured.values)"
        )
    }

    // MARK: - Helpers

    private func makeCore() -> TransparentProxyCore {
        TransparentProxyCore()
    }

    private enum OverrideField {
        case notice
        case error
    }

    /// Install a capturing override on the named `LifecycleLog` field
    /// and return a thread-safe accessor for the captured values.
    /// Cleared automatically in `tearDown`.
    private func expectAndCapture(overrideField field: OverrideField) -> CapturedMessages {
        let capture = CapturedMessages()
        switch field {
        case .notice:
            LifecycleLog.noticeOverride = { capture.append($0) }
        case .error:
            LifecycleLog.errorOverride = { capture.append($0) }
        }
        return capture
    }
}

/// Thread-safe captured-message accumulator. Pure helper; lives only
/// in the test target.
private final class CapturedMessages: @unchecked Sendable {
    private let lock = NSLock()
    private var _values: [String] = []

    func append(_ message: String) {
        lock.lock()
        _values.append(message)
        lock.unlock()
    }

    var values: [String] {
        lock.lock()
        defer { lock.unlock() }
        return _values
    }
}

/// Trivial thread-safe counter for the concurrent-emit test.
private final class ConcurrentCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var _value = 0

    func increment() {
        lock.lock()
        _value += 1
        lock.unlock()
    }

    var value: Int {
        lock.lock()
        defer { lock.unlock() }
        return _value
    }
}
