import Foundation
import XCTest

final class TestValue<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Value

    init(_ value: Value) {
        self.value = value
    }

    func get() -> Value {
        lock.lock()
        defer { lock.unlock() }
        return value
    }

    func set(_ newValue: Value) {
        lock.lock()
        value = newValue
        lock.unlock()
    }

    @discardableResult
    func update<Result>(_ body: (inout Value) -> Result) -> Result {
        lock.lock()
        defer { lock.unlock() }
        return body(&value)
    }
}

extension XCTestCase {
    /// Poll until `condition` holds, or fail at `timeout`.
    ///
    /// Use this for assertions on real deadline-driven events (the pump
    /// linger / EOF-grace `DispatchWorkItem`s): it waits for the event to
    /// actually happen rather than sleeping a fixed slack past the deadline
    /// and ASSUMING it fired. The fixed-sleep pattern is the suite's main
    /// flake source — a CI runner stalled past the deadline made the
    /// "it fired" assertion fail spuriously. Polling for the event is robust:
    /// a late deadline still fires, and the poll catches it (only a genuine
    /// no-fire bug, or a real >`timeout` stall, fails). The poll interval is
    /// cadence, NOT a deadline assumption.
    func pollUntil(
        _ message: String = "condition not met within timeout",
        timeout: TimeInterval = 3.0,
        _ condition: () -> Bool,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        let deadline = Date().addingTimeInterval(timeout)
        while !condition() && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.005)
        }
        XCTAssertTrue(condition(), message, file: file, line: line)
    }
}
