import Foundation
import os.log

/// Direct `os.Logger` sink for lifecycle / critical events.
///
/// Lifecycle events (`extension startProxy`, `engine created`,
/// `system sleep:`, `system wake`, `extension stopProxy`, …) MUST be
/// visible in `log show` for post-incident debugging.
///
/// `Logger.notice(_:)` maps to `OS_LOG_TYPE_DEFAULT`, which is always
/// persistent and always returned by `log show` without flags. That's
/// the right level for these events — they're rare, signal-rich, and
/// should always survive in the logs.
///
/// Tests can intercept emissions by installing
/// [`LifecycleLog.noticeOverride`] / [`LifecycleLog.errorOverride`].
/// When set, the override is invoked INSTEAD OF the `os.Logger` sink,
/// so unit tests don't have to read back from `OSLogStore` (which
/// would require elevated entitlements in the test harness).
public enum LifecycleLog {
    /// Dedicated category so a focused query
    /// (`category == "lifecycle"`) surfaces exactly these events
    /// without the noise of the rest of the subsystem.
    public static let category = "lifecycle"

    /// Read / write the subsystem the lifecycle logger emits to.
    /// Host extensions configure it before any emission to route
    /// events into their own namespace; default is
    /// `Bundle.main.bundleIdentifier` (the host's bundle id —
    /// inside a system extension `Bundle.main` is the extension's
    /// own bundle).
    ///
    /// Both the get and set go through a serial lock — there's no
    /// process-wide guarantee that hosts mutate only at startup,
    /// and concurrent unsynchronised `String` mutation is a data
    /// race (Swift `String` has COW shared-Arc internals). The
    /// lock is uncontended in practice (one read per emission,
    /// vanishingly rare writes), so the cost is negligible vs the
    /// formal correctness it buys. Apple's `os.Logger` internally
    /// caches `os_log_t` on the `(subsystem, category)` tuple, so
    /// `Logger(subsystem:category:)` per emit is essentially free
    /// after the first call.
    public static var subsystem: String {
        get {
            subsystemLock.lock()
            defer { subsystemLock.unlock() }
            return _subsystem
        }
        set {
            subsystemLock.lock()
            defer { subsystemLock.unlock() }
            _subsystem = newValue
        }
    }

    /// Backing storage for [`subsystem`]. Only touched through the
    /// lock above; `nonisolated(unsafe)` is OK by construction.
    nonisolated(unsafe) private static var _subsystem: String =
        Bundle.main.bundleIdentifier ?? "org.plabayo.rama.ne"

    /// Serializes reads and writes of [`subsystem`]. `os_unfair_lock`
    /// would be lower-overhead but `NSLock` is enough here — the
    /// critical section is "read a `String` value" / "store a
    /// `String` value".
    private static let subsystemLock = NSLock()

    /// Build a `Logger` for the current subsystem + category.
    ///
    /// Reads `subsystem` under the lock once, then constructs the
    /// `Logger`. Apple's runtime caches the underlying `os_log_t`
    /// on the `(subsystem, category)` tuple, so re-constructing
    /// the Logger each call is cheap after the first emission. This
    /// lets a mid-run `subsystem =` reassignment take effect on the
    /// next emission without our maintaining a cache + invalidate.
    private static func logger() -> Logger {
        Logger(subsystem: subsystem, category: category)
    }

    /// Test-only override for `notice`. When non-nil, called instead
    /// of the `os.Logger` sink. Marked `nonisolated(unsafe)` because
    /// it's only mutated from test set-up / tear-down on a single
    /// thread; production code only reads it.
    nonisolated(unsafe) public static var noticeOverride: (@Sendable (String) -> Void)?

    /// Test-only override for `error`. Same contract as
    /// [`noticeOverride`].
    nonisolated(unsafe) public static var errorOverride: (@Sendable (String) -> Void)?

    /// Emit a lifecycle event at `OS_LOG_TYPE_DEFAULT`.
    ///
    /// Marked `@Sendable` so it can be stored / forwarded across
    /// queue boundaries without ceremony.
    public static func notice(_ message: String) {
        if let override = noticeOverride {
            override(message)
            return
        }
        // `privacy: .public` is the safe default for *our* lifecycle
        // strings — they don't carry user data; suppressing them
        // turns post-incident `log show` output into `<private>`
        // placeholders, which defeats the purpose.
        logger().notice("\(message, privacy: .public)")
    }

    /// Emit a lifecycle event at `OS_LOG_TYPE_ERROR` for failures that
    /// nevertheless don't crash the extension (engine init failure,
    /// network-settings push failure, …).
    public static func error(_ message: String) {
        if let override = errorOverride {
            override(message)
            return
        }
        logger().error("\(message, privacy: .public)")
    }
}
