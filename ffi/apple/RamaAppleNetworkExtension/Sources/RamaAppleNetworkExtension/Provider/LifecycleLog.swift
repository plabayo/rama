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
    /// Subsystem the lifecycle logger writes to. **Mutable** — host
    /// extensions can override before any emission to route lifecycle
    /// events into their own namespace.
    ///
    /// Default: `Bundle.main.bundleIdentifier`. Inside a system
    /// extension `Bundle.main` is the extension's own bundle.
    ///
    /// `nonisolated(unsafe)` is fine: production reads at startup
    /// (single-threaded), mutates at most once.
    nonisolated(unsafe) public static var subsystem: String =
        Bundle.main.bundleIdentifier ?? "org.plabayo.rama.ne"

    /// Dedicated category so a focused query
    /// (`category == "lifecycle"`) surfaces exactly these events
    /// without the noise of the rest of the subsystem.
    public static let category = "lifecycle"

    /// Build a `Logger` for the current subsystem + category.
    ///
    /// Apple's runtime caches the underlying `os_log_t` on the
    /// `(subsystem, category)` tuple, so re-constructing the Logger
    /// each call is essentially free after the first emission. This
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
