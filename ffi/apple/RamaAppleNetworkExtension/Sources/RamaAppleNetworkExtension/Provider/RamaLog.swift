import Foundation
import os.log

/// Native `os.Logger` sink for general diagnostic / per-flow events.
///
/// Replaces the former Swift → Rust `rama_log` forwarding: messages now
/// go straight to Apple unified logging instead of crossing the FFI
/// boundary into Rust `tracing` (which copied + reformatted every line).
/// Lifecycle / critical events keep their own dedicated sink in
/// [`LifecycleLog`].
enum RamaLog {
    enum Level {
        case trace
        case debug
        case info
        case warn
        case error
    }

    /// Distinct from `LifecycleLog`'s "lifecycle" category so a focused
    /// query can separate rare signal-rich lifecycle events from the
    /// higher-volume per-flow diagnostic stream.
    static let category = "flow"

    /// Shares `LifecycleLog`'s subsystem so all of our logging lives in
    /// one namespace; Apple caches the underlying `os_log_t` on the
    /// `(subsystem, category)` tuple, so constructing per emit is cheap.
    private static func logger() -> Logger {
        Logger(subsystem: LifecycleLog.subsystem, category: category)
    }

    static func log(_ level: Level, _ message: String) {
        let logger = logger()
        // `.public`: these are our own diagnostic strings, and this
        // matches the visibility the prior Rust-forwarding path gave
        // them. Without it `log show` redacts dynamic strings to
        // `<private>`, which defeats post-incident debugging.
        switch level {
        case .trace: logger.trace("\(message, privacy: .public)")
        case .debug: logger.debug("\(message, privacy: .public)")
        case .info: logger.info("\(message, privacy: .public)")
        case .warn: logger.warning("\(message, privacy: .public)")
        case .error: logger.error("\(message, privacy: .public)")
        }
    }

    static func trace(_ message: String) { log(.trace, message) }
    static func debug(_ message: String) { log(.debug, message) }
    static func info(_ message: String) { log(.info, message) }
    static func warn(_ message: String) { log(.warn, message) }
    static func error(_ message: String) { log(.error, message) }
}
