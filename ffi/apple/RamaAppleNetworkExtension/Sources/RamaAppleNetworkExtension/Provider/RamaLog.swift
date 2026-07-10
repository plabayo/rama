import Foundation
import os.log

/// Native `os.Logger` sink for general diagnostic and per-flow events.
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
        switch level {
        case .trace: logger.trace("\(message, privacy: .private)")
        case .debug: logger.debug("\(message, privacy: .private)")
        case .info: logger.info("\(message, privacy: .private)")
        case .warn: logger.warning("\(message, privacy: .private)")
        case .error: logger.error("\(message, privacy: .private)")
        }
    }

    static func trace(_ message: String) { log(.trace, message) }
    static func debug(_ message: String) { log(.debug, message) }
    static func info(_ message: String) { log(.info, message) }
    static func warn(_ message: String) { log(.warn, message) }
    static func error(_ message: String) { log(.error, message) }
}
