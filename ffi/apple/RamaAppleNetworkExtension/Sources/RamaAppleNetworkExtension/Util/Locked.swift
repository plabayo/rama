import Foundation

/// Type-enforced critical section: `T` is reachable only inside the
/// `withLock` closure, the lock is auto-released on closure exit
/// (including via `throw` or early `return`), and the closure can't
/// leak a reference past its scope because `inout T` is bound to the
/// closure.
///
/// Use this whenever a group of fields is "logically one mutex's
/// worth of state" — a free-standing `NSLock` plus separately-named
/// `lockedFoo` ivars relies on developer discipline to (a) always
/// take the lock before touching any of those fields, (b) always
/// release on every exit path, (c) never hold a stored reference to
/// them outside the locked region. `Locked<T>` makes those
/// invariants type-level instead of comment-level.
///
/// `NSLock` is non-reentrant; calling `withLock` from inside another
/// `withLock` on the same instance deadlocks deterministically
/// rather than silently double-entering. That's the safer failure
/// mode and matches the Rust `Mutex<T>` shape.
final class Locked<T> {
    private let lock = NSLock()
    private var value: T

    init(_ initial: T) {
        self.value = initial
    }

    @discardableResult
    func withLock<R>(_ body: (inout T) throws -> R) rethrows -> R {
        lock.lock()
        defer { lock.unlock() }
        return try body(&value)
    }
}
