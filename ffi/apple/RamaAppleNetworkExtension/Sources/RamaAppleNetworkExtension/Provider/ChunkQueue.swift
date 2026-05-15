import Foundation

/// FIFO queue for the write-pump hot path.
///
/// `Array.removeFirst()` shifts every element by one (O(n)) on each
/// dequeue, and `Array.insert(_:at: 0)` does the same on each retry
/// push-back. With ~256 queued datagrams (UDP) or thousands of
/// queued TCP chunks under backpressure, drain becomes O(n²)
/// element-moves.
///
/// `ChunkQueue` keeps a head index into an `Array` so dequeue is
/// amortised O(1) and `pushFront` is O(1) whenever it follows a
/// matching `popFront` (the retry path, where we put back the same
/// chunk we just popped). The buffer is compacted in-place once the
/// consumed prefix grows large enough that the live count is the
/// minority — bounded extra memory in exchange for the O(n²)
/// asymptotic.
///
/// Not thread-safe. Both write pumps confine state to a single
/// `DispatchQueue`; this type inherits that confinement.
struct ChunkQueue<T> {
    private var buffer: [T] = []
    private var head: Int = 0

    /// Threshold for in-place compaction: once the consumed prefix
    /// is at least `compactThreshold` long AND it exceeds the live
    /// tail count, drop it. Chosen empirically — small enough that
    /// stale items don't pin much memory, large enough that
    /// compaction itself isn't called on every other dequeue.
    private static var compactThreshold: Int { 64 }

    var isEmpty: Bool { head >= buffer.count }
    var count: Int { buffer.count - head }

    /// Append to the tail. Always O(1) amortised.
    mutating func pushBack(_ value: T) {
        buffer.append(value)
    }

    /// Pop the head. Returns `nil` when empty.
    mutating func popFront() -> T? {
        guard head < buffer.count else { return nil }
        let value = buffer[head]
        head += 1
        // Amortised compaction: drop the consumed prefix once it has
        // grown large enough to dominate the live tail.
        if head >= Self.compactThreshold && head > buffer.count - head {
            buffer.removeFirst(head)
            head = 0
        }
        return value
    }

    /// Push at the head — the retry path. Hot only on transient
    /// write errors. O(1) when there's room in the consumed prefix
    /// (the normal case after at least one `popFront`); O(n)
    /// fallback when called against an empty consumed prefix.
    mutating func pushFront(_ value: T) {
        if head > 0 {
            head -= 1
            buffer[head] = value
        } else {
            buffer.insert(value, at: 0)
        }
    }

    /// Peek the head without consuming.
    func first() -> T? {
        guard head < buffer.count else { return nil }
        return buffer[head]
    }

    /// Drop all queued elements.
    mutating func removeAll(keepingCapacity: Bool = false) {
        buffer.removeAll(keepingCapacity: keepingCapacity)
        head = 0
    }
}
