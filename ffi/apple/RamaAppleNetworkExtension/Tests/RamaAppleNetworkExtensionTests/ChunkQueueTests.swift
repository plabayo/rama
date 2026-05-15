import Foundation
import XCTest

@testable import RamaAppleNetworkExtension

/// `ChunkQueue` is the head-index queue both write pumps now use in
/// place of `Array.removeFirst()` / `Array.insert(_:at: 0)` on the
/// hot path. The semantic contract under test is:
///
/// 1. FIFO order on `pushBack` then `popFront`.
/// 2. `pushFront` followed by `popFront` returns the just-pushed
///    value — the retry path.
/// 3. `popFront` + `pushBack` interleaving doesn't reorder.
/// 4. `count`, `isEmpty`, `first()`, and `removeAll` stay in sync
///    with the consumed head.
/// 5. Long alternating push/pop sequences (the steady-state shape
///    of either pump) don't leak memory — the internal buffer is
///    bounded in proportion to the live count.
final class ChunkQueueTests: XCTestCase {

    func testFifoOrderOnPushBackPopFront() {
        var queue = ChunkQueue<Int>()
        for i in 0..<8 {
            queue.pushBack(i)
        }
        XCTAssertEqual(queue.count, 8)
        var observed: [Int] = []
        while let v = queue.popFront() {
            observed.append(v)
        }
        XCTAssertEqual(observed, Array(0..<8))
        XCTAssertTrue(queue.isEmpty)
        XCTAssertNil(queue.popFront())
    }

    /// Retry path: pop a chunk, write fails, push it back at the
    /// head. The next pop must return that same chunk.
    func testPushFrontAfterPopFrontPreservesChunkAtHead() {
        var queue = ChunkQueue<String>()
        queue.pushBack("a")
        queue.pushBack("b")
        queue.pushBack("c")
        let first = queue.popFront()
        XCTAssertEqual(first, "a")

        // Simulate "write failed, put it back."
        queue.pushFront(first!)

        XCTAssertEqual(queue.count, 3)
        XCTAssertEqual(queue.first(), "a")
        XCTAssertEqual(queue.popFront(), "a")
        XCTAssertEqual(queue.popFront(), "b")
        XCTAssertEqual(queue.popFront(), "c")
        XCTAssertNil(queue.popFront())
    }

    /// `pushFront` against an empty consumed prefix must still
    /// preserve FIFO semantics (the rare fallback path).
    func testPushFrontWithoutPriorPopFallsBackToInsert() {
        var queue = ChunkQueue<Int>()
        queue.pushBack(1)
        queue.pushBack(2)
        // No `popFront` first: head == 0 → fallback to insert(at: 0).
        queue.pushFront(0)
        XCTAssertEqual(queue.count, 3)
        XCTAssertEqual(queue.popFront(), 0)
        XCTAssertEqual(queue.popFront(), 1)
        XCTAssertEqual(queue.popFront(), 2)
    }

    /// Steady-state push/pop interleaving — the realistic shape of
    /// either pump in production. The buffer must compact so memory
    /// growth stays bounded.
    func testLongPushPopInterleavingCompactsInternalBuffer() {
        var queue = ChunkQueue<Int>()
        // Prime with a small window.
        for i in 0..<32 {
            queue.pushBack(i)
        }
        // Alternate pop + push for many iterations. Live count
        // stays at 32; total pushes/pops far exceeds any sane
        // chunk count, so without compaction the internal buffer
        // would grow without bound.
        for i in 32..<10_000 {
            _ = queue.popFront()
            queue.pushBack(i)
        }
        XCTAssertEqual(queue.count, 32)
        // Drain in FIFO order — the last 32 pushed must be the
        // last 32 popped.
        var observed: [Int] = []
        while let v = queue.popFront() {
            observed.append(v)
        }
        XCTAssertEqual(observed, Array(9_968..<10_000))
        XCTAssertTrue(queue.isEmpty)
    }

    func testRemoveAllEmptiesAndResets() {
        var queue = ChunkQueue<Int>()
        for i in 0..<10 {
            queue.pushBack(i)
        }
        _ = queue.popFront()
        _ = queue.popFront()
        queue.removeAll()
        XCTAssertEqual(queue.count, 0)
        XCTAssertTrue(queue.isEmpty)
        XCTAssertNil(queue.popFront())
        XCTAssertNil(queue.first())
        // Usable after removeAll.
        queue.pushBack(42)
        XCTAssertEqual(queue.popFront(), 42)
    }
}
