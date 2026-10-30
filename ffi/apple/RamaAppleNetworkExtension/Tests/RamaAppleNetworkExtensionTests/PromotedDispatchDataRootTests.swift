import CryptoKit
import Dispatch
import Foundation
import XCTest

@testable import RamaAppleNetworkExtension

/// Upload roots shaped like `readData` results: dispatch_data objects, single
/// region or concatenated, bridged to `Data` and poisoned when their storage is
/// destroyed. They travel through the production promotion wiring over a
/// `NativeTcpConnection`; the loopback peer checks the stream digest.
final class PromotedDispatchDataRootTests: XCTestCase {
    private static let rootBytes = 256 * 1024

    func testDispatchDataRootsReachThePeerIntact() throws {
        let milestones = Milestones()
        // Each root becomes several 64 KiB writer slices; the last one is short.
        let sizes = [Int](repeating: Self.rootBytes, count: 48) + [100_003]
        let total = sizes.reduce(0, +)
        let received = Locked<(count: Int, digest: Data)?>(nil)
        let peer = try ScriptedPeer(milestones: milestones) { peer in
            var digest = SHA256()
            // A slow reader keeps the socket full, so sends complete before the stack
            // has written all of their bytes.
            let count = try peer.readToEnd(into: &digest, chunk: 16_384, pacingMicros: 200)
            received.withLock { $0 = (count, Data(digest.finalize())) }
            try peer.shutdownWrite()
            milestones.reach("peer done")
        }
        defer { peer.stop() }

        let regions = Locked((created: 0, destroyed: 0))
        let h = try PromotedSessionHarness(
            port: peer.port, milestones: milestones, cap: 262_144,
            responseBytes: 0, uploadBytes: total)
        defer { h.cleanup() }
        guard milestones.expect("ready", timeout: 10) else { return }
        h.promote()

        var offset = 0
        for (index, size) in sizes.enumerated() {
            guard waitForClientRead(h.flow, milestones) else { return }
            let root = Self.root(
                offset: offset, count: size, regions: index.isMultiple(of: 3) ? 1 : 3,
                tracking: regions)
            h.flow.completeRead(data: root, error: nil)
            offset += size
        }
        guard waitForClientRead(h.flow, milestones) else { return }
        h.flow.completeRead(data: nil, error: nil)
        guard milestones.expect("peer done", timeout: 60) else { return }

        let result = try XCTUnwrap(received.withLock { $0 })
        XCTAssertEqual(result.count, total)
        XCTAssertEqual(result.digest, UploadPattern.digest(offset: 0, count: total))
        h.releaseClientWrites()
        pollUntil("flow not closed", timeout: 20) { h.queue.sync { h.ctx.isDone } }
        XCTAssertNil(h.flow.lastCloseReadError)
        XCTAssertNil(h.flow.lastCloseWriteError)
        XCTAssertTrue(milestones.failures.isEmpty, milestones.failures.joined(separator: "\n"))
        h.cleanup()
        // Every region is destroyed exactly once, after the last reference went away.
        pollUntil("dispatch_data regions not released", timeout: 10) {
            regions.withLock { $0.destroyed == $0.created }
        }
    }

    /// A `readData`-shaped root: a dispatch_data object seen through `Data`, made of
    /// `regions` pieces whose destructors poison their bytes before freeing them.
    private static func root(
        offset: Int, count: Int, regions: Int, tracking: Locked<(created: Int, destroyed: Int)>
    ) -> Data {
        var whole = DispatchData.empty
        var done = 0
        for region in 0..<regions {
            let size = region == regions - 1 ? count - done : count / regions
            let bytes = UnsafeMutablePointer<UInt8>.allocate(capacity: size)
            UploadPattern.fill(bytes, offset: offset + done, count: size)
            tracking.withLock { $0.created += 1 }
            let piece = DispatchData(
                bytesNoCopy: UnsafeRawBufferPointer(start: bytes, count: size),
                deallocator: .custom(nil) {
                    bytes.update(repeating: 0xEE, count: size)
                    bytes.deallocate()
                    tracking.withLock { $0.destroyed += 1 }
                })
            whole.append(piece)
            done += size
        }
        // dispatch_data objects are NSData instances; bridging keeps them as storage.
        return (whole as AnyObject as! NSData) as Data
    }
}
