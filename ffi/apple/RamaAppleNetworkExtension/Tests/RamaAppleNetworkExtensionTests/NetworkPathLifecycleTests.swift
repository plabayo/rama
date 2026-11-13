import Foundation
import XCTest

@testable import RamaAppleNetworkExtension

final class NetworkPathLifecycleTests: XCTestCase {
    override class func setUp() {
        super.setUp()
        TestFixtures.ensureInitialized()
    }

    func testMonitorFollowsEngineGenerationAndLateEventsAreHarmless() throws {
        let core = TransparentProxyCore()
        XCTAssertFalse(core.testHasNetworkPathMonitor)
        let old = try XCTUnwrap(RamaTransparentProxyEngineHandle(
            engineConfigJson: TestFixtures.engineConfigJson()))
        let first = core.attachEngine(old)
        XCTAssertTrue(core.testHasNetworkPathMonitor)
        old.notifyNetworkChange(status: 1, preferredInterface: 4, flags: 0)
        core.detachEngine(reason: 0)
        XCTAssertFalse(core.testHasNetworkPathMonitor)

        let current = try XCTUnwrap(RamaTransparentProxyEngineHandle(
            engineConfigJson: TestFixtures.engineConfigJson()))
        let second = core.attachEngine(current)
        XCTAssertGreaterThan(second, first)
        XCTAssertTrue(core.testHasNetworkPathMonitor)
        // Old callbacks retain only their exact engine handle; its lifetime gate refuses
        // entry after detach. They cannot publish into the replacement generation.
        old.notifyNetworkChange(status: 2, preferredInterface: 0, flags: 0)
        current.notifyNetworkChange(status: 1, preferredInterface: 8, flags: 3)
        XCTAssertEqual(core.testEngineGeneration, second)
        core.detachEngine(reason: 0)
        XCTAssertFalse(core.testHasNetworkPathMonitor)
    }

    func testNetworkNotificationsRaceStopThroughLifetimeLease() throws {
        let core = TransparentProxyCore()
        let engine = try XCTUnwrap(RamaTransparentProxyEngineHandle(
            engineConfigJson: TestFixtures.engineConfigJson()))
        core.attachEngine(engine)
        let group = DispatchGroup()
        for worker in 0..<4 {
            DispatchQueue.global().async(group: group) {
                for _ in 0..<256 {
                    engine.notifyNetworkChange(status: 1,
                        preferredInterface: UInt32(worker + 1), flags: 0)
                }
            }
        }
        core.detachEngine(reason: 0)
        XCTAssertEqual(group.wait(timeout: .now() + 5), .success)
        XCTAssertFalse(core.testHasNetworkPathMonitor)
        engine.notifyNetworkChange(status: UInt32.max, preferredInterface: 0, flags: UInt32.max)
    }
}
