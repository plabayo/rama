import Foundation
import XCTest

@testable import RamaAppleNetworkExtension

final class TcpOverloadAdmissionTests: XCTestCase {
    private var savedHardCap: UInt32 = 0
    private var savedSoftCap: UInt32 = 0
    private var savedOpenP95: UInt32 = 0
    private var savedCloseP95: UInt32 = 0
    private var savedPressureTimeout: UInt32 = 0
    private var savedBreakerTimeout: UInt32 = 0

    override func setUp() {
        super.setUp()
        savedHardCap = defaultTcpStartInFlightHardCap
        savedSoftCap = defaultTcpStartInFlightSoftCap
        savedOpenP95 = defaultTcpStartLatencyBreakerP95Ms
        savedCloseP95 = defaultTcpStartLatencyBreakerCloseP95Ms
        savedPressureTimeout = defaultTcpPressureConnectTimeoutMs
        savedBreakerTimeout = defaultTcpBreakerConnectTimeoutMs
    }

    override func tearDown() {
        LifecycleLog.noticeOverride = nil
        defaultTcpStartInFlightHardCap = savedHardCap
        defaultTcpStartInFlightSoftCap = savedSoftCap
        defaultTcpStartLatencyBreakerP95Ms = savedOpenP95
        defaultTcpStartLatencyBreakerCloseP95Ms = savedCloseP95
        defaultTcpPressureConnectTimeoutMs = savedPressureTimeout
        defaultTcpBreakerConnectTimeoutMs = savedBreakerTimeout
        super.tearDown()
    }

    func testHardStartCapRejectsBeforeAddingAnotherInFlightStart() {
        defaultTcpStartInFlightHardCap = 1
        let core = TransparentProxyCore()
        let first = NSObject()
        let second = NSObject()

        guard case .admit = core.testAdmitTcpStart(flowId: ObjectIdentifier(first), meta: meta())
        else {
            XCTFail("first start should be admitted")
            return
        }

        guard case .reject(let reason, _) = core.testAdmitTcpStart(
            flowId: ObjectIdentifier(second), meta: meta())
        else {
            XCTFail("second start should be rejected at hard cap")
            return
        }

        XCTAssertTrue(reason.contains("hard start cap reached"))
        XCTAssertEqual(core.testTcpStartsInFlight, 1)
    }

    func testStartCompletionDecrementsInFlightGaugeForReadyAndTimeout() {
        defaultTcpStartInFlightHardCap = 10
        let core = TransparentProxyCore()
        let readyFlow = NSObject()
        let timeoutFlow = NSObject()

        let readyToken = admittedToken(core, readyFlow)
        let timeoutToken = admittedToken(core, timeoutFlow)
        XCTAssertEqual(core.testTcpStartsInFlight, 2)

        core.testFinishTcpStart(readyToken, outcome: .ready)
        core.testFinishTcpStart(timeoutToken, outcome: .timeout)

        waitFor("in-flight gauge drains") { core.testTcpStartsInFlight == 0 }
    }

    func testLatencyBreakerRejectsAtSoftCapAfterSlowStart() {
        defaultTcpStartInFlightHardCap = 10
        defaultTcpStartInFlightSoftCap = 1
        defaultTcpStartLatencyBreakerP95Ms = 1
        let core = TransparentProxyCore()
        let first = NSObject()
        let second = NSObject()
        let third = NSObject()

        let firstToken = admittedToken(core, first)
        _ = admittedToken(core, second)
        Thread.sleep(forTimeInterval: 0.005)
        core.testFinishTcpStart(firstToken, outcome: .ready)

        waitFor("breaker opens") { core.testTcpOverloadBreakerOpen }

        guard case .reject(let reason, _) = core.testAdmitTcpStart(
            flowId: ObjectIdentifier(third), meta: meta(bundleId: "com.example.third"))
        else {
            XCTFail("breaker should reject while in-flight starts are still at the soft cap")
            return
        }
        XCTAssertTrue(reason.contains("latency breaker open"))
    }

    func testMaintenanceTelemetryIsPersistedAndIncludesOverloadFields() {
        defaultTcpStartInFlightHardCap = 10
        let core = TransparentProxyCore()
        let captured = CapturedNotices()
        LifecycleLog.noticeOverride = { captured.append($0) }

        let token = admittedToken(core, NSObject(), bundleId: "com.example.browser")
        core.testFinishTcpStart(token, outcome: .timeout)
        waitFor("in-flight gauge drains before telemetry") { core.testTcpStartsInFlight == 0 }

        core.testRunPeriodicMaintenance()

        let joined = captured.values.joined(separator: "\n")
        XCTAssertTrue(joined.contains("tproxy live-flow counts"))
        XCTAssertTrue(joined.contains("admissionRate="))
        XCTAssertTrue(joined.contains("timeoutRate="))
        XCTAssertTrue(joined.contains("startLatencyMs["))
        XCTAssertTrue(joined.contains("breaker="))
    }

    func testConnectTimeoutClampsUnderPressureAndBreaker() {
        defaultTcpStartInFlightHardCap = 10
        defaultTcpStartInFlightSoftCap = 1
        defaultTcpPressureConnectTimeoutMs = 5_000
        defaultTcpBreakerConnectTimeoutMs = 3_000
        defaultTcpStartLatencyBreakerP95Ms = 1
        let core = TransparentProxyCore()
        let first = NSObject()
        let second = NSObject()

        XCTAssertEqual(core.testTcpConnectTimeoutMs(base: 10_000), 10_000)

        let firstToken = admittedToken(core, first)
        XCTAssertEqual(
            core.testTcpConnectTimeoutMs(base: 10_000), 5_000,
            "soft-cap pressure clamps long connect timeouts")

        _ = admittedToken(core, second)
        Thread.sleep(forTimeInterval: 0.005)
        core.testFinishTcpStart(firstToken, outcome: .ready)
        waitFor("breaker opens") { core.testTcpOverloadBreakerOpen }

        XCTAssertEqual(
            core.testTcpConnectTimeoutMs(base: 10_000), 3_000,
            "open breaker uses the stricter timeout clamp")
        XCTAssertEqual(
            core.testTcpConnectTimeoutMs(base: 1_000), 1_000,
            "adaptive timeout never raises an already-short explicit timeout")
    }

    private func admittedToken(
        _ core: TransparentProxyCore, _ object: NSObject, bundleId: String = "com.example.app"
    ) -> TcpAdmissionToken {
        let decision = core.testAdmitTcpStart(
            flowId: ObjectIdentifier(object), meta: meta(bundleId: bundleId))
        guard case .admit(let token) = decision else {
            XCTFail("expected admission, got \(decision)")
            return TcpAdmissionToken(
                flowId: ObjectIdentifier(object), startedAt: .now(), appId: bundleId)
        }
        return token
    }

    private func meta(bundleId: String = "com.example.app") -> RamaTransparentProxyFlowMetaBridge {
        RamaTransparentProxyFlowMetaBridge(
            protocolRaw: 1,
            remoteHost: "example.com",
            remotePort: 443,
            localHost: nil,
            localPort: 0,
            sourceAppSigningIdentifier: nil,
            sourceAppBundleIdentifier: bundleId,
            sourceAppAuditToken: nil,
            sourceAppPid: 4242
        )
    }

    private func waitFor(
        _ description: String, timeout: TimeInterval = 2.0, _ condition: () -> Bool
    ) {
        let deadline = Date().addingTimeInterval(timeout)
        while !condition(), Date() < deadline {
            Thread.sleep(forTimeInterval: 0.002)
        }
        XCTAssertTrue(condition(), description)
    }
}

private final class CapturedNotices: @unchecked Sendable {
    private let lock = NSLock()
    private var messages: [String] = []

    func append(_ message: String) {
        lock.lock()
        messages.append(message)
        lock.unlock()
    }

    var values: [String] {
        lock.lock()
        defer { lock.unlock() }
        return messages
    }
}
