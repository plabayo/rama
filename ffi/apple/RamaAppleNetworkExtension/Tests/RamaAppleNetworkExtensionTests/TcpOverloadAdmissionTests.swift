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

        guard case .reject(let reason, _, _) = core.testAdmitTcpStart(
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

        XCTAssertEqual(core.testTcpStartsInFlight, 0)
    }

    func testStartCompletionUsesCapturedInstantWhenStateQueueIsBacklogged() {
        defaultTcpStartInFlightHardCap = 10
        let core = TransparentProxyCore()
        let token = admittedToken(core, NSObject())
        let gate = core.testHoldStateQueue()

        core.testFinishTcpStart(token, outcome: .ready, latencyMs: 7)
        gate.signal()

        XCTAssertEqual(core.testTcpStartsInFlight, 0)
        XCTAssertEqual(core.testTcpStartLatencySampleCount, 1)
        XCTAssertEqual(core.testTcpStartLatencyPercentile(0.95), 7)
    }

    func testStaleCompletionCannotFinishSameGenerationReplacementAdmission() {
        defaultTcpStartInFlightHardCap = 10
        let core = TransparentProxyCore()
        let reusedFlowIdentity = NSObject()

        let oldToken = admittedToken(core, reusedFlowIdentity)
        core.testFinishTcpStart(oldToken, outcome: .ready)
        XCTAssertEqual(core.testTcpStartsInFlight, 0)

        let replacementToken = admittedToken(core, reusedFlowIdentity)
        XCTAssertEqual(
            oldToken.identity.engineGeneration,
            replacementToken.identity.engineGeneration)
        XCTAssertNotEqual(oldToken.identity.nonce, replacementToken.identity.nonce)
        let latencySamplesBeforeStaleCompletion = core.testTcpStartLatencySampleCount
        let timeoutsBeforeStaleCompletion = core.testTcpTimeoutsSinceTick

        core.testFinishTcpStart(oldToken, outcome: .timeout)

        XCTAssertEqual(core.testTcpStartsInFlight, 1)
        XCTAssertEqual(core.testTcpLiveFlowReservations, 1)
        XCTAssertEqual(
            core.testTcpStartLatencySampleCount,
            latencySamplesBeforeStaleCompletion)
        XCTAssertEqual(core.testTcpTimeoutsSinceTick, timeoutsBeforeStaleCompletion)

        core.testFinishTcpStart(replacementToken, outcome: .failed)
        XCTAssertEqual(core.testTcpStartsInFlight, 0)
        XCTAssertEqual(core.testTcpLiveFlowReservations, 0)
    }

    func testRegistrationConsumesOnlyMatchingAdmissionReservation() {
        defaultTcpStartInFlightHardCap = 10
        let core = TransparentProxyCore()
        let reusedFlowIdentity = NSObject()
        let flowId = ObjectIdentifier(reusedFlowIdentity)

        let oldToken = admittedToken(core, reusedFlowIdentity)
        core.testFinishTcpStart(oldToken, outcome: .ready)
        XCTAssertEqual(core.testTcpStartsInFlight, 0)
        let currentToken = admittedToken(core, reusedFlowIdentity)
        let context = TcpFlowContext()
        let anchor = _TestTcpFlowSessionAnchor(ctx: context)

        XCTAssertNil(
            core.registerTcpFlow(
                flowId,
                anchor: anchor,
                appId: currentToken.appId,
                admissionToken: oldToken))
        XCTAssertEqual(core.testTcpLiveFlowReservations, 1)
        XCTAssertEqual(core.testTcpStartsInFlight, 1)

        XCTAssertEqual(
            core.registerTcpFlow(
                flowId,
                anchor: anchor,
                appId: currentToken.appId,
                admissionToken: currentToken),
            1)
        XCTAssertEqual(core.testTcpLiveFlowReservations, 0)

        core.testFinishTcpStart(oldToken, outcome: .timeout)
        XCTAssertEqual(core.testTcpStartsInFlight, 1)
        core.testFinishTcpStart(currentToken, outcome: .ready)
        XCTAssertEqual(core.testTcpStartsInFlight, 0)
    }

    func testLatencyBreakerRejectsAtSoftCapAfterSlowStart() {
        defaultTcpStartInFlightHardCap = 10
        defaultTcpStartInFlightSoftCap = 1
        defaultTcpStartLatencyBreakerP95Ms = 1
        let core = TransparentProxyCore()
        let first = NSObject()
        let second = NSObject()
        let third = NSObject()

        _ = admittedToken(core, first)
        _ = admittedToken(core, second)
        core.testInsertTcpStartLatencyMs(5)
        XCTAssertTrue(core.testTcpOverloadBreakerOpen)

        guard case .reject(let reason, _, _) = core.testAdmitTcpStart(
            flowId: ObjectIdentifier(third), meta: meta(bundleId: "com.example.third"))
        else {
            XCTFail("breaker should reject while in-flight starts are still at the soft cap")
            return
        }
        XCTAssertTrue(reason.contains("latency breaker open"))
    }

    // MARK: - Breaker evaluation off the completion path

    /// The window already says "slow" from a completion that happened under
    /// the soft cap (so that completion's own evaluation saw no pressure).
    /// The admission that brings in-flight up to the soft cap must open the
    /// breaker itself and be shed — a completion-only breaker would admit it
    /// and open on some later completion.
    func testBreakerOpensOnTheAdmissionThatBringsPressureOntoASlowWindow() {
        defaultTcpStartInFlightHardCap = 10
        defaultTcpStartInFlightSoftCap = 2
        defaultTcpStartLatencyBreakerP95Ms = 1
        let core = TransparentProxyCore()
        let captured = CapturedNotices()
        LifecycleLog.noticeOverride = { captured.append($0) }
        let second = NSObject()
        let third = NSObject()
        let fourth = NSObject()

        core.testInsertTcpStartLatencyMs(5)
        XCTAssertFalse(core.testTcpOverloadBreakerOpen, "slow window without pressure stays closed")

        _ = admittedToken(core, second)  // inFlight 0 → 1, under the soft cap
        _ = admittedToken(core, third)  // inFlight 1 → 2
        guard case .reject(let reason, _, _) = core.testAdmitTcpStart(
            flowId: ObjectIdentifier(fourth), meta: meta())
        else {
            XCTFail("the admission that reaches the soft cap on a slow window must open and shed")
            return
        }
        XCTAssertTrue(reason.contains("latency breaker open"), reason)
        XCTAssertTrue(core.testTcpOverloadBreakerOpen)
        XCTAssertEqual(core.testTcpStartsInFlight, 2, "the shed start never enters the gauge")
        XCTAssertTrue(
            captured.values.joined(separator: "\n").contains("breaker open (on admission)"),
            "the lifecycle line must say which evaluation opened it")
    }

    /// Pressure alone is not overload: with no slow completions on record the
    /// admission-path evaluation must leave the breaker closed and admit.
    func testPressureWithoutSlowCompletionsDoesNotOpenBreakerOnAdmission() {
        defaultTcpStartInFlightHardCap = 10
        defaultTcpStartInFlightSoftCap = 2
        defaultTcpStartLatencyBreakerP95Ms = 1
        let core = TransparentProxyCore()
        let first = NSObject()
        let second = NSObject()
        let third = NSObject()

        _ = admittedToken(core, first)
        _ = admittedToken(core, second)
        guard case .admit = core.testAdmitTcpStart(flowId: ObjectIdentifier(third), meta: meta())
        else {
            XCTFail("pressure without slow completions is not overload; must be admitted")
            return
        }
        XCTAssertFalse(core.testTcpOverloadBreakerOpen)
        XCTAssertEqual(core.testTcpStartsInFlight, 3)
    }

    /// Both conditions true, but no single event saw them together: the slow
    /// completion evaluated under the soft cap, and the admissions that then
    /// raised in-flight to the soft cap were each still under it when they
    /// evaluated. Nothing else arrives. The tick must open it.
    func testMaintenanceTickOpensBreakerWhenNoEventSawBothConditions() {
        defaultTcpStartInFlightHardCap = 10
        defaultTcpStartInFlightSoftCap = 2
        defaultTcpStartLatencyBreakerP95Ms = 1
        let core = TransparentProxyCore()
        let captured = CapturedNotices()
        LifecycleLog.noticeOverride = { captured.append($0) }
        let second = NSObject()
        let third = NSObject()

        core.testInsertTcpStartLatencyMs(5)
        _ = admittedToken(core, second)  // evaluates at inFlight 0: no pressure
        _ = admittedToken(core, third)  // evaluates at inFlight 1: no pressure
        XCTAssertFalse(core.testTcpOverloadBreakerOpen, "precondition: no event saw both")
        XCTAssertEqual(core.testTcpStartsInFlight, 2)

        core.testRunPeriodicMaintenance()

        XCTAssertTrue(core.testTcpOverloadBreakerOpen, "tick must evaluate the open direction")
        XCTAssertTrue(
            captured.values.joined(separator: "\n").contains("breaker=open"),
            "tick telemetry reflects the evaluation it just ran")
    }

    /// A healthy load with a small timeout-bound tail: 6 of 128 completions at
    /// 5s, the rest at 100ms, true p95 100ms. Pressure on top of it is not
    /// overload. (The pin against folding PENDING ages into the percentile is
    /// `testPressureWithoutSlowCompletionsDoesNotOpenBreakerOnAdmission`; this
    /// one pins the window shape itself via the tick's latency summary.)
    func testHealthyHeavyTailCompletionsDoNotOpenBreakerUnderPressure() {
        defaultTcpStartInFlightHardCap = 300
        defaultTcpStartInFlightSoftCap = 64
        defaultTcpStartLatencyBreakerP95Ms = 1_500
        let core = TransparentProxyCore()
        let captured = CapturedNotices()
        LifecycleLog.noticeOverride = { captured.append($0) }
        // Fill the 128-sample window with exact completed-start latencies.
        for i in 0..<128 {
            let slow = i % 25 == 0
            core.testInsertTcpStartLatencyMs(slow ? 5_000 : 100)
        }
        XCTAssertEqual(core.testTcpStartLatencySampleCount, 128)
        XCTAssertFalse(core.testTcpOverloadBreakerOpen)
        XCTAssertEqual(core.testTcpStartLatencyPercentile(0.50), 100)
        XCTAssertEqual(core.testTcpStartLatencyPercentile(0.95), 100)
        XCTAssertEqual(core.testTcpStartLatencyPercentile(0.99), 5_000)

        // The maintenance line must report the same exact distribution.
        core.testRunPeriodicMaintenance()
        let tick = captured.values.joined(separator: "\n")
        XCTAssertTrue(
            tick.contains("startLatencyMs[p50=100,p95=100,p99=5000]"), tick)

        // Genuine pressure on top: 64 starts pending and ageing, none completing.
        let pending = (0..<64).map { _ in NSObject() }
        for object in pending { _ = admittedToken(core, object) }
        let probe = NSObject()
        guard case .admit = core.testAdmitTcpStart(flowId: ObjectIdentifier(probe), meta: meta())
        else {
            XCTFail("a healthy tail is not overload; the at-soft-cap admission must pass")
            return
        }
        XCTAssertFalse(core.testTcpOverloadBreakerOpen)
    }

    #if DEBUG || RAMA_TESTING
        /// Admission and rejection paths may ask for p95 on every new flow.
        /// Once a completion has refreshed the bounded sorted cache, those
        /// reads must remain O(1) until another completion changes the window.
        func testPercentilesReuseCacheAndStayCorrectAfterWindowEviction() {
            var overload = TcpOverloadState()
            for latency in 0..<128 {
                overload.insertLatency(UInt64(latency))
            }
            XCTAssertEqual(overload.startLatencyCacheRefreshCount, 128)

            let refreshesBeforeRejectionChecks = overload.startLatencyCacheRefreshCount
            for _ in 0..<10_000 {
                XCTAssertEqual(overload.percentile(0.95), 121)
            }
            XCTAssertEqual(
                overload.startLatencyCacheRefreshCount,
                refreshesBeforeRejectionChecks,
                "unchanged-window admission checks must not rebuild the percentile cache")

            // The 129th insertion evicts the oldest value (0), leaving 1...128.
            overload.insertLatency(128)
            XCTAssertEqual(overload.startLatencyMsWindow, Array(1...128).map(UInt64.init))
            XCTAssertEqual(
                overload.startLatencyCacheRefreshCount,
                refreshesBeforeRejectionChecks + 1)

            let snapshot = overload.snapshotAndResetRates(intervalSeconds: 60)
            XCTAssertEqual(snapshot.p50StartMs, 65)
            XCTAssertEqual(snapshot.p95StartMs, 122)
            XCTAssertEqual(snapshot.p99StartMs, 127)
            XCTAssertEqual(
                overload.startLatencyCacheRefreshCount,
                refreshesBeforeRejectionChecks + 1,
                "one maintenance snapshot must reuse the same sorted view for p50/p95/p99")
        }
    #endif

    /// A refusal storm must not take the persisted log down with it: only the
    /// first few per-flow lines of a tick window are marked for persistence,
    /// and the tick carries the counts plus the top refusing apps.
    func testShedLinesArePersistedOnlyWithinThePerTickBudget() {
        defaultTcpStartInFlightHardCap = 1
        let core = TransparentProxyCore()
        let captured = CapturedNotices()
        LifecycleLog.noticeOverride = { captured.append($0) }
        let holder = NSObject()
        _ = admittedToken(core, holder)  // pins inFlight at the cap of 1

        var persisted = 0
        var demoted = 0
        let objects = (0..<20).map { _ in NSObject() }
        for (i, object) in objects.enumerated() {
            let app = i % 2 == 0 ? "com.example.noisy" : "com.example.quiet"
            guard case .reject(_, let appId, let persist) = core.testAdmitTcpStart(
                flowId: ObjectIdentifier(object), meta: meta(bundleId: app))
            else {
                XCTFail("at the hard cap every start is refused")
                return
            }
            XCTAssertEqual(appId, app)
            if persist { persisted += 1 } else { demoted += 1 }
        }
        XCTAssertEqual(persisted, TcpOverloadState.persistedShedLinesPerTick)
        XCTAssertEqual(demoted, 20 - TcpOverloadState.persistedShedLinesPerTick)

        core.testRunPeriodicMaintenance()
        let tick = captured.values.joined(separator: "\n")
        XCTAssertTrue(tick.contains("shedHardCap=20"), tick)
        XCTAssertTrue(
            tick.contains("shedApps=com.example.noisy=10,com.example.quiet=10"),
            "attribution for the demoted lines rides the tick: \(tick)")

        // A new window re-opens the budget.
        let later = NSObject()
        guard case .reject(_, _, let persistAgain) = core.testAdmitTcpStart(
            flowId: ObjectIdentifier(later), meta: meta())
        else {
            XCTFail("still at the cap")
            return
        }
        XCTAssertTrue(persistAgain, "the persist budget resets with the tick window")
    }

    func testMaintenanceTelemetryIsPersistedAndIncludesOverloadFields() {
        defaultTcpStartInFlightHardCap = 10
        let core = TransparentProxyCore()
        let captured = CapturedNotices()
        LifecycleLog.noticeOverride = { captured.append($0) }

        let token = admittedToken(core, NSObject(), bundleId: "com.example.browser")
        core.testFinishTcpStart(token, outcome: .timeout)
        XCTAssertEqual(core.testTcpStartsInFlight, 0)

        core.testRunPeriodicMaintenance()

        let joined = captured.values.joined(separator: "\n")
        XCTAssertTrue(joined.contains("tproxy live-flow counts"))
        XCTAssertTrue(joined.contains("admissionRate="))
        XCTAssertTrue(joined.contains("timeoutRate="))
        XCTAssertTrue(joined.contains("startLatencyMs["))
        XCTAssertTrue(joined.contains("breaker="))
        XCTAssertTrue(joined.contains("hardCap=10"), "the cap the peak is measured against")
        XCTAssertTrue(joined.contains("shedHardCap=0"))
        XCTAssertTrue(joined.contains("shedBreaker=0"))
        XCTAssertTrue(joined.contains("shedLiveCapTcp=0"))
        XCTAssertTrue(joined.contains("shedLiveCapUdp=0"))
        XCTAssertTrue(joined.contains("shedApps=-"))
        XCTAssertTrue(
            joined.contains(
                "pressure[triggers=0 scans=0 skipped=0 selected=0 evicted=0 "
                    + "spared=0 canceled=0 expired=0 pending=0]"
            ))
    }

    /// A burst that came within a few starts of the hard cap but shed nothing
    /// leaves no per-flow line behind. The tick's peak is the only trace, and
    /// it must survive the gauge having drained by the time the tick fires.
    func testTickReportsInFlightPeakAsTheNearMissSignal() {
        defaultTcpStartInFlightHardCap = 10
        let core = TransparentProxyCore()
        let captured = CapturedNotices()
        LifecycleLog.noticeOverride = { captured.append($0) }
        let objects = (0..<8).map { _ in NSObject() }
        let tokens = objects.map { admittedToken(core, $0) }
        for token in tokens.dropLast() { core.testFinishTcpStart(token, outcome: .ready) }
        XCTAssertEqual(core.testTcpStartsInFlight, 1)

        core.testRunPeriodicMaintenance()

        let joined = captured.values.joined(separator: "\n")
        XCTAssertTrue(joined.contains("tcpStartsInFlight=1 tcpStartsInFlightPeak=8"), joined)
    }

    /// Bundle ids are what a post-incident read needs first, and Apple logs
    /// them in the clear for every flow anyway: the tick's top-app summary
    /// must be in the message body, not in redacted metadata.
    func testTickTopAppsIsPublic() {
        defaultTcpStartInFlightHardCap = 10
        let core = TransparentProxyCore()
        let captured = CapturedNotices()
        LifecycleLog.noticeOverride = { captured.append($0) }
        let anchor = _TestTcpFlowSessionAnchor(ctx: TcpFlowContext())
        core.registerTcpFlow(ObjectIdentifier(anchor), anchor: anchor, appId: "com.example.chatty")

        core.testRunPeriodicMaintenance()

        XCTAssertTrue(
            captured.values.joined(separator: "\n").contains("topApps=com.example.chatty=1"))
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

        _ = admittedToken(core, first)
        XCTAssertEqual(
            core.testTcpConnectTimeoutMs(base: 10_000), 5_000,
            "soft-cap pressure clamps long connect timeouts")

        _ = admittedToken(core, second)
        core.testInsertTcpStartLatencyMs(5)
        XCTAssertTrue(core.testTcpOverloadBreakerOpen)

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
            preconditionFailure("admission helper called when admission was rejected")
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
