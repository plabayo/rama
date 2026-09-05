import Foundation

struct TcpAdmissionIdentity: Hashable, Sendable {
    let engineGeneration: UInt64
    let nonce: UInt64
}

struct TcpAdmissionToken: Sendable {
    let identity: TcpAdmissionIdentity
    let flowId: ObjectIdentifier
    let startedAt: DispatchTime
    let appId: String
}

enum TcpAdmissionDecision {
    case admit(TcpAdmissionToken)
    /// `persist`: whether the per-flow refusal line may go to the
    /// persisted lifecycle log. Only the first few refusals of each
    /// tick window do; the rest log at debug and are carried by the
    /// tick's counters. A refusal storm otherwise trips logd's
    /// per-process rate limit on persisted messages, which then
    /// drops the ticks and episode summaries too — observed on
    /// device: ~6,600 lines in 90s silenced the lifecycle category
    /// for well over ten minutes while the burst that mattered ran.
    case reject(reason: String, appId: String, persist: Bool)
}

enum TcpStartOutcome {
    case ready
    case timeout
    case failed
}

struct TcpOverloadSnapshot {
    var admissionRate: Double
    var timeoutRate: Double
    var shedRate: Double
    var startsInFlight: Int
    /// High-water mark of `startsInFlight` within the tick window — the
    /// near-miss signal a bundle needs when nothing was actually shed.
    var startsInFlightPeak: Int
    var shedHardCap: Int
    var shedBreaker: Int
    var shedLiveCapTcp: Int
    var shedLiveCapUdp: Int
    var p50StartMs: UInt64
    var p95StartMs: UInt64
    var p99StartMs: UInt64
    var breakerOpen: Bool
}

struct TcpOverloadState {
    private static let startLatencyWindowCapacity = 128

    var startsInFlight: [ObjectIdentifier: TcpAdmissionToken] = [:]
    /// TCP starts admitted but not yet inserted into the live-flow registry.
    /// Counted by the combined hard cap so UDP cannot race through the gap.
    /// The operation identity, rather than the reusable object address alone,
    /// prevents delayed completion from consuming a replacement admission.
    var liveFlowReservations: [ObjectIdentifier: TcpAdmissionIdentity] = [:]
    var flowApps: [ObjectIdentifier: String] = [:]
    var perAppFlowCounts: [String: Int] = [:]
    private(set) var startLatencyMsWindow: [UInt64] = []
    /// A sorted view of the same bounded samples. It is updated only when a
    /// completion inserts a latency, keeping admission-time breaker checks
    /// O(1) even when a refusal storm repeatedly evaluates the same window.
    private var sortedStartLatencyMsWindow: [UInt64] = []
    #if DEBUG || RAMA_TESTING
        /// Test-only proof that percentile reads do not rebuild the cache.
        private(set) var startLatencyCacheRefreshCount = 0
    #endif
    var admissionsSinceTick = 0
    var timeoutsSinceTick = 0
    var shedsSinceTick = 0
    var shedHardCapSinceTick = 0
    var shedBreakerSinceTick = 0
    var shedLiveCapTcpSinceTick = 0
    var shedLiveCapUdpSinceTick = 0
    var shedsByAppSinceTick: [String: Int] = [:]
    var startsInFlightPeakSinceTick = 0
    var breakerOpen = false

    /// Per-flow refusal lines allowed into the persisted log per tick
    /// window; see `TcpAdmissionDecision.reject(persist:)`.
    static let persistedShedLinesPerTick = 8

    mutating func appId(for meta: RamaTransparentProxyFlowMetaBridge) -> String {
        meta.sourceAppBundleIdentifier
            ?? meta.sourceAppSigningIdentifier
            ?? meta.sourceAppPid.map { "pid:\($0)" }
            ?? "pid:unknown"
    }

    mutating func insertLatency(_ latencyMs: UInt64) {
        let evicted =
            startLatencyMsWindow.count == Self.startLatencyWindowCapacity
            ? startLatencyMsWindow.removeFirst()
            : nil
        startLatencyMsWindow.append(latencyMs)

        if let evicted {
            let index = Self.lowerBound(of: evicted, in: sortedStartLatencyMsWindow)
            precondition(
                index < sortedStartLatencyMsWindow.count
                    && sortedStartLatencyMsWindow[index] == evicted,
                "latency window and sorted cache diverged")
            sortedStartLatencyMsWindow.remove(at: index)
        }

        let insertionIndex = Self.lowerBound(of: latencyMs, in: sortedStartLatencyMsWindow)
        sortedStartLatencyMsWindow.insert(latencyMs, at: insertionIndex)
        #if DEBUG || RAMA_TESTING
            startLatencyCacheRefreshCount += 1
        #endif
    }

    /// Over COMPLETED starts only. Pending starts are deliberately NOT
    /// folded in as censored samples: a slow start is pending longer, so
    /// the in-flight set over-represents the slow tail, and a healthy
    /// load with a ~1% dead-destination tail then trips a p95 rule on
    /// most at-soft-cap admissions. A genuine stall still reaches this
    /// window through its connect timeouts (≤ one pressure clamp), and
    /// under fail-open the hard cap already sheds in the meantime.
    func percentile(_ percentile: Double) -> UInt64 {
        guard !sortedStartLatencyMsWindow.isEmpty else { return 0 }
        let rawIndex = Int(
            (Double(sortedStartLatencyMsWindow.count - 1) * percentile).rounded(.up))
        let index = min(max(rawIndex, 0), sortedStartLatencyMsWindow.count - 1)
        return sortedStartLatencyMsWindow[index]
    }

    private static func lowerBound(of value: UInt64, in sorted: [UInt64]) -> Int {
        var lower = 0
        var upper = sorted.count
        while lower < upper {
            let middle = lower + (upper - lower) / 2
            if sorted[middle] < value {
                lower = middle + 1
            } else {
                upper = middle
            }
        }
        return lower
    }

    /// Top refusing apps this tick window — attribution for the sheds
    /// whose per-flow lines were not persisted.
    func topShedAppSummary(limit: Int = 3) -> String {
        shedsByAppSinceTick
            .sorted { lhs, rhs in
                if lhs.value == rhs.value { return lhs.key < rhs.key }
                return lhs.value > rhs.value
            }
            .prefix(limit)
            .map { "\($0.key)=\($0.value)" }
            .joined(separator: ",")
    }

    func topAppSummary(limit: Int = 3) -> String {
        perAppFlowCounts
            .filter { $0.value > 0 }
            .sorted { lhs, rhs in
                if lhs.value == rhs.value { return lhs.key < rhs.key }
                return lhs.value > rhs.value
            }
            .prefix(limit)
            .map { "\($0.key)=\($0.value)" }
            .joined(separator: ",")
    }

    mutating func snapshotAndResetRates(intervalSeconds: Double) -> TcpOverloadSnapshot {
        let seconds = max(intervalSeconds, 1.0)
        // All three values index the same already-sorted cache. Do not call
        // `sorted()` independently here: this tick runs during overload too.
        let latencyPercentiles = (
            p50: percentile(0.50),
            p95: percentile(0.95),
            p99: percentile(0.99)
        )
        let snapshot = TcpOverloadSnapshot(
            admissionRate: Double(admissionsSinceTick) / seconds,
            timeoutRate: Double(timeoutsSinceTick) / seconds,
            shedRate: Double(shedsSinceTick) / seconds,
            startsInFlight: startsInFlight.count,
            startsInFlightPeak: max(startsInFlightPeakSinceTick, startsInFlight.count),
            shedHardCap: shedHardCapSinceTick,
            shedBreaker: shedBreakerSinceTick,
            shedLiveCapTcp: shedLiveCapTcpSinceTick,
            shedLiveCapUdp: shedLiveCapUdpSinceTick,
            p50StartMs: latencyPercentiles.p50,
            p95StartMs: latencyPercentiles.p95,
            p99StartMs: latencyPercentiles.p99,
            breakerOpen: breakerOpen
        )
        admissionsSinceTick = 0
        timeoutsSinceTick = 0
        shedsSinceTick = 0
        shedHardCapSinceTick = 0
        shedBreakerSinceTick = 0
        shedLiveCapTcpSinceTick = 0
        shedLiveCapUdpSinceTick = 0
        shedsByAppSinceTick.removeAll(keepingCapacity: true)
        startsInFlightPeakSinceTick = startsInFlight.count
        return snapshot
    }
}
