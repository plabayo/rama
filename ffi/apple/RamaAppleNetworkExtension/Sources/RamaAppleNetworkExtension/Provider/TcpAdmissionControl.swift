import Foundation

struct TcpAdmissionToken: Sendable {
    let flowId: ObjectIdentifier
    let startedAt: DispatchTime
    let appId: String
}

enum TcpAdmissionDecision {
    case admit(TcpAdmissionToken)
    case reject(reason: String, appId: String)
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
    var p50StartMs: UInt64
    var p95StartMs: UInt64
    var p99StartMs: UInt64
    var breakerOpen: Bool
}

struct TcpOverloadState {
    var startsInFlight: [ObjectIdentifier: TcpAdmissionToken] = [:]
    var flowApps: [ObjectIdentifier: String] = [:]
    var perAppFlowCounts: [String: Int] = [:]
    var startLatencyMsWindow: [UInt64] = []
    var admissionsSinceTick = 0
    var timeoutsSinceTick = 0
    var shedsSinceTick = 0
    var breakerOpen = false

    mutating func appId(for meta: RamaTransparentProxyFlowMetaBridge) -> String {
        meta.sourceAppBundleIdentifier
            ?? meta.sourceAppSigningIdentifier
            ?? meta.sourceAppPid.map { "pid:\($0)" }
            ?? "pid:unknown"
    }

    mutating func insertLatency(_ latencyMs: UInt64) {
        startLatencyMsWindow.append(latencyMs)
        if startLatencyMsWindow.count > 128 {
            startLatencyMsWindow.removeFirst(startLatencyMsWindow.count - 128)
        }
    }

    func percentile(_ percentile: Double) -> UInt64 {
        guard !startLatencyMsWindow.isEmpty else { return 0 }
        let sorted = startLatencyMsWindow.sorted()
        let rawIndex = Int((Double(sorted.count - 1) * percentile).rounded(.up))
        return sorted[min(max(rawIndex, 0), sorted.count - 1)]
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
        let snapshot = TcpOverloadSnapshot(
            admissionRate: Double(admissionsSinceTick) / seconds,
            timeoutRate: Double(timeoutsSinceTick) / seconds,
            shedRate: Double(shedsSinceTick) / seconds,
            startsInFlight: startsInFlight.count,
            p50StartMs: percentile(0.50),
            p95StartMs: percentile(0.95),
            p99StartMs: percentile(0.99),
            breakerOpen: breakerOpen
        )
        admissionsSinceTick = 0
        timeoutsSinceTick = 0
        shedsSinceTick = 0
        return snapshot
    }
}
