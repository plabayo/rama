import CryptoKit
import Darwin
import Foundation
import XCTest

@testable import RamaAppleNetworkExtension

/// Opt-in component benchmark: production promoted pumps and native TCP on
/// loopback, with a synthetic NE flow. No signed provider, TLS or Rust relay.
final class PayloadViewBenchmarkTests: XCTestCase {
    func testPayloadViewTransferMatrix() throws {
        let env = ProcessInfo.processInfo.environment
        guard env["RAMA_PVMB_BENCH"] == "1" else { throw XCTSkip("opt-in payload view benchmark") }
        let kib = try XCTUnwrap(env["RAMA_PVMB_KIB"].flatMap(Int.init))
        let scenario = try XCTUnwrap(env["RAMA_PVMB_SCENARIO"])
        let upload = scenario.contains("upload")
        let slow = scenario.contains("slow")
        let flows = scenario.contains("concurrent") ? 8 : 1
        let mib = env["RAMA_PVMB_MIB"].flatMap(Int.init) ?? (slow ? 16 : (flows == 1 ? 512 : 64))
        let total = mib * 1024 * 1024 + 19
        // The same source and digest work for every view size. Input read callbacks
        // are fixed at 256 KiB; the benchmark never makes them follow the knob.
        let block = UploadPattern.data(offset: 0, count: 1024 * 1024)
        var digest = SHA256()
        for _ in 0..<mib { digest.update(data: block) }
        digest.update(data: block.prefix(19))
        let expected = Data(digest.finalize())
        // A small diagnostic envelope intentionally exercises failure reporting;
        // the comparison runner leaves this unset (64 MiB in every measured case).
        let budgetMiB = env["RAMA_PVMB_BUDGET_MIB"].flatMap(Int.init) ?? 64
        let budget = WriterMemoryBudget(policy: WriterMemoryPolicy(
            maxBytes: budgetMiB * 1024 * 1024, maxItems: 65_536,
            tcpWaiterMaxBytes: 256 * 1024, tcpPayloadViewMaxBytes: kib * 1024))
        let doneAt = Locked<[UInt64]>([])
        var peers: [ScriptedPeer] = []
        var harnesses: [NativeForwarderHarness] = []
        var clients: [PayloadBenchmarkFlow] = []
        var milestones: [Milestones] = []
        let peerDigests = Locked<[Data]>([])
        defer {
            for h in harnesses { h.cleanup() }
            for p in peers { p.stop() }
        }
        for _ in 0..<flows {
            let marks = Milestones()
            let peer = try ScriptedPeer(milestones: marks) { peer in
                if upload {
                    var received = SHA256()
                    let count = try peer.readToEnd(
                        into: &received, chunk: 65536, bytesPerSecond: slow ? 32 * 1048576 : nil)
                    if count != total { marks.fail("peer count \(count) != \(total)") }
                    peerDigests.withLock { $0.append(Data(received.finalize())) }
                    doneAt.withLock { $0.append(DispatchTime.now().uptimeNanoseconds) }
                } else {
                    for _ in 0..<mib { try peer.send(block) }
                    try peer.send(Data(block.prefix(19)))
                    var empty = SHA256()
                    let count = try peer.readToEnd(into: &empty)
                    if count != 0 { marks.fail("unexpected upload \(count)") }
                }
                try peer.shutdownWrite()
                marks.reach("peer done")
            }
            let flow = PayloadBenchmarkFlow(
                block: block, total: upload ? total : 0,
                expectedDownload: upload ? 0 : total, slow: slow && !upload,
                onDownloaded: { doneAt.withLock { $0.append(DispatchTime.now().uptimeNanoseconds) } })
            let h = try NativeForwarderHarness(
                port: peer.port, flow: flow, milestones: marks,
                cap: 256 * 1024, budget: budget)
            peers.append(peer); harnesses.append(h); clients.append(flow); milestones.append(marks)
        }
        let pingMarks = Milestones()
        let pingPeer = try ScriptedPeer(milestones: pingMarks) { peer in
            try peer.echoUntilEOF()
            try peer.shutdownWrite()
            pingMarks.reach("peer done")
        }
        let pingFlow = PayloadBenchmarkPingFlow()
        let ping = try NativeForwarderHarness(
            port: pingPeer.port, flow: pingFlow, milestones: pingMarks,
            cap: 256 * 1024, budget: budget)
        defer { ping.cleanup(); pingPeer.stop() }
        XCTAssertTrue(pingMarks.expect("ready", timeout: 10))
        for marks in milestones { XCTAssertTrue(marks.expect("ready", timeout: 10)) }
        let sampler = PayloadBenchmarkSampler(budget: budget)
        let cpuStart = Self.cpuSeconds()
        let start = DispatchTime.now().uptimeNanoseconds
        sampler.start()
        ping.client.markOpened(); ping.startForwarding()
        for h in harnesses { h.client.markOpened(); h.startForwarding() }
        // XCTest symbolicates assertion failures using the linked Rust debug
        // archive; that alone can add GiB of RSS. End measurement before any
        // assertion/reporting so failure-path RSS still describes the workload.
        let completed = milestones.map { $0.waitFor(["terminal", "peer done"], timeout: 90) }
        let cpu = Self.cpuSeconds() - cpuStart
        pingFlow.stop()
        let pingCompleted = pingMarks.waitFor(["terminal", "peer done"], timeout: 10)
        let samples = sampler.stop()
        let ends = doneAt.withLock { $0 }.sorted()
        guard completed.allSatisfy({ $0 }) && ends.count == flows && pingCompleted else {
            let failure: [String: Any] = [
                "scenario": scenario, "kib": kib, "completed_flows": ends.count,
                "retained_peak_bytes": samples.retained, "rss_peak_bytes": samples.peak,
                "errors": milestones.flatMap { $0.failures } + pingMarks.failures,
                "completed": completed, "ping_completed": pingCompleted,
                "rss_excludes_failure_reporting": true,
                "pause_checks": harnesses.map { $0.pauseChecks.withLock { $0 } },
            ]
            let json = try JSONSerialization.data(withJSONObject: failure, options: [.sortedKeys])
            print("PVMB_FAILURE " + String(decoding: json, as: UTF8.self))
            throw PeerError("incomplete benchmark transfer; see PVMB_FAILURE")
        }
        XCTAssertTrue(pingFlow.intact)
        for d in peerDigests.withLock({ $0 }) { XCTAssertEqual(d, expected) }
        if !upload {
            for flow in clients {
                XCTAssertEqual(flow.downloadCount, total)
                XCTAssertEqual(flow.downloadDigest, expected)
            }
        }
        let elapsed = Double((ends.last ?? start) - start) / 1e9
        let durations = ends.map { Double($0 - start) / 1e6 }
        let writeCounts = clients.map { $0.writeCount }
        let report: [String: Any] = [
            "kib": kib, "scenario": scenario, "flows": flows, "bytes": total * flows,
            "seconds": elapsed, "mib_per_second": Double(total * flows) / 1048576 / elapsed,
            "cpu_seconds": cpu, "cpu_percent": cpu / elapsed * 100,
            "rss_start_bytes": samples.baseline, "rss_peak_bytes": samples.peak,
            "rss_delta_bytes": max(0, samples.peak - samples.baseline),
            "retained_peak_bytes": samples.retained, "flow_completion_ms": durations,
            "client_write_calls": writeCounts,
            "pause_checks": harnesses.map { $0.pauseChecks.withLock { $0 } },
            "first_client_write_ms": clients.compactMap { f -> Double? in
                guard let first = f.firstWrite else { return nil }
                return Double(first - start) / 1e6
            },
            "ping_rtt_ms": pingFlow.latencies,
            "verified": true,
        ]
        let json = try JSONSerialization.data(withJSONObject: report, options: [.sortedKeys])
        print("PVMB_RESULT " + String(decoding: json, as: UTF8.self))
    }

    private static func cpuSeconds() -> Double {
        var usage = rusage()
        getrusage(RUSAGE_SELF, &usage)
        return Double(usage.ru_utime.tv_sec + usage.ru_stime.tv_sec)
            + Double(usage.ru_utime.tv_usec + usage.ru_stime.tv_usec) / 1e6
    }
}

private final class PayloadBenchmarkFlow: TcpFlowReadable, TcpFlowWritable, @unchecked Sendable {
    private let queue = DispatchQueue(label: "rama.pvmb.client", autoreleaseFrequency: .workItem)
    private let block: Data
    private let total: Int
    private let expectedDownload: Int
    private let slow: Bool
    private let onDownloaded: @Sendable () -> Void
    private var offset = 0
    private var received = 0
    private var digest = SHA256()
    private var writes = 0
    private var first: UInt64?
    private var slowStart: UInt64?

    init(block: Data, total: Int, expectedDownload: Int, slow: Bool,
         onDownloaded: @escaping @Sendable () -> Void) {
        self.block = block; self.total = total; self.expectedDownload = expectedDownload
        self.slow = slow; self.onDownloaded = onDownloaded
    }
    func readData(completionHandler: @escaping @Sendable (Data?, Error?) -> Void) {
        queue.async {
            guard self.offset < self.total else { completionHandler(nil, nil); return }
            let index = self.offset % self.block.count
            let count = min(256 * 1024, self.total - self.offset, self.block.count - index)
            let data = self.block.subdata(in: index..<(index + count))
            self.offset += count
            completionHandler(data, nil)
        }
    }
    func write(_ data: Data, withCompletionHandler completion: @escaping @Sendable (Error?) -> Void) {
        queue.async {
            if self.first == nil { self.first = DispatchTime.now().uptimeNanoseconds }
            self.writes += 1
            self.digest.update(data: data)
            self.received += data.count
            let finish: @Sendable () -> Void = {
                if self.received == self.expectedDownload { self.onDownloaded() }
                completion(nil)
            }
            if self.slow {
                // Byte-proportional pacing, independent of the view size (32 MiB/s).
                let now = DispatchTime.now().uptimeNanoseconds
                if self.slowStart == nil { self.slowStart = now }
                let due = self.slowStart! + UInt64(Double(self.received) / (32 * 1048576) * 1e9)
                self.queue.asyncAfter(deadline: DispatchTime(uptimeNanoseconds: max(now, due)), execute: finish)
            } else { finish() }
        }
    }
    var downloadCount: Int { queue.sync { received } }
    var downloadDigest: Data { queue.sync { Data(digest.finalize()) } }
    var writeCount: Int { queue.sync { writes } }
    var firstWrite: UInt64? { queue.sync { first } }
}

private final class PayloadBenchmarkSampler: @unchecked Sendable {
    struct Samples { var baseline: UInt64; var peak: UInt64; var retained: Int = 0 }
    private let queue = DispatchQueue(label: "rama.pvmb.sampler")
    private let timer: DispatchSourceTimer
    private let budget: WriterMemoryBudget
    private var samples = Samples(baseline: 0, peak: 0)
    init(budget: WriterMemoryBudget) {
        self.budget = budget
        timer = DispatchSource.makeTimerSource(queue: queue)
    }
    func start() {
        let baseline = Self.rss()
        samples = Samples(baseline: baseline, peak: baseline)
        timer.setEventHandler { [self] in
            samples.peak = max(samples.peak, Self.rss())
            samples.retained = max(samples.retained, budget.snapshot().retainedBytes)
        }
        timer.schedule(deadline: .now(), repeating: .milliseconds(1))
        timer.resume()
    }
    func stop() -> Samples {
        timer.cancel()
        return queue.sync {
            timer.setEventHandler {}
            return samples
        }
    }
    private static func rss() -> UInt64 {
        var info = mach_task_basic_info()
        var count = mach_msg_type_number_t(MemoryLayout<mach_task_basic_info>.size / MemoryLayout<integer_t>.size)
        let status = withUnsafeMutablePointer(to: &info) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(MACH_TASK_BASIC_INFO), $0, &count)
            }
        }
        precondition(status == KERN_SUCCESS)
        return info.resident_size
    }
}

/// One 1 KiB echo at a time through another production forwarder sharing the
/// aggregate budget. Measure application RTT under bulk load, excluding connect.
private final class PayloadBenchmarkPingFlow: TcpFlowReadable, TcpFlowWritable, @unchecked Sendable {
    private let queue = DispatchQueue(label: "rama.pvmb.ping")
    private var pending: (@Sendable (Data?, Error?) -> Void)?
    private var inFlight = false
    private var stopped = false
    private var sentAt: UInt64 = 0
    private var response = Data()
    private var samples: [Double] = []
    private var valid = true
    private var sequence: UInt8 = 0
    func readData(completionHandler: @escaping @Sendable (Data?, Error?) -> Void) {
        queue.async { self.pending = completionHandler; self.issue() }
    }
    private func issue() {
        guard !inFlight, let callback = pending else { return }
        pending = nil
        if stopped { callback(nil, nil); return }
        inFlight = true
        sentAt = DispatchTime.now().uptimeNanoseconds
        callback(Data(repeating: sequence, count: 1024), nil)
    }
    func write(_ data: Data, withCompletionHandler completion: @escaping @Sendable (Error?) -> Void) {
        queue.async {
            self.response.append(data)
            if self.response.count >= 1024 {
                self.valid = self.valid && self.response == Data(repeating: self.sequence, count: 1024)
                self.samples.append(Double(DispatchTime.now().uptimeNanoseconds - self.sentAt) / 1e6)
                self.response.removeAll(keepingCapacity: true)
                self.sequence &+= 1
                self.inFlight = false
                self.queue.asyncAfter(deadline: .now() + .milliseconds(1)) { self.issue() }
            }
            completion(nil)
        }
    }
    func stop() { queue.async { self.stopped = true; self.issue() } }
    var latencies: [Double] { queue.sync { samples } }
    var intact: Bool { queue.sync { valid && response.isEmpty } }
}
