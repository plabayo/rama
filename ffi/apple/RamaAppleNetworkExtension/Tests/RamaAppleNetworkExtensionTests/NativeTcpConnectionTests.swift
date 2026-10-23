import Darwin
import Foundation
import Network
import OSLog
import RamaAppleNEFFI
import RamaAppleNetwork
import XCTest

@testable import RamaAppleNetworkExtension

final class NativeTcpConnectionTests: XCTestCase {
    private func assertNoCancellationErrors(_ store: OSLogStore, since position: OSLogPosition)
        throws
    {
        // Native cancellation diagnostics are emitted asynchronously.
        Thread.sleep(forTimeInterval: 0.5)
        let errors = try store.getEntries(at: position).compactMap {
            ($0 as? OSLogEntryLog)?.composedMessage
        }
        .filter { $0.contains("already cancelled") || $0.contains("handler after cancel") }
        XCTAssertTrue(errors.isEmpty, errors.joined(separator: "\n"))
    }

    private func noProxy(_ parameters: nw_parameters_t) throws -> Bool {
        let symbol = try XCTUnwrap(
            dlsym(UnsafeMutableRawPointer(bitPattern: -2), "nw_parameters_get_no_proxy"))
        return unsafeBitCast(symbol, to: (@convention(c) (nw_parameters_t) -> Bool).self)(
            parameters)
    }

    func testPolicyAndCopyAndAllowAfterDeny() throws {
        #if !PrivateNetworkProxyControl
            XCTAssertNil(TcpProxyControl.system.setter)
            let publicOnly = makeTcpNwParameters(nil)
            XCTAssertEqual(publicOnly.proxyPolicy, .preferDirectOnly)
            XCTAssertTrue(nw_parameters_get_prefer_no_proxy(publicOnly.native))
            return
        #else
            guard TcpProxyControl.system.setter != nil else {
                throw XCTSkip("private no-proxy symbol unavailable")
            }
            let params = makeTcpNwParameters(nil)
            XCTAssertEqual(params.proxyPolicy, .noProxyApplied)
            XCTAssertTrue(try noProxy(params.native))
            XCTAssertTrue(try noProxy(nw_parameters_copy(params.native)))
            XCTAssertTrue(nw_parameters_get_prefer_no_proxy(params.native))
            XCTAssertEqual(
                TcpProxyControl.system.apply(to: params.native, allowProxy: true), .allowed)
            XCTAssertFalse(try noProxy(params.native))
            XCTAssertFalse(nw_parameters_get_prefer_no_proxy(params.native))
        #endif
    }

    func testUnavailableSymbolAndMetadataOrder() throws {
        var stamped: nw_parameters_t?
        let params = makeTcpNwParameters(nil, proxyControl: TcpProxyControl(setter: nil)) {
            native in
            stamped = native
            nw_parameters_set_prefer_no_proxy(native, false)
        }
        XCTAssertTrue(stamped === params.native)
        XCTAssertEqual(params.proxyPolicy, .preferDirectOnly)
        XCTAssertTrue(
            nw_parameters_get_prefer_no_proxy(params.native), "policy applied after metadata")
        XCTAssertEqual(
            TcpProxyControl(setter: nil).apply(to: params.native, allowProxy: true), .allowed)
        XCTAssertFalse(nw_parameters_get_prefer_no_proxy(params.native))
        var opts = RamaTcpEgressConnectOptions()
        opts.parameters.preserve_original_meta_data = false
        _ = makeTcpNwParameters(opts) { _ in XCTFail("metadata explicitly disabled") }
    }

    func testCommonParametersAndInvalidValues() {
        var opts = RamaTcpEgressConnectOptions()
        opts.parameters.has_service_class = true
        opts.parameters.service_class = 4
        opts.parameters.has_multipath_service_type = true
        opts.parameters.multipath_service_type = 1
        opts.parameters.has_required_interface_type = true
        opts.parameters.required_interface_type = 3
        opts.parameters.prohibited_interface_types_mask = 0b10011
        opts.parameters.has_attribution = true
        opts.parameters.attribution = 1
        let p = makeTcpNwParameters(opts).native
        XCTAssertEqual(nw_parameters_get_service_class(p), nw_service_class_responsive_data)
        XCTAssertEqual(nw_parameters_get_multipath_service(p), nw_multipath_service_handover)
        XCTAssertEqual(nw_parameters_get_required_interface_type(p), nw_interface_type_wifi)
        XCTAssertEqual(nw_parameters_get_attribution(p), .user)
        var prohibited: Set<UInt32> = []
        nw_parameters_iterate_prohibited_interface_types(p) {
            prohibited.insert($0.rawValue)
            return true
        }
        XCTAssertEqual(
            prohibited,
            [
                nw_interface_type_cellular.rawValue, nw_interface_type_loopback.rawValue,
                nw_interface_type_wired.rawValue,
            ])
        opts.parameters.service_class = 255
        opts.parameters.multipath_service_type = 255
        opts.parameters.required_interface_type = 255
        let invalid = makeTcpNwParameters(opts).native
        XCTAssertEqual(nw_parameters_get_service_class(invalid), nw_service_class_best_effort)
        XCTAssertEqual(nw_parameters_get_multipath_service(invalid), nw_multipath_service_disabled)
        XCTAssertEqual(nw_parameters_get_required_interface_type(invalid), nw_interface_type_other)
    }

    func testDirectBulkTransferHalfCloseAndReport() throws {
        let server = try EchoServer(proxy: false)
        defer { server.cancel() }
        try exchange(
            host: "127.0.0.1", port: server.port, parameters: makeTcpNwParameters(nil).native,
            usedProxy: false)
    }

    func testIPv6BulkTransferAndHalfClose() throws {
        let server = try EchoServer(proxy: false, ipv6: true)
        defer { server.cancel() }
        try exchange(
            host: "::1", port: server.port, parameters: makeTcpNwParameters(nil).native,
            usedProxy: false)
    }

    // The send completion fires before Network.framework stops reading the
    // payload. Slices are dropped at completion, as the write pump does, over
    // roots that are poisoned once freed: a borrowed view sends garbage.
    func testPayloadSlicesOutliveTheirSendCompletion() throws {
        let server = try EchoServer(proxy: false)
        defer { server.cancel() }
        let connection = try XCTUnwrap(
            NativeTcpConnection(
                host: "127.0.0.1", port: server.port, parameters: makeTcpNwParameters(nil).native))
        let callbacks = DispatchGroup()
        defer {
            connection.cancelAndDetach()
            XCTAssertEqual(callbacks.wait(timeout: .now() + 5), .success)
        }
        let queue = DispatchQueue(label: "rama.test.slices")
        let ready = expectation(description: "ready")
        let readied = Locked(false)
        connection.stateUpdateHandler = { state in
            if case .ready = state, !readied.withLock({ $0 }) {
                readied.withLock { $0 = true }
                ready.fulfill()
            }
        }
        connection.start(queue: queue)
        wait(for: [ready], timeout: 10)

        let chunk = 16 * 1024
        let chunks = 512
        let pattern: @Sendable (Int) -> UInt8 = { UInt8(truncatingIfNeeded: $0 % 251) }
        let budget = WriterMemoryBudget()
        @Sendable func makeSlice(_ index: Int) -> TcpPayloadSlice {
            let pointer = UnsafeMutableRawPointer.allocate(
                byteCount: chunk, alignment: MemoryLayout<UInt8>.alignment)
            pointer.initializeMemory(as: UInt8.self, repeating: pattern(index), count: chunk)
            let data = Data(
                bytesNoCopy: pointer, count: chunk,
                deallocator: .custom { pointer, count in
                    pointer.initializeMemory(as: UInt8.self, repeating: 0xEE, count: count)
                    pointer.deallocate()
                })
            XCTAssertTrue(budget.tryReserve(bytes: chunk))
            return budget.makePregrantedWriterPayload(data)
        }

        let errors = Locked<[String]>([])
        let sent = expectation(description: "all sends completed")
        @Sendable func send(_ index: Int) {
            guard index < chunks else {
                callbacks.enter()
                connection.send(
                    content: nil, contentContext: .finalMessage, isComplete: true,
                    completion: .contentProcessed { error in
                        defer { callbacks.leave() }
                        if let error { errors.withLock { $0.append("fin: \(error)") } }
                        sent.fulfill()
                    })
                return
            }
            // One write in flight; the slice dies with this scope at completion.
            let slice = makeSlice(index)
            callbacks.enter()
            connection.send(
                content: slice.data, contentContext: .defaultMessage, isComplete: true,
                completion: .contentProcessed { [slice] error in
                    defer {
                        withExtendedLifetime(slice) {}
                        callbacks.leave()
                    }
                    if let error { errors.withLock { $0.append("send \(index): \(error)") } }
                    send(index + 1)
                })
        }

        let received = Locked(Data())
        let eof = expectation(description: "echo after FIN")
        @Sendable func read() {
            callbacks.enter()
            connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) {
                data, _, complete, error in
                defer { callbacks.leave() }
                if let error { errors.withLock { $0.append("receive: \(error)") } }
                if let data { received.withLock { $0.append(data) } }
                if complete || error != nil { eof.fulfill() } else { read() }
            }
        }
        read()
        queue.async { send(0) }
        wait(for: [sent, eof], timeout: 60)

        XCTAssertTrue(
            errors.withLock { $0.isEmpty }, errors.withLock { $0.joined(separator: "\n") })
        let echoed = received.withLock { $0 }
        XCTAssertEqual(echoed.count, chunk * chunks)
        let firstMismatch = echoed.withUnsafeBytes { bytes in
            (0..<bytes.count).first { bytes[$0] != pattern($0 / chunk) }
        }
        XCTAssertNil(firstMismatch, "payload bytes changed after their send completion")
        XCTAssertEqual(budget.snapshot().retainedBytes, 0)
    }

    // nw_connection can report `.failed` while a receive is still in flight, so the read
    // pump lets that receive end the read rather than ending it at `.failed`. Pin what that
    // relies on, on the production connection: after a reset right behind a response tail,
    // the pending receive still completes (with the error), whichever comes first. Tails
    // stay small: macOS loopback can drop the reset behind a large unread send buffer.
    func testAPendingReceiveStillCompletesAfterAReset() throws {
        for size in [1, 1_000, 16 * 1024, 64 * 1024] {
            for round in 0..<5 {
                let order = try resetOrder(tailBytes: size)
                XCTAssertNotNil(order.firstIndex(of: "failed"), "no .failed: \(order) size=\(size)")
                XCTAssertNotNil(
                    order.firstIndex(of: "receive-error"),
                    "the pending receive never completed: \(order) size=\(size) #\(round)")
            }
        }
    }

    /// Events of one connection whose peer sends `tailBytes`, then resets.
    private func resetOrder(tailBytes: Int) throws -> [String] {
        let listener = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        XCTAssertGreaterThanOrEqual(listener, 0)
        defer { Darwin.close(listener) }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        try withUnsafeMutablePointer(to: &address) { pointer in
            try pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { raw in
                guard Darwin.bind(listener, raw, length) == 0, Darwin.listen(listener, 1) == 0,
                    Darwin.getsockname(listener, raw, &length) == 0
                else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
            }
        }
        let port = UInt16(bigEndian: address.sin_port)

        let accepted = DispatchSemaphore(value: 0)
        let receivePending = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            let peer = Darwin.accept(listener, nil, nil)
            accepted.signal()
            guard peer >= 0 else { return }
            // The client's receive is outstanding before anything arrives.
            _ = receivePending.wait(timeout: .now() + 5)
            usleep(50_000)
            let tail = [UInt8](repeating: 0x5A, count: tailBytes)
            var sent = 0
            while sent < tail.count {
                let n = tail.withUnsafeBytes { Darwin.send(peer, $0.baseAddress! + sent, tail.count - sent, 0) }
                if n <= 0 { break }
                sent += n
            }
            var linger = Darwin.linger(l_onoff: 1, l_linger: 0)
            Darwin.setsockopt(peer, SOL_SOCKET, SO_LINGER, &linger, socklen_t(MemoryLayout<Darwin.linger>.size))
            Darwin.close(peer)
        }

        let connection = try XCTUnwrap(
            NativeTcpConnection(
                host: "127.0.0.1", port: port, parameters: makeTcpNwParameters(nil).native))
        let queue = DispatchQueue(label: "rama.test.reset-order")
        let events = Locked<[String]>([])
        let ended = DispatchGroup()
        ended.enter()
        ended.enter()
        let failedOnce = Locked(false)
        connection.stateUpdateHandler = { state in
            switch state {
            case .ready:
                events.withLock { $0.append("ready") }
            case .failed:
                events.withLock { $0.append("failed") }
                if !failedOnce.withLock({ old in defer { old = true }; return old }) {
                    ended.leave()
                }
            default: break
            }
        }
        @Sendable func read() {
            connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) {
                data, _, complete, error in
                if let data, !data.isEmpty { events.withLock { $0.append("data") } }
                if error != nil {
                    events.withLock { $0.append("receive-error") }
                    ended.leave()
                } else if complete {
                    events.withLock { $0.append("eof") }
                    ended.leave()
                } else {
                    read()
                }
            }
        }
        connection.start(queue: queue)
        queue.async {
            read()
            receivePending.signal()
        }
        XCTAssertEqual(accepted.wait(timeout: .now() + 5), .success)
        XCTAssertEqual(ended.wait(timeout: .now() + 10), .success, "\(events.withLock { $0 })")
        connection.cancelAndDetach()
        return queue.sync { events.withLock { $0 } }
    }

    func testEchoServerDrainsCancelledSendCompletion() throws {
        let pending = Locked<(@Sendable (NWError?) -> Void)?>(nil)
        let queued = expectation(description: "echo send pending")
        let server = try EchoServer(proxy: false) { _, _, _, completion in
            pending.withLock { $0 = completion }
            queued.fulfill()
        }
        defer {
            server.beginCancellation()
            // Also release an injected completion if an earlier assertion or
            // unwrap fails, so the failure path cannot retain the fixture.
            let completion = pending.withLock { value in
                defer { value = nil }
                return value
            }
            completion?(.posix(.ECANCELED))
            server.cancel()
        }
        let connection = try XCTUnwrap(
            NativeTcpConnection(
                host: "127.0.0.1", port: server.port,
                parameters: makeTcpNwParameters(nil).native))
        defer { connection.cancelAndDetach() }
        connection.start(queue: DispatchQueue(label: "rama.test.pending-echo"))
        let sent = expectation(description: "client FIN sent")
        let sendError = Locked<NWError?>(nil)
        connection.send(
            content: nil, contentContext: .finalMessage, isComplete: true,
            completion: .contentProcessed { error in
                sendError.withLock { $0 = error }
                sent.fulfill()
            })
        wait(for: [queued, sent], timeout: 5)
        XCTAssertNil(sendError.withLock { $0 })
        let completion = try XCTUnwrap(
            pending.withLock { value in
                defer { value = nil }
                return value
            })
        // Force the ordering seen in CI: cancellation occurs while a final send
        // completion is still outstanding, then ECANCELED arrives asynchronously.
        server.beginCancellation()
        DispatchQueue.global().async { completion(.posix(.ECANCELED)) }
        server.cancel()
    }

    func testEchoServerDrainsPendingReceivesAndRepeatedCancellation() throws {
        for proxy in [false, true] {
            let server = try EchoServer(proxy: proxy)
            defer { server.cancel() }
            let connection = try XCTUnwrap(
                NativeTcpConnection(
                    host: "127.0.0.1", port: server.port,
                    parameters: makeTcpNwParameters(nil).native))
            defer { connection.cancelAndDetach() }
            let ready = expectation(description: "idle client ready")
            connection.stateUpdateHandler = { if case .ready = $0 { ready.fulfill() } }
            connection.start(queue: DispatchQueue(label: "rama.test.idle-echo"))
            wait(for: [ready], timeout: 5)
            XCTAssertEqual(server.receiveStarted.wait(timeout: .now() + 5), .success)
            // The peer may be waiting for either CONNECT or application data.
            server.cancel()
            server.cancel()
        }
    }

    func testReportCallbackSurvivesCancellationAndRelease() throws {
        let server = try EchoServer(proxy: false)
        defer { server.cancel() }
        var connection =
            try XCTUnwrap(
                NativeTcpConnection(
                    host: "127.0.0.1", port: server.port,
                    parameters: makeTcpNwParameters(nil).native)) as NativeTcpConnection?
        let ready = expectation(description: "ready")
        connection!.stateUpdateHandler = { if case .ready = $0 { ready.fulfill() } }
        let queue = DispatchQueue(label: "rama.test.late-report")
        connection!.start(queue: queue)
        wait(for: [ready], timeout: 5)
        let reported = expectation(description: "report callback after cancel")
        queue.suspend()
        connection!.requestTcpEstablishmentReport(queue: queue) { _ in reported.fulfill() }
        connection!.cancelAndDetach()
        connection = nil
        queue.resume()
        wait(for: [reported], timeout: 5)
    }

    func testRepeatedCancellationAndDetachment() throws {
        let store = try OSLogStore(scope: .currentProcessIdentifier)
        let position = store.position(date: Date())
        for force in [false, true] {
            var connection: NativeTcpConnection? = try XCTUnwrap(
                NativeTcpConnection(
                    host: "127.0.0.1", port: 9, parameters: makeTcpNwParameters(nil).native))
            let cancelled = expectation(description: "cancelled once")
            cancelled.assertForOverFulfill = true
            connection!.stateUpdateHandler = { if case .cancelled = $0 { cancelled.fulfill() } }
            connection!.start(queue: DispatchQueue(label: "rama.test.cancel"))
            if force { connection!.forceCancel() } else { connection!.cancel() }
            connection!.cancel()
            connection!.forceCancel()
            wait(for: [cancelled], timeout: 5)
            connection!.cancelAndDetach()
            connection!.forceCancelAndDetach()
            weak var released = connection
            connection = nil
            XCTAssertNil(released)
        }
        try assertNoCancellationErrors(store, since: position)
    }

    func testFrameworkCancellationAndConcurrentTeardown() throws {
        let store = try OSLogStore(scope: .currentProcessIdentifier)
        let position = store.position(date: Date())
        let connection = try XCTUnwrap(
            NativeTcpConnection(
                host: "127.0.0.1", port: 9, parameters: makeTcpNwParameters(nil).native))
        let cancelled = expectation(description: "framework cancelled")
        connection.stateUpdateHandler = { if case .cancelled = $0 { cancelled.fulfill() } }
        connection.start(queue: DispatchQueue(label: "rama.test.external-cancel"))
        nw_connection_cancel(connection.native)
        wait(for: [cancelled], timeout: 5)
        DispatchQueue.concurrentPerform(iterations: 64) { index in
            if index.isMultiple(of: 2) {
                connection.cancelAndDetach()
            } else {
                connection.forceCancelAndDetach()
            }
        }
        if case .cancelled = connection.state {} else { XCTFail("terminal state lost") }
        try assertNoCancellationErrors(store, since: position)
    }

    func testReleaseCancelsLiveConnection() throws {
        let store = try OSLogStore(scope: .currentProcessIdentifier)
        let position = store.position(date: Date())
        let server = try EchoServer(proxy: false)
        defer { server.cancel() }
        var connection: NativeTcpConnection? = try XCTUnwrap(
            NativeTcpConnection(
                host: "127.0.0.1", port: server.port, parameters: makeTcpNwParameters(nil).native))
        let ready = expectation(description: "ready")
        connection!.stateUpdateHandler = { if case .ready = $0 { ready.fulfill() } }
        connection!.start(queue: DispatchQueue(label: "rama.test.release"))
        wait(for: [ready], timeout: 5)
        let native = connection!.native
        let cancelled = expectation(description: "deinit cancels live native connection")
        nw_connection_set_state_changed_handler(native) { state, _ in
            if state == nw_connection_state_cancelled { cancelled.fulfill() }
        }
        weak var released = connection
        connection = nil
        XCTAssertNil(released)
        wait(for: [cancelled], timeout: 5)
        try assertNoCancellationErrors(store, since: position)
    }

    @available(macOS 14.0, *)
    private func proxiedParameters(
        port: UInt16, allow: Bool, missingSymbol: Bool = false, proxyHost: String = "127.0.0.1"
    )
        -> nw_parameters_t
    {
        let params = makeTcpNwParameters(nil).native
        let proxy = nw_proxy_config_create_http_connect(
            nw_endpoint_create_host(proxyHost, String(port)), nil)
        let privacy = nw_privacy_context_create("rama native TCP tests")
        nw_privacy_context_add_proxy(privacy, proxy)
        nw_parameters_set_privacy_context(params, privacy)
        // Reset the builder's policy before simulating a missing symbol.
        _ = TcpProxyControl.system.apply(to: params, allowProxy: true)
        _ = (missingSymbol ? TcpProxyControl(setter: nil) : .system).apply(
            to: params, allowProxy: allow)
        return params
    }

    func testExplicitProxyOptInAndPreferenceOnlyFallback() throws {
        guard #available(macOS 14.0, *) else {
            throw XCTSkip("proxy configuration requires macOS 14")
        }
        for missing in [false, true] {
            let server = try EchoServer(proxy: true)
            defer { server.cancel() }
            try exchange(
                host: "rama-egress-test.invalid", port: 443,
                parameters: proxiedParameters(
                    port: server.port, allow: !missing, missingSymbol: missing),
                usedProxy: true)
            XCTAssertEqual(server.contacts.withLock { $0 }, 1)
        }
    }

    func testIPv6ProxyEndpointFormatting() throws {
        guard #available(macOS 14.0, *) else {
            throw XCTSkip("proxy configuration requires macOS 14")
        }
        let server = try EchoServer(proxy: true, ipv6: true)
        defer { server.cancel() }
        try exchange(
            host: "rama-egress-test.invalid", port: 443,
            parameters: proxiedParameters(port: server.port, allow: true, proxyHost: "::1"),
            usedProxy: true, proxyEndpoint: "[::1]:\(server.port)")
    }

    func testNoProxyDoesNotFallBackAfterDnsFailure() throws {
        guard #available(macOS 14.0, *), TcpProxyControl.system.setter != nil else {
            throw XCTSkip("requires proxy configuration and private no-proxy symbol")
        }
        let server = try EchoServer(proxy: true)
        defer { server.cancel() }
        let connection = try XCTUnwrap(
            NativeTcpConnection(
                host: "rama-egress-test.invalid", port: 443,
                parameters: proxiedParameters(port: server.port, allow: false)))
        defer { connection.cancelAndDetach() }
        let failed = expectation(description: "direct DNS failure")
        let seen = Locked(false)
        let failures = Locked<[String]>([])
        connection.stateUpdateHandler = { state in
            switch state {
            case .ready: failures.withLock { $0.append("unexpected proxy fallback") }
            case .waiting(let error), .failed(let error):
                if !seen.withLock({ previous in
                    let old = previous
                    previous = true
                    return old
                }) {
                    if case .dns = error {
                    } else {
                        failures.withLock { $0.append("expected DNS failure, got \(error)") }
                    }
                    failed.fulfill()
                }
            default: break
            }
        }
        connection.start(queue: DispatchQueue(label: "rama.test.deny"))
        wait(for: [failed], timeout: 10)
        let reportRead = expectation(description: "failed establishment has no report")
        let reportValue = Locked<TcpEstablishmentReport?>(nil)
        connection.requestTcpEstablishmentReport(
            queue: DispatchQueue(label: "rama.test.failed-report")
        ) { report in
            reportValue.withLock { $0 = report }
            reportRead.fulfill()
        }
        wait(for: [reportRead], timeout: 5)
        XCTAssertNil(reportValue.withLock { $0 })
        let observed = expectation(description: "fallback observation window")
        DispatchQueue.global().asyncAfter(deadline: .now() + 2) { observed.fulfill() }
        wait(for: [observed], timeout: 3)
        XCTAssertEqual(server.contacts.withLock { $0 }, 0)
        XCTAssertTrue(
            failures.withLock { $0.isEmpty }, failures.withLock { $0.joined(separator: "\n") })
    }

    func testInvalidPortAndCancellation() throws {
        XCTAssertNil(
            NativeTcpConnection(
                host: "localhost", port: 0, parameters: makeTcpNwParameters(nil).native))
        let connection = try XCTUnwrap(
            NativeTcpConnection(
                host: "rama-egress-test.invalid", port: 443,
                parameters: makeTcpNwParameters(nil).native))
        let cancelled = expectation(description: "cancelled")
        connection.stateUpdateHandler = { if case .cancelled = $0 { cancelled.fulfill() } }
        connection.start(queue: DispatchQueue(label: "rama.test.cancel"))
        connection.forceCancel()
        wait(for: [cancelled], timeout: 5)
        if case .cancelled = connection.state {} else { XCTFail("state not updated") }
    }

    // Used by the opt-in developer PAC harness as well as the isolated tests.
    func testDeveloperSystemProxyScenario() throws {
        let env = ProcessInfo.processInfo.environment
        guard let host = env["RAMA_EGRESS_TEST_HOST"], let rawPort = env["RAMA_EGRESS_TEST_PORT"],
            let port = UInt16(rawPort)
        else { throw XCTSkip("developer PAC harness only") }
        let allow = env["RAMA_EGRESS_TEST_ALLOW_PROXY"] == "1"
        var opts = RamaTcpEgressConnectOptions()
        opts.parameters.allow_proxy = allow
        let missingSymbol = env["RAMA_EGRESS_TEST_MISSING_SYMBOL"] == "1"
        let parameters = makeTcpNwParameters(
            opts, proxyControl: missingSymbol ? TcpProxyControl(setter: nil) : .system)
        XCTAssertEqual(
            parameters.proxyPolicy,
            allow ? .allowed : (missingSymbol ? .preferDirectOnly : .noProxyApplied))
        if env["RAMA_EGRESS_TEST_EXPECT_FAILURE"] == "1" {
            XCTAssertEqual(
                parameters.proxyPolicy, .noProxyApplied,
                "PAC denial requires the private capability")
            let connection = try XCTUnwrap(
                NativeTcpConnection(host: host, port: port, parameters: parameters.native))
            defer { connection.cancelAndDetach() }
            let failed = expectation(description: "direct DNS failure")
            let seen = Locked(false)
            let failures = Locked<[String]>([])
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready: failures.withLock { $0.append("unexpected PAC fallback") }
                case .waiting(let error), .failed(let error):
                    if !seen.withLock({ previous in
                        let old = previous
                        previous = true
                        return old
                    }) {
                        if case .dns = error {
                        } else {
                            failures.withLock { $0.append("expected DNS failure: \(error)") }
                        }
                        failed.fulfill()
                    }
                default: break
                }
            }
            connection.start(queue: DispatchQueue(label: "rama.test.system-pac"))
            wait(for: [failed], timeout: 10)
            let observed = expectation(description: "PAC fallback observation")
            DispatchQueue.global().asyncAfter(deadline: .now() + 10) { observed.fulfill() }
            wait(for: [observed], timeout: 11)
            XCTAssertTrue(
                failures.withLock { $0.isEmpty }, failures.withLock { $0.joined(separator: "\n") })
        } else {
            try exchange(
                host: host, port: port, parameters: parameters.native,
                usedProxy: env["RAMA_EGRESS_TEST_USED_PROXY"] == "1")
        }
    }

    private func exchange(
        host: String, port: UInt16, parameters: nw_parameters_t, usedProxy: Bool,
        proxyEndpoint: String? = nil
    )
        throws
    {
        let connection = try XCTUnwrap(
            NativeTcpConnection(host: host, port: port, parameters: parameters))
        let callbacks = DispatchGroup()
        defer {
            connection.cancelAndDetach()
            XCTAssertEqual(
                callbacks.wait(timeout: .now() + 5), .success,
                "client callbacks did not drain")
        }
        let queue = DispatchQueue(label: "rama.test.exchange")
        let ready = expectation(description: "ready")
        let states = Locked<[String]>([])
        let wasReady = Locked(false)
        connection.stateUpdateHandler = { state in
            states.withLock { $0.append(String(describing: state)) }
            if case .ready = state,
                !wasReady.withLock({ previous in
                    let old = previous
                    previous = true
                    return old
                })
            {
                ready.fulfill()
            }
        }
        connection.start(queue: queue)
        guard XCTWaiter.wait(for: [ready], timeout: 10) == .completed else {
            let path =
                nw_connection_copy_current_path(connection.native)
                .map { String(describing: $0) } ?? "unavailable"
            XCTFail("connection never ready: states=\(states.withLock { $0 }), path=\(path)")
            return
        }
        let reported = expectation(description: "report")
        let reportValue = Locked<TcpEstablishmentReport?>(nil)
        callbacks.enter()
        connection.requestTcpEstablishmentReport(queue: queue) { report in
            defer { callbacks.leave() }
            reportValue.withLock { $0 = report }
            reported.fulfill()
        }
        let payload = Data((0..<(512 * 1024)).map { UInt8(truncatingIfNeeded: $0) })
        let received = Locked(Data())
        let errors = Locked<[String]>([])
        let eof = expectation(description: "response after client FIN")
        @Sendable func read() {
            callbacks.enter()
            connection.receive(minimumIncompleteLength: 1, maximumLength: 32 * 1024) {
                data, _, complete, error in
                defer { callbacks.leave() }
                if let error { errors.withLock { $0.append("receive: \(error)") } }
                if let data { received.withLock { $0.append(data) } }
                if complete || error != nil { eof.fulfill() } else { read() }
            }
        }
        // EOF can precede send completions. Await every completion before
        // cancelling, and keep assertions out of callbacks on timeout paths.
        let sent = expectation(description: "all client sends completed")
        sent.expectedFulfillmentCount = 2 + payload.count / 8192
        @Sendable func send(_ content: Data?, final: Bool = false) {
            callbacks.enter()
            connection.send(
                content: content, contentContext: final ? .finalMessage : .defaultMessage,
                isComplete: true,
                completion: .contentProcessed { error in
                    defer { callbacks.leave() }
                    if let error { errors.withLock { $0.append("send: \(error)") } }
                    sent.fulfill()
                })
        }
        read()
        send(Data())
        // The server responds only after FIN: cancellation masquerading as a
        // half-close, dropped buffers, and final-context mistakes all fail this.
        for offset in stride(from: 0, to: payload.count, by: 8192) {
            send(payload.subdata(in: offset..<(offset + 8192)))
        }
        send(nil, final: true)
        wait(for: [eof, reported, sent], timeout: 15)
        XCTAssertTrue(
            errors.withLock { $0.isEmpty }, errors.withLock { $0.joined(separator: "\n") })
        XCTAssertEqual(received.withLock { $0 }, payload)
        let report = try XCTUnwrap(reportValue.withLock { $0 })
        XCTAssertEqual(report.usedProxy, usedProxy)
        if let proxyEndpoint { XCTAssertEqual(report.proxyEndpoint, proxyEndpoint) }
        if usedProxy {
            XCTAssertEqual(report.proxyConfigured, true)
            XCTAssertNotNil(report.proxyEndpoint)
        }
    }
}

/// Loopback-only peer; optional HTTP CONNECT handshake, then echo after FIN.
private final class EchoServer: @unchecked Sendable {
    typealias Send =
        @Sendable (
            NWConnection, Data, NWConnection.ContentContext,
            @escaping @Sendable (NWError?) -> Void
        ) -> Void
    let listener: NWListener
    let queue = DispatchQueue(label: "rama.test.echo")
    let contacts = Locked(0)
    let receiveStarted = DispatchSemaphore(value: 0)
    private let callbacks = DispatchGroup()
    private let sendContent: Send
    // All mutable fixture state and socket callbacks belong to queue.
    private var connections: [NWConnection] = []
    private var stopping = false
    private var failures: [String] = []
    var port: UInt16 { listener.port!.rawValue }

    init(
        proxy: Bool, ipv6: Bool = false,
        send: @escaping Send = { connection, content, context, completion in
            connection.send(
                content: content, contentContext: context, isComplete: true,
                completion: .contentProcessed(completion))
        }
    ) throws {
        sendContent = send
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(
            host: ipv6 ? .ipv6(.loopback) : .ipv4(.loopback), port: .any)
        listener = try NWListener(using: parameters)
        let started = DispatchSemaphore(value: 0)
        callbacks.enter()
        listener.stateUpdateHandler = { [callbacks] state in
            switch state {
            case .ready: started.signal()
            case .cancelled: callbacks.leave()
            default: break
            }
        }
        listener.newConnectionHandler = { [weak self] connection in
            guard let self, !self.stopping else {
                connection.cancel()
                return
            }
            self.contacts.withLock { $0 += 1 }
            self.connections.append(connection)
            connection.start(queue: self.queue)
            self.read(connection, buffer: Data(), handshake: proxy)
        }
        listener.start(queue: queue)
        guard started.wait(timeout: .now() + 5) == .success else {
            cancel()
            throw NSError(domain: "rama.test.listener", code: 1)
        }
    }

    private func read(_ connection: NWConnection, buffer: Data, handshake: Bool) {
        callbacks.enter()
        connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) {
            [self] data, _, complete, error in
            defer { callbacks.leave() }
            guard !stopping, error == nil else { return }
            var buffer = buffer
            if let data { buffer.append(data) }
            if handshake, let end = buffer.range(of: Data("\r\n\r\n".utf8)) {
                guard String(decoding: buffer.prefix(8), as: UTF8.self).hasPrefix("CONNECT ")
                else {
                    failures.append("expected HTTP CONNECT request")
                    return
                }
                let rest = Data(buffer[end.upperBound...])
                send(connection, content: Data("HTTP/1.1 200 Connection Established\r\n\r\n".utf8))
                {
                    self.read(connection, buffer: rest, handshake: false)
                }
            } else if complete {
                guard !handshake else {
                    failures.append("EOF during HTTP CONNECT request")
                    return
                }
                send(connection, content: buffer, final: true)
            } else {
                read(connection, buffer: buffer, handshake: handshake)
            }
        }
        receiveStarted.signal()
    }

    private func send(
        _ connection: NWConnection, content: Data, final: Bool = false,
        then continuation: (@Sendable () -> Void)? = nil
    ) {
        callbacks.enter()
        sendContent(connection, content, final ? .finalMessage : .defaultMessage) { [self] error in
            queue.async { [self] in
                defer { callbacks.leave() }
                // Only our own teardown may cancel an outstanding send. Preserve
                // other errors, but report them in the owning test after draining.
                if let error, !(stopping && error == .posix(.ECANCELED)) {
                    failures.append("echo send failed: \(error)")
                }
                guard !stopping, error == nil else { return }
                continuation?()
            }
        }
    }

    func beginCancellation() {
        dispatchPrecondition(condition: .notOnQueue(queue))
        queue.sync {
            guard !stopping else { return }
            stopping = true
            listener.cancel()
            for connection in connections { connection.cancel() }
            connections.removeAll()
        }
    }

    func cancel(file: StaticString = #filePath, line: UInt = #line) {
        beginCancellation()
        // A queue barrier alone cannot drain callbacks that Network.framework
        // has not submitted yet. Count every receive/send and listener shutdown.
        let drained = callbacks.wait(timeout: .now() + 5) == .success
        XCTAssertTrue(drained, "echo server callbacks did not drain", file: file, line: line)
        let errors = queue.sync { failures }
        XCTAssertTrue(errors.isEmpty, errors.joined(separator: "\n"), file: file, line: line)
    }
}
