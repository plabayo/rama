import Darwin
import Foundation
import Network
import RamaAppleNEFFI
import RamaAppleNetwork
import XCTest

@testable import RamaAppleNetworkExtension

final class NativeTcpConnectionTests: XCTestCase {
    private func noProxy(_ parameters: nw_parameters_t) throws -> Bool {
        let symbol = try XCTUnwrap(
            dlsym(UnsafeMutableRawPointer(bitPattern: -2), "nw_parameters_get_no_proxy"))
        return unsafeBitCast(symbol, to: (@convention(c) (nw_parameters_t) -> Bool).self)(
            parameters)
    }

    func testPolicyAndCopyAndAllowAfterDeny() throws {
        guard TcpProxyControl.system.setter != nil else {
            throw XCTSkip("private no-proxy symbol unavailable")
        }
        let params = makeTcpNwParameters(nil)
        XCTAssertEqual(params.proxyPolicy, .noProxyApplied)
        XCTAssertTrue(try noProxy(params.native))
        XCTAssertTrue(try noProxy(nw_parameters_copy(params.native)))
        XCTAssertTrue(nw_parameters_get_prefer_no_proxy(params.native))
        XCTAssertEqual(TcpProxyControl.system.apply(to: params.native, allowProxy: true), .allowed)
        XCTAssertFalse(try noProxy(params.native))
        XCTAssertFalse(nw_parameters_get_prefer_no_proxy(params.native))
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
        defer { connection.cancel() }
        let failed = expectation(description: "direct DNS failure")
        let seen = Locked(false)
        connection.stateUpdateHandler = { state in
            switch state {
            case .ready: XCTFail("unexpected proxy fallback")
            case .waiting(let error), .failed(let error):
                if !seen.withLock({ previous in
                    let old = previous
                    previous = true
                    return old
                }) {
                    if case .dns = error {} else { XCTFail("expected DNS failure, got \(error)") }
                    failed.fulfill()
                }
            default: break
            }
        }
        connection.start(queue: DispatchQueue(label: "rama.test.deny"))
        wait(for: [failed], timeout: 10)
        let observed = expectation(description: "fallback observation window")
        DispatchQueue.global().asyncAfter(deadline: .now() + 2) { observed.fulfill() }
        wait(for: [observed], timeout: 3)
        XCTAssertEqual(server.contacts.withLock { $0 }, 0)
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
            defer { connection.cancel() }
            let failed = expectation(description: "direct DNS failure")
            let seen = Locked(false)
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready: XCTFail("unexpected PAC fallback")
                case .waiting(let error), .failed(let error):
                    if !seen.withLock({ previous in
                        let old = previous
                        previous = true
                        return old
                    }) {
                        if case .dns = error {} else { XCTFail("expected DNS failure: \(error)") }
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
        defer { connection.cancel() }
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
        connection.requestTcpEstablishmentReport(queue: queue) { report in
            XCTAssertNotNil(report)
            XCTAssertEqual(report?.usedProxy, usedProxy)
            if let proxyEndpoint { XCTAssertEqual(report?.proxyEndpoint, proxyEndpoint) }
            if usedProxy {
                XCTAssertEqual(report?.proxyConfigured, true)
                XCTAssertNotNil(report?.proxyEndpoint)
            }
            reported.fulfill()
        }
        let payload = Data((0..<(512 * 1024)).map { UInt8(truncatingIfNeeded: $0) })
        let received = Locked(Data())
        let eof = expectation(description: "response after client FIN")
        @Sendable func read() {
            connection.receive(minimumIncompleteLength: 1, maximumLength: 32 * 1024) {
                data, _, complete, error in
                XCTAssertNil(error)
                if let data { received.withLock { $0.append(data) } }
                if complete || error != nil { eof.fulfill() } else { read() }
            }
        }
        read()
        connection.send(
            content: Data(), contentContext: .defaultMessage, isComplete: true,
            completion: .contentProcessed { XCTAssertNil($0) })
        // The server responds only after FIN: cancellation masquerading as a
        // half-close, dropped buffers, and final-context mistakes all fail this.
        for offset in stride(from: 0, to: payload.count, by: 8192) {
            connection.send(
                content: payload.subdata(in: offset..<(offset + 8192)),
                contentContext: .defaultMessage,
                isComplete: true, completion: .contentProcessed { XCTAssertNil($0) })
        }
        connection.send(
            content: nil, contentContext: .finalMessage, isComplete: true,
            completion: .contentProcessed { XCTAssertNil($0) })
        wait(for: [eof, reported], timeout: 15)
        XCTAssertEqual(received.withLock { $0 }, payload)
    }
}

/// Loopback-only peer; optional HTTP CONNECT handshake, then echo after FIN.
private final class EchoServer: @unchecked Sendable {
    let listener: NWListener
    let queue = DispatchQueue(label: "rama.test.echo")
    let connections = Locked<[NWConnection]>([])
    let contacts = Locked(0)
    var port: UInt16 { listener.port!.rawValue }

    init(proxy: Bool, ipv6: Bool = false) throws {
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(
            host: ipv6 ? .ipv6(.loopback) : .ipv4(.loopback), port: .any)
        listener = try NWListener(using: parameters)
        let started = DispatchSemaphore(value: 0)
        listener.stateUpdateHandler = { if case .ready = $0 { started.signal() } }
        listener.newConnectionHandler = { [weak self] connection in
            guard let self else { return }
            self.contacts.withLock { $0 += 1 }
            self.connections.withLock { $0.append(connection) }
            connection.start(queue: self.queue)
            self.read(connection, buffer: Data(), handshake: proxy)
        }
        listener.start(queue: queue)
        guard started.wait(timeout: .now() + 5) == .success else {
            listener.cancel()
            throw NSError(domain: "rama.test.listener", code: 1)
        }
    }

    private func read(_ connection: NWConnection, buffer: Data, handshake: Bool) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) {
            [weak self] data, _, complete, error in
            guard let self, error == nil else { return }
            var buffer = buffer
            if let data { buffer.append(data) }
            if handshake, let end = buffer.range(of: Data("\r\n\r\n".utf8)) {
                XCTAssertTrue(
                    String(decoding: buffer.prefix(8), as: UTF8.self).hasPrefix("CONNECT "))
                let rest = Data(buffer[end.upperBound...])
                connection.send(
                    content: Data("HTTP/1.1 200 Connection Established\r\n\r\n".utf8),
                    completion: .contentProcessed { error in
                        XCTAssertNil(error)
                        self.read(connection, buffer: rest, handshake: false)
                    })
            } else if complete {
                XCTAssertFalse(handshake)
                connection.send(
                    content: buffer, contentContext: .finalMessage, isComplete: true,
                    completion: .contentProcessed { XCTAssertNil($0) })
            } else {
                self.read(connection, buffer: buffer, handshake: handshake)
            }
        }
    }

    func cancel() {
        listener.cancel()
        connections.withLock {
            $0.forEach { $0.cancel() }
            $0.removeAll()
        }
    }
}
