use std::cell::Cell;

use rama::{
    http::{
        Version,
        inspect::control::{Direction, PendingSummary},
        ws::inspect::WebSocketMessagePreview,
    },
    net::{Protocol, stream::SocketInfo},
    tls::{
        ExtensionId, ProtocolVersion,
        client::{ClientHello, ClientHelloExtension},
    },
};

use super::*;

#[test]
fn approval_fragments_are_consumed_only_when_writing_the_parent() {
    let pending = PendingSummary {
        kind: None,
        id: 42,
        connection: 1,
        connection_display_id: Some(1),
        exchange: Some(2),
        protocol: Protocol::HTTP,
        direction: Direction::Ingress,
        method: Method::GET,
        url: "/".parse().unwrap(),
        status: None,
        queued_at: None,
    };
    let visited = Cell::new(0);
    let fragment = render_approval_slots(std::iter::repeat_n(&pending, 3).inspect(|_| {
        visited.set(visited.get() + 1);
    }));
    let parent = div!(fragment);
    assert_eq!(visited.get(), 0);
    let mut output = String::with_capacity(kib(8));
    parent.escape_and_write(&mut output);
    assert_eq!(visited.get(), 3);
    assert_eq!(output.matches("id=\"approval-slot-42\"").count(), 3);
    assert_eq!(output.capacity(), kib(8));
}

#[test]
fn details_are_escaped_by_rama_html() {
    let mut details = test_details(vec![StoredRecord::RequestBody {
        data: Bytes::from_static("<script>alert(1)</script>".as_bytes()),
    }]);
    details.summary.user_agent = Some("</pre><script>alert(1)</script>".parse().unwrap());
    let rendered = render_details(&details).into_string();
    assert!(!rendered.contains("<script>alert(1)</script>"));
    assert!(!rendered.contains("</pre>"));
}

#[test]
fn request_details_keep_tls_on_connection_and_render_lazy_http_data() {
    let client_hello = ClientHello::new(
        ProtocolVersion::TLSv1_2,
        vec![
            rama::tls::CipherSuite::TLS13_AES_128_GCM_SHA256,
            rama::tls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        ],
        Vec::new(),
        vec![
            ClientHelloExtension::SupportedGroups(vec![
                rama::tls::SupportedGroup::X25519,
                rama::tls::SupportedGroup::SECP256R1,
            ]),
            ClientHelloExtension::SignatureAlgorithms(vec![
                rama::tls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rama::tls::SignatureScheme::RSA_PSS_SHA256,
            ]),
            ClientHelloExtension::Opaque {
                id: ExtensionId::SESSION_TICKET,
                data: Vec::new(),
            },
        ],
    );
    let mut details = test_details(vec![
        StoredRecord::RequestHead {
            method: Method::POST,
            url: "https://example.test/upload".parse().unwrap(),
            version: Version::HTTP_2,
            headers: test_headers([
                ("content-type".to_owned(), "application/json".to_owned()),
                ("x-request".to_owned(), "yes".to_owned()),
            ]),
        },
        StoredRecord::ResponseHead {
            status: StatusCode::from_u16(201).unwrap(),
            version: Version::HTTP_2,
            headers: test_headers([("content-type".to_owned(), "text/plain".to_owned())]),
        },
    ]);
    let ja3 = rama::tls::fingerprint::Ja3::compute_from_client_hello(&client_hello, None).unwrap();
    details.metadata.upstream.insert(SocketInfo::new(
        None,
        "[2606:4700:10::6814:17aa]:443".parse().unwrap(),
    ));
    details.metadata.connection.insert(TlsObservation {
        client_hello: Some(client_hello),
        parameters: Some(CapturedTlsParameters {
            protocol_version: ProtocolVersion::TLSv1_3,
            application_layer_protocol: Some(rama::net::tls::ApplicationProtocol::HTTP_2),
            peer_certificate_count: Some(1),
        }),
        ja3: Some(ja3),
        ja4: None,
        peetprint: None,
    });
    details.metadata.upstream.insert(TlsObservation {
        client_hello: None,
        parameters: Some(CapturedTlsParameters {
            protocol_version: ProtocolVersion::TLSv1_3,
            application_layer_protocol: Some(rama::net::tls::ApplicationProtocol::HTTP_2),
            peer_certificate_count: Some(2),
        }),
        ja3: None,
        ja4: None,
        peetprint: None,
    });
    details.summary.method = Method::POST;
    details.summary.protocol = Protocol::HTTPS;
    details.summary.http_version = Version::HTTP_2;
    details.summary.request_bytes = 128;
    details.summary.response_bytes = 64;

    let rendered = render_details(&details).into_string();
    for expected in [
        "Request headers",
        "Response headers · 201 HTTP/2.0",
        "Request payload",
        "Response payload",
        "data-capture-preview",
        "capture-spinner",
        "/api/capture/1/body/request?limit=65536",
        "Stream captured body",
        "header-name\">x-request",
        ">yes</span>",
        "data-copy-header",
        "data-copy-target",
        "data-copy-overview",
        "data-copy-curl=\"/api/capture/1/curl\"",
        "/api/har/export?ids=1",
        "[2606:4700:10::6814:17aa]:443",
    ] {
        assert!(rendered.contains(expected), "missing {expected}");
    }
    assert!(!rendered.contains("Handshake &amp; capture metadata"));
    assert!(!rendered.contains("Emulation profile"));
    assert!(!rendered.contains("Chromium"));
    assert!(!rendered.contains("RequestBody"));
    assert!(!rendered.contains("Client hello"));
    assert!(!rendered.contains("Client ↔ inspector"));
    assert!(!rendered.contains("ja3-value"));

    let connection_tls = render_connection_tls(&details).into_string();
    for expected in [
        "Client hello",
        "Client ↔ inspector",
        "Inspector ↔ server",
        "TLS 1.3",
        "h2",
        "Client identity &amp; TLS fingerprints",
        "tls-offer",
        "2 offered",
        "TLS13_AES_128_GCM_SHA256 (0x1301)",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)",
        "SUPPORTED_GROUPS (0x000a)",
        "SESSION_TICKET (0x0023)",
        "X25519 (0x001d)",
        "SECP256R1 (0x0017)",
        "ECDSA_NISTP256_SHA256 (0x0403)",
        "RSA_PSS_SHA256 (0x0804)",
    ] {
        assert!(connection_tls.contains(expected), "missing {expected}");
    }
    assert!(!connection_tls.contains("<details open"));
    assert!(!connection_tls.contains("protocol_version"));
}

#[test]
fn websocket_details_decode_directional_text_and_binary_cards() {
    let mut details = test_details(vec![
        StoredRecord::RequestHead {
            method: Method::GET,
            url: "https://example.test/socket".parse().unwrap(),
            version: Version::HTTP_11,
            headers: test_headers([("upgrade".to_owned(), "websocket".to_owned())]),
        },
        StoredRecord::ResponseHead {
            status: StatusCode::from_u16(101).unwrap(),
            version: Version::HTTP_11,
            headers: test_headers([("upgrade".to_owned(), "websocket".to_owned())]),
        },
    ]);
    details.websocket.messages = vec![
        CapturedWebSocketMessage {
            at: "2026-08-22T20:00:00Z".parse().unwrap(),
            direction: WebSocketRelayDirection::Ingress,
            kind: WebSocketMessageKind::Text,
            data: Bytes::from("hello over websocket"),
            close_code: None,
            origin: WebSocketMessageOrigin::Peer,
        },
        CapturedWebSocketMessage {
            at: "2026-08-22T20:00:01Z".parse().unwrap(),
            direction: WebSocketRelayDirection::Egress,
            kind: WebSocketMessageKind::Binary,
            data: Bytes::from_static(&[0, 1, 254, 255]),
            close_code: None,
            origin: WebSocketMessageOrigin::Replay,
        },
    ]
    .into_iter()
    .map(Into::into)
    .collect();
    details.websocket.total = details.websocket.messages.len();
    details.summary.protocol = Protocol::WSS;
    details.websocket.replay_active = true;

    let rendered = render_details(&details).into_string();
    assert!(!rendered.contains("data-copy-curl"));
    assert!(rendered.contains("WebSocket traffic"));
    assert!(rendered.contains("Upstream server"));
    assert!(rendered.contains("Downstream client"));
    assert!(rendered.contains("Binary (base64)"));
    assert!(rendered.contains("/api/websocket/1/send"));
    assert!(rendered.contains("Client → Server"));
    assert!(rendered.contains("Server → Client"));
    assert!(rendered.contains("hello over websocket"));
    assert!(rendered.contains("0x0001FEFF"));
    assert!(rendered.contains("Replay to server"));
    assert!(rendered.contains("Replay to client"));
    assert!(rendered.contains("/api/websocket/1/replay/0"));
    assert!(rendered.contains("/api/websocket/1/replay/1"));
    assert!(rendered.contains("ws-message egress replayed"));
    assert!(!rendered.contains("Replay off"));
    let headers = rendered.find("Request headers").unwrap();
    let messages = rendered.find("WebSocket traffic").unwrap();
    assert!(
        headers < messages,
        "WebSocket messages should follow headers"
    );
    assert!(!rendered.contains("TLS client hello"));
    assert!(!rendered.contains(&BASE64.encode("hello over websocket")));
    assert!(!rendered.contains("Handshake &amp; capture metadata"));
}

#[test]
fn websocket_previews_are_bounded_and_paginated() {
    assert!(render_websocket_messages(&test_details(Vec::new())).is_none());

    let text_limit = vec![b'a'; WS_TEXT_PREVIEW_LIMIT];
    let exact_text = websocket_payload(WebSocketMessageKind::Text, &text_limit);
    assert_eq!(exact_text.1, WS_TEXT_PREVIEW_LIMIT);
    assert!(!exact_text.2);
    drop(exact_text);
    let long_data = [text_limit, vec![b'b']].concat();
    let long_text = websocket_payload(WebSocketMessageKind::Text, &long_data);
    assert_eq!(long_text.1, WS_TEXT_PREVIEW_LIMIT + 1);
    assert!(long_text.2);
    assert!(long_text.0.to_string().ends_with('…'));

    let exact_binary =
        websocket_payload(WebSocketMessageKind::Binary, &[0; WS_BINARY_PREVIEW_LIMIT]);
    assert!(!exact_binary.2);
    let long_binary = websocket_payload(
        WebSocketMessageKind::Binary,
        &[0; WS_BINARY_PREVIEW_LIMIT + 1],
    );
    assert_eq!(long_binary.1, WS_BINARY_PREVIEW_LIMIT + 1);
    assert!(long_binary.2);

    let record = CapturedWebSocketMessage {
        at: jiff::Timestamp::now(),
        direction: WebSocketRelayDirection::Ingress,
        kind: WebSocketMessageKind::Text,
        data: Bytes::from(vec![b'm'; WS_TEXT_PREVIEW_LIMIT + 1]),
        close_code: None,
        origin: WebSocketMessageOrigin::Peer,
    };
    let mut details = test_details(Vec::new());
    details.websocket.messages = vec![record.into(); MAX_VISIBLE_WS_MESSAGES];
    details.websocket.total = MAX_VISIBLE_WS_MESSAGES + 1;
    let rendered = render_websocket_messages(&details)
        .expect("messages render a WebSocket section")
        .into_string();
    assert!(rendered.contains("messages 2–101 of 101"));
    assert!(rendered.contains("Older"));
    assert!(!rendered.contains("Newer"));
    assert!(rendered.contains("Preview first 64 KiB"));
    assert!(rendered.contains("/api/capture/1/websocket/1"));
    assert_eq!(
        rendered.matches("class=\"ws-message ingress\"").count(),
        100
    );
    assert_eq!(rendered.matches("Replay off").count(), 1);
    assert!(!rendered.contains("connection closed · replay unavailable"));

    details.summary.request_truncated = true;
    let rendered = render_websocket_messages(&details).unwrap().into_string();
    assert_eq!(rendered.matches("Capture truncated").count(), 1);
    assert!(!rendered.contains("capture truncated · replay unavailable"));

    details.websocket.messages.truncate(1);
    details.websocket.page = 1;
    let rendered = render_websocket_messages(&details).unwrap().into_string();
    assert!(rendered.contains("messages 1–1 of 101"));
    assert!(!rendered.contains("Older"));
    assert!(rendered.contains("Newer"));
}

#[test]
fn presentation_helpers_cover_boundaries() {
    assert_eq!(format_bytes(0).to_string(), "0 B");
    assert_eq!(format_bytes(1023).to_string(), "1023 B");
    assert_eq!(format_bytes(kib_u64(1)).to_string(), "1.0 KiB");
    assert_eq!(format_bytes(mib(1) as u64 - 1).to_string(), "1024.0 KiB");
    assert_eq!(format_bytes(mib(1) as u64).to_string(), "1.0 MiB");
    assert_eq!(
        status_class(Some(StatusCode::from_u16(199).unwrap())),
        "status"
    );
    assert_eq!(
        status_class(Some(StatusCode::from_u16(200).unwrap())),
        "status ok"
    );
    assert_eq!(
        status_class(Some(StatusCode::from_u16(399).unwrap())),
        "status ok"
    );
    assert_eq!(
        status_class(Some(StatusCode::from_u16(400).unwrap())),
        "status error"
    );
    assert_eq!(
        status_class(Some(StatusCode::from_u16(599).unwrap())),
        "status error"
    );
    assert_eq!(status_class(None), "status");
    assert_eq!(StatusCode::OK.to_string(), "200 OK");
    assert_eq!(StatusCode::NOT_FOUND.to_string(), "404 Not Found");
    assert_eq!(
        tls_version_label(ProtocolVersion::TLSv1_3).to_string(),
        "TLS 1.3"
    );
    assert_eq!(
        display_timestamp(&"2026-08-23T19:19:35.568646Z".parse().unwrap()).to_string(),
        "2026-08-23 19:19:35.568 UTC"
    );

    let mut summary = test_details(Vec::new()).http.summary;
    summary.protocol = Protocol::HTTPS;
    let protocol = render_protocol_badge(&summary).into_string();
    assert!(protocol.contains("protocol-lock"));
    assert!(protocol.contains("HTTPS"));
    assert!(protocol.contains("HTTP/1.1"));
    summary.status = None;
    summary.active = true;
    let waiting = render_exchange_status(&summary).into_string();
    assert!(waiting.contains("data-response-state=\"waiting\""));
    assert!(waiting.contains("response-spinner"));
    assert!(waiting.contains("Waiting for response"));

    summary.status = Some(StatusCode::from_u16(200).unwrap());
    let streaming = render_exchange_status(&summary).into_string();
    assert!(streaming.contains("data-response-state=\"streaming\""));
    assert!(streaming.contains("response-spinner"));
    assert!(streaming.contains("200 OK"));
    assert!(!streaming.contains("complete"));

    summary.protocol = Protocol::WSS;
    summary.status = Some(StatusCode::from_u16(101).unwrap());
    let live_websocket = render_exchange_status(&summary).into_string();
    assert!(live_websocket.contains("data-response-state=\"live\""));
    assert!(live_websocket.contains("response-live-dot"));
    assert!(live_websocket.contains("101 Switching Protocols"));

    summary.active = false;
    let finished = render_exchange_status(&summary).into_string();
    assert!(finished.contains("data-response-state=\"finished\""));
    assert!(!finished.contains("response-live-dot"));
    assert!(!finished.contains("complete"));

    summary.status = None;
    let no_response = render_exchange_status(&summary).into_string();
    assert!(no_response.contains("data-response-state=\"no-response\""));
    assert!(no_response.contains("No response"));
    assert_eq!(escape_js_string(r"a\b'c"), r"a\\b\'c");
    for value in [
        "application/problem+json",
        "APPLICATION/PROBLEM+JSON",
        "TEXT/PLAIN",
        "text/event-stream; charset=utf-8",
        "application/atom+xml",
        "application/x-www-form-urlencoded",
        "application/x-ndjson",
        "application/json-seq",
    ] {
        assert!(is_textual_content_type(&value.parse().unwrap()), "{value}");
    }
    for value in [
        "application/octet-stream",
        "application/octet-stream; filename=data.json",
        "application/not-json",
    ] {
        assert!(!is_textual_content_type(&value.parse().unwrap()), "{value}");
    }
}

#[test]
fn websocket_preview_keeps_utf8_prefix_and_original_length() {
    let mut preview: WebSocketMessagePreview = CapturedWebSocketMessage::new(
        WebSocketRelayDirection::Ingress,
        WebSocketMessageKind::Text,
        Bytes::from_static("hello 💖 tail".as_bytes()),
    )
    .into();
    // Keep only the first byte of the final multi-byte character.
    preview.data.truncate(7);
    let mut details = test_details(Vec::new());
    details.websocket.total = 1;
    details.websocket.messages.push(preview);
    let rendered = render_websocket_messages(&details).unwrap().into_string();
    assert!(rendered.contains("hello …"));
    assert!(!rendered.contains('�'));
    assert!(rendered.contains("15 B"));
    assert!(rendered.contains("Download full message"));
    assert!(rendered.contains("data-byte-limit=\"65536\""));
}
