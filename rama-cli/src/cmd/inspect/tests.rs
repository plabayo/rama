use super::*;

use std::time::Duration;

use rama::inspect::timeline::{Level, Section, SectionBody};
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

const HAR: &[u8] = include_bytes!("../../../tests/fixtures/example.har");
const QLOG: &[u8] = include_bytes!("../../../tests/fixtures/quic.qlog");

const LIMITS: Limits = Limits {
    max_records: 10_000,
    max_body: 4096,
    max_bytes: 16 * 1024 * 1024,
};

fn decode_bytes(
    format: CaptureFormat,
    bytes: &[u8],
    source: &str,
    limits: Limits,
) -> Result<Timeline, BoxError> {
    decode(format, std::io::Cursor::new(bytes), source, limits)
}

fn har_timeline() -> Timeline {
    decode_bytes(CaptureFormat::Har, HAR, "example.har", LIMITS).unwrap()
}

fn qlog_timeline() -> Timeline {
    decode_bytes(CaptureFormat::Qlog, QLOG, "quic.qlog", LIMITS).unwrap()
}

fn section<'a>(entry: &'a rama::inspect::timeline::Entry, title: &str) -> &'a SectionBody {
    &entry
        .sections
        .iter()
        .find(|section| section.title == title)
        .unwrap_or_else(|| panic!("no `{title}` section in {:?}", entry.label))
        .body
}

fn field(body: &SectionBody, name: &str) -> String {
    match body {
        SectionBody::Fields(fields) => fields
            .iter()
            .find(|field| field.name == name)
            .unwrap_or_else(|| panic!("no `{name}` field"))
            .value
            .to_string(),
        other => panic!("not a field section: {other:?}"),
    }
}

fn text(body: &SectionBody) -> String {
    match body {
        SectionBody::Text(text) => text.to_string(),
        other => panic!("not a text section: {other:?}"),
    }
}

// --- format detection ---

#[test]
fn the_format_is_detected_from_the_extension_first_and_the_content_otherwise() {
    assert_eq!(
        CaptureFormat::from_extension(Path::new("/tmp/capture.har")),
        Some(CaptureFormat::Har),
    );
    assert_eq!(
        CaptureFormat::from_extension(Path::new("/tmp/CAPTURE.QLOG")),
        Some(CaptureFormat::Qlog),
    );
    assert_eq!(
        CaptureFormat::from_extension(Path::new("/tmp/capture.sqlog")),
        Some(CaptureFormat::Qlog),
    );
    assert_eq!(
        CaptureFormat::from_extension(Path::new("capture.json")),
        None
    );

    assert_eq!(CaptureFormat::from_content(HAR), Some(CaptureFormat::Har));
    assert_eq!(CaptureFormat::from_content(QLOG), Some(CaptureFormat::Qlog));
    assert_eq!(CaptureFormat::from_content(b"GET / HTTP/1.1\r\n"), None);
    assert_eq!(CaptureFormat::from_content(&[]), None);
}

#[test]
fn an_explicit_format_is_respected_and_reports_its_own_error() {
    let error = decode_bytes(CaptureFormat::Qlog, HAR, "example.har", LIMITS)
        .unwrap_err()
        .to_string();
    assert!(error.contains("not a qlog file"), "error: {error}");

    let error = decode_bytes(CaptureFormat::Har, QLOG, "quic.qlog", LIMITS)
        .unwrap_err()
        .to_string();
    assert!(error.contains("parse HAR file"), "error: {error}");
}

// --- HAR ---

#[test]
fn har_entries_expose_a_timeline_with_connections_and_websocket_messages() {
    let timeline = har_timeline();
    assert_eq!(timeline.format, "HAR 1.2");
    assert_eq!(
        timeline.epoch.map(|epoch| epoch.to_string()),
        Some("2026-09-14T10:00:00Z".to_owned()),
    );

    // four exchanges plus three websocket messages, ordered by start offset
    assert_eq!(timeline.entries().len(), 7);
    let offsets: Vec<u64> = timeline
        .entries()
        .iter()
        .map(|entry| entry.start.as_millis() as u64)
        .collect();
    assert_eq!(offsets, [0, 200, 500, 700, 900, 1000, 1100]);

    // grouped by authority and HAR connection id
    let labels: Vec<_> = timeline
        .connections
        .iter()
        .map(|connection| connection.label.to_string())
        .collect();
    assert_eq!(
        labels,
        [
            "example.test #443",
            "stream.example.test #8443",
            "cdn.example.test",
        ],
    );

    let first = &timeline.entries()[0];
    assert_eq!(first.badge.as_deref(), Some("GET"));
    assert_eq!(first.label, "https://example.test/index.html");
    assert_eq!(first.detail.as_deref(), Some("200 OK"));
    assert_eq!(first.level, Level::Success);
    assert_eq!(first.duration, Duration::from_millis(120));
    assert_eq!(first.connection, Some(0));
}

#[test]
fn har_bodies_and_timings_are_shown_or_marked_unavailable() {
    let timeline = har_timeline();
    let entries = timeline.entries();

    let timings = section(&entries[0], "timings");
    assert_eq!(field(timings, "dns"), "4 ms");
    assert_eq!(field(timings, "ssl"), "12 ms");
    assert_eq!(
        text(section(&entries[0], "response body")),
        "<html>hello world</html>",
    );

    // HAR's -1 means "does not apply", and stays visibly unavailable
    let login = &entries[1];
    let timings = section(login, "timings");
    assert_eq!(field(timings, "dns"), Section::UNAVAILABLE);
    assert_eq!(field(timings, "connect"), Section::UNAVAILABLE);
    assert_eq!(field(timings, "wait"), "40 ms");
    assert_eq!(text(section(login, "request body")), r#"{"user":"rama"}"#);
    assert!(
        matches!(
            section(login, "response body"),
            SectionBody::Unavailable(reason) if reason.contains("not captured"),
        ),
        "an empty response body must stay visibly unavailable",
    );
    assert_eq!(login.level, Level::Warning);
    assert_eq!(field(section(login, "query string"), "next"), "/home");

    // a base64 body that is not text is rendered as hex, never as raw bytes
    let failure = entries
        .iter()
        .find(|entry| entry.label == "https://cdn.example.test/app.js")
        .expect("the failing exchange");
    assert_eq!(failure.level, Level::Failure);
    assert_eq!(text(section(failure, "response body")), "0x00FF0102");
    let request = section(failure, "request");
    assert_eq!(field(request, "headers size"), Section::UNAVAILABLE);
    assert_eq!(field(request, "body size"), Section::UNAVAILABLE);
}

#[test]
fn har_websocket_messages_become_their_own_entries() {
    let timeline = har_timeline();
    let messages: Vec<_> = timeline
        .entries()
        .iter()
        .filter(|entry| {
            entry
                .badge
                .as_deref()
                .is_some_and(|badge| badge.starts_with("WS"))
        })
        .collect();
    assert_eq!(messages.len(), 3);

    assert_eq!(messages[0].badge.as_deref(), Some("WS →"));
    assert_eq!(messages[0].start, Duration::from_millis(700));
    assert_eq!(
        text(section(messages[0], "payload")),
        r#"{"subscribe":"prices"}"#
    );
    assert_eq!(messages[1].badge.as_deref(), Some("WS ←"));
    // a binary frame is shown as hex
    assert_eq!(text(section(messages[2], "payload")), "0x000102AA");
    assert_eq!(messages[2].connection, messages[0].connection);
}

#[test]
fn har_requests_copy_as_a_curl_command_for_this_platform() {
    let timeline = har_timeline();
    let login = &timeline.entries()[1];
    let item = login.copy.first().expect("a curl copy item");
    assert_eq!(item.label, "curl");

    let command = item.text().unwrap();
    assert!(command.starts_with("curl "), "command: {command}");
    assert!(
        command.contains("https://example.test/api/login?next=%2Fhome"),
        "command: {command}",
    );
    assert!(command.contains(r#"{"user":"rama"}"#), "command: {command}");
    assert!(command.contains("content-type"), "command: {command}");
}

#[test]
fn har_bodies_are_bounded_by_the_body_limit() {
    let timeline = decode_bytes(
        CaptureFormat::Har,
        HAR,
        "example.har",
        Limits {
            max_body: 8,
            ..LIMITS
        },
    )
    .unwrap();
    let body = text(section(&timeline.entries()[0], "response body"));
    assert!(body.starts_with("<html>he"), "body: {body}");
    assert!(body.contains("truncated"), "body: {body}");
    assert!(body.contains("--max-body 8"), "body: {body}");
}

#[test]
fn the_record_limit_is_reported_instead_of_truncating_silently() {
    let error = decode_bytes(
        CaptureFormat::Har,
        HAR,
        "example.har",
        Limits {
            max_records: 2,
            ..LIMITS
        },
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("HAR entry limit exceeded"), "error: {error}");

    let error = decode_bytes(
        CaptureFormat::Qlog,
        QLOG,
        "quic.qlog",
        Limits {
            max_records: 2,
            ..LIMITS
        },
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("event limit exceeded"), "error: {error}");
}

// --- qlog ---

#[test]
fn a_rama_recorded_qlog_trace_opens_with_its_connection_group() {
    let timeline = qlog_timeline();
    assert_eq!(timeline.format, "qlog draft-14 (json-seq)");
    // a monotonic reference has no wall clock to anchor the timeline to
    assert!(timeline.epoch.is_none());
    assert!(!timeline.entries().is_empty());
    assert_eq!(timeline.connections.len(), 1);

    let started = timeline
        .entries()
        .iter()
        .find(|entry| entry.label == "connection_started")
        .expect("the trace starts a connection");
    assert_eq!(started.badge.as_deref(), Some("quic"));
    assert_eq!(started.level, Level::Success);
    assert_eq!(started.start, Duration::ZERO);
    assert!(
        matches!(section(started, "data"), SectionBody::Fields(fields) if fields
            .iter()
            .any(|field| field.name.starts_with("remote."))),
        "nested event data is flattened into fields",
    );
}

#[test]
fn qlog_connection_groups_and_unknown_events_survive() {
    const FILE: &str = concat!(
        "\u{1e}{\"file_schema\":\"urn:ietf:params:qlog:file:sequential\",",
        "\"trace\":{\"title\":\"two peers\",\"vantage_point\":{\"type\":\"server\"}}}\n",
        "\u{1e}{\"time\":0,\"group_id\":\"aaaa\",\"name\":\"quic:packet_sent\",",
        "\"data\":{\"header\":{\"packet_type\":\"initial\"}}}\n",
        "\u{1e}{\"time\":5,\"group_id\":\"bbbb\",\"name\":\"quic:packet_lost\",\"data\":{\"trigger\":\"timer\"}}\n",
        "\u{1e}{\"time\":9,\"group_id\":\"aaaa\",\"name\":\"h3:frame_parsed\",",
        "\"data\":{\"stream_id\":0,\"frame\":{\"frame_type\":\"headers\"}},\"vendor_note\":\"kept\"}\n",
    );

    let timeline = decode_bytes(CaptureFormat::Qlog, FILE.as_bytes(), "two.qlog", LIMITS).unwrap();
    assert_eq!(timeline.connections.len(), 2, "one per group_id");
    assert_eq!(timeline.entries().len(), 3);

    let lost = &timeline.entries()[1];
    assert_eq!(lost.level, Level::Warning, "a loss event stands out");
    assert_eq!(lost.connection, Some(1));

    // an event from a schema this build does not implement stays readable
    let unknown = &timeline.entries()[2];
    assert_eq!(unknown.badge.as_deref(), Some("h3"));
    assert_eq!(unknown.label, "frame_parsed");
    assert_eq!(
        field(section(unknown, "data"), "frame.frame_type"),
        "headers"
    );
    assert_eq!(
        field(section(unknown, "other members"), "vendor_note"),
        "kept",
    );
    assert!(
        unknown
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("stream_id=0")),
        "detail: {:?}",
        unknown.detail,
    );
}

// --- viewer ---

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

#[test]
fn the_viewer_renders_the_same_shape_for_every_format() {
    for timeline in [har_timeline(), qlog_timeline()] {
        let format = timeline.format.to_string();
        let source = timeline.source.to_string();
        let mut state = tui::AppState::new(View::new(timeline));
        let screen = tui::render_to_string(&mut state, 140, 40);
        assert!(screen.contains(&format), "format missing:\n{screen}");
        assert!(screen.contains(&source), "source missing:\n{screen}");
        assert!(screen.contains("timeline"), "timeline missing:\n{screen}");
        assert!(screen.contains("details"), "details missing:\n{screen}");
        assert!(screen.contains("entries"), "footer missing:\n{screen}");
    }
}

#[test]
fn the_viewer_selects_filters_and_scopes_to_a_connection() {
    let mut state = tui::AppState::new(View::new(har_timeline()));
    assert_eq!(state.view().cursor(), 0);

    state.on_key(key(KeyCode::Char('j')));
    assert_eq!(
        state.view().selected().unwrap().label,
        "https://example.test/api/login?next=%2Fhome"
    );
    let screen = tui::render_to_string(&mut state, 140, 40);
    assert!(screen.contains("401 Unauthorized"), "screen:\n{screen}");
    assert!(screen.contains("request headers"), "screen:\n{screen}");

    // filter mode narrows as it is typed
    state.on_key(key(KeyCode::Char('/')));
    for c in "cdn".chars() {
        state.on_key(key(KeyCode::Char(c)));
    }
    assert_eq!(state.view().len(), 1);
    assert_eq!(
        state.view().selected().unwrap().label,
        "https://cdn.example.test/app.js"
    );
    state.on_key(key(KeyCode::Enter));

    // and is cleared by removing what was typed
    state.on_key(key(KeyCode::Char('/')));
    for _ in 0..3 {
        state.on_key(key(KeyCode::Backspace));
    }
    state.on_key(key(KeyCode::Esc));
    assert_eq!(state.view().len(), 7);

    state.on_key(key(KeyCode::Tab));
    assert_eq!(state.view().connection(), Some(0));
    assert_eq!(state.view().len(), 2);
    let screen = tui::render_to_string(&mut state, 140, 40);
    assert!(screen.contains("example.test #443"), "screen:\n{screen}");
}

#[test]
fn the_viewer_quits_and_offers_a_copy_for_a_request() {
    let mut state = tui::AppState::new(View::new(har_timeline()));
    assert!(matches!(
        state.on_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)),
        tui::Action::Quit,
    ));
    assert!(matches!(
        state.on_key(key(KeyCode::Char('q'))),
        tui::Action::Quit
    ));
    assert!(matches!(
        state.on_key(key(KeyCode::Char('c'))),
        tui::Action::Copy
    ));

    state.on_key(key(KeyCode::Char('?')));
    let screen = tui::render_to_string(&mut state, 140, 40);
    assert!(
        screen.contains("copy the selected entry"),
        "screen:\n{screen}"
    );
}

#[test]
fn the_summary_lists_connections_and_entries() {
    let summary = summary::render(&View::new(har_timeline()));
    assert!(
        summary.contains("HAR 1.2 · example.har"),
        "summary:\n{summary}"
    );
    assert!(
        summary.contains("creator: rama-test 0.5.0"),
        "summary:\n{summary}"
    );
    assert!(
        summary.contains("[0] example.test #443"),
        "summary:\n{summary}"
    );
    assert!(
        summary.contains("GET    https://example.test/index.html  200 OK"),
        "summary:\n{summary}"
    );
    assert!(summary.contains("WS →"), "summary:\n{summary}");
}
