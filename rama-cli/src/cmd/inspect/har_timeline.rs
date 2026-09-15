//! HTTP Archive 1.2 into the shared [`Timeline`] view model.

use std::{collections::BTreeMap, io::BufRead, time::Duration};

use rama::{
    error::{BoxError, BoxErrorExt as _, ErrorContext as _, ErrorExt as _},
    http::{
        convert::curl,
        layer::har::spec::{
            Cookie, Entry as HarEntry, Header, LogFile, QueryStringPair, Request as HarRequest,
            Timings, WebSocketMessage, WebSocketMessageOpcode, WebSocketMessageType,
        },
    },
    inspect::timeline::{Connection, CopyItem, Entry, Field, Level, Section, Timeline},
    utils::str::arcstr::ArcStr,
};

use super::{Limits, util};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use jiff::Timestamp;

pub(super) fn decode(
    reader: impl BufRead,
    source: &str,
    limits: Limits,
) -> Result<Timeline, BoxError> {
    // An archive is one JSON document: serde streams it, so the file's bytes are
    // not held alongside the entries they decode into.
    let file: LogFile = serde_json::from_reader(reader).context("parse HAR file")?;
    let log = file.log;
    if log.entries.len() > limits.max_records {
        return Err(BoxError::from_static_str("HAR entry limit exceeded")
            .context_field("limit", limits.max_records)
            .context_field("entries", log.entries.len()));
    }

    let mut timeline = Timeline::new(format!("HAR {}", log.version), source);
    timeline.epoch = log
        .entries
        .iter()
        .map(|entry| entry.started_date_time)
        .min();
    timeline.summary = vec![
        Field::new(
            "creator",
            format!("{} {}", log.creator.name, log.creator.version),
        ),
        Field::new(
            "browser",
            log.browser.as_ref().map_or_else(
                || ArcStr::from(Section::UNAVAILABLE),
                |browser| {
                    format!(
                        "{} {}",
                        browser.name,
                        browser.version.as_deref().unwrap_or("")
                    )
                    .trim()
                    .into()
                },
            ),
        ),
        Field::new("pages", log.pages.as_ref().map_or(0, Vec::len).to_string()),
        Field::new("exchanges", log.entries.len().to_string()),
        Field::new(
            "started",
            timeline.epoch.map_or_else(
                || ArcStr::from(Section::UNAVAILABLE),
                |at| at.to_string().into(),
            ),
        ),
    ];
    if let Some(comment) = log.comment {
        timeline.summary.push(Field::new("comment", comment));
    }

    let epoch = timeline.epoch.unwrap_or_else(Timestamp::now);
    let mut connections = Connections::default();
    let mut entries = Vec::with_capacity(log.entries.len());
    for har in log.entries {
        let connection = connections.index_of(&har);
        entries.extend(websocket_entries(&har, connection, epoch, limits));
        entries.push(exchange_entry(har, connection, epoch, limits));
    }
    timeline.connections = connections.finish();
    timeline.set_entries(entries);
    Ok(timeline)
}

/// HAR identifies a connection by its `connection` field, which is optional;
/// the request authority is the next best grouping a viewer can offer.
#[derive(Debug, Default)]
struct Connections {
    index: BTreeMap<String, usize>,
    connections: Vec<Connection>,
    counts: Vec<usize>,
}

impl Connections {
    fn index_of(&mut self, entry: &HarEntry) -> Option<usize> {
        let authority = util::authority(&entry.request.url);
        let key = match &entry.connection {
            Some(id) => format!("{authority}#{id}"),
            None => authority.to_string(),
        };
        let index = *self.index.entry(key).or_insert_with(|| {
            let mut fields = vec![Field::new("host", authority.clone())];
            if let Some(id) = &entry.connection {
                fields.push(Field::new("connection id", id.clone()));
            }
            if let Some(ip) = entry.server_ip_address {
                fields.push(Field::new("server ip", ip.to_string()));
            }
            self.connections.push(Connection {
                id: entry
                    .connection
                    .clone()
                    .unwrap_or_else(|| authority.clone()),
                label: match &entry.connection {
                    Some(id) => format!("{authority} #{id}").into(),
                    None => authority.clone(),
                },
                fields,
            });
            self.counts.push(0);
            self.connections.len() - 1
        });
        if let Some(count) = self.counts.get_mut(index) {
            *count += 1;
        }
        Some(index)
    }

    fn finish(mut self) -> Vec<Connection> {
        for (connection, count) in self.connections.iter_mut().zip(&self.counts) {
            connection
                .fields
                .push(Field::new("exchanges", count.to_string()));
        }
        self.connections
    }
}

fn exchange_entry(
    har: HarEntry,
    connection: Option<usize>,
    epoch: Timestamp,
    limits: Limits,
) -> Entry {
    let status = har.response.status;
    let mut entry = Entry::new(
        util::offset(epoch, har.started_date_time),
        har.request.url.clone(),
    );
    entry.connection = connection;
    entry.duration = Duration::from_millis(har.time.max(0).unsigned_abs());
    entry.badge = Some(har.request.method.clone());
    entry.level = match status {
        100..=299 => Level::Success,
        300..=399 => Level::Info,
        400..=499 => Level::Warning,
        // a 5xx, or the 0 a recorder writes when no response arrived
        _ => Level::Failure,
    };
    entry.detail = Some(
        match (status, har.response.status_text.as_deref()) {
            (0, _) => "no response".to_owned(),
            (status, Some(text)) => format!("{status} {text}"),
            (status, None) => status.to_string(),
        }
        .into(),
    );

    let request = &har.request;
    let response = &har.response;
    entry.sections = vec![
        Section::fields(
            "request",
            vec![
                Field::new("method", request.method.clone()),
                Field::new("url", request.url.clone()),
                Field::new("http version", request.http_version.to_string()),
                Field::new("headers size", util::optional_size(request.headers_size)),
                Field::new("body size", util::optional_size(request.body_size)),
                Field::new(
                    "server ip",
                    har.server_ip_address
                        .map_or_else(|| Section::UNAVAILABLE.into(), |ip| ip.to_string()),
                ),
                Field::new(
                    "connection",
                    har.connection
                        .clone()
                        .unwrap_or(Section::UNAVAILABLE.into()),
                ),
            ],
        ),
        headers_section("request headers", &request.headers),
        Section::fields(
            "query string",
            request
                .query_string
                .iter()
                .map(|QueryStringPair { name, value, .. }| Field::new(name.clone(), value.clone()))
                .collect(),
        ),
        cookies_section("request cookies", &request.cookies),
        match request
            .post_data
            .as_ref()
            .and_then(|data| data.text.as_ref())
        {
            Some(text) => Section::text("request body", util::preview(text, limits.max_body)),
            None => Section::unavailable("request body", "no request payload recorded"),
        },
        Section::fields(
            "response",
            vec![
                Field::new("status", status.to_string()),
                Field::new(
                    "status text",
                    response
                        .status_text
                        .clone()
                        .unwrap_or(Section::UNAVAILABLE.into()),
                ),
                Field::new("http version", response.http_version.to_string()),
                Field::new(
                    "mime type",
                    response
                        .content
                        .mime_type
                        .as_ref()
                        .map_or_else(|| Section::UNAVAILABLE.to_owned(), ToString::to_string),
                ),
                Field::new("content size", util::optional_size(response.content.size)),
                Field::new(
                    "compression",
                    response.content.compression.map_or_else(
                        || Section::UNAVAILABLE.into(),
                        |saved| format!("{saved} bytes saved"),
                    ),
                ),
                Field::new("headers size", util::optional_size(response.headers_size)),
                Field::new("body size", util::optional_size(response.body_size)),
                Field::new(
                    "redirect",
                    response
                        .redirect_url
                        .clone()
                        .filter(|url| !url.is_empty())
                        .unwrap_or(Section::UNAVAILABLE.into()),
                ),
            ],
        ),
        headers_section("response headers", &response.headers),
        cookies_section("response cookies", &response.cookies),
        response_body_section(&har, limits),
        timings_section(&har.timings),
    ];
    entry.sections.retain(|section| !section.is_empty());

    if let Some(comment) = har.comment.clone() {
        entry.sections.push(Section::text("comment", comment));
    }
    // only the request is retained for the copy: keeping the whole entry alive
    // would hold every response body of the archive for the whole session.
    entry.copy = vec![curl_copy_item(har.request, limits)];
    entry
}

fn headers_section(title: &'static str, headers: &[Header]) -> Section {
    Section::fields(
        title,
        headers
            .iter()
            .map(|header| Field::new(header.name.clone(), header.value.clone()))
            .collect(),
    )
}

fn cookies_section(title: &'static str, cookies: &[Cookie]) -> Section {
    Section::fields(
        title,
        cookies
            .iter()
            .map(|cookie| Field::new(cookie.name.clone(), cookie.value.clone()))
            .collect(),
    )
}

fn response_body_section(har: &HarEntry, limits: Limits) -> Section {
    let content = &har.response.content;
    let Some(text) = content.text.as_ref() else {
        return Section::unavailable("response body", "body not captured");
    };
    if content.encoding.as_deref() == Some("base64") {
        return match BASE64.decode(text.as_bytes()) {
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(text) => Section::text("response body", util::preview(&text, limits.max_body)),
                Err(error) => Section::text(
                    "response body",
                    util::hex_preview(error.as_bytes(), limits.max_body),
                ),
            },
            Err(_) => Section::text(
                "response body (undecodable base64)",
                util::preview(text, limits.max_body),
            ),
        };
    }
    Section::text("response body", util::preview(text, limits.max_body))
}

fn timings_section(timings: &Timings) -> Section {
    Section::fields(
        "timings",
        vec![
            Field::new("blocked", util::optional_ms(timings.blocked)),
            Field::new("dns", util::optional_ms(timings.dns)),
            Field::new("connect", util::optional_ms(timings.connect)),
            Field::new("ssl", util::optional_ms(timings.ssl)),
            Field::new("send", util::optional_ms(Some(timings.send))),
            Field::new("wait", util::optional_ms(Some(timings.wait))),
            Field::new("receive", util::optional_ms(Some(timings.receive))),
        ],
    )
}

/// Render the request as a curl command for the shell of the current platform.
///
/// Built when asked for, not for every entry of the archive: a capture holds
/// thousands of requests and only the selected one is ever copied.
fn curl_copy_item(request: HarRequest, limits: Limits) -> CopyItem {
    CopyItem::lazy("curl", move || {
        let payload = request_payload(&request);
        let request: rama::http::Request = request
            .clone()
            .try_into()
            .context("convert HAR request into an http request")?;
        let (parts, body) = request.into_parts();
        drop(body);
        // An inline payload is duplicated into the command; past the preview
        // limit, point curl at stdin instead of embedding a huge body.
        let payload_mode = if payload.len() > limits.max_body {
            curl::CurlScriptPayloadMode::Stdin
        } else {
            curl::CurlScriptPayloadMode::Inline
        };
        curl::try_cmd_string_for_request_parts_and_payload_with_options(
            &parts,
            &payload,
            curl::CurlExportOptions::default()
                .with_script_compatibility(curl::CurlScriptCompatibility::native()),
            &payload_mode,
        )
        .map(ArcStr::from)
        .context("render curl command")
    })
}

fn request_payload(request: &HarRequest) -> rama::bytes::Bytes {
    let Some(text) = request
        .post_data
        .as_ref()
        .and_then(|data| data.text.as_ref())
    else {
        return rama::bytes::Bytes::new();
    };
    // HAR has no encoding marker on postData: a body that decodes as base64 was
    // written by a recorder that encoded it, the same assumption the HAR ->
    // request conversion makes.
    match BASE64.decode(text.as_bytes()) {
        Ok(bytes) => bytes.into(),
        Err(_) => rama::bytes::Bytes::copy_from_slice(text.as_bytes()),
    }
}

fn websocket_entries(
    har: &HarEntry,
    connection: Option<usize>,
    epoch: Timestamp,
    limits: Limits,
) -> Vec<Entry> {
    let Some(messages) = har.web_socket_messages.as_ref() else {
        return Vec::new();
    };
    messages
        .iter()
        .map(|message| websocket_entry(har, message, connection, epoch, limits))
        .collect()
}

fn websocket_entry(
    har: &HarEntry,
    message: &WebSocketMessage,
    connection: Option<usize>,
    epoch: Timestamp,
    limits: Limits,
) -> Entry {
    let (direction, level) = match message.r#type {
        WebSocketMessageType::Send => ("→", Level::Info),
        WebSocketMessageType::Receive => ("←", Level::Info),
        WebSocketMessageType::Error => ("!", Level::Failure),
    };
    // a binary frame is hex; text, an error record, or a frame whose base64 does
    // not decode stay as the recorded text
    let payload = match message.binary_data() {
        Some(Ok(bytes)) => util::hex_preview(&bytes, limits.max_body),
        _ => util::preview(&message.data, limits.max_body),
    };

    let mut entry = Entry::new(
        util::offset_seconds(epoch, message.time),
        har.request.url.clone(),
    );
    entry.connection = connection;
    entry.level = level;
    entry.badge = Some(format!("WS {direction}").into());
    entry.detail = Some(
        format!(
            "{} · {} bytes",
            opcode_name(message.opcode),
            message.data.len()
        )
        .into(),
    );
    entry.sections = vec![
        Section::fields(
            "message",
            vec![
                Field::new("type", format!("{:?}", message.r#type).to_lowercase()),
                Field::new("opcode", opcode_name(message.opcode)),
                Field::new("url", har.request.url.clone()),
            ],
        ),
        Section::text("payload", payload),
    ];
    entry.copy = vec![CopyItem::new("payload", message.data.clone())];
    entry
}

fn opcode_name(opcode: WebSocketMessageOpcode) -> ArcStr {
    match opcode {
        WebSocketMessageOpcode::ERROR => "error".into(),
        WebSocketMessageOpcode::CONTINUATION => "continuation".into(),
        WebSocketMessageOpcode::TEXT => "text".into(),
        WebSocketMessageOpcode::BINARY => "binary".into(),
        WebSocketMessageOpcode::CLOSE => "close".into(),
        WebSocketMessageOpcode::PING => "ping".into(),
        WebSocketMessageOpcode::PONG => "pong".into(),
        other => format!("opcode {}", other.as_i32()).into(),
    }
}
