//! Protocol-shaped, coloured terminal text for one decoded capture.
//!
//! Every captured string passes through `display_text`, so a capture can never
//! emit terminal control sequences.

use crate::utils::terminal::display_text;
use rama::{
    http::proto::{h2::frame::SettingId as H2SettingId, h3::SettingId as H3SettingId},
    quic::proto::transport_parameters::TransportParameterId,
    tls::{
        CertificateCompressionAlgorithm, CipherSuite, CompressionAlgorithm, ECPointFormat,
        ExtensionId, ProtocolVersion, PskKeyExchangeMode, SignatureScheme, SupportedGroup,
        fingerprint::{Ja3, Ja4},
        is_grease_u16,
    },
    ua::profile::{
        analysis::capture::VariantValue,
        capture::{
            headers::{HeaderCapture, HeaderValueSource},
            http2::{H2Capture, H2CapturedFrame},
            order::{OrderNamespace, OrderedProtocolCapture, ProtocolValue},
            pseudo_headers::PseudoHeaderCapture,
            tls::{TlsCapture, TlsCapturedExtensionValue},
        },
        format::{
            canonical::{CanonicalDomain, CanonicalValue},
            decoded::{CaptureDecodeLimits, DecodedCapture},
        },
    },
};
use ratatui::{
    style::{Color, Modifier, Style},
    text::{Line, Span},
};
use serde::Serialize;
use serde_json::Value;

pub(super) const KEY: Style = Style::new().fg(Color::Cyan);
pub(super) const DIM: Style = Style::new().fg(Color::DarkGray);
pub(super) const NUMBER: Style = Style::new().fg(Color::Yellow);
const TEXT: Style = Style::new().fg(Color::Green);
const BOUND: Style = Style::new()
    .fg(Color::Magenta)
    .add_modifier(Modifier::ITALIC);
pub(super) const SECTION: Style = Style::new()
    .fg(Color::LightBlue)
    .add_modifier(Modifier::BOLD);
const ERROR: Style = Style::new().fg(Color::Red);

/// Longest literal shown as hex before it is elided.
const HEX_BYTES: usize = 48;

#[derive(Default)]
pub(super) struct Lines(pub(super) Vec<Line<'static>>);

impl Lines {
    fn push(&mut self, indent: usize, spans: impl IntoIterator<Item = Span<'static>>) {
        let mut line = vec![Span::raw("  ".repeat(indent))];
        line.extend(spans);
        self.0.push(Line::from(line));
    }

    fn section(&mut self, indent: usize, title: impl Into<String>) {
        self.push(indent, [Span::styled(title.into(), SECTION)]);
    }

    fn field(&mut self, indent: usize, key: impl Into<String>, value: Span<'static>) {
        self.push(
            indent,
            [
                Span::styled(key.into(), KEY),
                Span::styled(": ", DIM),
                value,
            ],
        );
    }
}

/// A short name for what one scope captured, decoding joint and order scopes for their parts.
pub(super) fn domain_label(domain: CanonicalDomain, sample: Option<&CanonicalValue>) -> String {
    match sample.map(|value| DecodedCapture::from_canonical(value, &CaptureDecodeLimits::default()))
    {
        Some(Ok(DecodedCapture::Joint(joint))) => joint
            .slots
            .iter()
            .map(|slot| format!("{:?}", slot.kind))
            .collect::<Vec<_>>()
            .join(" + "),
        Some(Ok(DecodedCapture::Order(order))) => namespace_label(order.namespace).to_owned(),
        _ => match domain {
            CanonicalDomain::Headers => "Headers",
            CanonicalDomain::PseudoHeaders => "PseudoHeaders",
            CanonicalDomain::Tls => "ClientHello",
            CanonicalDomain::H2 => "Http2EarlyFrames",
            CanonicalDomain::QuicFlight => "QuicFirstFlight",
            CanonicalDomain::H3Sequence => "Http3Sequence",
            CanonicalDomain::H3Bootstrap => "Http3Bootstrap",
            CanonicalDomain::RuntimeMetadata => "RuntimeMetadata",
            CanonicalDomain::LegacyField => "LegacyField",
            _ => "Capture",
        }
        .to_owned(),
    }
}

fn namespace_label(namespace: OrderNamespace) -> &'static str {
    match namespace {
        OrderNamespace::QuicParameter => "QuicParameters",
        OrderNamespace::Http3Setting => "Http3Settings",
        OrderNamespace::QuicVersion => "QuicVersions",
    }
}

/// Lay out one retained variant, rebuilding a compact capture first.
pub(super) fn variant(value: &VariantValue) -> Lines {
    match value.canonical() {
        Ok(value) => capture(&value),
        Err(error) => {
            let mut lines = Lines::default();
            lines.push(
                0,
                [Span::styled(format!("undecodable capture: {error}"), ERROR)],
            );
            lines
        }
    }
}

/// Decode and lay out one captured variant.
pub(super) fn capture(value: &CanonicalValue) -> Lines {
    let mut lines = Lines::default();
    match DecodedCapture::from_canonical(value, &CaptureDecodeLimits::default()) {
        Ok(decoded) => decoded_lines(&mut lines, &decoded, 0),
        Err(error) => lines.push(
            0,
            [Span::styled(format!("undecodable capture: {error}"), ERROR)],
        ),
    }
    lines
}

fn decoded_lines(lines: &mut Lines, decoded: &DecodedCapture<'_>, indent: usize) {
    match decoded {
        DecodedCapture::Headers(capture) => headers(lines, capture, indent),
        DecodedCapture::PseudoHeaders(capture) => pseudo_headers(lines, capture, indent),
        DecodedCapture::Tls(capture) => tls(lines, capture, indent),
        DecodedCapture::H2(capture) => h2(lines, capture, indent),
        DecodedCapture::Order(capture) => order(lines, capture, indent),
        DecodedCapture::Joint(joint) => {
            for slot in &joint.slots {
                lines.section(indent, format!("▸ {:?}", slot.kind));
                match DecodedCapture::from_canonical(&slot.value, &CaptureDecodeLimits::default()) {
                    // Joint captures never nest; a nested one is shown structurally.
                    Ok(DecodedCapture::Joint(_)) | Err(_) => {
                        lines.push(indent + 1, [Span::styled("undecodable slot", ERROR)]);
                    }
                    Ok(nested) => decoded_lines(lines, &nested, indent + 1),
                }
            }
        }
        DecodedCapture::Quic(capture) => tree(lines, capture, indent),
        DecodedCapture::H3(capture) => tree(lines, capture, indent),
        DecodedCapture::H3Bootstrap(capture) => tree(lines, capture, indent),
        DecodedCapture::Runtime(capture) => tree(lines, capture, indent),
        DecodedCapture::Canonical { domain, value } => lines.push(
            indent,
            [Span::styled(
                format!(
                    "{domain:?}: {} bytes kept as captured, no decoder",
                    value.bytes.len()
                ),
                DIM,
            )],
        ),
    }
}

fn headers(lines: &mut Lines, capture: &HeaderCapture, indent: usize) {
    lines.push(
        indent,
        [Span::styled(
            format!(
                "{:?} · {} fields in wire order",
                capture.version,
                capture.fields.len()
            ),
            DIM,
        )],
    );
    for field in &capture.fields {
        let value = match &field.value {
            _ if field.sensitive => Span::styled("‹sensitive›", BOUND),
            HeaderValueSource::Profile(value) | HeaderValueSource::CaptureSafeProfile(value) => {
                Span::raw(display_text(&String::from_utf8_lossy(value)))
            }
            HeaderValueSource::Request(binding) => {
                Span::styled(format!("‹{binding:?}, from the request›"), BOUND)
            }
        };
        let mut spans = vec![
            Span::styled(display_text(field.name.as_str()), KEY),
            Span::styled(": ", DIM),
            value,
        ];
        if let Some(representation) = &field.representation {
            spans.push(Span::styled(
                format!(
                    "  {:?}{}{}",
                    representation.representation,
                    representation
                        .index
                        .map(|index| format!(" #{index}"))
                        .unwrap_or_default(),
                    if representation.value_huffman {
                        " huffman"
                    } else {
                        ""
                    }
                ),
                DIM,
            ));
        }
        lines.push(indent, spans);
    }
}

fn pseudo_headers(lines: &mut Lines, capture: &PseudoHeaderCapture, indent: usize) {
    lines.push(
        indent,
        [Span::styled(
            format!("{:?} · pseudo-header order", capture.version),
            DIM,
        )],
    );
    let mut spans = Vec::new();
    for (index, field) in capture.fields.iter().enumerate() {
        if index > 0 {
            spans.push(Span::styled(" → ", DIM));
        }
        spans.push(Span::styled(field.name.as_str(), KEY));
    }
    lines.push(indent, spans);
}

fn tls(lines: &mut Lines, capture: &TlsCapture, indent: usize) {
    let hello = capture.representative_client_hello();
    lines.push(
        indent,
        [
            Span::styled(
                format!("{:?} transport · legacy_version ", capture.transport),
                DIM,
            ),
            Span::styled(
                ProtocolVersion::from(capture.protocol_version).to_string(),
                TEXT,
            ),
        ],
    );
    if let Ok(ja4) = Ja4::compute_from_client_hello(&hello) {
        lines.field(indent, "JA4", Span::styled(ja4.to_string(), NUMBER));
    }
    if let Ok(ja3) = Ja3::compute_from_client_hello(&hello) {
        lines.field(indent, "JA3", Span::styled(format!("{ja3:x}"), NUMBER));
    }
    lines.section(indent, format!("cipher suites ({})", capture.ciphers.len()));
    for cipher in &capture.ciphers {
        lines.push(
            indent + 1,
            id_spans(*cipher, &CipherSuite::from(*cipher).variant_name()),
        );
    }
    if capture.compression.iter().any(|method| *method != 0) {
        lines.section(indent, "compression");
        for method in &capture.compression {
            lines.push(
                indent + 1,
                [Span::raw(CompressionAlgorithm::from(*method).to_string())],
            );
        }
    }
    lines.section(indent, format!("extensions ({})", capture.extensions.len()));
    for extension in &capture.extensions {
        let id = ExtensionId::from(extension.id);
        let mut spans = id_spans(extension.id, &id.variant_name().to_ascii_lowercase());
        if !is_grease_u16(extension.id) {
            spans.push(Span::raw("  "));
            spans.extend(extension_value(id, &extension.value));
        }
        lines.push(indent + 1, spans);
    }
}

fn id_spans(id: u16, name: &str) -> Vec<Span<'static>> {
    if is_grease_u16(id) {
        return vec![Span::styled(format!("{id:#06x}  GREASE"), DIM)];
    }
    vec![
        Span::styled(format!("{id:#06x}  "), DIM),
        Span::raw(name.to_owned()),
    ]
}

fn names<I: IntoIterator>(values: I, name: impl Fn(I::Item) -> String) -> Span<'static> {
    Span::styled(
        values.into_iter().map(name).collect::<Vec<_>>().join(", "),
        TEXT,
    )
}

fn extension_value(id: ExtensionId, value: &TlsCapturedExtensionValue) -> Vec<Span<'static>> {
    let grease_or = |value: u16, name: String| {
        if is_grease_u16(value) {
            "GREASE".to_owned()
        } else {
            name
        }
    };
    vec![match value {
        TlsCapturedExtensionValue::U16List(values) => {
            let values = values.iter().copied();
            match id {
                ExtensionId::SUPPORTED_GROUPS => names(values, |value| {
                    grease_or(value, SupportedGroup::from(value).variant_name().into())
                }),
                ExtensionId::SIGNATURE_ALGORITHMS
                | ExtensionId::SIGNATURE_ALGORITHMS_CERT
                | ExtensionId::DELEGATED_CREDENTIAL => names(values, |value| {
                    SignatureScheme::from(value).variant_name().into()
                }),
                ExtensionId::SUPPORTED_VERSIONS => names(values, |value| {
                    grease_or(value, ProtocolVersion::from(value).to_string())
                }),
                ExtensionId::COMPRESS_CERTIFICATE => names(values, |value| {
                    CertificateCompressionAlgorithm::from(value)
                        .variant_name()
                        .into()
                }),
                _ => names(values, |value| format!("{value:#06x}")),
            }
        }
        TlsCapturedExtensionValue::U8List(values) => {
            let values = values.iter().copied();
            match id {
                ExtensionId::EC_POINT_FORMATS => names(values, |value| {
                    ECPointFormat::from(value).variant_name().into()
                }),
                ExtensionId::PSK_KEY_EXCHANGE_MODES => names(values, |value| {
                    PskKeyExchangeMode::from(value).variant_name().into()
                }),
                _ => names(values, |value| value.to_string()),
            }
        }
        TlsCapturedExtensionValue::Protocols(protocols) => names(protocols.iter(), |protocol| {
            display_text(&String::from_utf8_lossy(protocol))
        }),
        TlsCapturedExtensionValue::ServerName { present } => Span::styled(
            if *present {
                "‹destination host›"
            } else {
                "‹empty›"
            },
            BOUND,
        ),
        TlsCapturedExtensionValue::KeyShares(shares) => names(shares.iter(), |share| {
            format!(
                "{} ({} B)",
                grease_or(
                    share.group,
                    SupportedGroup::from(share.group).variant_name().into()
                ),
                share.length
            )
        }),
        TlsCapturedExtensionValue::PreSharedKeys {
            identities,
            binders,
        } => Span::styled(
            format!(
                "‹{} identities, {} binders, per connection›",
                identities.len(),
                binders.len()
            ),
            BOUND,
        ),
        TlsCapturedExtensionValue::EchOuter {
            kdf,
            aead,
            enc,
            payload,
        } => Span::styled(
            format!("kdf {kdf:#06x} · aead {aead:#06x} · enc {enc} B · payload {payload} B"),
            TEXT,
        ),
        TlsCapturedExtensionValue::EchInner => Span::styled("inner", TEXT),
        TlsCapturedExtensionValue::ConnectionLength(length) => {
            Span::styled(format!("‹{length} B, per connection›"), BOUND)
        }
        TlsCapturedExtensionValue::Literal(bytes) => hex(bytes),
    }]
}

fn hex(bytes: &[u8]) -> Span<'static> {
    if bytes.is_empty() {
        return Span::styled("empty", DIM);
    }
    let mut text: String = bytes
        .iter()
        .take(HEX_BYTES)
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if bytes.len() > HEX_BYTES {
        text.push_str(&format!("… ({} B)", bytes.len()));
    }
    Span::styled(text, NUMBER)
}

fn h2(lines: &mut Lines, capture: &H2Capture, indent: usize) {
    for frame in &capture.frames {
        match frame {
            H2CapturedFrame::Settings { ack, entries } => {
                lines.section(indent, if *ack { "SETTINGS ack" } else { "SETTINGS" });
                for entry in entries {
                    lines.field(
                        indent + 1,
                        H2SettingId::from(entry.id).variant_name(),
                        Span::styled(entry.value.to_string(), NUMBER),
                    );
                }
            }
            H2CapturedFrame::WindowUpdate { stream, increment } => {
                lines.section(indent, "WINDOW_UPDATE");
                lines.field(
                    indent + 1,
                    "stream",
                    Span::styled(stream.to_string(), NUMBER),
                );
                lines.field(
                    indent + 1,
                    "increment",
                    Span::styled(increment.to_string(), NUMBER),
                );
            }
            H2CapturedFrame::Priority {
                stream,
                dependency,
                weight,
                exclusive,
            } => {
                lines.section(indent, "PRIORITY");
                lines.push(
                    indent + 1,
                    [Span::styled(
                        format!(
                            "stream {stream} → {dependency} · weight {weight}{}",
                            if *exclusive { " · exclusive" } else { "" }
                        ),
                        NUMBER,
                    )],
                );
            }
        }
    }
}

fn order(lines: &mut Lines, capture: &OrderedProtocolCapture, indent: usize) {
    lines.push(
        indent,
        [Span::styled(
            format!("{} in wire order", namespace_label(capture.namespace)),
            DIM,
        )],
    );
    for field in &capture.fields {
        let name = match capture.namespace {
            OrderNamespace::QuicParameter => TransportParameterId::from(field.id)
                .variant_name()
                .into_owned(),
            OrderNamespace::Http3Setting => H3SettingId::from(field.id)
                .name()
                .map_or_else(|| format!("{:#x}", field.id), str::to_owned),
            OrderNamespace::QuicVersion => format!("{:#010x}", field.id),
        };
        let value = match &field.value {
            ProtocolValue::Literal(bytes) => hex(bytes),
            ProtocolValue::ConnectionLength(length) => {
                Span::styled(format!("‹{length} B, per connection›"), BOUND)
            }
        };
        lines.field(indent, name, value);
    }
}

/// A coloured outline of any capture without a dedicated layout.
fn tree(lines: &mut Lines, capture: &impl Serialize, indent: usize) {
    match serde_json::to_value(capture) {
        Ok(value) => value_lines(lines, None, &value, indent),
        Err(error) => lines.push(
            indent,
            [Span::styled(format!("unprintable capture: {error}"), ERROR)],
        ),
    }
}

fn value_lines(lines: &mut Lines, key: Option<&str>, value: &Value, indent: usize) {
    let leaf = match value {
        Value::Null => Some(Span::styled("none", DIM)),
        Value::Bool(value) => Some(Span::styled(value.to_string(), NUMBER)),
        Value::Number(value) => Some(Span::styled(value.to_string(), NUMBER)),
        Value::String(value) => Some(Span::styled(display_text(value), TEXT)),
        Value::Array(items) if items.is_empty() => Some(Span::styled("[]", DIM)),
        Value::Object(fields) if fields.is_empty() => Some(Span::styled("{}", DIM)),
        // Byte strings read better as hex than as a column of numbers.
        Value::Array(items)
            if items
                .iter()
                .all(|item| item.as_u64().is_some_and(|n| n <= 255)) =>
        {
            let bytes: Vec<u8> = items
                .iter()
                .filter_map(|item| item.as_u64().and_then(|n| u8::try_from(n).ok()))
                .collect();
            Some(hex(&bytes))
        }
        Value::Array(items)
            if items
                .iter()
                .all(|item| !item.is_object() && !item.is_array()) =>
        {
            Some(Span::styled(
                items
                    .iter()
                    .map(|item| match item {
                        Value::String(value) => display_text(value),
                        other => other.to_string(),
                    })
                    .collect::<Vec<_>>()
                    .join(", "),
                NUMBER,
            ))
        }
        _ => None,
    };
    let mut spans = match key {
        Some(key) => vec![Span::styled(key.to_owned(), KEY), Span::styled(": ", DIM)],
        None => vec![Span::styled("- ", DIM)],
    };
    if let Some(leaf) = leaf {
        spans.push(leaf);
        lines.push(indent, spans);
        return;
    }
    if key.is_some() {
        lines.push(indent, spans);
    }
    let child = indent + usize::from(key.is_some());
    match value {
        Value::Object(fields) => {
            for (name, field) in fields {
                value_lines(lines, Some(&display_text(name)), field, child);
            }
        }
        Value::Array(items) => {
            for item in items {
                // Each structured element gets a marker so neighbours stay apart.
                if item.is_object() || item.is_array() {
                    lines.push(child, [Span::styled("•", DIM)]);
                    value_lines(lines, None, item, child + 1);
                } else {
                    value_lines(lines, None, item, child);
                }
            }
        }
        _ => (),
    }
}
