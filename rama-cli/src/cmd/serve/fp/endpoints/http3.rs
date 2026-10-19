use std::{slice, str};

use itertools::Itertools as _;
use rama::{
    cli::service::wire_names::{
        h3_error_name, h3_frame_type_name, h3_setting_name, h3_stream_type_name, quic_frame_name,
        quic_version_name, transport_parameter_name,
    },
    http::{
        proto::h3::observation::{
            FieldRepresentation, ObservationCompleteness, ObservedControlFrame,
            ObservedEncoderInstruction, ObservedFieldRepresentation, ObservedSetting,
            ObservedUniStream,
        },
        protocols::html::{IntoHtml, PreEscaped, script},
    },
    quic::proto::{
        VarInt, Version,
        capture::{
            CaptureCompleteness, FirstFlight, ObservedFrame, QuicObservation, RawParameter,
            version_information,
        },
        coding::Codec as _,
        profile::PaddingPlacement,
        transport_parameters::TransportParameterId,
    },
    utils::fmt::hex as hex_bytes,
};
use serde_json::to_string as to_json;

use super::{super::data::Http3Info, Table};

// Opaque values are shown as hex; longer values are cut to keep rows readable.
const MAX_HEX_BYTES: usize = 32;

/// The native H3 view as a JSON data block, for tooling that binds it to a capture.
pub(super) fn http3_observation_data(h3: Option<&Http3Info>) -> Option<impl IntoHtml> {
    let json = to_json(h3?).ok()?;
    // '<' only occurs inside JSON strings, so its escape keeps the block closed.
    Some(script!(
        r#type = "application/json",
        id = "rama-h3-observation",
        PreEscaped(json.replace('<', "\\u003c")),
    ))
}

/// HTTP/3 and QUIC report tables, one per logical section.
pub(super) fn http3_tables(h3: Option<&Http3Info>, quic: Option<&QuicObservation>) -> Vec<Table> {
    let mut tables = vec![http3_overview(h3)];
    if let Some(h3) = h3 {
        tables.push(http3_settings(
            h3.connection.settings.as_deref(),
            h3.connection.settings_received,
        ));
        tables.push(http3_streams(h3));
    }
    if let Some(quic) = quic {
        tables.push(quic_overview(quic));
        tables.push(quic_transport_parameters(&quic.transport_parameters));
        if let Some(flight) = &quic.first_flight {
            tables.push(quic_initial_flight(flight));
        }
    }
    tables
}

fn http3_overview(h3: Option<&Http3Info>) -> Table {
    let mut rows = Vec::new();
    match h3 {
        Some(h3) => {
            rows.push((
                "SETTINGS observation".to_owned(),
                h3.settings_status.to_string(),
            ));
            rows.push((
                "request stream id".to_owned(),
                h3.request.stream_id.to_string(),
            ));
            if let Some(pseudo) = &h3.pseudo_headers {
                rows.push(("pseudo header order".to_owned(), pseudo.iter().join(", ")));
            }
            let mut completeness = h3.connection.completeness;
            completeness.fields = h3.request.fields_complete;
            rows.push((
                "incomplete parts".to_owned(),
                h3_incomplete_parts(completeness),
            ));
            if let Some(code) = h3.connection.connection_error {
                rows.push(("connection error".to_owned(), h3_error_label(code)));
            }
        }
        None => rows.push(("observation".to_owned(), "unavailable".to_owned())),
    }
    Table {
        title: "🚀 HTTP/3".to_owned(),
        rows,
    }
}

fn http3_settings(settings: Option<&[ObservedSetting]>, received: bool) -> Table {
    let rows = match settings {
        Some([]) => vec![("settings".to_owned(), "none sent".to_owned())],
        Some(settings) => settings
            .iter()
            .map(|setting| (h3_setting_label(setting), setting.value.to_string()))
            .collect(),
        None if received => vec![(
            "settings".to_owned(),
            "received, over capture budget".to_owned(),
        )],
        None => vec![("settings".to_owned(), "not received".to_owned())],
    };
    Table {
        title: "🚀 HTTP/3 SETTINGS".to_owned(),
        rows,
    }
}

fn http3_streams(h3: &Http3Info) -> Table {
    let connection = &h3.connection;
    let mut rows = vec![
        (
            "unidirectional streams".to_owned(),
            none_if_empty(connection.streams.iter().map(h3_stream_label).join(", ")),
        ),
        (
            "control frames".to_owned(),
            none_if_empty(connection.control.iter().map(h3_control_label).join(", ")),
        ),
        (
            "QPACK encoder instructions".to_owned(),
            none_if_empty(
                connection
                    .encoder_instructions
                    .iter()
                    .map(qpack_instruction_label)
                    .join(", "),
            ),
        ),
        (
            "request field representations".to_owned(),
            none_if_empty(h3.request.fields.iter().map(field_label).join(", ")),
        ),
    ];
    if let Some(priority) = &h3.request.priority {
        rows.push(("request priority".to_owned(), text_or_hex(priority)));
    }
    Table {
        title: "🚀 HTTP/3 streams and frames".to_owned(),
        rows,
    }
}

fn quic_overview(quic: &QuicObservation) -> Table {
    let mut rows = Vec::new();
    if let Some(flight) = &quic.first_flight {
        rows.push(("version".to_owned(), version_label(flight.version)));
        if let Some(chosen) = flight.chosen_version {
            rows.push(("chosen version".to_owned(), version_label(chosen)));
        }
        if !flight.available_versions.is_empty() {
            rows.push((
                "available versions".to_owned(),
                flight
                    .available_versions
                    .iter()
                    .copied()
                    .map(version_label)
                    .join(", "),
            ));
        }
        rows.push((
            "destination CID length".to_owned(),
            flight.dcid_len.to_string(),
        ));
        rows.push(("source CID length".to_owned(), flight.scid_len.to_string()));
        rows.push(("token length".to_owned(), flight.token_len.to_string()));
    } else {
        rows.push(("Initial flight".to_owned(), "not captured".to_owned()));
    }
    rows.push((
        "incomplete parts".to_owned(),
        quic_incomplete_parts(quic.completeness),
    ));
    Table {
        title: "🧊 QUIC".to_owned(),
        rows,
    }
}

fn quic_transport_parameters(parameters: &[RawParameter]) -> Table {
    let rows = if parameters.is_empty() {
        vec![(
            "transport parameters".to_owned(),
            "none captured".to_owned(),
        )]
    } else {
        parameters
            .iter()
            .map(|parameter| {
                (
                    transport_parameter_label(parameter.id),
                    transport_parameter_value(parameter),
                )
            })
            .collect()
    };
    Table {
        title: "🧊 QUIC transport parameters".to_owned(),
        rows,
    }
}

fn quic_initial_flight(flight: &FirstFlight) -> Table {
    let mut rows = Vec::new();
    for (index, size) in flight.datagram_sizes.iter().enumerate() {
        let trailing = flight
            .trailing_bytes
            .get(index)
            .copied()
            .unwrap_or_default();
        let value = if trailing == 0 {
            format!("{size} bytes")
        } else {
            format!("{size} bytes ({trailing} trailing)")
        };
        rows.push((format!("datagram #{}", index + 1), value));
    }
    rows.push((
        "packet numbers".to_owned(),
        flight.packet_numbers.iter().join(", "),
    ));
    rows.push((
        "packet number lengths".to_owned(),
        flight.packet_number_lengths.iter().join(", "),
    ));
    for (index, frames) in flight.frames.iter().enumerate() {
        let label = match flight.packet_numbers.get(index) {
            Some(number) => format!("Initial #{} (pn {number})", index + 1),
            None => format!("Initial #{}", index + 1),
        };
        rows.push((
            label,
            none_if_empty(frames.iter().map(quic_frame_label).join(", ")),
        ));
    }
    rows.push((
        "padding".to_owned(),
        match flight.padding {
            PaddingPlacement::Frames => "PADDING frames".to_owned(),
            PaddingPlacement::DatagramTail => "datagram tail".to_owned(),
            other => format!("{other:?}"),
        },
    ));
    rows.push(("coalesced".to_owned(), flight.coalesced.to_string()));
    rows.push(("complete".to_owned(), flight.complete.to_string()));
    Table {
        title: "🧊 QUIC Initial flight".to_owned(),
        rows,
    }
}

fn version_label(version: Version) -> String {
    quic_version_name(version).label(u64::from(version.as_u32()))
}

fn h3_setting_label(setting: &ObservedSetting) -> String {
    h3_setting_name(setting.id).label(setting.id)
}

fn h3_stream_label(stream: &ObservedUniStream) -> String {
    let label = h3_stream_type_name(stream.stream_type).label(stream.stream_type);
    format!("{label} (id {})", stream.stream_id)
}

fn h3_control_label(frame: &ObservedControlFrame) -> String {
    let label = h3_frame_type_name(frame.frame_type).label(frame.frame_type);
    match frame.element_id {
        Some(element) => format!("{label} ({} bytes, element {element})", frame.length),
        None => format!("{label} ({} bytes)", frame.length),
    }
}

fn h3_error_label(code: u64) -> String {
    h3_error_name(code).label(code)
}

fn qpack_instruction_label(instruction: &ObservedEncoderInstruction) -> String {
    match instruction {
        ObservedEncoderInstruction::Capacity { capacity } => format!("capacity {capacity}"),
        ObservedEncoderInstruction::InsertNameReference {
            is_static,
            index,
            value_bytes,
            value_huffman,
        } => format!(
            "insert {} name {index} (value {value_bytes} B{})",
            if *is_static { "static" } else { "dynamic" },
            if *value_huffman { ", huffman" } else { "" },
        ),
        ObservedEncoderInstruction::InsertLiteral {
            name_bytes,
            value_bytes,
            name_huffman,
            value_huffman,
        } => format!(
            "insert literal (name {name_bytes} B{}, value {value_bytes} B{})",
            if *name_huffman { " huffman" } else { "" },
            if *value_huffman { " huffman" } else { "" },
        ),
        ObservedEncoderInstruction::Duplicate { index } => format!("duplicate {index}"),
    }
}

fn field_label(field: &ObservedFieldRepresentation) -> String {
    let mut label = match field.representation {
        FieldRepresentation::StaticIndex => "static",
        FieldRepresentation::DynamicIndex => "dynamic",
        FieldRepresentation::DynamicPostBaseIndex => "post-base",
        FieldRepresentation::LiteralStaticName => "literal static-name",
        FieldRepresentation::LiteralDynamicName => "literal dynamic-name",
        FieldRepresentation::LiteralPostBaseName => "literal post-base-name",
        FieldRepresentation::LiteralName => "literal",
    }
    .to_owned();
    if let Some(index) = field.index {
        label = format!("{label} {index}");
    }
    let flags = [
        (field.name_huffman, "H-name"),
        (field.value_huffman, "H-value"),
        (field.never_index, "never-index"),
    ]
    .into_iter()
    .filter_map(|(set, flag)| set.then_some(flag))
    .join(" ");
    if !flags.is_empty() {
        label = format!("{label} [{flags}]");
    }
    label
}

fn h3_incomplete_parts(completeness: ObservationCompleteness) -> String {
    let ObservationCompleteness {
        settings,
        local_settings,
        streams,
        control,
        qpack,
        fields,
        snapshot,
    } = completeness;
    missing_parts([
        (settings, "settings"),
        (local_settings, "local settings"),
        (streams, "streams"),
        (control, "control"),
        (qpack, "qpack"),
        (fields, "fields"),
        (snapshot, "snapshot"),
    ])
}

fn quic_incomplete_parts(completeness: CaptureCompleteness) -> String {
    let CaptureCompleteness {
        datagrams,
        frames,
        client_hello,
        transport_parameters,
        original_attempt,
    } = completeness;
    missing_parts([
        (datagrams, "datagrams"),
        (frames, "frames"),
        (client_hello, "ClientHello"),
        (transport_parameters, "transport parameters"),
        (original_attempt, "original attempt"),
    ])
}

fn missing_parts<const N: usize>(parts: [(bool, &str); N]) -> String {
    let missing = parts
        .into_iter()
        .filter_map(|(complete, name)| (!complete).then_some(name))
        .join(", ");
    if missing.is_empty() {
        "none".to_owned()
    } else {
        missing
    }
}

fn transport_parameter_label(id: TransportParameterId) -> String {
    transport_parameter_name(id).label(u64::from(id))
}

fn transport_parameter_value(parameter: &RawParameter) -> String {
    let id = parameter.id;
    let value = parameter.value.as_slice();
    if id.has_connection_specific_value() {
        return format!("{} bytes (connection-specific)", value.len());
    }
    if id == TransportParameterId::VersionInformation
        && let Some(info) = version_information(slice::from_ref(parameter))
    {
        return format!(
            "chosen {}; available {}",
            version_label(info.chosen()),
            info.available()
                .iter()
                .copied()
                .map(version_label)
                .join(", ")
        );
    }
    if id.has_native_integer_value()
        && let Some(integer) = single_varint(value)
    {
        return integer.to_string();
    }
    if value.is_empty() {
        return "(empty)".to_owned();
    }
    hex(value)
}

fn single_varint(mut value: &[u8]) -> Option<u64> {
    let integer = VarInt::decode(&mut value).ok()?;
    value.is_empty().then(|| integer.into_inner())
}

fn quic_frame_label(frame: &ObservedFrame) -> String {
    match frame {
        ObservedFrame::Padding { len } => format!("PADDING {len}"),
        ObservedFrame::Ping => "PING".to_owned(),
        ObservedFrame::Ack => "ACK".to_owned(),
        ObservedFrame::Crypto { offset, len } => {
            format!("CRYPTO {offset}..{}", offset.saturating_add(*len as u64))
        }
        ObservedFrame::Other { ty } => quic_frame_name(*ty).label(*ty),
    }
}

fn text_or_hex(value: &[u8]) -> String {
    match str::from_utf8(value) {
        Ok(text)
            if text
                .bytes()
                .all(|byte| byte.is_ascii_graphic() || byte == b' ') =>
        {
            text.to_owned()
        }
        _ => hex(value),
    }
}

fn hex(value: &[u8]) -> String {
    let shown = &value[..value.len().min(MAX_HEX_BYTES)];
    if shown.len() < value.len() {
        format!("{:#x}… ({} bytes)", hex_bytes(shown), value.len())
    } else {
        format!("{:#x}", hex_bytes(shown))
    }
}

fn none_if_empty(value: String) -> String {
    if value.is_empty() {
        "none".to_owned()
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama::{
        http::proto::h3::observation::{
            H3ObservationSnapshot, H3RequestObservation, SettingsStatus,
        },
        quic::proto::Version as QuicVersion,
    };
    use serde_json::{Value, from_str, to_value};
    use std::sync::{Arc, OnceLock};

    fn h3() -> Http3Info {
        let connection = Arc::new(H3ObservationSnapshot {
            revision: 2,
            settings_received: true,
            settings: Some(vec![ObservedSetting {
                id: 1,
                value: 4096,
                grease: false,
            }]),
            streams: vec![ObservedUniStream {
                sequence: 1,
                stream_id: 2,
                stream_type: 0,
                grease: false,
            }],
            control: vec![ObservedControlFrame {
                sequence: 2,
                frame_type: 4,
                length: 3,
                element_id: None,
                value: Box::default(),
            }],
            completeness: ObservationCompleteness {
                settings: true,
                local_settings: true,
                streams: true,
                control: true,
                qpack: true,
                fields: true,
                snapshot: true,
            },
            ..H3ObservationSnapshot::default()
        });
        Http3Info {
            request: Arc::new(H3RequestObservation {
                stream_id: 0,
                connection: connection.clone(),
                first_request: Arc::new(OnceLock::from(connection.clone())),
                fields: vec![],
                fields_complete: true,
                priority: None,
            }),
            connection,
            settings_status: SettingsStatus::Received,
            pseudo_headers: None,
        }
    }

    fn observed() -> QuicObservation {
        QuicObservation {
            connection_id: b"connection".to_vec(),
            attempt_id: b"attempt".to_vec(),
            retry_parent: None,
            first_flight: Some(FirstFlight {
                datagram_sizes: vec![1200],
                trailing_bytes: vec![0],
                version: QuicVersion::V1,
                dcid_len: 8,
                scid_len: 0,
                token_len: 0,
                first_packet_number: 0,
                packet_number_len: 1,
                packet_number_lengths: vec![1],
                frames: vec![vec![ObservedFrame::Crypto {
                    offset: 0,
                    len: 100,
                }]],
                padding: PaddingPlacement::Frames,
                coalesced: false,
                parameters: vec![TransportParameterId::from(1)],
                chosen_version: None,
                available_versions: vec![],
                packet_numbers: vec![0],
                complete: true,
            }),
            transport_parameters: vec![parameter(1, &[1])],
            client_hello_message: b"hello".to_vec(),
            completeness: CaptureCompleteness {
                datagrams: true,
                frames: true,
                client_hello: true,
                transport_parameters: true,
                original_attempt: true,
            },
        }
    }

    fn rows(table: &Table) -> Vec<(&str, &str)> {
        table
            .rows
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect()
    }

    fn parameter(id: u64, value: &[u8]) -> RawParameter {
        RawParameter {
            id: TransportParameterId::from(id),
            value: value.to_vec(),
        }
    }

    #[test]
    fn http3_observation_data_embeds_the_native_view_as_closed_json() {
        let info = h3();
        let html = http3_observation_data(Some(&info)).unwrap().into_string();
        let prefix = r#"<script type="application/json" id="rama-h3-observation">"#;
        let body = html
            .strip_prefix(prefix)
            .and_then(|rest| rest.strip_suffix("</script>"))
            .unwrap();
        assert!(!body.contains('<'));
        let value: Value = from_str(body).unwrap();
        assert_eq!(value, to_value(&info).unwrap());
        assert!(http3_observation_data(None).is_none());
    }

    #[test]
    fn http3_settings_rows_follow_wire_order_with_reserved_and_unknown_ids() {
        let settings = [
            ObservedSetting {
                id: 0x06,
                value: 65536,
                grease: false,
            },
            ObservedSetting {
                id: 0x1f * 3 + 0x21,
                value: 7,
                grease: true,
            },
            ObservedSetting {
                id: 0x01,
                value: 0,
                grease: false,
            },
            ObservedSetting {
                id: 0x4d45,
                value: 1,
                grease: false,
            },
        ];
        let table = http3_settings(Some(&settings), true);
        assert_eq!(table.title, "🚀 HTTP/3 SETTINGS");
        assert_eq!(
            rows(&table),
            [
                ("MAX_FIELD_SECTION_SIZE", "65536"),
                ("grease 0x7e", "7"),
                ("QPACK_MAX_TABLE_CAPACITY", "0"),
                ("unknown 0x4d45", "1"),
            ]
        );
        assert_eq!(
            rows(&http3_settings(None, true)),
            [("settings", "received, over capture budget")]
        );
        assert_eq!(
            rows(&http3_settings(None, false)),
            [("settings", "not received")]
        );
        assert_eq!(
            rows(&http3_settings(Some(&[]), true)),
            [("settings", "none sent")]
        );
    }

    #[test]
    fn http3_tables_render_overview_streams_and_frames() {
        let mut info = h3();
        let request = Arc::make_mut(&mut info.request);
        request.fields = vec![
            ObservedFieldRepresentation {
                representation: FieldRepresentation::StaticIndex,
                index: Some(17),
                name_huffman: false,
                value_huffman: false,
                never_index: false,
            },
            ObservedFieldRepresentation {
                representation: FieldRepresentation::LiteralName,
                index: None,
                name_huffman: true,
                value_huffman: true,
                never_index: true,
            },
        ];
        request.priority = Some(b"u=0, i".to_vec().into_boxed_slice());
        let connection = Arc::make_mut(&mut info.connection);
        connection.encoder_instructions = vec![
            ObservedEncoderInstruction::Capacity { capacity: 4096 },
            ObservedEncoderInstruction::InsertLiteral {
                name_bytes: 4,
                value_bytes: 9,
                name_huffman: false,
                value_huffman: true,
            },
        ];
        connection.streams.push(ObservedUniStream {
            sequence: 3,
            stream_id: 6,
            stream_type: 0x21,
            grease: true,
        });
        connection.connection_error = Some(0x0101);
        let tables = http3_tables(Some(&info), None);
        let titles: Vec<_> = tables.iter().map(|table| table.title.as_str()).collect();
        assert_eq!(
            titles,
            [
                "🚀 HTTP/3",
                "🚀 HTTP/3 SETTINGS",
                "🚀 HTTP/3 streams and frames"
            ]
        );
        assert_eq!(
            rows(&tables[0]),
            [
                ("SETTINGS observation", "received"),
                ("request stream id", "0"),
                ("incomplete parts", "none"),
                ("connection error", "H3_GENERAL_PROTOCOL_ERROR"),
            ]
        );
        assert_eq!(rows(&tables[1]), [("QPACK_MAX_TABLE_CAPACITY", "4096")]);
        assert_eq!(
            rows(&tables[2]),
            [
                (
                    "unidirectional streams",
                    "CONTROL (id 2), grease 0x21 (id 6)"
                ),
                ("control frames", "SETTINGS (3 bytes)"),
                (
                    "QPACK encoder instructions",
                    "capacity 4096, insert literal (name 4 B, value 9 B huffman)"
                ),
                (
                    "request field representations",
                    "static 17, literal [H-name H-value never-index]"
                ),
                ("request priority", "u=0, i"),
            ]
        );
        assert_eq!(
            rows(&http3_tables(None, None)[0]),
            [("observation", "unavailable")]
        );
    }

    #[test]
    fn quic_tables_render_versions_parameters_and_initial_flight() {
        let mut quic = observed();
        let flight = quic.first_flight.as_mut().unwrap();
        flight.datagram_sizes = vec![1200, 1252];
        flight.trailing_bytes = vec![0, 40];
        flight.packet_numbers = vec![0, 1];
        flight.packet_number_lengths = vec![1, 1];
        flight.frames = vec![
            vec![ObservedFrame::Crypto {
                offset: 0,
                len: 1141,
            }],
            vec![
                ObservedFrame::Ping,
                ObservedFrame::Crypto {
                    offset: 1141,
                    len: 376,
                },
                ObservedFrame::Padding { len: 764 },
                ObservedFrame::Other { ty: 0x1c },
            ],
        ];
        flight.chosen_version = Some(QuicVersion::V1);
        flight.available_versions = vec![QuicVersion::V1, QuicVersion::V2];
        quic.completeness.original_attempt = false;
        quic.transport_parameters = vec![
            parameter(0x0f, &[1; 8]),
            parameter(0x01, &[0x80, 0x00, 0x75, 0x30]),
            parameter(
                0x11,
                &[
                    0, 0, 0, 1, 0, 0, 0, 1, 0x6b, 0x33, 0x43, 0xcf, 0x0a, 0x1a, 0x2a, 0x3a,
                ],
            ),
            parameter(0xff04_de1b, &[0x43, 0xe8]),
            parameter(31 * 5 + 27, &[0x3b, 0x67]),
            parameter(0x2ab2, &[]),
            parameter(0x4243, &[0xaa; 40]),
        ];
        let tables = http3_tables(None, Some(&quic));
        let titles: Vec<_> = tables.iter().map(|table| table.title.as_str()).collect();
        assert_eq!(
            titles,
            [
                "🚀 HTTP/3",
                "🧊 QUIC",
                "🧊 QUIC transport parameters",
                "🧊 QUIC Initial flight"
            ]
        );
        assert_eq!(
            rows(&tables[1]),
            [
                ("version", "v1"),
                ("chosen version", "v1"),
                ("available versions", "v1, v2"),
                ("destination CID length", "8"),
                ("source CID length", "0"),
                ("token length", "0"),
                ("incomplete parts", "original attempt"),
            ]
        );
        let long_hex = format!("0x{}… (40 bytes)", "aa".repeat(MAX_HEX_BYTES));
        assert_eq!(
            rows(&tables[2]),
            [
                (
                    "initial_source_connection_id",
                    "8 bytes (connection-specific)"
                ),
                ("max_idle_timeout", "30000"),
                (
                    "version_information",
                    "chosen v1; available v1, v2, grease 0xa1a2a3a"
                ),
                ("min_ack_delay_draft07", "1000"),
                ("grease 0xb6", "0x3b67"),
                ("grease_quic_bit", "(empty)"),
                ("unknown 0x4243", long_hex.as_str()),
            ]
        );
        assert_eq!(
            rows(&tables[3]),
            [
                ("datagram #1", "1200 bytes"),
                ("datagram #2", "1252 bytes (40 trailing)"),
                ("packet numbers", "0, 1"),
                ("packet number lengths", "1, 1"),
                ("Initial #1 (pn 0)", "CRYPTO 0..1141"),
                (
                    "Initial #2 (pn 1)",
                    "PING, CRYPTO 1141..1517, PADDING 764, CONNECTION_CLOSE"
                ),
                ("padding", "PADDING frames"),
                ("coalesced", "false"),
                ("complete", "true"),
            ]
        );
    }

    #[test]
    fn quic_overview_without_first_flight_says_so() {
        let mut quic = observed();
        quic.first_flight = None;
        quic.transport_parameters.clear();
        let tables = http3_tables(None, Some(&quic));
        assert_eq!(tables.len(), 3);
        assert_eq!(
            rows(&tables[1]),
            [
                ("Initial flight", "not captured"),
                ("incomplete parts", "none")
            ]
        );
        assert_eq!(
            rows(&tables[2]),
            [("transport parameters", "none captured")]
        );
    }
}
