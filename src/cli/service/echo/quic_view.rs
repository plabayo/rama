//! Echo presentation of QUIC and HTTP/3 observations.
//!
//! Codepoints are echoed as `{raw, name}` records; the observation types keep
//! their own serialization because captured profiles persist it.

use serde::Serialize;

use crate::{
    cli::service::wire_names::{
        Named, h3_frame_type_name, h3_setting_name, h3_stream_type_name, named, named_quic_version,
        named_transport_parameter, quic_frame_name,
    },
    http::proto::{
        h2::PseudoHeaderOrder,
        h3::observation::{
            H3ObservationView, ObservationCompleteness, ObservedControlFrame,
            ObservedEncoderInstruction, ObservedFieldRepresentation, ObservedSetting,
            ObservedUniStream, SettingsStatus,
        },
    },
    quic::proto::{
        capture::{CaptureCompleteness, FirstFlight, ObservedFrame, QuicObservation},
        profile::PaddingPlacement,
    },
};

#[derive(Debug, Serialize)]
pub(super) struct EchoQuic<'a> {
    first_flight: Option<EchoFirstFlight<'a>>,
    transport_parameters: Vec<EchoParameter<'a>>,
    completeness: CaptureCompleteness,
}

impl<'a> From<&'a QuicObservation> for EchoQuic<'a> {
    fn from(observation: &'a QuicObservation) -> Self {
        Self {
            first_flight: observation.first_flight.as_ref().map(EchoFirstFlight::from),
            transport_parameters: observation
                .transport_parameters
                .iter()
                .map(|parameter| {
                    // Connection-specific values are echoed by length only, as captures do.
                    let private = parameter.id.has_connection_specific_value();
                    EchoParameter {
                        id: named_transport_parameter(parameter.id),
                        value: (!private).then_some(parameter.value.as_slice()),
                        length: private.then_some(parameter.value.len()),
                    }
                })
                .collect(),
            completeness: observation.completeness,
        }
    }
}

#[derive(Debug, Serialize)]
struct EchoParameter<'a> {
    id: Named<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<&'a [u8]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    length: Option<usize>,
}

#[derive(Debug, Serialize)]
struct EchoFirstFlight<'a> {
    datagram_sizes: &'a [usize],
    trailing_bytes: &'a [usize],
    version: Named<String>,
    dcid_len: usize,
    scid_len: usize,
    token_len: usize,
    first_packet_number: u64,
    packet_number_len: u8,
    packet_number_lengths: &'a [u8],
    frames: Vec<Vec<EchoFrame>>,
    padding: &'a PaddingPlacement,
    coalesced: bool,
    parameters: Vec<Named<u64>>,
    chosen_version: Option<Named<String>>,
    available_versions: Vec<Named<String>>,
    packet_numbers: &'a [u64],
    complete: bool,
}

impl<'a> From<&'a FirstFlight> for EchoFirstFlight<'a> {
    fn from(flight: &'a FirstFlight) -> Self {
        Self {
            datagram_sizes: &flight.datagram_sizes,
            trailing_bytes: &flight.trailing_bytes,
            version: named_quic_version(flight.version),
            dcid_len: flight.dcid_len,
            scid_len: flight.scid_len,
            token_len: flight.token_len,
            first_packet_number: flight.first_packet_number,
            packet_number_len: flight.packet_number_len,
            packet_number_lengths: &flight.packet_number_lengths,
            frames: flight
                .frames
                .iter()
                .map(|frames| frames.iter().map(EchoFrame::from).collect())
                .collect(),
            padding: &flight.padding,
            coalesced: flight.coalesced,
            parameters: flight
                .parameters
                .iter()
                .copied()
                .map(named_transport_parameter)
                .collect(),
            chosen_version: flight.chosen_version.map(named_quic_version),
            available_versions: flight
                .available_versions
                .iter()
                .copied()
                .map(named_quic_version)
                .collect(),
            packet_numbers: &flight.packet_numbers,
            complete: flight.complete,
        }
    }
}

#[derive(Debug, Serialize)]
enum EchoFrame {
    Padding { len: usize },
    Ping,
    Ack,
    Crypto { offset: u64, len: usize },
    Other { ty: Named<u64> },
}

impl From<&ObservedFrame> for EchoFrame {
    fn from(frame: &ObservedFrame) -> Self {
        match frame {
            ObservedFrame::Padding { len } => Self::Padding { len: *len },
            ObservedFrame::Ping => Self::Ping,
            ObservedFrame::Ack => Self::Ack,
            ObservedFrame::Crypto { offset, len } => Self::Crypto {
                offset: *offset,
                len: *len,
            },
            ObservedFrame::Other { ty } => Self::Other {
                ty: named(*ty, quic_frame_name),
            },
        }
    }
}

#[derive(Debug, Serialize)]
pub(super) struct EchoH3<'a> {
    request_stream_id: u64,
    connection_revision: u64,
    request_revision: u64,
    settings_status: SettingsStatus,
    settings: Option<Vec<EchoSetting>>,
    local_settings: Vec<EchoSetting>,
    streams: Vec<EchoUniStream>,
    control: Vec<EchoControlFrame<'a>>,
    qpack: &'a [ObservedEncoderInstruction],
    priorities: &'a Option<Box<[u8]>>,
    pseudo_headers: Option<&'a PseudoHeaderOrder>,
    request_fields: &'a [ObservedFieldRepresentation],
    completeness: ObservationCompleteness,
}

impl<'a> From<H3ObservationView<'a>> for EchoH3<'a> {
    fn from(view: H3ObservationView<'a>) -> Self {
        Self {
            request_stream_id: view.request_stream_id,
            connection_revision: view.connection_revision,
            request_revision: view.request_revision,
            settings_status: view.settings_status,
            settings: view
                .settings
                .as_ref()
                .map(|settings| settings.iter().map(EchoSetting::from).collect()),
            local_settings: view.local_settings.iter().map(EchoSetting::from).collect(),
            streams: view.streams.iter().map(EchoUniStream::from).collect(),
            control: view.control.iter().map(EchoControlFrame::from).collect(),
            qpack: view.qpack,
            priorities: view.priorities,
            pseudo_headers: view.pseudo_headers,
            request_fields: view.request_fields,
            completeness: view.completeness,
        }
    }
}

#[derive(Debug, Serialize)]
struct EchoSetting {
    id: Named<u64>,
    value: u64,
    grease: bool,
}

impl From<&ObservedSetting> for EchoSetting {
    fn from(setting: &ObservedSetting) -> Self {
        Self {
            id: named(setting.id, h3_setting_name),
            value: setting.value,
            grease: setting.grease,
        }
    }
}

#[derive(Debug, Serialize)]
struct EchoUniStream {
    sequence: u64,
    stream_id: u64,
    stream_type: Named<u64>,
    grease: bool,
}

impl From<&ObservedUniStream> for EchoUniStream {
    fn from(stream: &ObservedUniStream) -> Self {
        Self {
            sequence: stream.sequence,
            stream_id: stream.stream_id,
            stream_type: named(stream.stream_type, h3_stream_type_name),
            grease: stream.grease,
        }
    }
}

#[derive(Debug, Serialize)]
struct EchoControlFrame<'a> {
    sequence: u64,
    frame_type: Named<u64>,
    length: u64,
    element_id: Option<u64>,
    value: &'a [u8],
}

impl<'a> From<&'a ObservedControlFrame> for EchoControlFrame<'a> {
    fn from(frame: &'a ObservedControlFrame) -> Self {
        Self {
            sequence: frame.sequence,
            frame_type: named(frame.frame_type, h3_frame_type_name),
            length: frame.length,
            element_id: frame.element_id,
            value: &frame.value,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic::proto::{
        Version, capture::RawParameter, transport_parameters::TransportParameterId,
    };
    use serde_json::{json, to_value};

    #[test]
    fn quic_echo_names_codepoints_and_keeps_private_values_as_lengths() {
        let observation = QuicObservation {
            connection_id: b"cid".to_vec(),
            attempt_id: b"attempt".to_vec(),
            retry_parent: None,
            first_flight: Some(FirstFlight {
                datagram_sizes: vec![1200],
                trailing_bytes: vec![0],
                version: Version::V1,
                dcid_len: 8,
                scid_len: 0,
                token_len: 0,
                first_packet_number: 0,
                packet_number_len: 1,
                packet_number_lengths: vec![1],
                frames: vec![vec![
                    ObservedFrame::Crypto { offset: 0, len: 9 },
                    ObservedFrame::Other { ty: 0x1c },
                    ObservedFrame::Padding { len: 3 },
                ]],
                padding: PaddingPlacement::Frames,
                coalesced: false,
                parameters: vec![
                    TransportParameterId::from(0x0f),
                    TransportParameterId::from(27),
                ],
                chosen_version: Some(Version::V1),
                available_versions: vec![Version::V2, Version::from_u32(0x0a1a_2a3a)],
                packet_numbers: vec![0],
                complete: true,
            }),
            transport_parameters: vec![
                RawParameter {
                    id: TransportParameterId::from(0x0f),
                    value: vec![1; 8],
                },
                RawParameter {
                    id: TransportParameterId::from(27),
                    value: vec![7],
                },
            ],
            client_hello_message: Vec::new(),
            completeness: CaptureCompleteness::default(),
        };
        let value = to_value(EchoQuic::from(&observation)).unwrap();
        let flight = &value["first_flight"];
        assert_eq!(
            flight["version"],
            json!({"raw": "0x00000001", "name": "v1"})
        );
        assert_eq!(
            flight["available_versions"],
            json!([
                {"raw": "0x6b3343cf", "name": "v2"},
                {"raw": "0x0a1a2a3a", "name": "grease"},
            ])
        );
        assert_eq!(
            flight["parameters"],
            json!([
                {"raw": 15, "name": "initial_source_connection_id"},
                {"raw": 27, "name": "grease"},
            ])
        );
        assert_eq!(
            flight["frames"],
            json!([[
                {"Crypto": {"offset": 0, "len": 9}},
                {"Other": {"ty": {"raw": 28, "name": "CONNECTION_CLOSE"}}},
                {"Padding": {"len": 3}},
            ]])
        );
        assert_eq!(flight["padding"], "Frames");
        assert_eq!(
            value["transport_parameters"],
            json!([
                {"id": {"raw": 15, "name": "initial_source_connection_id"}, "length": 8},
                {"id": {"raw": 27, "name": "grease"}, "value": [7]},
            ])
        );
        assert!(value.get("connection_id").is_none());
    }

    #[test]
    fn h3_echo_names_settings_streams_and_control_frames() {
        let view = H3ObservationView {
            request_stream_id: 0,
            connection_revision: 2,
            request_revision: 1,
            settings_status: SettingsStatus::Received,
            settings: &Some(vec![
                ObservedSetting {
                    id: 0x06,
                    value: 65536,
                    grease: false,
                },
                ObservedSetting {
                    id: 0x21,
                    value: 1,
                    grease: true,
                },
            ]),
            local_settings: &[],
            streams: &[ObservedUniStream {
                sequence: 1,
                stream_id: 2,
                stream_type: 0,
                grease: false,
            }],
            control: &[ObservedControlFrame {
                sequence: 2,
                frame_type: 4,
                length: 0,
                element_id: None,
                value: Box::default(),
            }],
            qpack: &[],
            priorities: &None,
            pseudo_headers: None,
            request_fields: &[],
            completeness: ObservationCompleteness::default(),
        };
        let value = to_value(EchoH3::from(view)).unwrap();
        assert_eq!(
            value["settings"],
            json!([
                {"id": {"raw": 6, "name": "MAX_FIELD_SECTION_SIZE"}, "value": 65536, "grease": false},
                {"id": {"raw": 33, "name": "grease"}, "value": 1, "grease": true},
            ])
        );
        assert_eq!(
            value["streams"][0]["stream_type"],
            json!({"raw": 0, "name": "CONTROL"})
        );
        assert_eq!(
            value["control"][0]["frame_type"],
            json!({"raw": 4, "name": "SETTINGS"})
        );
        assert_eq!(value["control"][0]["value"], json!([]));
        assert_eq!(value["settings_status"], "received");
    }
}
