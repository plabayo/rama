//! Build optional profile observations from accepted request metadata.

use rama::{
    error::BoxError,
    extensions::Extensions,
    http::{
        HeaderMap, Method, Version,
        proto::{
            h2::{PseudoHeaderOrder, frame::EarlyFrameCapture},
            h3::observation::H3RequestObservation,
        },
    },
    net::stream::SocketInfo,
    quic::proto::capture::QuicObservation,
    tls::SecureTransport,
    ua::{
        UserAgent,
        profile::{
            capture::{
                completeness::ProfileCaptureCompleteness,
                headers::HeaderCapturePolicy,
                http2::{H2Capture, H2CaptureLimits},
                http3::{H3ClientSequenceCapture, H3SequenceCaptureLimits},
                joint::{
                    CaptureLevel, CapturedSlot, CapturedSlotKind, JointCapture, JointCaptureLimits,
                },
                observation::ProfileCapture,
                order::{OrderCaptureLimits, OrderNamespace, OrderedProtocolCapture},
                pseudo_headers::PseudoHeaderCapture,
                quic::{QuicFlightCapture, QuicFlightCaptureLimits},
                tls::{TlsCapture, TlsCaptureLimits, TlsCaptureTransport},
            },
            format::canonical::ProfileDataError,
            model::{
                identity::{
                    ConnectionContext, ConnectionIpFamily, FetchContext, FlowKey, ProfileKey,
                },
                runtime_hints::RequestInitiator,
            },
        },
    },
    utils::octets::kib,
};

use super::super::data::{Http3Info, Initiator};

/// The exact observed User-Agent separates unknown implementations. Missing
/// identity is not collapsed into one shared anonymous client profile.
pub(super) fn profile_key(ua: &str) -> Result<ProfileKey, ProfileDataError> {
    if ua.is_empty() {
        return Err(ProfileDataError::Incomplete("client identity"));
    }
    if ua.len() > kib(8) {
        return Err(ProfileDataError::LimitExceeded("client identity"));
    }
    let parsed = UserAgent::new(ua.to_owned());
    let profile = ProfileKey::from_user_agent(&parsed);
    profile.canonical(JointCaptureLimits::default().value_bytes)?;
    Ok(profile)
}

pub(super) fn connection_context(ext: &Extensions) -> ConnectionContext {
    ConnectionContext {
        token_present: ext
            .get_ref::<QuicObservation>()
            .and_then(|observation| observation.first_flight.as_ref())
            .map(|flight| flight.token_len != 0),
        ip_family: SocketInfo::ingress(ext).map(|socket| {
            if socket.peer_addr().ip_addr.is_ipv4() {
                ConnectionIpFamily::V4
            } else {
                ConnectionIpFamily::V6
            }
        }),
        // Offered PSK/early_data does not prove acceptance or session reuse.
        ..ConnectionContext::default()
    }
}

pub(super) fn request_capture(
    profile: ProfileKey,
    connection: ConnectionContext,
    version: Version,
    method: Method,
    initiator: &Initiator,
    headers: &HeaderMap,
    ext: &Extensions,
) -> Result<ProfileCapture, BoxError> {
    let pseudo_order = if matches!(version, Version::HTTP_2 | Version::HTTP_3) {
        Some(
            ext.get_ref::<PseudoHeaderOrder>()
                .ok_or(ProfileDataError::Incomplete("request pseudo-header order"))?,
        )
    } else {
        None
    };
    let (representations, pseudo_representations) = if version == Version::HTTP_3 {
        let observation = ext
            .get_ref::<H3RequestObservation>()
            .ok_or(ProfileDataError::Incomplete("H3 request observation"))?;
        if !observation.fields_complete {
            return Err(ProfileDataError::Incomplete("H3 request fields").into());
        }
        let count = pseudo_order
            .ok_or(ProfileDataError::Incomplete("H3 pseudo-header order"))?
            .len();
        if observation.fields.len() < count {
            return Err(ProfileDataError::Incomplete("H3 field alignment").into());
        }
        let (pseudo, regular) = observation.fields.split_at(count);
        (Some(regular), Some(pseudo))
    } else {
        (None, None)
    };
    let policy = HeaderCapturePolicy {
        bytes: JointCaptureLimits::default().value_bytes,
        ..HeaderCapturePolicy::default()
    };
    let captured = policy.capture(
        ProfileCaptureCompleteness::Complete,
        version,
        headers,
        representations,
    )?;
    let mut slots = vec![CapturedSlot {
        kind: CapturedSlotKind::Headers,
        value: captured.canonical(&policy)?,
    }];
    if let Some(order) = pseudo_order {
        let pseudo = PseudoHeaderCapture::capture(
            ProfileCaptureCompleteness::Complete,
            version,
            order,
            pseudo_representations,
            policy.bytes,
        )?;
        pseudo.validate_method(&method)?;
        slots.push(CapturedSlot {
            kind: CapturedSlotKind::PseudoHeaders,
            value: pseudo.canonical(policy.bytes)?,
        });
    }
    let flow = FlowKey::Http {
        version,
        method,
        initiator: Some(match initiator {
            Initiator::Navigator => RequestInitiator::Navigate,
            Initiator::Fetch => RequestInitiator::Fetch,
            Initiator::XMLHttpRequest => RequestInitiator::Xhr,
            Initiator::Form => RequestInitiator::Form,
            Initiator::Ws => RequestInitiator::Ws,
        }),
        fetch: FetchContext::from_headers(headers, policy.bytes)?,
        connection: connection.clone(),
    };
    Ok(ProfileCapture {
        profile,
        flow: Some(flow),
        connection,
        joint: JointCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            level: CaptureLevel::Request,
            slots: slots.into(),
        },
    })
}

pub(super) fn connection_capture(
    profile: ProfileKey,
    connection: ConnectionContext,
    version: Version,
    ext: &Extensions,
    h3: Option<&Http3Info>,
) -> Result<Option<ProfileCapture>, BoxError> {
    // Negotiated TLS with unavailable capture is not a cleartext observation.
    if ext
        .get_ref::<SecureTransport>()
        .is_some_and(|transport| transport.client_hello().is_none())
    {
        return Err(ProfileDataError::Incomplete("TLS ClientHello").into());
    }
    let mut slots = Vec::new();
    let quic = ext.get_ref::<QuicObservation>();
    let orders = OrderCaptureLimits::default();
    if version == Version::HTTP_3 {
        let observed = quic.ok_or(ProfileDataError::Incomplete("QUIC observation"))?;
        let flight_limits = QuicFlightCaptureLimits::default();
        let flight = QuicFlightCapture::capture(observed, flight_limits)?;
        slots.push(CapturedSlot {
            kind: CapturedSlotKind::QuicFirstFlight,
            value: flight.canonical(flight_limits)?,
        });
        let parameters = OrderedProtocolCapture::capture(
            ProfileCaptureCompleteness::from_complete(observed.completeness.transport_parameters),
            OrderNamespace::QuicParameter,
            observed
                .transport_parameters
                .iter()
                .map(|parameter| (u64::from(parameter.id), parameter.value.as_slice())),
            orders,
        )?;
        slots.push(CapturedSlot {
            kind: CapturedSlotKind::QuicParameters,
            value: parameters.canonical(orders)?,
        });
        let h3 = h3.ok_or(ProfileDataError::Incomplete("H3 connection observation"))?;
        let sequence_limits = H3SequenceCaptureLimits::default();
        let sequence = H3ClientSequenceCapture::capture_at_request_head(
            h3.request
                .first_request
                .get()
                .ok_or(ProfileDataError::Incomplete(
                    "H3 first request and SETTINGS boundary",
                ))?,
            sequence_limits,
        )?;
        slots.push(CapturedSlot {
            kind: CapturedSlotKind::Http3Sequence,
            value: sequence.canonical(sequence_limits)?,
        });
        let settings = h3
            .connection
            .settings
            .as_ref()
            .ok_or(ProfileDataError::Incomplete("H3 SETTINGS"))?;
        let settings = OrderedProtocolCapture::capture(
            ProfileCaptureCompleteness::from_complete(
                h3.connection.settings_received && h3.connection.completeness.settings,
            ),
            OrderNamespace::Http3Setting,
            settings
                .iter()
                .map(|setting| (setting.id, setting.value.to_be_bytes())),
            orders,
        )?;
        slots.push(CapturedSlot {
            kind: CapturedSlotKind::Http3Settings,
            value: settings.canonical(orders)?,
        });
    }
    if version == Version::HTTP_2 {
        let input = ext
            .get_ref::<EarlyFrameCapture>()
            .ok_or(ProfileDataError::Incomplete("H2 early frames"))?;
        let limits = H2CaptureLimits::default();
        let capture = H2Capture::capture(input, limits)?;
        slots.push(CapturedSlot {
            kind: CapturedSlotKind::Http2EarlyFrames,
            value: capture.canonical(limits)?,
        });
    }
    if let Some(hello) = ext
        .get_ref::<SecureTransport>()
        .and_then(SecureTransport::client_hello)
    {
        let limits = TlsCaptureLimits {
            bytes: JointCaptureLimits::default().value_bytes,
            ..TlsCaptureLimits::default()
        };
        let is_quic = version == Version::HTTP_3;
        let captured = TlsCapture::capture(
            ProfileCaptureCompleteness::from_complete(
                !is_quic || quic.is_some_and(|observation| observation.completeness.client_hello),
            ),
            if is_quic {
                TlsCaptureTransport::Quic
            } else {
                TlsCaptureTransport::Tcp
            },
            hello,
            limits,
        )?;
        slots.push(CapturedSlot {
            kind: if is_quic {
                CapturedSlotKind::QuicTls
            } else {
                CapturedSlotKind::TcpTls
            },
            value: captured.canonical(limits)?,
        });
    }
    // A complete empty tuple records the cleartext HTTP/1 connection.
    // Dropping it would make an exported header-only profile unselectable.
    if slots.is_empty() && !ext.contains::<super::super::CleartextConnection>() {
        return Err(ProfileDataError::Incomplete("cleartext connection provenance").into());
    }
    slots.sort_unstable_by_key(|slot| slot.kind);
    Ok(Some(ProfileCapture {
        profile,
        flow: None,
        connection,
        joint: JointCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            level: CaptureLevel::Connection,
            slots: slots.into_boxed_slice(),
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama::{
        http::proto::{
            h2::frame::{EarlyFrameStreamContext, Head, Kind, Settings, StreamId, WindowUpdate},
            h3::observation::{
                H3ObservationSnapshot, ObservationCompleteness, ObservedControlFrame,
                ObservedEncoderInstruction, ObservedSetting, ObservedUniStream, SettingsStatus,
            },
        },
        quic::proto::{
            Version as QuicVersion,
            capture::{CaptureCompleteness, FirstFlight, ObservedFrame, RawParameter},
            profile::PaddingPlacement,
            transport_parameters::TransportParameterId,
        },
    };
    use std::sync::{Arc, OnceLock};

    fn observed() -> QuicObservation {
        QuicObservation {
            connection_id: b"connection-canary".to_vec(),
            attempt_id: b"attempt-canary".to_vec(),
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
            transport_parameters: vec![RawParameter {
                id: TransportParameterId::from(1),
                value: vec![1],
            }],
            client_hello_message: b"hello-canary".to_vec(),
            completeness: CaptureCompleteness {
                datagrams: true,
                frames: true,
                client_hello: true,
                transport_parameters: true,
                original_attempt: true,
            },
        }
    }

    fn h3() -> Http3Info {
        let connection = Arc::new(H3ObservationSnapshot {
            revision: 2,
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
            local_settings: vec![ObservedSetting {
                id: 1,
                value: 4096,
                grease: false,
            }],
            settings_received: true,
            settings: Some(vec![ObservedSetting {
                id: 1,
                value: 4096,
                grease: false,
            }]),
            completeness: ObservationCompleteness {
                settings: true,
                snapshot: true,
                local_settings: true,
                streams: true,
                control: true,
                qpack: true,
                ..ObservationCompleteness::default()
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

    #[test]
    fn quic_connection_adapter_retains_flight_and_settings_in_one_tuple() {
        let ext = Extensions::new();
        ext.insert(observed());
        let context = connection_context(&ext);
        assert_eq!(context.token_present, Some(false));
        let captured = connection_capture(
            profile_key("synthetic/1").unwrap(),
            context,
            Version::HTTP_3,
            &ext,
            Some(&h3()),
        )
        .unwrap()
        .unwrap();
        assert_eq!(captured.joint.slots.len(), 4);
        assert_eq!(captured.joint.level, CaptureLevel::Connection);
        assert!(captured.flow.is_none());
        let slot = captured
            .joint
            .slots
            .iter()
            .find(|slot| slot.kind == CapturedSlotKind::QuicFirstFlight)
            .unwrap();
        let flight =
            QuicFlightCapture::from_canonical(&slot.value, QuicFlightCaptureLimits::default())
                .unwrap();
        assert_eq!(flight.flight.datagram_sizes, [1200]);
        let canonical = captured
            .joint
            .canonical(JointCaptureLimits::default())
            .unwrap();
        for secret in [
            b"connection-canary".as_slice(),
            b"attempt-canary",
            b"hello-canary",
        ] {
            assert!(
                !canonical
                    .bytes
                    .windows(secret.len())
                    .any(|bytes| bytes == secret)
            );
        }
    }

    #[test]
    fn quic_connection_adapter_rejects_incomplete_or_mismatched_flights() {
        for case in 0..3 {
            let mut observed = observed();
            match case {
                0 => observed.completeness.original_attempt = false,
                1 => observed.first_flight = None,
                _ => observed.transport_parameters.clear(),
            }
            let ext = Extensions::new();
            ext.insert(observed);
            connection_capture(
                profile_key("synthetic/1").unwrap(),
                connection_context(&ext),
                Version::HTTP_3,
                &ext,
                Some(&h3()),
            )
            .unwrap_err();
        }
    }

    #[test]
    fn h3_connection_sequence_uses_the_immutable_request_boundary() {
        let ext = Extensions::new();
        ext.insert(observed());
        let mut info = h3();
        let mut later = (*info.connection).clone();
        later.revision = 3;
        later.streams.push(ObservedUniStream {
            sequence: 3,
            stream_id: 6,
            stream_type: 2,
            grease: false,
        });
        later
            .encoder_instructions
            .push(ObservedEncoderInstruction::Capacity { capacity: 4096 });
        info.connection = Arc::new(later);
        let captured = connection_capture(
            profile_key("synthetic/1").unwrap(),
            connection_context(&ext),
            Version::HTTP_3,
            &ext,
            Some(&info),
        )
        .unwrap()
        .unwrap();
        let slot = captured
            .joint
            .slots
            .iter()
            .find(|slot| slot.kind == CapturedSlotKind::Http3Sequence)
            .unwrap();
        let sequence = H3ClientSequenceCapture::from_canonical(
            &slot.value,
            H3SequenceCaptureLimits::default(),
        )
        .unwrap();
        assert_eq!(sequence.events.len(), 2);
        assert!(sequence.encoder_instructions.is_empty());
        assert_eq!(info.connection.encoder_instructions.len(), 1);
    }

    #[test]
    fn preconnected_h2_ack_keeps_the_same_collected_connection_structure() {
        let mut structures = Vec::new();
        for acknowledged in [false, true] {
            let mut recorder = EarlyFrameStreamContext::new_recorder();
            let settings =
                Settings::load_observed(Head::new(Kind::Settings, 0, StreamId::zero()), &[], true)
                    .unwrap();
            recorder.record_settings_frame(&settings);
            if acknowledged {
                // The peer's SETTINGS arrived before the first request.
                let ack = Settings::load_observed(
                    Head::new(Kind::Settings, 1, StreamId::zero()),
                    &[],
                    true,
                )
                .unwrap();
                recorder.record_settings_frame(&ack);
            }
            recorder.record_windows_update_frame(WindowUpdate::new(StreamId::zero(), 100));
            let ext = Extensions::new();
            ext.insert(recorder.freeze_recorder().unwrap());
            let capture = connection_capture(
                profile_key("synthetic/1").unwrap(),
                connection_context(&ext),
                Version::HTTP_2,
                &ext,
                None,
            )
            .unwrap()
            .unwrap();
            structures.push(
                capture
                    .joint
                    .structural(JointCaptureLimits::default())
                    .unwrap()
                    .id,
            );
        }
        assert_eq!(structures[0], structures[1]);
    }

    #[test]
    fn cleartext_h1_retains_an_explicit_empty_connection() {
        let ext = Extensions::new();
        let error = connection_capture(
            profile_key("synthetic/1").unwrap(),
            connection_context(&ext),
            Version::HTTP_11,
            &ext,
            None,
        )
        .unwrap_err();
        assert!(matches!(
            error.downcast_ref::<ProfileDataError>(),
            Some(ProfileDataError::Incomplete(
                "cleartext connection provenance"
            ))
        ));
        ext.insert(super::super::super::CleartextConnection);
        let capture = connection_capture(
            profile_key("synthetic/1").unwrap(),
            connection_context(&ext),
            Version::HTTP_11,
            &ext,
            None,
        )
        .unwrap()
        .expect("cleartext connection evidence");
        assert!(capture.joint.slots.is_empty());
        assert_eq!(capture.joint.level, CaptureLevel::Connection);
        assert_eq!(
            capture
                .prepare(false, JointCaptureLimits::default())
                .unwrap()
                .buckets
                .len(),
            1
        );
    }

    #[test]
    fn secure_connections_require_the_client_hello_for_every_http_version() {
        for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
            let ext = Extensions::new();
            ext.insert(SecureTransport::default());
            ext.insert(observed());
            let error = connection_capture(
                profile_key("synthetic/1").unwrap(),
                connection_context(&ext),
                version,
                &ext,
                Some(&h3()),
            )
            .unwrap_err();
            assert!(matches!(
                error.downcast_ref::<ProfileDataError>(),
                Some(ProfileDataError::Incomplete("TLS ClientHello"))
            ));
        }
    }
}
