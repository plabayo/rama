//! Initial QPACK admission must finish before the inner connector performs I/O.

use super::{qpack::QpackRequestSink, *};
use crate::profile::capture::{
    http3::{
        H3CapturedEvent, H3ClientSequenceCapture, H3SequenceCaptureLimits,
        bootstrap::{H3BootstrapCapture, H3BootstrapLimits},
    },
    pseudo_headers::{PseudoHeaderCapture, PseudoHeaderOccurrence},
};
use rama_http::proto::{
    h2::PseudoHeader,
    h3::{
        observation::{
            FieldRepresentation, InsertionFieldMatch, ObservedEncoderBindings,
            ObservedEncoderInstruction, ObservedFieldRepresentation, ObservedInsertionBinding,
        },
        qpack::EncoderPreferences,
    },
};

fn context(fields: usize, initial_insertions: bool) -> EmulationContext {
    let pseudo = CapturedSlot {
        kind: CapturedSlotKind::PseudoHeaders,
        value: PseudoHeaderCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            version: Version::HTTP_3,
            fields: [
                PseudoHeader::Method,
                PseudoHeader::Scheme,
                PseudoHeader::Authority,
                PseudoHeader::Path,
            ]
            .into_iter()
            .map(|name| PseudoHeaderOccurrence {
                name,
                representation: Some(ObservedFieldRepresentation {
                    representation: FieldRepresentation::LiteralName,
                    index: None,
                    name_huffman: false,
                    value_huffman: false,
                    never_index: false,
                }),
            })
            .collect(),
        }
        .canonical(4096)
        .unwrap(),
    };
    let request = JointCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        level: CaptureLevel::Request,
        slots: vec![
            CapturedSlot {
                kind: CapturedSlotKind::Headers,
                value: HeaderCapture {
                    completeness: ProfileCaptureCompleteness::Complete,
                    version: Version::HTTP_3,
                    fields: Box::default(),
                }
                .canonical(&HeaderCapturePolicy::default())
                .unwrap(),
            },
            pseudo.clone(),
        ]
        .into(),
    }
    .canonical(JointCaptureLimits::default())
    .unwrap();
    let mut bootstrap = H3BootstrapCapture {
        request: request.id,
        method: Method::GET,
        fields,
        bindings: ObservedEncoderBindings {
            stream_id: 0,
            complete: true,
            insertions: vec![ObservedInsertionBinding {
                instruction_index: 1,
                insertion_index: 0,
                field: InsertionFieldMatch::Unique { field_index: 3 },
            }],
        },
    };
    let mut sequence = H3ClientSequenceCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        local_settings: OrderedProtocolCapture::capture(
            ProfileCaptureCompleteness::Complete,
            OrderNamespace::Http3Setting,
            [(1, 4096u64.to_be_bytes())],
            OrderCaptureLimits::default(),
        )
        .unwrap(),
        events: vec![
            H3CapturedEvent::Stream {
                stream_id: 2,
                stream_type: 0,
            },
            H3CapturedEvent::Control {
                frame_type: 4,
                length: 0,
                element_id: None,
                value: Box::default(),
            },
            H3CapturedEvent::Stream {
                stream_id: 10,
                stream_type: 2,
            },
        ]
        .into(),
        encoder_instructions: vec![
            ObservedEncoderInstruction::Capacity { capacity: 4096 },
            ObservedEncoderInstruction::InsertLiteral {
                name_bytes: 5,
                value_bytes: 1,
                name_huffman: false,
                value_huffman: false,
            },
        ]
        .into(),
    };
    if !initial_insertions {
        bootstrap.bindings.insertions.clear();
        sequence.encoder_instructions = Box::default();
    }
    bootstrap.validate_sequence(&sequence).unwrap();

    h3_emulation_context_with_slots(
        [
            CapturedSlot {
                kind: CapturedSlotKind::Http3Sequence,
                value: sequence
                    .canonical(H3SequenceCaptureLimits::default())
                    .unwrap(),
            },
            CapturedSlot {
                kind: CapturedSlotKind::Http3Bootstrap,
                value: bootstrap.canonical(H3BootstrapLimits::default()).unwrap(),
            },
        ],
        Box::default(),
        [pseudo],
    )
}

#[tokio::test]
async fn initial_qpack_admission_rejects_unbound_fields_before_transport_io() {
    for mode in [
        ProfilePreservationMode::Strict,
        ProfilePreservationMode::BestEffort,
    ] {
        for case in 0..4 {
            let mut context = context(if case == 2 { 5 } else { 4 }, true);
            if case != 1 {
                context.selected = Arc::new(
                    context
                        .selected
                        .as_ref()
                        .clone()
                        .for_connection_bootstrap(context.seed, context.connection_key)
                        .unwrap(),
                );
            }
            let input = ConnectRequest::new("example.com:443".parse().unwrap())
                .with_application_protocol(Protocol::HTTPS);
            input
                .extensions()
                .insert(TargetHttpVersion(Version::HTTP_3));
            context.publish(input.extensions());
            input.extensions().insert(mode);
            if case == 3 {
                input.extensions().insert(EncoderPreferences {
                    target_capacity: Some(8192),
                    ..EncoderPreferences::default()
                });
            }
            let calls = Arc::new(AtomicUsize::new(0));
            let observed = calls.clone();
            let inner = service_fn(move |input: ConnectRequest| {
                observed.fetch_add(1, Ordering::Relaxed);
                async move {
                    let encoding = input.extensions().get_ref::<EncoderPreferences>().unwrap();
                    assert_eq!(encoding.target_capacity, Some(4096));
                    assert_eq!(encoding.defer_dynamic_first_section, Some(true));
                    assert!(input.extensions().contains::<ClientSettingsProfile>());
                    let conn = ServiceInput::new(());
                    conn.extensions().insert(TargetHttpVersion(Version::HTTP_3));
                    Ok::<_, ConnectionError>(EstablishedClientConnection { input, conn })
                }
            });
            let result = UserAgentEmulateHttpConnectModifier::new(inner)
                .serve(input)
                .await;
            if case == 0 {
                assert!(result.is_ok(), "{result:?}");
                assert_eq!(calls.load(Ordering::Relaxed), 1);
            } else {
                assert!(
                    result.is_err(),
                    "case {case} unexpectedly reached transport"
                );
                assert_eq!(calls.load(Ordering::Relaxed), 0, "case {case}");
            }
        }
    }
}

#[tokio::test]
async fn empty_qpack_bootstrap_keeps_ordinary_request_replay() {
    for initial_insertions in [false, true] {
        for retain_prepared in [false, true] {
            let mut context = context(4, initial_insertions);
            context.selected = Arc::new(
                context
                    .selected
                    .as_ref()
                    .clone()
                    .for_connection_bootstrap(context.seed, context.connection_key)
                    .unwrap(),
            );
            let input = ConnectRequest::new("example.com:443".parse().unwrap())
                .with_application_protocol(Protocol::HTTPS);
            input
                .extensions()
                .insert(TargetHttpVersion(Version::HTTP_3));
            context.clone().publish(input.extensions());
            input
                .extensions()
                .insert(ProfilePreservationMode::BestEffort);
            let inner = service_fn(|input: ConnectRequest| async move {
                let conn = ServiceInput::new(());
                conn.extensions().insert(TargetHttpVersion(Version::HTTP_3));
                Ok::<_, ConnectionError>(EstablishedClientConnection { input, conn })
            });
            let established = UserAgentEmulateHttpConnectModifier::new(inner)
                .serve(input)
                .await
                .unwrap();
            let prepared = established
                .input
                .extensions()
                .get_ref::<PreparedConnectionComponents>()
                .unwrap();
            assert_eq!(
                !prepared
                    .h3_sequence
                    .as_ref()
                    .unwrap()
                    .encoder_instructions
                    .is_empty(),
                initial_insertions,
            );

            // Exercise the admitted connection through the actual request modifier.
            // Removing prepared state is the ordinary-replay control. Nonempty
            // startup recipes must still install their current-field insertions.
            let request = Request::builder()
                .method(Method::GET)
                .uri("https://example.com/")
                .version(Version::HTTP_3)
                .body(())
                .unwrap();
            if retain_prepared {
                request.extensions().extend(established.input.extensions());
            } else {
                context.publish(request.extensions());
                request
                    .extensions()
                    .insert(ProfilePreservationMode::BestEffort);
            }
            let calls = Arc::new(AtomicUsize::new(0));
            let sink = QpackRequestSink {
                extensions: established.conn.extensions().clone(),
                calls: calls.clone(),
            };
            let result = ProfileEmulateHttpRequestModifier::new(sink)
                .serve(request)
                .await;
            assert!(
                result.is_ok(),
                "initial_insertions={initial_insertions}, retain_prepared={retain_prepared}: {result:?}",
            );
            let request = result.unwrap();
            assert_eq!(calls.load(Ordering::Relaxed), 1);
            let preferences = request.extensions().get_ref::<HeaderPreferences>().unwrap();
            assert_eq!(
                preferences.pseudo_headers[&PseudoHeader::Path]
                    .insertion
                    .is_some(),
                initial_insertions && retain_prepared,
            );
        }
    }
}
