//! Static first sections retain their exact safe request association.

use super::bootstrap::{empty_initial_request, later_request};
use super::*;
use crate::cmd::serve::fp::collection::CollectionLease;
use rama::{
    http::{
        HeaderMap, HeaderValue, Version,
        header::COOKIE,
        proto::{
            h2::PseudoHeader,
            h3::{
                observation::{
                    FieldRepresentation, H3RequestObservation, ObservedFieldRepresentation,
                },
                qpack::{EncoderPreferences, FieldSectionBase, encoding::Representation},
            },
        },
    },
    service::service_fn,
    ua::profile::{
        analysis::profile::ProfileAnalysisLimits,
        capture::http3::bootstrap::{H3BootstrapCapture, H3BootstrapLimits},
        evidence::{collector::ProfileEvidenceCollector, transaction::CaptureRunId},
        format::archive::ProfileArchiveEntry,
        model::{runtime_hints::RequestInitiator, ua::UserAgentProfile},
        replay::{
            connection::{compiler::CompiledConnectionProfile, preparation::ConnectionPreparation},
            request::ProfilePreservationDifference,
        },
        selection::{
            DrawKey, ProfileSeed,
            capabilities::CapabilitySet,
            database::UserAgentDatabase,
            variants::{ProfileSelector, SelectionRequest, VariantPins},
        },
    },
};

#[derive(Debug)]
struct CapturedTransport;

impl CompiledConnectionProfile for CapturedTransport {
    fn supports(&self, component: CapturedSlotKind) -> bool {
        matches!(
            component,
            CapturedSlotKind::QuicParameters | CapturedSlotKind::QuicFirstFlight
        )
    }
}

#[tokio::test]
async fn static_initial_navigation_survives_capture_export_and_warmup_selection() {
    for path in [
        "/report",
        "/report?h3_probe=1",
        "/",
        "/another-navigation?private=uri-canary",
    ] {
        for capacity_only in [false, true] {
            let (queue, receiver) = queue(8);
            let service = CaptureLayer::new(queue.clone()).into_layer(service_fn(
                |input: Request<()>| async { Ok::<_, Infallible>(input) },
            ));
            let ingress = Extensions::new();
            ingress.insert(CollectionLease::default());
            ingress.insert(collector::tests::observed());
            let mut first = empty_initial_request(&ingress, capacity_only);
            *first.uri_mut() = Uri::parse(path).unwrap();
            // This public capture has no request-owned credential binding. The
            // auth/persistence tests below cover private records separately.
            first.headers_mut().remove(COOKIE);
            let mut native = first
                .extensions()
                .get_ref::<H3RequestObservation>()
                .unwrap()
                .clone();
            native.fields.truncate(4 + first.headers().len());
            first.extensions().insert(native.clone());
            let first = service.serve(first).await.unwrap();
            let info = data::http3_info(first.extensions()).await.unwrap();
            submit(first.extensions(), Some(&info));

            let mut later = later_request(&ingress, &native, false, true);
            *later.method_mut() = Method::GET;
            *later.uri_mut() = Uri::parse("/report").unwrap();
            later
                .headers_mut()
                .insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
            later
                .headers_mut()
                .insert("sec-fetch-dest", HeaderValue::from_static("document"));
            later
                .headers_mut()
                .insert("sec-fetch-user", HeaderValue::from_static("?1"));
            let mut observed = native.clone();
            observed.stream_id = 4;
            observed.fields = vec![
                ObservedFieldRepresentation {
                    representation: FieldRepresentation::LiteralName,
                    index: None,
                    name_huffman: false,
                    value_huffman: false,
                    never_index: false,
                };
                4 + later.headers().len()
            ];
            observed.fields[1].representation = FieldRepresentation::DynamicIndex;
            observed.fields[1].index = Some(0);
            later.extensions().insert(observed);
            let later = service.serve(later).await.unwrap();
            let info = data::http3_info(later.extensions()).await.unwrap();
            submit(later.extensions(), Some(&info));

            let records = Arc::new(Mutex::new(Vec::new()));
            worker::run(
                receiver,
                MemorySink(records.clone()),
                store_limits(),
                QueueConfig {
                    capacity: 8,
                    ..QueueConfig::default()
                },
                async {},
                current_day,
                || Ok([8; 12]),
            )
            .await
            .unwrap();
            let records = records.lock();
            assert_eq!(records.len(), 3);
            assert_eq!(
                records
                    .iter()
                    .map(|(_, capture)| capture.joint.level)
                    .collect::<Vec<_>>(),
                [
                    CaptureLevel::Request,
                    CaptureLevel::Connection,
                    CaptureLevel::Request
                ]
            );
            let first = &records[0].1;
            let connection = &records[1].1;
            let later = &records[2].1;
            let first_id = first
                .joint
                .canonical(JointCaptureLimits::default())
                .unwrap()
                .id;
            let later_id = later
                .joint
                .canonical(JointCaptureLimits::default())
                .unwrap()
                .id;
            assert_ne!(first_id, later_id);
            let reference = connection
                .joint
                .slots
                .iter()
                .find(|slot| slot.kind == CapturedSlotKind::Http3Bootstrap)
                .unwrap();
            let bootstrap =
                H3BootstrapCapture::from_canonical(&reference.value, H3BootstrapLimits::default())
                    .unwrap();
            assert_eq!(bootstrap.request, first_id);
            assert!(bootstrap.bindings.complete);
            assert!(bootstrap.bindings.insertions.is_empty());
            let Some(FlowKey::Http {
                fetch: Some(fetch), ..
            }) = first.flow.as_ref()
            else {
                panic!("actual initial navigation context")
            };
            assert!(fetch.user_activation.is_none());

            let day = current_day().unwrap();
            let limits = ProfileAnalysisLimits::default();
            let mut evidence = ProfileEvidenceCollector::new(
                &first.profile,
                false,
                CaptureRunId::new(day, [9; 12]),
                [7; 32],
                day,
                limits,
            )
            .unwrap();
            for (_, capture) in records.iter() {
                evidence.observe(day, capture).unwrap();
            }
            let analysis = ProfileArchiveEntry {
                evidence: evidence.finish(),
                sampler_seed: [7; 32],
            }
            .analyze(false, day, 14, limits)
            .unwrap()
            .analysis;
            let database: UserAgentDatabase = [UserAgentProfile::from_captured(analysis)]
                .into_iter()
                .collect();
            let seed = ProfileSeed([1; 32]);
            let connection_key = DrawKey([2; 32]);
            let request_key = DrawKey([3; 32]);
            let flow = FlowKey::Http {
                version: Version::HTTP_3,
                method: Method::GET,
                initiator: Some(RequestInitiator::Navigate),
                fetch: None,
                connection: first.connection.clone(),
            };
            let selected = database
                .select(
                    &SelectionRequest {
                        client: ProfileSelector::default(),
                        required: CapabilitySet {
                            h3: true,
                            ..CapabilitySet::default()
                        },
                        flow: flow.clone(),
                        pins: VariantPins {
                            connection: Some(
                                connection
                                    .joint
                                    .canonical(JointCaptureLimits::default())
                                    .unwrap()
                                    .id,
                            ),
                            request: None,
                        },
                    },
                    seed,
                    connection_key,
                )
                .unwrap();
            let connection = selected
                .connection(&first.connection, seed, connection_key)
                .unwrap();
            if capacity_only {
                // Preserve its first request association without claiming the
                // existing adapter can reproduce a capacity-only prefix.
                let (prepared, _) = connection
                    .prepare_for_replay_with(|_| Ok(CapturedTransport))
                    .unwrap();
                assert!(prepared.preservation_report.differences.contains(
                    &ProfilePreservationDifference::UnsupportedConnectionComponent {
                        component: CapturedSlotKind::Http3Sequence
                    }
                ));
            }
            let ordinary = selected
                .request(&connection, &flow, &HeaderMap::new(), seed, request_key)
                .unwrap();
            if !capacity_only {
                assert_eq!(
                    ordinary.variant, later_id,
                    "ordinary draw must expose the later dynamic recipe"
                );
            }
            // Check the retained later recipe independently of the initial
            // request marker; no comparison or field policy is downgraded.
            // The ordinary fixed draw above proves the failing empty-startup case.
            let mut later_request = SelectionRequest {
                client: ProfileSelector::default(),
                required: CapabilitySet {
                    h3: true,
                    ..CapabilitySet::default()
                },
                flow: flow.clone(),
                pins: selected.pins(),
            };
            later_request.pins.request = Some(later_id);
            let later_selection = database
                .select(&later_request, seed, connection_key)
                .unwrap();
            let ordinary = later_selection
                .request(&connection, &flow, &HeaderMap::new(), seed, request_key)
                .unwrap();
            let ordinary = ordinary.replay_request(&HeaderMap::new()).unwrap();
            assert_eq!(
                ordinary.qpack_base,
                Some(FieldSectionBase::FromFieldPreferences)
            );
            assert_eq!(
                ordinary.qpack_headers.unwrap().pseudo_headers[&PseudoHeader::Authority]
                    .representation,
                Representation::DynamicIndexBeforeBase
            );

            let selected = selected
                .for_connection_bootstrap(seed, connection_key)
                .unwrap();
            assert_eq!(selected.pins().request, Some(first_id));
            if !capacity_only {
                let input = Extensions::new();
                Arc::new(selected.clone())
                    .emulation_context(seed, connection_key, request_key)
                    .publish(&input);
                let (mut admitted, _) =
                    ConnectionPreparation::prepare(&input, |_, _| Ok(CapturedTransport))
                        .unwrap()
                        .unwrap();
                admitted.apply_http(&input).unwrap();
                assert_eq!(
                    input
                        .get_ref::<EncoderPreferences>()
                        .unwrap()
                        .defer_dynamic_first_section,
                    Some(true),
                    "an empty association must not enable initial insertions"
                );
            }
            let initial = selected
                .request(&connection, &flow, &HeaderMap::new(), seed, request_key)
                .unwrap();
            assert_eq!(initial.variant, first_id);
            assert!(
                initial
                    .replay_request(&HeaderMap::new())
                    .unwrap()
                    .qpack_base
                    .is_none()
            );
            assert_eq!(queue.counts().invalid_capture, 0);
        }
    }
}
