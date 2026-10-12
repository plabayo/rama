use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use rama_core::{
    ServiceInput,
    extensions::{Extensions, ExtensionsRef},
    service::service_fn,
};
use rama_http::{
    HeaderName, Method, Request, Version,
    conn::{H2ClientContextParams, TargetHttpVersion},
};
use rama_net::{
    Protocol,
    client::{
        ConnectRequest, EstablishedClientConnection,
        pool::{BasicConnIdentifier, ConnectionReuse, MultiplexPool, PooledConnector},
    },
    tls::TlsAlpn,
};
use rama_utils::octets::kib;

use super::*;
use crate::{
    layer::emulate::UserAgentEmulateHttpConnectModifier,
    profile::{
        AnalyzedCaptureVariant, AnalyzedOrderWeight, AnalyzedProfile, AnalyzedProfileComponents,
        AnalyzedProfileScope, CanonicalDomain, CanonicalValue, CaptureLevel, CapturedSlot,
        CapturedSlotKind, CountedCaptureAnalysis, CounterSnapshot, H2Capture, H2CaptureLimits,
        H2CapturedFrame, H2CapturedSetting, H2ClientParameter, HeaderCapture, HeaderCapturePolicy,
        HeaderOccurrence, HeaderValueSource, JointCapture, JointCaptureLimits, ObservationLosses,
        ObservationWeight, PreparedConnectionComponents, ProfileCaptureCompleteness, ProfileKey,
        ProfileObservationScope, ProfilePreservationDifference, ProfilePreservationReport,
        RequestSelection, UntrackedDistinctSnapshot, ValueId,
    },
};

fn counts(total: u64) -> CounterSnapshot {
    CounterSnapshot {
        total,
        untracked: total,
        values: Box::default(),
        losses: ObservationLosses {
            history_known: true,
            ..ObservationLosses::default()
        },
        untracked_distinct: UntrackedDistinctSnapshot {
            history_known: true,
            ..UntrackedDistinctSnapshot::default()
        },
    }
}

fn variant(level: CaptureLevel, value: u64) -> CanonicalValue {
    if level == CaptureLevel::Request {
        let headers = HeaderCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            version: Version::HTTP_2,
            fields: vec![HeaderOccurrence {
                name: HeaderName::from_static("user-agent"),
                occurrence: 0,
                sensitive: false,
                representation: None,
                value: HeaderValueSource::Profile(b"captured-browser".to_vec().into()),
            }]
            .into(),
        }
        .canonical(&HeaderCapturePolicy::default())
        .unwrap();
        return JointCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            level,
            slots: vec![CapturedSlot {
                kind: CapturedSlotKind::Headers,
                value: headers,
            }]
            .into(),
        }
        .canonical(JointCaptureLimits::default())
        .unwrap();
    }
    let value = H2Capture {
        completeness: ProfileCaptureCompleteness::Complete,
        frames: vec![H2CapturedFrame::Settings {
            ack: false,
            entries: vec![
                H2CapturedSetting {
                    id: 1,
                    value: 4_096,
                },
                H2CapturedSetting {
                    id: 0xf000 | value as u16,
                    value: value as u32,
                },
                H2CapturedSetting {
                    id: 1,
                    value: 8_192,
                },
            ]
            .into(),
        }]
        .into(),
    }
    .canonical(H2CaptureLimits::default())
    .unwrap();
    JointCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        level,
        slots: vec![CapturedSlot {
            kind: CapturedSlotKind::Http2EarlyFrames,
            value,
        }]
        .into(),
    }
    .canonical(JointCaptureLimits::default())
    .unwrap()
}

fn scope(
    tag: u8,
    profile: ValueId,
    flow: Option<ValueId>,
    level: CaptureLevel,
) -> AnalyzedProfileScope {
    let id = ValueId([tag; 32]);
    let value = variant(level, tag.into());
    AnalyzedProfileScope {
        id,
        context: ProfileObservationScope {
            authorized: false,
            profile,
            flow,
            connection: ConnectionContext::default(),
            structure: ValueId([tag.wrapping_add(100); 32]),
        },
        flow: None,
        structure: value.clone(),
        observations: CountedCaptureAnalysis {
            classifier_revision: 2,
            order_work: 0,
            domain: CanonicalDomain::Joint,
            scope: id,
            counts: counts(1),
            retained_samples: 1,
            sample_values: vec![value.id].into(),
            variants: vec![AnalyzedCaptureVariant {
                value,
                weight: AnalyzedOrderWeight::Counted(ObservationWeight::Exact(1)),
            }]
            .into(),
            orders: Box::default(),
            numeric: Box::default(),
        },
    }
}

fn flow() -> FlowKey {
    FlowKey::Http {
        version: Version::HTTP_2,
        method: Method::GET,
        initiator: None,
        fetch: None,
        connection: ConnectionContext::default(),
    }
}

fn database() -> Arc<UserAgentDatabase> {
    let mut key = ProfileKey::new("test-browser");
    key.version = Some("1".into());
    let canonical = key.canonical(MAXIMUM_FETCH_CONTEXT_BYTES).unwrap();
    let flow = flow().canonical(MAXIMUM_FETCH_CONTEXT_BYTES).unwrap();
    let profile = crate::profile::UserAgentProfile::from_captured(AnalyzedProfile {
        work_units: 0,
        format_version: 1,
        classifier_revision: 2,
        id: canonical.id,
        key,
        current_day: 1,
        horizon: 1,
        components: AnalyzedProfileComponents {
            h2: Some(vec![0, 1].into()),
            tls_tcp: Some(vec![0].into()),
            ..AnalyzedProfileComponents::default()
        },
        scopes: vec![
            scope(1, canonical.id, None, CaptureLevel::Connection),
            scope(2, canonical.id, Some(flow.id), CaptureLevel::Request),
        ]
        .into(),
    });
    Arc::new([profile].into_iter().collect())
}

fn emulation_context() -> EmulationContext {
    let required = CapabilitySet {
        h2: true,
        tls_tcp: true,
        ..CapabilitySet::default()
    };
    let selected = database()
        .select(
            &SelectionRequest {
                client: ProfileSelector {
                    client: Some("test-browser".into()),
                    ..ProfileSelector::default()
                },
                required,
                flow: flow(),
                pins: VariantPins::default(),
            },
            ProfileSeed([1; 32]),
            DrawKey([2; 32]),
        )
        .unwrap();
    Arc::new(selected).emulation_context(ProfileSeed([1; 32]), DrawKey([2; 32]), DrawKey([3; 32]))
}

fn h2_request() -> Request<()> {
    Request::builder()
        .method(Method::GET)
        .uri("https://example.com/")
        .version(Version::HTTP_2)
        .extension(TargetHttpVersion(Version::HTTP_2))
        .body(())
        .unwrap()
}

#[test]
fn request_capabilities_follow_real_transport_and_alpn_inputs() {
    let automatic = Request::builder()
        .uri("https://example.com/")
        .body(())
        .unwrap();
    assert_eq!(
        required_capabilities(&automatic).unwrap(),
        CapabilitySet {
            h1: true,
            h2: true,
            tls_tcp: true,
            ..CapabilitySet::default()
        }
    );

    let clear_h2 = Request::builder()
        .uri("http://example.com/")
        .version(Version::HTTP_2)
        .body(())
        .unwrap();
    assert_eq!(
        required_capabilities(&clear_h2).unwrap(),
        CapabilitySet {
            h2: true,
            ..CapabilitySet::default()
        }
    );

    let h3 = Request::builder()
        .uri("https://example.com/")
        .version(Version::HTTP_3)
        .body(())
        .unwrap();
    assert_eq!(
        required_capabilities(&h3).unwrap(),
        CapabilitySet {
            h3: true,
            tls_quic: true,
            quic: true,
            ..CapabilitySet::default()
        }
    );

    let incompatible = h2_request();
    incompatible
        .extensions()
        .insert(TlsAlpn([ApplicationProtocol::HTTP_3].into_iter().collect()));
    assert!(matches!(
        required_capabilities(&incompatible),
        Err(crate::profile::SelectionError::IncompatibleTransport)
    ));
}

#[tokio::test]
async fn profile_layer_selects_once_and_publishes_the_immutable_context() {
    let inner = service_fn(|req: Request<()>| async move {
        let context = req.extensions().get_ref::<EmulationContext>().unwrap();
        assert_eq!(
            context.selected.profile().key.client.as_ref(),
            "test-browser"
        );
        assert_eq!(context.seed, ProfileSeed([1; 32]));
        assert_eq!(context.connection_key, DrawKey([2; 32]));
        assert_eq!(context.request_key, DrawKey([3; 32]));
        assert!(req.extensions().contains::<SelectedUserAgentProfile>());
        assert_eq!(
            req.extensions()
                .get_ref::<ProfilePreservationMode>()
                .copied(),
            Some(ProfilePreservationMode::BestEffort)
        );
        Ok::<_, Infallible>(req)
    });
    let service = ProfileEmulateLayer::new(database())
        .with_selector(ProfileSelector {
            client: Some("test-browser".into()),
            ..ProfileSelector::default()
        })
        .with_seed(ProfileSeed([1; 32]))
        .with_connection_key(DrawKey([2; 32]))
        .with_request_key(DrawKey([3; 32]))
        .with_preservation(ProfilePreservationMode::BestEffort)
        .into_layer(inner);

    service.serve(h2_request()).await.unwrap();
}

#[tokio::test]
async fn connect_modifier_prepares_before_connect_and_publishes_reuse() {
    let inner = service_fn(|input: ConnectRequest| async move {
        assert!(input.extensions().contains::<ConnectionSelection>());
        assert!(
            input
                .extensions()
                .contains::<PreparedConnectionComponents>()
        );
        assert!(
            input
                .extensions()
                .get_ref::<H2ClientContextParams>()
                .is_some_and(|params| params.replay_early_frames.is_some())
        );
        let params = input
            .extensions()
            .get_ref::<H2ClientContextParams>()
            .unwrap();
        assert_eq!(params.keep_alive_interval, Some(Duration::from_secs(30)));
        assert_eq!(params.max_send_buf_size, Some(kib(128) as u32));
        assert!(matches!(
            input
                .extensions()
                .get_ref::<ProfilePreservationReport>()
                .unwrap()
                .differences
                .as_ref(),
            [ProfilePreservationDifference::RetainedH2ClientParameter {
                parameter: H2ClientParameter::KeepAliveInterval
            }]
        ));
        let conn = ServiceInput::new(());
        conn.extensions().insert(TargetHttpVersion(Version::HTTP_2));
        Ok::<_, rama_net::client::ConnectionError>(EstablishedClientConnection { input, conn })
    });
    let input = ConnectRequest::new("example.com:443".parse().unwrap())
        .with_application_protocol(Protocol::HTTPS);
    input
        .extensions()
        .insert(TargetHttpVersion(Version::HTTP_2));
    input.extensions().insert(emulation_context());
    input
        .extensions()
        .insert(ProfilePreservationMode::BestEffort);
    input.extensions().insert(H2ClientContextParams {
        keep_alive_interval: Some(Duration::from_secs(30)),
        max_send_buf_size: Some(kib(128) as u32),
        ..H2ClientContextParams::default()
    });

    let established = UserAgentEmulateHttpConnectModifier::new(inner)
        .serve(input)
        .await
        .unwrap();
    assert!(
        established
            .conn
            .extensions()
            .contains::<ConnectionSelection>()
    );
    let reuse = established
        .conn
        .extensions()
        .get_ref::<ConnectionReuse>()
        .unwrap();
    assert!(reuse.matches(established.input.extensions()));
}

#[tokio::test]
async fn profile_layer_reuses_the_connection_selected_on_the_first_pool_miss() {
    let connector_calls = Arc::new(AtomicUsize::new(0));
    let transport = service_fn({
        let connector_calls = Arc::clone(&connector_calls);
        move |input: ConnectRequest| {
            let connector_calls = Arc::clone(&connector_calls);
            async move {
                connector_calls.fetch_add(1, Ordering::Relaxed);
                let conn = ServiceInput::new(());
                conn.extensions().insert(TargetHttpVersion(Version::HTTP_2));
                Ok::<_, rama_net::client::ConnectionError>(EstablishedClientConnection {
                    input,
                    conn,
                })
            }
        }
    });
    let connector = Arc::new(PooledConnector::new(
        UserAgentEmulateHttpConnectModifier::new(transport),
        MultiplexPool::new(),
        BasicConnIdentifier::new(),
    ));
    let connect = service_fn(move |request: Request<()>| {
        let connector = Arc::clone(&connector);
        async move {
            let input = ConnectRequest::new("example.com:443".parse().unwrap())
                .with_application_protocol(Protocol::HTTPS);
            input
                .extensions()
                .insert(TargetHttpVersion(Version::HTTP_2));
            input.extensions().insert(
                request
                    .extensions()
                    .get_ref::<EmulationContext>()
                    .unwrap()
                    .clone(),
            );

            let established = connector.serve(input).await.unwrap();
            let selection = established
                .conn
                .extensions()
                .get_ref::<ConnectionSelection>()
                .unwrap()
                .clone();
            Ok::<_, Infallible>(selection)
        }
    });
    let service = ProfileEmulateLayer::new(database())
        .with_selector(ProfileSelector {
            client: Some("test-browser".into()),
            ..ProfileSelector::default()
        })
        .with_seed(ProfileSeed([1; 32]))
        .with_connection_key(DrawKey([2; 32]))
        .with_request_key(DrawKey([3; 32]))
        .into_layer(connect);

    let first = service.serve(h2_request()).await.unwrap();
    let second = service.serve(h2_request()).await.unwrap();

    assert_eq!(connector_calls.load(Ordering::Relaxed), 1);
    assert_eq!(second.variant, first.variant);
    assert_eq!(second.draw, first.draw);
}

#[tokio::test]
async fn strict_connect_rejects_caller_h2_connection_window_override() {
    let inner = service_fn(|input: ConnectRequest| async move {
        Ok::<_, rama_net::client::ConnectionError>(EstablishedClientConnection {
            input,
            conn: ServiceInput::new(()),
        })
    });
    let input = ConnectRequest::new("example.com:443".parse().unwrap())
        .with_application_protocol(Protocol::HTTPS);
    input
        .extensions()
        .insert(TargetHttpVersion(Version::HTTP_2));
    input.extensions().insert(emulation_context());
    input.extensions().insert(H2ClientContextParams {
        init_connection_window_size: Some(1_000_000),
        ..H2ClientContextParams::default()
    });

    let error = UserAgentEmulateHttpConnectModifier::new(inner)
        .serve(input)
        .await
        .unwrap_err();
    assert_eq!(
        error.kind(),
        rama_net::client::ConnectionErrorKind::InvalidInput
    );
    assert!(error.to_string().contains("InitialConnectionWindowSize"));
}

#[tokio::test]
async fn connect_modifier_rejects_an_unadvertised_negotiated_protocol() {
    let inner = service_fn(|input: ConnectRequest| async move {
        let conn = ServiceInput::new(());
        conn.extensions()
            .insert(TargetHttpVersion(Version::HTTP_11));
        Ok::<_, rama_net::client::ConnectionError>(EstablishedClientConnection { input, conn })
    });
    let input = ConnectRequest::new("example.com:443".parse().unwrap())
        .with_application_protocol(Protocol::HTTPS);
    input
        .extensions()
        .insert(TargetHttpVersion(Version::HTTP_2));
    input.extensions().insert(emulation_context());

    let error = UserAgentEmulateHttpConnectModifier::new(inner)
        .serve(input)
        .await
        .unwrap_err();
    assert_eq!(
        error.kind(),
        rama_net::client::ConnectionErrorKind::Protocol
    );
}

#[tokio::test]
async fn request_modifier_draws_from_the_actual_connection_ticket() {
    let context = emulation_context();
    let connection = context
        .selected
        .connection(
            &ConnectionContext::default(),
            context.seed,
            context.connection_key,
        )
        .unwrap();
    let inner = RequestSink {
        extensions: Extensions::new(),
        profile: connection.profile,
        connection_variant: connection.variant,
    };
    inner.extensions().insert(connection);
    inner
        .extensions()
        .insert(TargetHttpVersion(Version::HTTP_2));
    let request = h2_request();
    request.extensions().insert(context);

    ProfileEmulateHttpRequestModifier::new(inner)
        .serve(request)
        .await
        .unwrap();
}

#[derive(Debug)]
struct RequestSink {
    extensions: Extensions,
    profile: ValueId,
    connection_variant: ValueId,
}

impl ExtensionsRef for RequestSink {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl rama_core::Service<Request<()>> for RequestSink {
    type Output = Request<()>;
    type Error = Infallible;

    async fn serve(&self, req: Request<()>) -> Result<Self::Output, Self::Error> {
        let selection = req.extensions().get_ref::<RequestSelection>().unwrap();
        assert_eq!(selection.profile, self.profile);
        assert_eq!(selection.connection_variant, self.connection_variant);
        assert_eq!(
            selection
                .effective
                .flow
                .canonical(MAXIMUM_FETCH_CONTEXT_BYTES)
                .unwrap()
                .id,
            flow().canonical(MAXIMUM_FETCH_CONTEXT_BYTES).unwrap().id
        );
        assert_eq!(req.headers()["user-agent"], "captured-browser");
        assert!(
            req.extensions()
                .get_ref::<ProfilePreservationReport>()
                .unwrap()
                .is_exact()
        );
        Ok(req)
    }
}

#[tokio::test]
async fn modifiers_do_no_profile_work_without_an_emulation_context() {
    let inner = service_fn(|input: ConnectRequest| async move {
        assert!(!input.extensions().contains::<ConnectionSelection>());
        let conn = ServiceInput::new(());
        conn.extensions().insert(TargetHttpVersion(Version::HTTP_2));
        Ok::<_, rama_net::client::ConnectionError>(EstablishedClientConnection { input, conn })
    });
    let input = ConnectRequest::new("example.com:443".parse().unwrap())
        .with_application_protocol(Protocol::HTTPS);
    input
        .extensions()
        .insert(TargetHttpVersion(Version::HTTP_2));

    let established = UserAgentEmulateHttpConnectModifier::new(inner)
        .serve(input)
        .await
        .unwrap();
    assert!(
        !established
            .conn
            .extensions()
            .contains::<ConnectionSelection>()
    );
    assert!(!established.conn.extensions().contains::<ConnectionReuse>());
}
