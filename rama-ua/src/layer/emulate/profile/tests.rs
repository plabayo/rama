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
    extensions::{Extension, Extensions, ExtensionsRef},
    service::service_fn,
};
use rama_http::{
    HeaderName, Method, Request, Version,
    conn::{H2ClientContextParams, TargetHttpVersion},
    proto::h3::{ClientSettingsProfile, SettingId, Settings},
};
use rama_net::{
    Protocol,
    client::{
        ConnectRequest, ConnectionError, ConnectionErrorKind, EstablishedClientConnection,
        pool::{
            BasicConnId, BasicConnIdentifier, ConnectionReuse, ConnectionReusePolicy, LruDropPool,
            MultiplexPool, Pool, PoolPartition, PooledConnector, ReuseKey,
        },
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
        ObservationWeight, OrderCaptureLimits, OrderNamespace, OrderedProtocolCapture,
        PreparedConnectionComponents, ProfileCaptureCompleteness, ProfileKey,
        ProfileObservationScope, ProfilePreservationDifference, ProfilePreservationReport,
        RequestSelection, UntrackedDistinctSnapshot, UserAgentProfile, ValueId,
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
    database_for_clients(&["test-browser"])
}

fn database_for_clients(clients: &[&str]) -> Arc<UserAgentDatabase> {
    let profiles = clients.iter().map(|client| {
        let mut key = ProfileKey::new(*client);
        key.version = Some("1".into());
        let canonical = key.canonical(MAXIMUM_FETCH_CONTEXT_BYTES).unwrap();
        let flow = flow().canonical(MAXIMUM_FETCH_CONTEXT_BYTES).unwrap();
        crate::profile::UserAgentProfile::from_captured(AnalyzedProfile {
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
        })
    });
    Arc::new(profiles.collect())
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
        let context = EmulationContext::of(req.extensions()).unwrap();
        assert_eq!(
            context.selected.profile().key.client.as_ref(),
            "test-browser"
        );
        assert_eq!(context.seed, ProfileSeed([1; 32]));
        assert_eq!(context.connection_key, DrawKey([2; 32]));
        assert_eq!(context.request_key, DrawKey([3; 32]));
        assert!(req.extensions().contains::<SelectedUserAgentProfile>());
        assert!(req.extensions().contains::<PoolPartition>());
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
        Ok::<_, ConnectionError>(EstablishedClientConnection { input, conn })
    });
    let input = ConnectRequest::new("example.com:443".parse().unwrap())
        .with_application_protocol(Protocol::HTTPS);
    input
        .extensions()
        .insert(TargetHttpVersion(Version::HTTP_2));
    emulation_context().publish(input.extensions());
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
    pooled_profile_reuse(&["test-browser"], false).await;
}

#[tokio::test]
async fn different_profiles_reuse_their_own_connections_in_one_pool() {
    pooled_profile_reuse(&["test-browser", "other-browser"], false).await;
}

#[tokio::test]
async fn pooled_requests_inherit_connection_preservation_differences() {
    pooled_profile_reuse(&["test-browser"], true).await;
}

async fn pooled_profile_reuse(clients: &[&str], best_effort: bool) {
    let connector_calls = Arc::new(AtomicUsize::new(0));
    let transport = service_fn({
        let connector_calls = Arc::clone(&connector_calls);
        move |input: ConnectRequest| {
            let connector_calls = Arc::clone(&connector_calls);
            async move {
                connector_calls.fetch_add(1, Ordering::Relaxed);
                let selection = input.extensions().get_ref::<ConnectionSelection>().unwrap();
                let conn = RequestSink {
                    extensions: Extensions::new(),
                    profile: selection.profile,
                    connection_variant: selection.variant,
                    expected_differences: usize::from(best_effort),
                };
                conn.extensions().insert(TargetHttpVersion(Version::HTTP_2));
                Ok::<_, ConnectionError>(EstablishedClientConnection { input, conn })
            }
        }
    });
    let connector = Arc::new(PooledConnector::new(
        UserAgentEmulateHttpConnectModifier::new(transport),
        MultiplexPool::new(),
        BasicConnIdentifier::new(),
    ));
    let connect = Arc::new(service_fn(move |request: Request<()>| {
        let connector = Arc::clone(&connector);
        async move {
            let input = ConnectRequest::new("example.com:443".parse().unwrap())
                .with_application_protocol(Protocol::HTTPS);
            input
                .extensions()
                .insert(TargetHttpVersion(Version::HTTP_2));
            EmulationContext::of(request.extensions())
                .unwrap()
                .clone()
                .publish(input.extensions());

            if best_effort {
                input
                    .extensions()
                    .insert(ProfilePreservationMode::BestEffort);
                input.extensions().insert(H2ClientContextParams {
                    init_connection_window_size: Some(1_000_000),
                    ..H2ClientContextParams::default()
                });
            }
            let established = connector.serve(input).await.unwrap();
            let selection = established
                .conn
                .extensions()
                .get_ref::<ConnectionSelection>()
                .unwrap()
                .clone();
            established
                .input
                .extensions()
                .clone_to_if_absent::<ProfilePreservationReport>(request.extensions());
            ProfileEmulateHttpRequestModifier::new(established.conn)
                .serve(request)
                .await
                .unwrap();
            Ok::<_, Infallible>(selection)
        }
    }));
    let database = database_for_clients(clients);
    for (index, client) in clients.iter().enumerate() {
        let service = ProfileEmulateLayer::new(database.clone())
            .with_selector(ProfileSelector {
                client: Some((*client).into()),
                ..ProfileSelector::default()
            })
            .with_seed(ProfileSeed([1; 32]))
            .with_connection_key(DrawKey([2; 32]))
            .with_request_key(DrawKey([3; 32]))
            .with_preservation(if best_effort {
                ProfilePreservationMode::BestEffort
            } else {
                ProfilePreservationMode::Strict
            })
            .into_layer(connect.clone());

        let first = service.serve(h2_request()).await.unwrap();
        let second = service.serve(h2_request()).await.unwrap();

        let third = service.serve(h2_request()).await.unwrap();
        assert_eq!(connector_calls.load(Ordering::Relaxed), index + 1);
        assert_eq!(third.variant, first.variant);
        assert_eq!(second.variant, first.variant);
        assert_eq!(second.draw, first.draw);
    }
}

#[tokio::test]
async fn strict_connect_rejects_caller_h2_connection_window_override() {
    let inner = service_fn(|input: ConnectRequest| async move {
        Ok::<_, ConnectionError>(EstablishedClientConnection {
            input,
            conn: ServiceInput::new(()),
        })
    });
    let input = ConnectRequest::new("example.com:443".parse().unwrap())
        .with_application_protocol(Protocol::HTTPS);
    input
        .extensions()
        .insert(TargetHttpVersion(Version::HTTP_2));
    emulation_context().publish(input.extensions());
    input.extensions().insert(H2ClientContextParams {
        init_connection_window_size: Some(1_000_000),
        ..H2ClientContextParams::default()
    });

    let error = UserAgentEmulateHttpConnectModifier::new(inner)
        .serve(input)
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ConnectionErrorKind::InvalidInput);
    assert!(error.to_string().contains("InitialConnectionWindowSize"));
}

#[tokio::test]
async fn connect_modifier_rejects_an_unadvertised_negotiated_protocol() {
    let inner = service_fn(|input: ConnectRequest| async move {
        let conn = ServiceInput::new(());
        conn.extensions()
            .insert(TargetHttpVersion(Version::HTTP_11));
        Ok::<_, ConnectionError>(EstablishedClientConnection { input, conn })
    });
    let input = ConnectRequest::new("example.com:443".parse().unwrap())
        .with_application_protocol(Protocol::HTTPS);
    input
        .extensions()
        .insert(TargetHttpVersion(Version::HTTP_2));
    emulation_context().publish(input.extensions());

    let error = UserAgentEmulateHttpConnectModifier::new(inner)
        .serve(input)
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ConnectionErrorKind::Protocol);
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
        expected_differences: 0,
    };
    inner.extensions().insert(connection);
    inner
        .extensions()
        .insert(TargetHttpVersion(Version::HTTP_2));
    let request = h2_request();
    context.publish(request.extensions());

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
    expected_differences: usize,
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
        assert_eq!(
            req.extensions()
                .get_ref::<ProfilePreservationReport>()
                .unwrap()
                .differences
                .len(),
            self.expected_differences,
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
        Ok::<_, ConnectionError>(EstablishedClientConnection { input, conn })
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

#[tokio::test]
async fn repeated_connect_keeps_its_own_replay_but_rejects_caller_replacement() {
    let inner = service_fn(|input: ConnectRequest| async move {
        let conn = ServiceInput::new(());
        conn.extensions().insert(TargetHttpVersion(Version::HTTP_2));
        Ok::<_, ConnectionError>(EstablishedClientConnection { input, conn })
    });
    let modifier = UserAgentEmulateHttpConnectModifier::new(inner);
    let input = ConnectRequest::new("example.com:443".parse().unwrap())
        .with_application_protocol(Protocol::HTTPS);
    input
        .extensions()
        .insert(TargetHttpVersion(Version::HTTP_2));
    emulation_context().publish(input.extensions());
    let input = modifier.serve(input).await.unwrap().input;
    let input = modifier.serve(input).await.unwrap().input;
    assert!(
        input
            .extensions()
            .get_ref::<ProfilePreservationReport>()
            .unwrap()
            .is_exact()
    );

    let mut params = input
        .extensions()
        .get_ref::<H2ClientContextParams>()
        .unwrap()
        .clone();
    params.replay_early_frames = Some(Vec::new().into());
    input.extensions().insert(params);
    let error = modifier.serve(input).await.unwrap_err();
    assert_eq!(error.kind(), ConnectionErrorKind::InvalidInput);
    assert!(error.to_string().contains("ReplayEarlyFrames"));
}

#[derive(Debug)]
struct OrdinaryTransportReuse;

impl ConnectionReusePolicy for OrdinaryTransportReuse {
    fn classifier(&self) -> ReuseKey {
        ReuseKey::of::<Self>()
    }
    fn connection_key(&self) -> Option<ReuseKey> {
        Some(ReuseKey::of::<Self>())
    }
    fn request_key(&self, _: &Extensions) -> Option<ReuseKey> {
        Some(ReuseKey::of::<Self>())
    }
}

#[tokio::test]
async fn profile_pool_partition_separates_multiplex_connections_in_both_orders() {
    for profile_first in [false, true] {
        for transport_policy in [false, true] {
            mixed_profile_pool(MultiplexPool::new(), profile_first, transport_policy).await;
        }
    }
}

#[tokio::test]
async fn profile_pool_partition_separates_exclusive_connections_in_both_orders() {
    for profile_first in [false, true] {
        for transport_policy in [false, true] {
            // This connector-only test does not send a request through the lease.
            let pool = LruDropPool::try_new(4, 4)
                .unwrap()
                .with_drop_connection_if_no_response(false);
            mixed_profile_pool(pool, profile_first, transport_policy).await;
        }
    }
}

async fn mixed_profile_pool<P>(pool: P, profile_first: bool, transport_policy: bool)
where
    P: Pool<ServiceInput<()>, BasicConnId> + Extension,
{
    let calls = Arc::new(AtomicUsize::new(0));
    let transport = service_fn({
        let calls = calls.clone();
        move |input: ConnectRequest| {
            let calls = calls.clone();
            async move {
                calls.fetch_add(1, Ordering::Relaxed);
                let conn = ServiceInput::new(());
                conn.extensions().insert(TargetHttpVersion(Version::HTTP_2));
                if transport_policy {
                    // A transport policy can accept both requests while knowing
                    // nothing about application-level profile requirements.
                    conn.extensions()
                        .insert(ConnectionReuse::new(OrdinaryTransportReuse));
                }
                Ok::<_, ConnectionError>(EstablishedClientConnection { input, conn })
            }
        }
    });
    let connector = PooledConnector::new(
        UserAgentEmulateHttpConnectModifier::new(transport),
        pool,
        BasicConnIdentifier::new(),
    );
    for profile in [profile_first, !profile_first, profile_first, !profile_first] {
        let input = ConnectRequest::new("example.com:443".parse().unwrap())
            .with_application_protocol(Protocol::HTTPS);
        input
            .extensions()
            .insert(TargetHttpVersion(Version::HTTP_2));
        if profile {
            emulation_context().publish(input.extensions());
        }
        let established = connector.serve(input).await.unwrap();
        assert_eq!(
            established
                .conn
                .extensions()
                .contains::<ConnectionSelection>(),
            profile
        );
    }
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}

#[test]
fn profile_pool_partition_preserves_application_boundaries_and_is_idempotent() {
    struct FirstTenant;
    struct SecondTenant;
    let first = Extensions::new();
    let second = Extensions::new();
    first.insert(PoolPartition::of::<FirstTenant>());
    second.insert(PoolPartition::of::<SecondTenant>());
    let first_tenant = first.get_ref::<PoolPartition>().unwrap().clone();
    emulation_context().publish(&first);
    emulation_context().publish(&second);
    let published = first.get_ref::<PoolPartition>().unwrap().clone();
    assert_ne!(published, first_tenant);
    assert_ne!(&published, second.get_ref::<PoolPartition>().unwrap());
    emulation_context().publish(&first);
    assert_eq!(&published, first.get_ref::<PoolPartition>().unwrap());
}

fn h3_emulation_context() -> EmulationContext {
    h3_emulation_context_with_extra_slot(None)
}

fn h3_emulation_context_with_extra_slot(mut extra: Option<CapturedSlot>) -> EmulationContext {
    let original = emulation_context();
    let mut analyzed = original
        .selected
        .profile()
        .captured
        .as_ref()
        .unwrap()
        .as_ref()
        .clone();
    analyzed.components = AnalyzedProfileComponents {
        h3: Some(vec![0, 1].into()),
        ..AnalyzedProfileComponents::default()
    };
    let flow = FlowKey::Http {
        version: Version::HTTP_3,
        method: Method::GET,
        initiator: None,
        fetch: None,
        connection: ConnectionContext::default(),
    };
    let settings = OrderedProtocolCapture::capture(
        ProfileCaptureCompleteness::Complete,
        OrderNamespace::Http3Setting,
        [(SettingId::FIRST_RESERVED.value(), 17u64.to_be_bytes())],
        OrderCaptureLimits::default(),
    )
    .unwrap()
    .canonical(OrderCaptureLimits::default())
    .unwrap();
    let headers = HeaderCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        version: Version::HTTP_3,
        fields: Box::default(),
    }
    .canonical(&HeaderCapturePolicy::default())
    .unwrap();
    for (index, level, kind, value) in [
        (
            0,
            CaptureLevel::Connection,
            CapturedSlotKind::Http3Settings,
            settings.clone(),
        ),
        (1, CaptureLevel::Request, CapturedSlotKind::Headers, headers),
    ] {
        let value = JointCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            level,
            slots: {
                let mut slots = vec![CapturedSlot { kind, value }];
                if level == CaptureLevel::Connection {
                    slots.extend(extra.take());
                }
                slots.into()
            },
        }
        .canonical(JointCaptureLimits::default())
        .unwrap();
        let scope = &mut analyzed.scopes[index];
        scope.structure = value.clone();
        scope.observations.sample_values = vec![value.id].into();
        scope.observations.variants[0].value = value;
        if level == CaptureLevel::Request {
            scope.context.flow = Some(flow.canonical(MAXIMUM_FETCH_CONTEXT_BYTES).unwrap().id);
        }
    }
    let mut leaf = analyzed.scopes[0].clone();
    leaf.structure =
        OrderedProtocolCapture::from_canonical(&settings, OrderCaptureLimits::default())
            .unwrap()
            .structural(OrderCaptureLimits::default())
            .unwrap();
    leaf.context.structure = leaf.structure.id;
    leaf.id = leaf
        .context
        .canonical(MAXIMUM_FETCH_CONTEXT_BYTES)
        .unwrap()
        .id;
    let mut bucket = crate::profile::CountedObservationBucket::new(
        CanonicalDomain::Order,
        leaf.id,
        [3; 32],
        crate::profile::ProfileBucketLimits::default(),
    )
    .unwrap();
    for sequence in 1..=64 {
        bucket
            .observe(
                crate::profile::ObservationId {
                    run: [1; 16],
                    sequence,
                },
                &settings,
            )
            .unwrap();
    }
    leaf.observations = crate::profile::analyze_capture_bucket(
        &bucket,
        crate::profile::OrderAnalysisConfig::default(),
    )
    .unwrap();
    let mut scopes = analyzed.scopes.to_vec();
    scopes.push(leaf);
    analyzed.scopes = scopes.into();
    let db: UserAgentDatabase = [UserAgentProfile::from_captured(analyzed)]
        .into_iter()
        .collect();
    let selected = db
        .select(
            &SelectionRequest {
                client: ProfileSelector::default(),
                required: CapabilitySet {
                    h3: true,
                    ..CapabilitySet::default()
                },
                flow,
                pins: VariantPins::default(),
            },
            ProfileSeed([1; 32]),
            DrawKey([2; 32]),
        )
        .unwrap();
    Arc::new(selected).emulation_context(ProfileSeed([1; 32]), DrawKey([2; 32]), DrawKey([3; 32]))
}

#[tokio::test]
async fn connect_modifier_applies_selected_h3_settings_before_connect() {
    for caller_profile in [false, true] {
        let inner = service_fn(|input: ConnectRequest| async move {
            let settings = input
                .extensions()
                .get_ref::<ClientSettingsProfile>()
                .unwrap();
            assert_eq!(settings.0.entries().len(), 1);
            assert!(settings.0.entries()[0].id.is_reserved());
            assert_eq!(settings.0.entries()[0].id, SettingId::FIRST_RESERVED);
            assert_eq!(settings.0.entries()[0].value, 17);
            let conn = ServiceInput::new(());
            conn.extensions().insert(TargetHttpVersion(Version::HTTP_3));
            Ok::<_, ConnectionError>(EstablishedClientConnection { input, conn })
        });
        let input = ConnectRequest::new("example.com:443".parse().unwrap())
            .with_application_protocol(Protocol::HTTPS);
        input
            .extensions()
            .insert(TargetHttpVersion(Version::HTTP_3));
        h3_emulation_context().publish(input.extensions());
        if caller_profile {
            let context = h3_emulation_context();
            let selection = context
                .selected
                .connection(
                    &ConnectionContext::default(),
                    context.seed,
                    context.connection_key,
                )
                .unwrap();
            let settings = selection
                .prepare_components()
                .unwrap()
                .h3_client_settings(&mut selection.h3_settings_draw(context.seed))
                .unwrap()
                .unwrap();
            input.extensions().insert(settings);
        }
        UserAgentEmulateHttpConnectModifier::new(inner)
            .serve(input)
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn connect_modifier_rejects_conflicting_h3_settings_before_connect() {
    for mode in [
        ProfilePreservationMode::Strict,
        ProfilePreservationMode::BestEffort,
    ] {
        let attempts = Arc::new(AtomicUsize::new(0));
        let inner = service_fn({
            let attempts = attempts.clone();
            move |input: ConnectRequest| {
                attempts.fetch_add(1, Ordering::Relaxed);
                async move {
                    let conn = ServiceInput::new(());
                    conn.extensions().insert(TargetHttpVersion(Version::HTTP_3));
                    Ok::<_, ConnectionError>(EstablishedClientConnection { input, conn })
                }
            }
        });
        let input = ConnectRequest::new("example.com:443".parse().unwrap())
            .with_application_protocol(Protocol::HTTPS);
        input
            .extensions()
            .insert(TargetHttpVersion(Version::HTTP_3));
        h3_emulation_context().publish(input.extensions());
        input.extensions().insert(mode);
        input
            .extensions()
            .insert(ClientSettingsProfile(Arc::new(Settings::new())));
        let error = UserAgentEmulateHttpConnectModifier::new(inner)
            .serve(input)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ConnectionErrorKind::InvalidInput);
        assert_eq!(attempts.load(Ordering::Relaxed), 0);
    }
}

#[tokio::test]
async fn connect_modifier_enforces_selected_component_support_before_dial() {
    let capture = OrderedProtocolCapture::capture(
        ProfileCaptureCompleteness::Complete,
        OrderNamespace::QuicVersion,
        [(1, Vec::<u8>::new())],
        OrderCaptureLimits::default(),
    )
    .unwrap()
    .canonical(OrderCaptureLimits::default())
    .unwrap();
    for mode in [
        ProfilePreservationMode::Strict,
        ProfilePreservationMode::BestEffort,
    ] {
        let calls = Arc::new(AtomicUsize::new(0));
        let inner_calls = calls.clone();
        let inner = service_fn(move |input: ConnectRequest| {
            inner_calls.fetch_add(1, Ordering::SeqCst);
            async move {
                assert!(matches!(
                    input
                        .extensions()
                        .get_ref::<ProfilePreservationReport>()
                        .unwrap()
                        .differences
                        .as_ref(),
                    [
                        ProfilePreservationDifference::UnsupportedConnectionComponent {
                            component: CapturedSlotKind::QuicVersions
                        }
                    ]
                ));
                let conn = ServiceInput::new(());
                conn.extensions().insert(TargetHttpVersion(Version::HTTP_3));
                Ok::<_, ConnectionError>(EstablishedClientConnection { input, conn })
            }
        });
        let input = ConnectRequest::new("example.com:443".parse().unwrap())
            .with_application_protocol(Protocol::HTTPS);
        input
            .extensions()
            .insert(TargetHttpVersion(Version::HTTP_3));
        input.extensions().insert(mode);
        h3_emulation_context_with_extra_slot(Some(CapturedSlot {
            kind: CapturedSlotKind::QuicVersions,
            value: capture.clone(),
        }))
        .publish(input.extensions());
        let result = UserAgentEmulateHttpConnectModifier::new(inner)
            .serve(input)
            .await;
        if mode == ProfilePreservationMode::Strict {
            assert_eq!(
                result.unwrap_err().kind(),
                ConnectionErrorKind::InvalidInput
            );
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        } else {
            let established = result.unwrap();
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert!(
                !established
                    .conn
                    .extensions()
                    .get_ref::<ProfilePreservationReport>()
                    .unwrap()
                    .is_exact()
            );
        }
    }
}

/// Publishing is the only way in, and it always brings the pool partition along.
#[test]
fn a_published_context_always_carries_its_partition() {
    let extensions = Extensions::new();
    assert!(EmulationContext::of(&extensions).is_none());
    emulation_context().publish(&extensions);
    assert!(EmulationContext::of(&extensions).is_some());
    assert!(extensions.get_ref::<PoolPartition>().is_some());
}
