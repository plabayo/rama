use super::*;
use crate::{
    layer::emulate::UserAgentEmulateHttpConnectModifierLayer,
    profile::replay::connection::compiler::{
        CompiledConnectionProfile, ConnectionProfileCompiler, InstalledConnectionProfile,
    },
};

#[derive(Clone)]
struct TestCompiler {
    fail: bool,
    supports_versions: bool,
    applied: Arc<AtomicUsize>,
}

struct Compiled {
    versions: Option<OrderedProtocolCapture>,
    applied: Arc<AtomicUsize>,
}

#[derive(Debug, Clone, Extension)]
struct Applied(Option<OrderedProtocolCapture>);

impl ConnectionProfileCompiler<ConnectRequest> for TestCompiler {
    type Compiled = Compiled;

    fn compile(
        &self,
        _input: &ConnectRequest,
        _selection: &ConnectionSelection,
        components: &mut PreparedConnectionComponents,
        _mode: ProfilePreservationMode,
    ) -> Result<Compiled, BoxError> {
        assert!(components.quic_versions.is_some());
        if self.fail {
            return Err(BoxError::from_static_str("fixture compilation error"));
        }
        Ok(Compiled {
            versions: if self.supports_versions {
                components.quic_versions.take()
            } else {
                None
            },
            applied: self.applied.clone(),
        })
    }
}

impl CompiledConnectionProfile for Compiled {
    fn supports(&self, component: CapturedSlotKind) -> bool {
        self.versions.is_some() && component == CapturedSlotKind::QuicVersions
    }
}

impl InstalledConnectionProfile for Compiled {
    fn apply(self, extensions: &Extensions) {
        self.applied.fetch_add(1, Ordering::Relaxed);
        extensions.insert(Applied(self.versions));
    }
}

fn input(extra_parameters: bool) -> ConnectRequest {
    let version = OrderedProtocolCapture::capture(
        ProfileCaptureCompleteness::Complete,
        OrderNamespace::QuicVersion,
        [(1, Vec::<u8>::new())],
        OrderCaptureLimits::default(),
    )
    .unwrap()
    .canonical(OrderCaptureLimits::default())
    .unwrap();
    let mut slots = vec![CapturedSlot {
        kind: CapturedSlotKind::QuicVersions,
        value: version,
    }];
    if extra_parameters {
        let parameters = OrderedProtocolCapture::capture(
            ProfileCaptureCompleteness::Complete,
            OrderNamespace::QuicParameter,
            [(4, vec![0])],
            OrderCaptureLimits::default(),
        )
        .unwrap()
        .canonical(OrderCaptureLimits::default())
        .unwrap();
        slots.push(CapturedSlot {
            kind: CapturedSlotKind::QuicParameters,
            value: parameters,
        });
    }
    let input = ConnectRequest::new("example.com:443".parse().unwrap())
        .with_application_protocol(Protocol::HTTPS);
    input
        .extensions()
        .insert(TargetHttpVersion(Version::HTTP_3));
    h3_emulation_context_with(slots, Box::default()).publish(input.extensions());
    input
}

fn connector(
    calls: Arc<AtomicUsize>,
) -> impl Service<
    ConnectRequest,
    Output = EstablishedClientConnection<ServiceInput<()>, ConnectRequest>,
    Error = ConnectionError,
> {
    service_fn(move |input: ConnectRequest| {
        calls.fetch_add(1, Ordering::Relaxed);
        async move {
            let installed = input.extensions().get_ref::<Applied>().unwrap();
            let versions = installed.0.as_ref().unwrap();
            assert!(matches!(versions.namespace, OrderNamespace::QuicVersion));
            assert_eq!(versions.fields.len(), 1);
            assert_eq!(versions.fields[0].id, 1);
            // The compiler owns the recipe; the request must not retain a copy.
            assert!(
                input
                    .extensions()
                    .get_ref::<PreparedConnectionComponents>()
                    .unwrap()
                    .quic_versions
                    .is_none()
            );
            let conn = ServiceInput::new(());
            conn.extensions().insert(TargetHttpVersion(Version::HTTP_3));
            Ok(EstablishedClientConnection { input, conn })
        }
    })
}

#[tokio::test]
async fn registered_compiler_enables_only_prepared_components() {
    for (supports_versions, extra_parameters) in [(true, false), (false, false), (true, true)] {
        let calls = Arc::new(AtomicUsize::new(0));
        let applied = Arc::new(AtomicUsize::new(0));
        let service = UserAgentEmulateHttpConnectModifierLayer::default()
            .with_connection_compiler(TestCompiler {
                fail: false,
                supports_versions,
                applied: applied.clone(),
            })
            .layer(connector(calls.clone()));
        let result = service.serve(input(extra_parameters)).await;
        if supports_versions && !extra_parameters {
            let connection = result.unwrap();
            assert!(
                connection
                    .conn
                    .extensions()
                    .get_ref::<ProfilePreservationReport>()
                    .unwrap()
                    .differences
                    .is_empty()
            );
            assert_eq!(calls.load(Ordering::Relaxed), 1);
            assert_eq!(applied.load(Ordering::Relaxed), 1);
        } else {
            assert_eq!(
                result.unwrap_err().kind(),
                ConnectionErrorKind::InvalidInput
            );
            assert_eq!(calls.load(Ordering::Relaxed), 0);
            assert_eq!(applied.load(Ordering::Relaxed), 0);
        }
    }
}

#[tokio::test]
async fn compiler_errors_stop_before_dial_even_in_best_effort_mode() {
    for mode in [
        ProfilePreservationMode::Strict,
        ProfilePreservationMode::BestEffort,
    ] {
        let calls = Arc::new(AtomicUsize::new(0));
        let applied = Arc::new(AtomicUsize::new(0));
        let request = input(false);
        request.extensions().insert(mode);
        let error = UserAgentEmulateHttpConnectModifier::new(connector(calls.clone()))
            .with_connection_compiler(TestCompiler {
                fail: true,
                supports_versions: true,
                applied: applied.clone(),
            })
            .serve(request)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ConnectionErrorKind::InvalidInput);
        assert!(error.to_string().contains("fixture compilation error"));
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        assert_eq!(applied.load(Ordering::Relaxed), 0);
    }
}

#[tokio::test]
async fn compiled_output_waits_for_builtin_preservation_checks() {
    let calls = Arc::new(AtomicUsize::new(0));
    let applied = Arc::new(AtomicUsize::new(0));
    let request = input(false);
    let extensions = request.extensions().clone();
    extensions.insert(ClientSettingsProfile(Arc::new(Settings::new())));
    let error = UserAgentEmulateHttpConnectModifier::new(connector(calls.clone()))
        .with_connection_compiler(TestCompiler {
            fail: false,
            supports_versions: true,
            applied: applied.clone(),
        })
        .serve(request)
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ConnectionErrorKind::InvalidInput);
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    assert_eq!(applied.load(Ordering::Relaxed), 0);
    assert!(!extensions.contains::<Applied>());
}

#[tokio::test]
async fn best_effort_reports_only_uncompiled_components() {
    let calls = Arc::new(AtomicUsize::new(0));
    let applied = Arc::new(AtomicUsize::new(0));
    let request = input(true);
    request
        .extensions()
        .insert(ProfilePreservationMode::BestEffort);
    let connection = UserAgentEmulateHttpConnectModifier::new(connector(calls.clone()))
        .with_connection_compiler(TestCompiler {
            fail: false,
            supports_versions: true,
            applied: applied.clone(),
        })
        .serve(request)
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(applied.load(Ordering::Relaxed), 1);
    assert_eq!(
        connection
            .conn
            .extensions()
            .get_ref::<ProfilePreservationReport>()
            .unwrap()
            .differences
            .as_ref(),
        &[
            ProfilePreservationDifference::UnsupportedConnectionComponent {
                component: CapturedSlotKind::QuicParameters,
            }
        ]
    );
}

#[tokio::test]
async fn admitted_connection_bindings_survive_inner_connector_io() {
    #[derive(Clone, Copy, Debug)]
    enum Change {
        None,
        RequestDraw,
        Seed,
        ConnectionDraw,
        ConnectionScope,
        Pin,
    }

    for mode in [
        ProfilePreservationMode::Strict,
        ProfilePreservationMode::BestEffort,
    ] {
        for change in [
            Change::None,
            Change::RequestDraw,
            Change::Seed,
            Change::ConnectionDraw,
            Change::ConnectionScope,
            Change::Pin,
        ] {
            let applied = Arc::new(AtomicUsize::new(0));
            let request = input(false);
            request.extensions().insert(mode);
            let published = Extensions::new();
            let observed = published.clone();
            let service = service_fn(move |input: ConnectRequest| {
                let extensions = published.clone();
                async move {
                    let mut context = EmulationContext::of(input.extensions()).unwrap().clone();
                    match change {
                        Change::None => {}
                        Change::RequestDraw => context.request_key = DrawKey([17; 32]),
                        Change::Seed => context.seed = ProfileSeed([18; 32]),
                        Change::ConnectionDraw => context.connection_key = DrawKey([19; 32]),
                        Change::ConnectionScope => {
                            input.extensions().insert(ConnectionContext {
                                token_present: Some(true),
                                ..ConnectionContext::default()
                            });
                        }
                        Change::Pin => context.pins.connection = Some(ValueId([20; 32])),
                    }
                    context.publish(input.extensions());
                    let conn = ServiceInput {
                        input: (),
                        extensions,
                    };
                    conn.extensions().insert(TargetHttpVersion(Version::HTTP_3));
                    Ok::<_, ConnectionError>(EstablishedClientConnection { input, conn })
                }
            });
            let result = UserAgentEmulateHttpConnectModifier::new(service)
                .with_connection_compiler(TestCompiler {
                    fail: false,
                    supports_versions: true,
                    applied: applied.clone(),
                })
                .serve(request)
                .await;
            assert_eq!(applied.load(Ordering::Relaxed), 1);
            if matches!(change, Change::None | Change::RequestDraw) {
                let connection = result.unwrap();
                assert!(
                    connection
                        .conn
                        .extensions()
                        .contains::<ConnectionSelection>()
                );
            } else {
                let error = result.unwrap_err();
                assert!(!observed.contains::<ConnectionSelection>());
                assert!(!observed.contains::<ProfilePreservationReport>());
                assert_eq!(
                    error.kind(),
                    ConnectionErrorKind::InvalidInput,
                    "{mode:?}: {change:?}"
                );
                assert!(
                    error
                        .to_string()
                        .contains("connection context differs from its admitted selection"),
                    "{mode:?}: {change:?}: {error}"
                );
            }
        }
    }
}
