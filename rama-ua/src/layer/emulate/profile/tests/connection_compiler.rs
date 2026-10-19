use super::*;
use crate::{
    layer::emulate::UserAgentEmulateHttpConnectModifierLayer,
    profile::replay::connection::compiler::{
        CompiledConnectionProfile, ConnectionProfileBindings, ConnectionProfileCompiler,
        InstalledConnectionProfile,
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

impl InstalledConnectionProfile<ConnectRequest> for Compiled {
    type Bindings = ();

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
        let inner = service_fn({
            let calls = calls.clone();
            move |input: ConnectRequest| {
                calls.fetch_add(1, Ordering::Relaxed);
                async move {
                    let installed = input.extensions().get_ref::<Applied>().unwrap();
                    assert_eq!(installed.0.is_some(), supports_versions);
                    let conn = ServiceInput::new(());
                    conn.extensions().insert(TargetHttpVersion(Version::HTTP_3));
                    Ok::<_, ConnectionError>(EstablishedClientConnection { input, conn })
                }
            }
        });
        let service = UserAgentEmulateHttpConnectModifierLayer::default()
            .with_connection_compiler(TestCompiler {
                fail: false,
                supports_versions,
                applied: applied.clone(),
            })
            .layer(inner);
        let connection = service.serve(input(extra_parameters)).await.unwrap();
        let mut expected = Vec::new();
        if !supports_versions {
            expected.push(
                ProfilePreservationDifference::UnsupportedConnectionComponent {
                    component: CapturedSlotKind::QuicVersions,
                },
            );
        }
        if extra_parameters {
            expected.push(
                ProfilePreservationDifference::UnsupportedConnectionComponent {
                    component: CapturedSlotKind::QuicParameters,
                },
            );
        }
        assert_eq!(
            connection
                .conn
                .extensions()
                .get_ref::<ProfilePreservationReport>()
                .unwrap()
                .differences
                .as_ref(),
            expected
        );
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(applied.load(Ordering::Relaxed), 1);
    }
}

#[tokio::test]
async fn compiler_errors_stop_before_dial() {
    let calls = Arc::new(AtomicUsize::new(0));
    let applied = Arc::new(AtomicUsize::new(0));
    let request = input(false);
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

#[tokio::test]
async fn caller_h3_settings_are_reported_and_compiled_output_is_applied() {
    let calls = Arc::new(AtomicUsize::new(0));
    let applied = Arc::new(AtomicUsize::new(0));
    let request = input(false);
    let caller = ClientSettingsProfile(Arc::new(Settings::new()));
    request.extensions().insert(caller.clone());
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
            .input
            .extensions()
            .get_ref::<ClientSettingsProfile>(),
        Some(&caller)
    );
    assert_eq!(
        connection
            .conn
            .extensions()
            .get_ref::<ProfilePreservationReport>()
            .unwrap()
            .differences
            .as_ref(),
        [ProfilePreservationDifference::LoweredProfileItem {
            item: LoweredProfileItem::CallerHttp3Settings
        }]
    );
}

#[tokio::test]
async fn reports_only_uncompiled_components() {
    let calls = Arc::new(AtomicUsize::new(0));
    let applied = Arc::new(AtomicUsize::new(0));
    let request = input(true);
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
                "{change:?}"
            );
            assert!(
                error
                    .to_string()
                    .contains("connection context differs from its admitted selection"),
                "{change:?}: {error}"
            );
        }
    }
}

#[derive(Debug, Clone, Copy, Extension)]
struct InputBinding(u64);

struct BindingCompiler(TestCompiler);

struct BindingCompiled {
    native: Compiled,
    binding: InputBinding,
}

impl ConnectionProfileCompiler<ConnectRequest> for BindingCompiler {
    type Compiled = BindingCompiled;

    fn compile(
        &self,
        input: &ConnectRequest,
        selection: &ConnectionSelection,
        components: &mut PreparedConnectionComponents,
    ) -> Result<Self::Compiled, BoxError> {
        Ok(BindingCompiled {
            native: self.0.compile(input, selection, components)?,
            binding: *input.extensions().get_ref::<InputBinding>().unwrap(),
        })
    }
}

impl CompiledConnectionProfile for BindingCompiled {
    fn supports(&self, component: CapturedSlotKind) -> bool {
        self.native.supports(component)
    }
}

impl InstalledConnectionProfile<ConnectRequest> for BindingCompiled {
    type Bindings = InputBinding;

    fn apply(self, extensions: &Extensions) -> InputBinding {
        self.native.apply(extensions);
        self.binding
    }
}

impl ConnectionProfileBindings<ConnectRequest> for InputBinding {
    fn check(&self, input: &ConnectRequest) -> Result<(), BoxError> {
        if input.extensions().get_ref::<Self>().map(|value| value.0) != Some(self.0) {
            return Err(BoxError::from_static_str(
                "fixture input binding changed during dial",
            ));
        }
        Ok(())
    }
}

#[tokio::test]
async fn compiler_bindings_are_checked_before_connection_publication() {
    for change_binding in [false, true] {
        let request = input(false);
        request.extensions().insert(InputBinding(7));
        let published = Extensions::new();
        let observed = published.clone();
        let applied = Arc::new(AtomicUsize::new(0));
        let service = service_fn(move |input: ConnectRequest| {
            let extensions = published.clone();
            async move {
                // Settings have moved into the native input before transport runs.
                assert!(input.extensions().get_ref::<Applied>().unwrap().0.is_some());
                assert!(
                    input
                        .extensions()
                        .get_ref::<PreparedConnectionComponents>()
                        .unwrap()
                        .quic_versions
                        .is_none()
                );
                if change_binding {
                    input.extensions().insert(InputBinding(8));
                }
                let conn = ServiceInput {
                    input: (),
                    extensions,
                };
                conn.extensions().insert(TargetHttpVersion(Version::HTTP_3));
                Ok::<_, ConnectionError>(EstablishedClientConnection { input, conn })
            }
        });
        let result = UserAgentEmulateHttpConnectModifier::new(service)
            .with_connection_compiler(BindingCompiler(TestCompiler {
                fail: false,
                supports_versions: true,
                applied: applied.clone(),
            }))
            .serve(request)
            .await;
        assert_eq!(applied.load(Ordering::Relaxed), 1);
        if change_binding {
            let error = result.unwrap_err();
            assert_eq!(error.kind(), ConnectionErrorKind::InvalidInput);
            assert!(
                error
                    .to_string()
                    .contains("fixture input binding changed during dial")
            );
            assert!(!observed.contains::<ConnectionSelection>());
            assert!(!observed.contains::<ProfilePreservationReport>());
            assert!(!observed.contains::<ConnectionReuse>());
        } else {
            result.unwrap();
            assert!(observed.contains::<ConnectionSelection>());
            assert!(observed.contains::<ProfilePreservationReport>());
            assert!(observed.contains::<ConnectionReuse>());
        }
    }
}
