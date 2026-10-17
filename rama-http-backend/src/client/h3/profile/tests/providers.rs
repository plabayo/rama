use super::*;
use parking_lot::Mutex;
use rama_core::extensions::Extensions;
use rama_net::address::Host;
use rama_quic::{
    ClientConfig,
    tls::{ClientHandshake, ClientHelloCheck, QuicClientConfigProvider, TlsConfigError},
};
use rama_tls::client::{TlsClientConfig, TlsClientConfigProvider, TlsSessionProfileScope};
use rama_ua::profile::selection::DrawKey;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug)]
struct OrdinaryOnly {
    inner: Arc<dyn QuicClientConfigProvider>,
    calls: Arc<AtomicUsize>,
}

impl TlsClientConfigProvider for OrdinaryOnly {
    fn pool_id(&self, extensions: &Extensions) -> Option<TlsPoolId> {
        self.inner.pool_id(extensions)
    }

    fn pool_classifier(&self) -> ReuseKey {
        self.inner.pool_classifier()
    }

    fn authenticates_server(&self, extensions: &Extensions) -> bool {
        self.inner.authenticates_server(extensions)
    }
}

impl QuicClientConfigProvider for OrdinaryOnly {
    fn client_config(
        &self,
        policy: &TlsClientConfig,
        options: TlsOptions,
    ) -> Result<ClientConfig, TlsConfigError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.client_config(policy, options)
    }
}

#[tokio::test]
async fn ordinary_provider_support_cannot_grant_captured_tls_support() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut fixture = fixture().await;
        let calls = Arc::new(AtomicUsize::new(0));
        fixture.connector = Http3Connector::builder(Executor::new())
            .with_tls_config(fixture.connector.tls.clone())
            .with_tls_provider(Arc::new(OrdinaryOnly {
                inner: fixture.connector.tls_provider().clone(),
                calls: calls.clone(),
            }))
            .build_lazy()
            .unwrap();
        for parameters in [None, Some(&fixture.parameters)] {
            let input = fixture.target();
            let (context, _) =
                selection::selected("unsupported-provider", &fixture.capture, parameters);
            context.publish(input.extensions());
            rejected(fixture.connector.prepare_connection(&input));
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }
    })
    .await
    .unwrap();
}

#[derive(Debug)]
struct CaptureAware {
    ordinary: OrdinaryOnly,
    captured_calls: Arc<AtomicUsize>,
    scopes: Arc<Mutex<Vec<TlsSessionProfileScope>>>,
}

impl TlsClientConfigProvider for CaptureAware {
    fn pool_id(&self, extensions: &Extensions) -> Option<TlsPoolId> {
        self.ordinary.pool_id(extensions)
    }

    fn pool_classifier(&self) -> ReuseKey {
        self.ordinary.pool_classifier()
    }

    fn authenticates_server(&self, extensions: &Extensions) -> bool {
        self.ordinary.authenticates_server(extensions)
    }
}

impl QuicClientConfigProvider for CaptureAware {
    fn client_config(
        &self,
        policy: &TlsClientConfig,
        options: TlsOptions,
    ) -> Result<ClientConfig, TlsConfigError> {
        self.ordinary.client_config(policy, options)
    }

    fn prepare_client_config(
        &self,
        policy: &TlsClientConfig,
        options: TlsOptions,
        peer: Host,
        handshake: ClientHandshake,
        check: Box<ClientHelloCheck>,
    ) -> Result<Option<ClientConfig>, TlsConfigError> {
        self.captured_calls.fetch_add(1, Ordering::SeqCst);
        self.scopes.lock().push(
            policy
                .as_extensions()
                .get_ref::<TlsSessionProfileScope>()
                .unwrap()
                .clone(),
        );
        self.ordinary
            .inner
            .prepare_client_config(policy, options, peer, handshake, check)
    }
}

#[tokio::test]
async fn ordinary_requests_skip_native_capture_preparation() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut fixture = fixture().await;
        let ordinary_calls = Arc::new(AtomicUsize::new(0));
        let captured_calls = Arc::new(AtomicUsize::new(0));
        fixture.connector = Http3Connector::builder(Executor::new())
            .with_tls_config(fixture.connector.tls.clone())
            .with_tls_provider(Arc::new(CaptureAware {
                ordinary: OrdinaryOnly {
                    inner: fixture.connector.tls_provider().clone(),
                    calls: ordinary_calls.clone(),
                },
                captured_calls: captured_calls.clone(),
                scopes: Arc::default(),
            }))
            .build_lazy()
            .unwrap();
        let input = fixture.input();
        fixture.connector.prepare_connection(&input).unwrap();
        assert_eq!(ordinary_calls.load(Ordering::SeqCst), 1);
        assert_eq!(captured_calls.load(Ordering::SeqCst), 0);

        fixture.install(&input);
        fixture.connector.prepare_connection(&input).unwrap();
        assert_eq!(ordinary_calls.load(Ordering::SeqCst), 1);
        assert_eq!(captured_calls.load(Ordering::SeqCst), 1);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn current_profile_and_caller_scope_isolate_tickets_without_keying_each_draw() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut fixture = fixture().await;
        let scopes = Arc::new(Mutex::new(Vec::new()));
        fixture.connector = Http3Connector::builder(Executor::new())
            .with_tls_config(fixture.connector.tls.clone())
            .with_tls_provider(Arc::new(CaptureAware {
                ordinary: OrdinaryOnly {
                    inner: fixture.connector.tls_provider().clone(),
                    calls: Arc::default(),
                },
                captured_calls: Arc::default(),
                scopes: scopes.clone(),
            }))
            .build_lazy()
            .unwrap();
        for (profile, caller, draw) in [
            ("profile A", "tenant A", 1),
            ("profile A", "tenant A", 2),
            ("profile B", "tenant A", 1),
            ("profile A", "tenant B", 1),
        ] {
            let input = fixture.input();
            let (mut context, _) = selection::selected(profile, &fixture.capture, None);
            context.connection_key = DrawKey([draw; 32]);
            context.publish(input.extensions());
            let caller = TlsSessionProfileScope(caller.into());
            input.extensions().insert(caller.clone());
            fixture.connector.prepare_connection(&input).unwrap();
            assert_eq!(
                input.extensions().get_ref::<TlsSessionProfileScope>(),
                Some(&caller)
            );
        }
        let scopes = scopes.lock();
        assert_eq!(scopes.len(), 4);
        assert_eq!(scopes[0], scopes[1]);
        assert_ne!(scopes[0], scopes[2]);
        assert_ne!(scopes[0], scopes[3]);
    })
    .await
    .unwrap();
}
