use super::*;
use rama_core::extensions::Extensions;
use rama_net::address::Host;
use rama_quic::{
    ClientConfig,
    tls::{QuicClientConfigProvider, TlsConfigError},
};
use rama_tls::client::{TlsClientConfig, TlsClientConfigProvider};
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
        let input = fixture.input();
        fixture.install(&input);
        rejected(fixture.connector.prepare_connection(&input));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    })
    .await
    .unwrap();
}

#[derive(Debug)]
struct CaptureAware {
    ordinary: OrdinaryOnly,
    captured_calls: Arc<AtomicUsize>,
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

    fn captured_client_config(
        &self,
        policy: &TlsClientConfig,
        peer: Host,
        capture: TlsCapture,
    ) -> Result<Option<ClientConfig>, TlsConfigError> {
        self.captured_calls.fetch_add(1, Ordering::SeqCst);
        self.ordinary
            .inner
            .captured_client_config(policy, peer, capture)
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
