use super::*;
use rama_tls::client::TlsClientConfigProvider;
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
    ) -> Result<ClientConfig, rama_quic::tls::TlsConfigError> {
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
        let compiled = fixture.compile(&input);
        assert!(!compiled.supports(CapturedSlotKind::QuicTls));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        compiled.apply(input.extensions());
        assert!(!input.extensions().contains::<Pending>());
    })
    .await
    .unwrap();
}
