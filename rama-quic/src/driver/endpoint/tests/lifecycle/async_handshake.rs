use std::future::pending;

use rama_crypto::dep::boring::ssl::{AsyncSelectCertError, BoxCertificateFinish, SslVerifyMode};
use rama_utils::guard::DropGuard;
use tokio::sync::oneshot;

use super::*;
use crate::{
    proto::crypto::boring::HandshakeInitializer,
    tls::{
        BoringTlsProvider, QuicClientConfigProvider as _, QuicServerConfigProvider as _, TlsOptions,
    },
};

#[tokio::test]
async fn pending_certificate_policy_is_released_when_the_udp_driver_fails() {
    tokio::time::timeout(Duration::from_secs(20), async {
        for version in [Version::V1, Version::V2] {
            let (client_config, server_config, started, dropped) = pending_policy(version);
            let server = endpoint(Some(server_config), Executor::new(), Duration::from_secs(1));
            let (socket, _gate, fault, _) = breakable_socket(None);
            let client = endpoint_with(EndpointConfig::try_with_rand_key().unwrap(), None, socket);
            let mut connecting = Box::pin(
                client
                    .connect_with(client_config, server.local_addr().unwrap(), "localhost")
                    .unwrap(),
            );
            let accepting_endpoint = server.clone();
            let mut accepting =
                tokio::spawn(async move { accepting_endpoint.accept().await.unwrap().await });
            tokio::select! {
                result = &mut connecting => panic!("completed before callback: {result:?}"),
                result = &mut accepting => panic!("server completed before callback: {result:?}"),
                result = started => result.unwrap(),
            }
            // Retain the TLS object's owner after the endpoint removes its channel.
            // The policy must be cancelled by termination, not eventual destruction.
            let retained = client
                .inner
                .state
                .lock()
                .recv_state
                .connections
                .channels
                .values()
                .next()
                .unwrap()
                .inner
                .clone();
            assert_eq!(dropped.load(Ordering::SeqCst), 0);
            fail_receiver(&client, &fault);
            // Do not poll Connecting to completion yet: its final handle drop
            // closes the protocol and would mask missing driver cancellation.
            let error = tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    if let Some(error) = retained.state.lock().error.clone() {
                        break error;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            let ConnectionError::TransportError(transport) = error else {
                panic!("fatal endpoint failure returned {error:?}");
            };
            assert_eq!(
                transport.code,
                rama_quic_proto::TransportErrorCode::INTERNAL_ERROR
            );
            assert_eq!(transport.reason, "endpoint driver future was dropped");
            assert_eq!(
                dropped.load(Ordering::SeqCst),
                1,
                "pending policy survived driver failure"
            );
            connecting.await.unwrap_err();
            drop(retained);
            accepting.abort();
            if let Err(error) = accepting.await {
                assert!(error.is_cancelled());
            }
            tokio::join!(client.shutdown(), server.shutdown());
        }
    })
    .await
    .unwrap();
}

/// Configurations whose client waits forever in its certificate policy once the server asks
/// for a certificate: `started` fires when it began, `dropped` counts its release.
fn pending_policy(
    version: Version,
) -> (
    ClientConfig,
    ServerConfig,
    oneshot::Receiver<()>,
    Arc<AtomicUsize>,
) {
    let identity = crate::test_helpers::identity();
    let alpn = || {
        [b"rama-quic-driver-failure".as_slice().into()]
            .into_iter()
            .collect()
    };
    let client_tls = TlsClientConfig::new()
        .with_alpn(alpn())
        .try_with_server_trust_anchors([identity.cert_chain.last().unwrap().clone()])
        .unwrap();
    let server_tls = TlsServerConfig::new()
        .with_alpn(alpn())
        .with_server_auth(identity);
    let (began, started) = oneshot::channel();
    let began = Arc::new(Mutex::new(Some(began)));
    let dropped = Arc::new(AtomicUsize::new(0));
    let policy_dropped = dropped.clone();
    client_tls
        .as_extensions()
        .insert(HandshakeInitializer(Arc::new(move |ssl| {
            let began = began.clone();
            let dropped = policy_dropped.clone();
            ssl.set_async_certificate_callback(move |_| {
                let dropped = dropped.clone();
                let guard = DropGuard::new(move || {
                    dropped.fetch_add(1, Ordering::SeqCst);
                });
                began.lock().take().unwrap().send(()).unwrap();
                Ok(Box::pin(async move {
                    let _guard = guard;
                    pending::<Result<BoxCertificateFinish, AsyncSelectCertError>>().await
                }))
            });
            Ok(())
        })));
    server_tls
        .as_extensions()
        .insert(HandshakeInitializer(Arc::new(|ssl| {
            ssl.set_verify(SslVerifyMode::PEER);
            Ok(())
        })));
    let mut client_config = BoringTlsProvider
        .client_config(&client_tls, TlsOptions::default())
        .unwrap();
    client_config.set_version(version).unwrap();
    let server_config = BoringTlsProvider
        .server_config(&server_tls, TlsOptions::default())
        .unwrap();
    (client_config, server_config, started, dropped)
}

/// Giving up on a connection drops its pending certificate policy at once, though the
/// connection is kept while it drains.
#[tokio::test]
async fn closing_drops_a_pending_certificate_policy_before_draining_ends() {
    tokio::time::timeout(Duration::from_secs(20), async {
        for version in [Version::V1, Version::V2] {
            let (client_config, server_config, started, dropped) = pending_policy(version);
            let server = endpoint(Some(server_config), Executor::new(), Duration::from_secs(1));
            let client = endpoint(None, Executor::new(), Duration::from_secs(1));
            let connecting = client
                .connect_with(client_config, server.local_addr().unwrap(), "localhost")
                .unwrap();
            let accepting_endpoint = server.clone();
            let accepting =
                tokio::spawn(async move { accepting_endpoint.accept().await.unwrap().await });
            started.await.unwrap();
            assert_eq!(dropped.load(Ordering::SeqCst), 0);
            drop(connecting);
            // Well within the draining period, which lasts three probe timeouts.
            tokio::time::timeout(Duration::from_millis(100), async {
                while dropped.load(Ordering::SeqCst) == 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("the pending policy outlived the close");
            accepting.abort();
            let _accepted = accepting.await;
            tokio::join!(client.shutdown(), server.shutdown());
        }
    })
    .await
    .unwrap();
}
