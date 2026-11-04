//! Connector verification must publish identity before waking ordinary admission.

use super::*;
use rama_quic_proto::Dir;
use rama_tls::client::TlsServerAuthentication;
use std::{
    future::{Future, poll_fn},
    task::Poll,
};

#[derive(Clone, Copy)]
enum Completion {
    Verified,
    Failed,
    Shutdown,
}

#[tokio::test]
async fn connector_verification_orders_identity_and_wakes_all_waiters() {
    verify(Completion::Verified).await;
}

#[tokio::test]
async fn connector_verification_failure_wakes_all_waiters() {
    verify(Completion::Failed).await;
}

#[tokio::test]
async fn connector_verification_waiters_and_task_end_on_shutdown() {
    verify(Completion::Shutdown).await;
}

async fn verify(completion: Completion) {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (client_config, server_config) = configs();
        let server = endpoint(
            Some(server_config),
            Executor::new(),
            Duration::from_millis(50),
        );
        let client = endpoint(None, Executor::new(), Duration::from_millis(50));
        let connecting = client
            .connect_with(client_config, server.local_addr().unwrap(), "localhost")
            .unwrap();
        let (c, s) = handshake(connecting, server.accept().await.unwrap()).await;
        // Ordinary connections have no additional verification barrier.
        assert!(c.is_handshake_confirmed());
        assert!(c.try_reserve_bi().unwrap().is_some());
        c.handshake_confirmed().await.unwrap();

        // Freeze the helper after raw confirmation to exercise its publication race.
        c.begin_connector_verification();
        assert!(!c.is_handshake_confirmed());
        assert!(c.try_reserve_bi().unwrap().is_none());
        assert!(!c.extensions().contains::<TlsServerAuthentication>());
        let mut budget = c.stream_budget_watch(Dir::Bi);
        let mut waiters: Vec<_> = (0..4).map(|_| Box::pin(c.handshake_confirmed())).collect();
        for waiter in &mut waiters {
            assert!(poll_fn(|cx| Poll::Ready(waiter.as_mut().poll(cx).is_pending())).await);
        }
        // Cancelling an individual wait cannot own or cancel connection verification.
        drop(waiters.pop());
        match completion {
            Completion::Verified => {
                c.extensions()
                    .insert(TlsServerAuthentication(Some("localhost".parse().unwrap())));
                c.finish_connector_verification(Ok(()));
            }
            Completion::Failed => {
                c.close(0u32, b"connector ALPN rejected");
                c.finish_connector_verification(Err(ConnectionError::LocallyClosed));
            }
            Completion::Shutdown => {
                let (started, starting) = tokio::sync::oneshot::channel();
                let (stopped, stopping) = tokio::sync::oneshot::channel::<()>();
                client.spawn_connection_task(async move {
                    let _cancelled_on_drop = stopped;
                    _ = started.send(());
                    std::future::pending::<()>().await;
                });
                starting.await.unwrap();
                client.shutdown().await;
                assert!(
                    stopping.await.is_err(),
                    "endpoint supervises the helper lifetime"
                );
            }
        }
        budget.changed().await.expect("admission was notified");
        for waiter in waiters {
            let result = waiter.await;
            if matches!(completion, Completion::Verified) {
                result.unwrap();
                assert!(c.extensions().contains::<TlsServerAuthentication>());
            } else {
                assert!(result.is_err());
                assert!(!c.extensions().contains::<TlsServerAuthentication>());
            }
        }
        if matches!(completion, Completion::Verified) {
            assert!(c.is_handshake_confirmed());
            assert!(c.try_reserve_bi().unwrap().is_some());
            exchange(&c, &s, b"reusable after cancelled waiter").await;
        } else if matches!(completion, Completion::Failed) {
            c.try_reserve_bi().unwrap_err();
        }
        drop((c, s));
        tokio::join!(client.shutdown(), server.shutdown());
    })
    .await
    .expect("verification cannot strand waiters");
}
