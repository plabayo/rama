use h2_support::prelude::*;
use parking_lot::Mutex;
use rama::http::proto::h2::alt_svc::{
    ALT_SVC_QUEUE_CAPACITY, AltSvcEvent, AltSvcObserver, AltSvcObserverExtension, AltSvcOrigin,
    AltSvcSendError, AltSvcSender,
};
use rama_core::{
    extensions::{Extensions, ExtensionsRef},
    futures::StreamExt,
};
use std::sync::Arc;

#[derive(Clone, Default)]
struct Observer(Arc<Mutex<Vec<AltSvcEvent>>>);

impl AltSvcObserver for Observer {
    fn observe(&self, event: AltSvcEvent, _: &Extensions) {
        self.0.lock().push(event);
    }
}

fn advertisement(id: u32, origin: &'static str) -> frame::AltSvc {
    frame::AltSvc::new(
        StreamId::from(id),
        Bytes::from_static(origin.as_bytes()),
        Bytes::from_static(b"h3=\":443\"; ma=60"),
    )
    .unwrap()
}

#[tokio::test]
async fn altsvc_resolves_request_origins_and_ignores_unknown_streams() {
    let (io, mut peer) = mock::new();
    let (handshake_tx, handshake_rx) = tokio::sync::oneshot::channel();
    let observer = Observer::default();
    io.extensions()
        .insert(AltSvcObserverExtension::new(observer.clone()));
    let client = async move {
        let (mut client, mut connection) = client::handshake(io).await.unwrap();
        connection
            .drive(async { handshake_rx.await.unwrap() })
            .await;
        let (response, body) = client
            .send_request(
                Request::get("https://example.com/")
                    .version(Version::HTTP_2)
                    .body(())
                    .unwrap(),
                true,
            )
            .unwrap();
        connection.drive(async { response.await.unwrap() }).await;
        let events = observer.0.lock();
        assert_eq!(events.len(), 2);
        assert!(matches!(events[0].origin, AltSvcOrigin::Explicit(_)));
        let AltSvcOrigin::Request(origin) = &events[1].origin else {
            panic!("expected the request's origin");
        };
        assert_eq!(origin.authority().to_string(), "example.com:443");
        assert!(origin.is_secure());
        drop(events);
        drop(body);
        drop(client);
    };
    let peer = async move {
        peer.assert_client_handshake().await;
        handshake_tx.send(()).unwrap();
        peer.recv_frame(
            frames::headers(1)
                .request("GET", "https://example.com/")
                .eos(),
        )
        .await;
        peer.send(advertisement(0, "https://example.com").into())
            .await
            .unwrap();
        peer.send(advertisement(1, "").into()).await.unwrap();
        peer.send(advertisement(3, "").into()).await.unwrap();
        peer.send(advertisement(2, "").into()).await.unwrap();
        peer.send_frame(frames::headers(1).response(200).eos())
            .await;
    };
    join(client, peer).await;
}

#[tokio::test]
async fn altsvc_observer_receives_burst_and_clear_in_order() {
    let (io, mut peer) = mock::new();
    let (handshake_tx, handshake_rx) = tokio::sync::oneshot::channel();
    let observer = Observer::default();
    io.extensions()
        .insert(AltSvcObserverExtension::new(observer.clone()));
    let client = async move {
        let (mut client, mut connection) = client::handshake(io).await.unwrap();
        connection
            .drive(async { handshake_rx.await.unwrap() })
            .await;
        let (response, body) = client
            .send_request(
                Request::get("https://example.com/")
                    .version(Version::HTTP_2)
                    .body(())
                    .unwrap(),
                true,
            )
            .unwrap();
        connection.drive(async { response.await.unwrap() }).await;
        let events = observer.0.lock();
        assert_eq!(events.len(), ALT_SVC_QUEUE_CAPACITY + 4);
        assert!(
            events[..events.len() - 1]
                .iter()
                .all(|event| event.field_value == b"h3=\":443\"; ma=60"[..])
        );
        assert_eq!(events.last().unwrap().field_value, b"clear"[..]);
        drop(events);
        drop(body);
        drop(client);
    };
    let peer = async move {
        peer.assert_client_handshake().await;
        handshake_tx.send(()).unwrap();
        peer.recv_frame(
            frames::headers(1)
                .request("GET", "https://example.com/")
                .eos(),
        )
        .await;
        for _ in 0..ALT_SVC_QUEUE_CAPACITY + 3 {
            peer.send(advertisement(0, "https://example.com").into())
                .await
                .unwrap();
        }
        peer.send(
            frame::AltSvc::new(
                StreamId::zero(),
                Bytes::from_static(b"https://example.com"),
                Bytes::from_static(b"clear"),
            )
            .unwrap()
            .into(),
        )
        .await
        .unwrap();
        peer.send_frame(frames::headers(1).response(200).eos())
            .await;
    };
    join(client, peer).await;
}

#[tokio::test]
async fn altsvc_observation_is_opt_in() {
    let (io, mut peer) = mock::new();
    let (handshake_tx, handshake_rx) = tokio::sync::oneshot::channel();
    let extensions = io.extensions().clone();
    let client = async move {
        let (mut client, mut connection) = client::handshake(io).await.unwrap();
        connection
            .drive(async { handshake_rx.await.unwrap() })
            .await;
        let (response, body) = client
            .send_request(Request::get("https://example.com/").body(()).unwrap(), true)
            .unwrap();
        let response = connection.drive(async { response.await.unwrap() }).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!extensions.contains::<AltSvcObserverExtension>());
        drop(body);
        drop(client);
    };
    let peer = async move {
        peer.assert_client_handshake().await;
        handshake_tx.send(()).unwrap();
        peer.recv_frame(
            frames::headers(1)
                .request("GET", "https://example.com/")
                .eos(),
        )
        .await;
        // An unobserved extension frame is ignored, including its payload.
        // Length=1, ALTSVC=0x0a, stream=0: too short to hold Origin-Len.
        peer.send_bytes(&[0, 0, 1, 0x0a, 0, 0, 0, 0, 0, 0]).await;
        peer.send(advertisement(0, "https://example.com").into())
            .await
            .unwrap();
        peer.send(advertisement(1, "").into()).await.unwrap();
        peer.send_frame(frames::headers(1).response(200).eos())
            .await;
    };
    join(client, peer).await;
}

#[tokio::test]
async fn altsvc_server_emission_is_bounded_and_drains_while_idle() {
    let (io, mut peer) = mock::new();
    let extensions = io.extensions().clone();
    let peer_extensions = extensions.clone();
    let server = async move {
        let mut connection = server::handshake(io).await.unwrap();
        let sender = extensions.get_ref::<AltSvcSender>().unwrap().clone();
        for _ in 0..ALT_SVC_QUEUE_CAPACITY {
            connection
                .send_alt_svc(advertisement(0, "https://example.com"))
                .unwrap();
        }
        assert_eq!(
            sender.try_send(advertisement(0, "https://example.com")),
            Err(AltSvcSendError::Full)
        );
        assert!(connection.accept().await.is_none());
        drop(connection);
        assert_eq!(
            sender.try_send(advertisement(0, "https://example.com")),
            Err(AltSvcSendError::Closed)
        );
    };
    let peer = async move {
        peer.assert_server_handshake().await;
        for _ in 0..ALT_SVC_QUEUE_CAPACITY {
            let actual = peer.next().await.unwrap().unwrap();
            assert_eq!(actual, advertisement(0, "https://example.com").into());
        }
        peer.send(advertisement(0, "https://untrusted.example").into())
            .await
            .unwrap();
        peer.send_frame(frames::ping([9; 8])).await;
        peer.recv_frame(frames::ping([9; 8]).pong()).await;

        // Wake an already-idle driver after its original batch was flushed.
        peer_extensions
            .get_ref::<AltSvcSender>()
            .unwrap()
            .try_send(advertisement(0, "https://example.com"))
            .unwrap();
        assert_eq!(
            peer.next().await.unwrap().unwrap(),
            advertisement(0, "https://example.com").into()
        );
    };
    join(server, peer).await;
}
