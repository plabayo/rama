use parking_lot::Mutex;

use super::{captured::captured_archive_for_slots, new_hermetic, send_cfg};
use crate::cmd::send::http::request::build as build_request;
use rama::{
    Service as _, ServiceInput,
    http::Method,
    net::{
        Protocol,
        client::{ConnectRequest, ConnectionError, EstablishedClientConnection},
    },
    service::service_fn,
    tls::{
        ProtocolVersion,
        boring::client::{BoringClientConfigExt as _, TlsConnector},
        client::TlsClientConfig,
        server::peek_client_hello_from_input,
    },
    ua::profile::capture::{
        completeness::ProfileCaptureCompleteness,
        joint::{CapturedSlot, CapturedSlotKind},
        tls::{TlsCapture, TlsCaptureLimits, TlsCaptureTransport},
    },
    utils::octets::kib,
};
use std::{io::ErrorKind, net::TcpListener, sync::Arc, time::Duration};

#[tokio::test]
async fn selected_tcp_tls_policy_is_admitted_before_the_cli_dials() {
    let capture = native_tls13_capture().await;
    let directory = rama::utils::fs::tempdir().unwrap();
    let archive = directory.path().join("captured.json");
    tokio::fs::write(
        &archive,
        captured_archive_for_slots(
            vec![CapturedSlot {
                kind: CapturedSlotKind::TcpTls,
                value: capture.canonical(TlsCaptureLimits::default()).unwrap(),
            }]
            .into(),
            None,
            Method::GET,
        ),
    )
    .await
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let uri = format!("https://{}/policy", listener.local_addr().unwrap());
    let output = directory.path().join("response");
    let cfg = send_cfg(&[
        &format!("--emulate={}", archive.display()),
        "--http1.1",
        "--tls-max",
        "1.2",
        "--output",
        output.to_str().unwrap(),
        &uri,
    ]);
    let client = new_hermetic(&cfg).await.unwrap();
    let request = build_request(&cfg, &cfg.req, false).await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(2), client.serve(request)).await;
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == ErrorKind::WouldBlock),
        "the selected TLS 1.3 recipe must conflict with the caller's TLS 1.2 ceiling before TCP dial"
    );
    let error = result
        .expect("admission terminates without a peer")
        .unwrap_err();
    assert!(format!("{error:?}").contains("version"), "{error:?}");
}

async fn native_tls13_capture() -> TlsCapture {
    let (client, peer) = tokio::io::duplex(kib(32));
    let client = Arc::new(Mutex::new(Some(client)));
    let transport = service_fn(move |input: ConnectRequest| {
        let stream = client.lock().take().unwrap();
        async move {
            Ok::<_, ConnectionError>(EstablishedClientConnection {
                input,
                conn: ServiceInput::new(stream),
            })
        }
    });
    let connector = TlsConnector::auto(transport).with_base_config(
        TlsClientConfig::new()
            .with_alpn_http_1()
            .with_min_version(ProtocolVersion::TLSv1_3)
            .with_max_version(ProtocolVersion::TLSv1_3),
    );
    let input = ConnectRequest::new("127.0.0.1:443".parse().unwrap())
        .with_application_protocol(Protocol::HTTPS);
    let client = async {
        drop(connector.serve(input).await.unwrap_err());
    };
    let peer = async {
        let (_, hello) =
            peek_client_hello_from_input(ServiceInput::new(peer), Some(Duration::from_secs(2)))
                .await
                .unwrap();
        TlsCapture::capture(
            ProfileCaptureCompleteness::Complete,
            TlsCaptureTransport::Tcp,
            &hello.expect("native client hello"),
            TlsCaptureLimits::default(),
        )
        .unwrap()
    };
    tokio::time::timeout(Duration::from_secs(3), async {
        let ((), capture) = tokio::join!(client, peer);
        capture
    })
    .await
    .unwrap()
}
