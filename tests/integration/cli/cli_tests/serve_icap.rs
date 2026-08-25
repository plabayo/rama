use rama::{
    bytes::{Bytes, BytesMut},
    extensions::ExtensionsRef,
    http::{Body, Request as HttpRequest, Response as HttpResponse},
    icap::{
        client::ClientConnection,
        codec::{Header, HeaderSlot, RequestLine},
        http::ClientRequest,
        message::{EncapsulatedParts, Request},
        proto::{Method, Preview, StatusCode},
    },
    io::Io,
    net::{
        address::HostWithPort,
        client::{ConnectRequest, ConnectorService as _, EstablishedClientConnection},
    },
    tcp::client::service::TcpConnector,
};

#[cfg(feature = "boring")]
use rama::tls::{
    boring::client::TlsConnector,
    client::{ServerVerifyMode, TlsClientConfig},
};

use super::utils::{self, IcapTlsMode};

#[ignore]
#[tokio::test]
async fn test_icap_echo() {
    utils::init_tracing();
    let port = utils::reserve_loopback_port();
    let _service = utils::RamaService::serve_icap(port, IcapTlsMode::Plain);

    let EstablishedClientConnection { conn, .. } = TcpConnector::new()
        .connect(ConnectRequest::new(HostWithPort::local_ipv4(port)))
        .await
        .unwrap();
    exercise_icap_echo(conn, port).await;
}

#[cfg(feature = "boring")]
#[ignore]
#[tokio::test]
async fn test_icap_echo_over_tls_with_self_signed_certificate() {
    utils::init_tracing();
    let port = utils::reserve_loopback_port();
    let _service = utils::RamaService::serve_icap(port, IcapTlsMode::SelfSigned);

    exercise_icap_echo(tls_connect(port).await, port).await;
}

#[cfg(feature = "boring")]
#[ignore]
#[tokio::test]
async fn test_icap_echo_over_tls_with_certificate_files() {
    utils::init_tracing();
    let port = utils::reserve_loopback_port();
    let _service = utils::RamaService::serve_icap(port, IcapTlsMode::Files);

    exercise_icap_echo(tls_connect(port).await, port).await;
}

#[cfg(feature = "boring")]
async fn tls_connect(port: u16) -> rama::tls::boring::TlsStream<rama::tcp::TcpStream> {
    let connector = TlsConnector::secure(TcpConnector::new())
        .with_base_config(TlsClientConfig::new().with_server_verify(ServerVerifyMode::Disable));
    let EstablishedClientConnection { conn, .. } = connector
        .connect(ConnectRequest::new(HostWithPort::local_ipv4(port)))
        .await
        .unwrap();
    conn
}

async fn exercise_icap_echo<IO>(io: IO, port: u16)
where
    IO: Io + Unpin + ExtensionsRef,
{
    let service_uri = format!("icap://127.0.0.1:{port}/echo");
    let host = format!("127.0.0.1:{port}");
    let headers = [Header::new("Host", host.as_bytes()).unwrap()];
    let mut connection = ClientConnection::new(io);

    let request = Request::new(
        RequestLine::new(Method::Options, &service_uri).unwrap(),
        &headers,
        Some(EncapsulatedParts::null()),
    )
    .unwrap();
    let mut response = connection
        .start(request)
        .await
        .unwrap()
        .finish()
        .await
        .unwrap();
    assert_eq!(response.response().status(), StatusCode::OK);
    let mut slots = [HeaderSlot::EMPTY; 16];
    let head = response.response().parse_head(&mut slots).unwrap();
    assert_eq!(
        head.header("Methods").unwrap().as_bytes(),
        Some(&b"REQMOD, RESPMOD"[..])
    );
    assert_eq!(head.preview(), Some(Preview::new(1024)));
    while response.next_data().await.unwrap().is_some() {}
    drop(response);
    assert!(connection.is_reusable());

    let request = HttpRequest::builder()
        .method("POST")
        .uri("/request")
        .header("Host", "example.test")
        .body(Body::from("request body"))
        .unwrap();
    let request = ClientRequest::reqmod(
        RequestLine::new(Method::Reqmod, &service_uri).unwrap(),
        &headers,
        request,
        Some(Preview::new(4)),
    )
    .unwrap();
    let mut response = connection.send_http(request).await.unwrap();
    assert_eq!(response.icap().status(), StatusCode::OK);
    assert_eq!(
        response.request().unwrap().uri().path().unwrap(),
        "/request"
    );
    assert_eq!(
        collect(&mut response).await,
        Bytes::from_static(b"request body")
    );
    drop(response);
    assert!(connection.is_reusable());

    let request = HttpRequest::builder()
        .method("GET")
        .uri("/response")
        .header("Host", "example.test")
        .body(())
        .unwrap();
    let response = HttpResponse::builder()
        .status(200)
        .header("Content-Type", "text/plain")
        .body(Body::from("response body"))
        .unwrap();
    let request = ClientRequest::respmod(
        RequestLine::new(Method::Respmod, &service_uri).unwrap(),
        &headers,
        &request,
        response,
        Some(Preview::new(4)),
    )
    .unwrap();
    let mut response = connection.send_http(request).await.unwrap();
    assert_eq!(response.icap().status(), StatusCode::OK);
    assert_eq!(response.response().unwrap().status(), 200);
    assert_eq!(
        collect(&mut response).await,
        Bytes::from_static(b"response body")
    );
    drop(response);
    assert!(connection.is_reusable());
}

async fn collect<IO>(response: &mut rama::icap::http::ClientResponse<'_, IO>) -> Bytes
where
    IO: Io + Unpin + ExtensionsRef,
{
    let mut bytes = BytesMut::new();
    while let Some(data) = response.next_data().await.unwrap() {
        bytes.extend_from_slice(&data);
    }
    bytes.freeze()
}
