//! Exercise real proxy processes against an origin that resets after its response.

use std::{convert::Infallible, fmt::Debug, net::SocketAddr, time::Duration};

use rama::{
    Service,
    io::Io,
    service::service_fn,
    tcp::{TcpStream, posted_recv::PostedRecv},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinHandle,
};

fn body() -> Vec<u8> {
    (0..6554).map(|i| b'a' + (i % 26) as u8).collect()
}

fn response() -> Vec<u8> {
    let body = body();
    let mut bytes = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len(),
    )
    .into_bytes();
    bytes.extend_from_slice(&body);
    bytes
}

async fn read_head(stream: &mut (impl Io + Unpin)) -> Vec<u8> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        assert!(head.len() < 16 * 1024, "HTTP head exceeded test limit");
        head.push(stream.read_u8().await.expect("read HTTP head"));
    }
    head
}

async fn serve_response(mut stream: impl Io + Unpin) -> Result<(), Infallible> {
    read_head(&mut stream).await;
    stream.write_all(&response()).await.unwrap();
    stream.flush().await.unwrap();
    // Let the loopback transport deliver the write before the abortive close,
    // which could otherwise discard the origin's own unsent bytes. No TLS
    // close_notify or TCP shutdown: the raw socket has zero linger set below.
    tokio::time::sleep(Duration::from_millis(200)).await;
    Ok(())
}

struct Origin {
    addr: SocketAddr,
    task: JoinHandle<()>,
}

impl Drop for Origin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn origin<S>(service: S) -> Origin
where
    S: Service<TcpStream, Error: Debug>,
{
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        stream.set_zero_linger().unwrap();
        service.serve(TcpStream::new(stream)).await.unwrap();
    });
    Origin { addr, task }
}

/// An opaque CONNECT tunnel must deliver the exact response and then the reset.
/// PostedRecv on the test client protects its own unread bytes independently
/// of the upstream wrapper in the proxy.
pub(crate) async fn through_connect(proxy: &str) {
    tokio::time::timeout(Duration::from_secs(20), async {
        let mut origin = origin(service_fn(serve_response)).await;
        let mut client = PostedRecv::new(tokio::net::TcpStream::connect(proxy).await.unwrap());
        let request = format!(
            "CONNECT {0} HTTP/1.1\r\nHost: {0}\r\nProxy-Authorization: Basic am9objpzZWNyZXQ=\r\n\r\n",
            origin.addr,
        );
        client.write_all(request.as_bytes()).await.unwrap();
        assert!(read_head(&mut client).await.starts_with(b"HTTP/1.1 200"));
        client.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
        (&mut origin.task).await.unwrap();
        let mut received = Vec::new();
        let error = client.read_to_end(&mut received).await.unwrap_err();
        assert_eq!(received, response(), "CONNECT lost bytes before reset");
        assert!(matches!(error.kind(), std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted), "{error}");
    }).await.expect("CONNECT reset response timed out");
}

#[cfg(feature = "boring")]
pub(crate) async fn through_mitm(proxy: &str) {
    use rama::{
        Layer,
        http::{BodyExtractExt, Request, Version, client::EasyHttpWebClient},
        net::{address::ProxyAddress, client::ProxyRoute},
        rt::Executor,
        tcp::{client::service::TcpConnector, posted_recv::PostedRecvLayer},
        tls::{
            boring::server::TlsAcceptorLayer,
            client::{ServerVerifyMode, TlsClientConfig},
            server::{GeneratedServerAuthConfig, TlsServerConfig},
        },
    };

    let client = EasyHttpWebClient::connector_builder()
        .with_custom_transport_connector(PostedRecvLayer::new().into_layer(TcpConnector::new()))
        .with_default_dns_connector()
        .without_tls_proxy_support()
        .with_proxy_support()
        .with_tls_support_using_boringssl(
            TlsClientConfig::default_http().with_server_verify(ServerVerifyMode::Disable),
        )
        .with_default_http_connector(Executor::default())
        .without_connection_pool()
        .build_client();
    let proxy = ProxyAddress::try_from(proxy).unwrap();
    for secure in [false, true] {
        tokio::time::timeout(Duration::from_secs(20), async {
            let mut origin = if secure {
                let config = TlsServerConfig::new()
                    .try_with_generated_server_auth(GeneratedServerAuthConfig::default())
                    .unwrap();
                origin(TlsAcceptorLayer::new(config).into_layer(service_fn(serve_response))).await
            } else {
                origin(service_fn(serve_response)).await
            };
            let scheme = if secure { "https" } else { "http" };
            let response = client
                .serve(
                    Request::builder()
                        .version(Version::HTTP_11)
                        .uri(format!("{scheme}://{}/", origin.addr))
                        .extension(ProxyRoute::Proxy(proxy.clone()))
                        .body(rama::http::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), rama::http::StatusCode::OK);
            (&mut origin.task).await.unwrap();
            // Read the body after the origin reset, including on the TLS path.
            assert_eq!(
                response.try_into_string().await.unwrap().as_bytes(),
                body(),
                "{scheme} lost response bytes"
            );
        })
        .await
        .expect("MITM reset response timed out");
    }
}
