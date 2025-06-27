//! Client h2 example with `example.com` as target server,
//! example in sync with `hyperium/h2`.
//!
//! # Run the example
//!
//! ```sh
//! cargo run -p rama-http-core --example h2_example
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62000`. You can use `curl` to check if the server is running:
//!
//! ```sh
//! curl -v http://127.0.0.1:62000
//! ```
//!
//! You should see an HTTP Status 200 OK with a HTML payload containing the
//! connection index and count of requests within that connection.

use rama_error::BoxError;
use rama_http_core::h2::client;
use rama_http_types::{Method, Request};

use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::{RootCertStore, pki_types::ServerName};

use std::net::ToSocketAddrs;

const ALPN_H2: &str = "h2";

#[tokio::main]
pub async fn main() -> Result<(), BoxError> {
    let _ = env_logger::try_init();

    let tls_client_config = std::sync::Arc::new({
        let root_store = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut c = tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        c.alpn_protocols.push(ALPN_H2.as_bytes().to_owned());
        c
    });

    // Sync DNS resolution.
    let addr = "example.com:443".to_socket_addrs().unwrap().next().unwrap();

    println!("ADDR: {addr:?}");

    let tcp = TcpStream::connect(&addr).await?;
    let dns_name = ServerName::try_from("example.com").unwrap();
    let connector = TlsConnector::from(tls_client_config);
    let res = connector.connect(dns_name, tcp).await;
    let tls = res.unwrap();
    {
        let (_, session) = tls.get_ref();
        let negotiated_protocol = session.alpn_protocol();
        assert_eq!(Some(ALPN_H2.as_bytes()), negotiated_protocol);
    }

    println!("Starting client handshake");
    let (mut client, h2) = client::handshake(tls).await?;

    println!("building request");
    let request = Request::builder()
        .method(Method::GET)
        .uri("https://example.com/")
        .body(())
        .unwrap();

    println!("sending request");
    let (response, other) = client.send_request(request, true).unwrap();

    tokio::spawn(async move {
        if let Err(e) = h2.await {
            println!("GOT ERR={e:?}");
        }
    });

    println!("waiting on response : {other:?}");
    let (_, mut body) = response.await?.into_parts();
    println!("processing body");
    while let Some(chunk) = body.data().await {
        println!("RX: {:?}", chunk?);
    }
    Ok(())
}
