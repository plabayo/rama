//! End-to-end regression for issue #1014.
//!
//! A rustls server (rama `TlsAcceptorLayer` + `HttpServer`) serves a response
//! whose body errors mid-stream. The downstream rustls client must observe a
//! graceful TLS `close_notify` (a clean EOF) rather than an abrupt, truncated
//! close (`ErrorKind::UnexpectedEof`, which is how rustls surfaces a peer that
//! closed without `close_notify`).
//!
//! Before the fix the H1 dispatcher's error path dropped the TLS stream without
//! driving `poll_shutdown`, so the client saw `UnexpectedEof`. This test fails
//! against that behavior and passes once the error path drives a best-effort
//! shutdown.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use rama::{
    Layer, Service, ServiceInput,
    bytes::Bytes,
    error::{BoxError, BoxErrorExt as _},
    futures::stream,
    http::{Body, Request, Response, server::HttpServer},
    rt::Executor,
    service::service_fn,
    tls::rustls::{
        dep::{
            rustls::{ClientConfig, crypto::aws_lc_rs, pki_types::ServerName},
            tokio_rustls::TlsConnector,
        },
        server::TlsAcceptorLayer,
        verify::NoServerCertVerifier,
    },
};
use rama_tls::server::TlsServerConfig;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, duplex};

#[tokio::test]
async fn server_sends_close_notify_when_response_body_errors() {
    // rustls needs a process-default crypto provider for `ClientConfig::builder`.
    _ = aws_lc_rs::default_provider().install_default();

    let acceptor_data = TlsServerConfig::default_http().unwrap();

    let svc = service_fn(|_req: Request| async move {
        // unknown-length (chunked) body that yields one chunk then fails: this
        // forces the h1 dispatcher onto its error path mid-response. (The http
        // layer discards the buffered, not-yet-completed response on a body
        // error, so no plaintext reaches the client — only the close_notify
        // does, which is exactly what we assert below.)
        let body = Body::from_stream(stream::iter(vec![
            Ok::<Bytes, BoxError>(Bytes::from_static(b"hello ")),
            Err::<Bytes, BoxError>(BoxError::from_static_str("upstream boom")),
        ]));
        Ok::<_, Infallible>(Response::new(body))
    });

    let server = TlsAcceptorLayer::new(acceptor_data)
        .into_layer(HttpServer::auto(Executor::default()).service(svc));

    let (client_io, server_io) = duplex(64 * 1024);

    tokio::spawn(async move {
        // result intentionally ignored: the response errors, but by then the
        // dispatcher has already driven close_notify (the thing under test).
        _ = server.serve(ServiceInput::new(server_io)).await;
    });

    // ----- client: rustls connect (no verify) + read until EOF / error -----
    let client_config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoServerCertVerifier::new()))
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(client_config));
    let server_name = ServerName::try_from("localhost").unwrap().to_owned();

    let outcome = tokio::time::timeout(Duration::from_secs(10), async move {
        let mut tls = connector
            .connect(server_name, client_io)
            .await
            .expect("client tls handshake");

        tls.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .expect("write request");
        tls.flush().await.expect("flush request");

        // Read the TLS stream to its end. A graceful `close_notify` surfaces as
        // a clean EOF (`Ok(0)`); a peer that drops the connection without one
        // surfaces (in rustls) as `Err(ErrorKind::UnexpectedEof)`.
        let mut buf = [0u8; 4096];
        loop {
            match tls.read(&mut buf).await {
                Ok(0) => return Ok(()),
                Ok(_) => {} // discard any plaintext; only the close matters here
                Err(e) => return Err(e),
            }
        }
    })
    .await
    .expect("client interaction timed out");

    // The assertion of #1014: a dispatch error on the server must still produce
    // a graceful TLS close_notify, not an abrupt truncation.
    outcome.unwrap_or_else(|e| {
        panic!(
            "expected a graceful TLS close_notify (clean EOF) on the error path, \
             but got an IO error: kind={:?}, err={e:?}",
            e.kind()
        )
    });
}
