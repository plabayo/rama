//! HTTP/3 with the ordinary Rama request, response, body and service interfaces.
//!
//! Run with `--features http-full,rustls,ring` (or `http-full,boring`).
//! Supply a PEM certificate/key for the server and its trusted CA for the client:
//!
//! ```sh
//! cargo run -p rama-examples --bin http3_client_server --features http-full,rustls,ring -- server --cert cert.pem --key key.pem
//! cargo run -p rama-examples --bin http3_client_server --features http-full,rustls,ring -- client --ca cert.pem --url https://localhost:4433/ --body hello
//! ```
//! The server echoes a streamed POST body, including trailers. GET returns a greeting.
//! The client repeats requests through the normal multiplex connection pool.

#![expect(
    clippy::print_stdout,
    reason = "example reports received responses and its listening address"
)]

use clap::{Parser, Subcommand};
use rama::{
    Service, ServiceInput,
    crypto::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _},
    error::BoxError,
    extensions::Extensions,
    http::{
        Body, Request, Response, Version, body::util::BodyExt as _,
        client::EasyHttpConnectorBuilder, core::h3::connection::Config, server::HttpServer,
    },
    quic::{Endpoint, ServerConfig, TransportConfig, tls::TlsOptions},
    rt::Executor,
    service::service_fn,
    tls::{
        client::TlsClientConfig,
        server::{ServerAuthData, TlsServerConfig},
    },
};
use std::{convert::Infallible, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    mode: Mode,
}
#[derive(Subcommand)]
enum Mode {
    Server {
        #[arg(long, default_value = "127.0.0.1:4433")]
        listen: SocketAddr,
        #[arg(long)]
        cert: PathBuf,
        #[arg(long)]
        key: PathBuf,
    },
    Client {
        #[arg(long)]
        ca: PathBuf,
        #[arg(long, default_value = "https://localhost:4433/")]
        url: String,
        #[arg(long)]
        body: Option<String>,
        #[arg(long, default_value_t = 3)]
        count: usize,
    },
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    rama::telemetry::tracing::subscriber::fmt()
        .with_env_filter(rama::telemetry::tracing::subscriber::EnvFilter::from_default_env())
        .init();
    match Args::parse().mode {
        Mode::Server { listen, cert, key } => {
            let auth = ServerAuthData {
                cert_chain: CertificateDer::pem_file_iter(cert)?.collect::<Result<Vec<_>, _>>()?,
                private_key: PrivateKeyDer::from_pem_file(key)?,
                ocsp: None,
            };
            let tls = TlsServerConfig::new()
                .with_server_auth(auth)
                .with_alpn([b"h3".as_slice().into()].into_iter().collect());
            let server = HttpServer::new_http3(Executor::new());
            let mut transport = TransportConfig::default();
            server.http3().configure_transport(&mut transport)?;
            let mut config = ServerConfig::try_from_rama_tls(&tls, TlsOptions::default())?;
            config.set_transport_config(Arc::new(transport));
            let endpoint = Endpoint::build(Executor::new())
                .with_server_config(config)
                .bind_address(listen)
                .await?;
            println!("HTTP/3 listening on {}", endpoint.local_addr()?);
            while let Some(incoming) = endpoint.accept().await {
                let server = server.clone();
                tokio::spawn(async move {
                    let result: Result<(), BoxError> = async {
                        let connection = incoming.await?;
                        server
                            .serve_quic(
                                ServiceInput {
                                    input: connection,
                                    extensions: Extensions::new(),
                                },
                                service_fn(async |request: Request| {
                                    let body = if request.method() == rama::http::Method::GET {
                                        Body::from("hello over HTTP/3\n")
                                    } else {
                                        request.into_body()
                                    };
                                    Ok::<_, Infallible>(Response::new(body))
                                }),
                            )
                            .await?;
                        Ok(())
                    }
                    .await;
                    if let Err(error) = result {
                        eprintln!("connection ended: {error}");
                    }
                });
            }
        }
        Mode::Client {
            ca,
            url,
            body,
            count,
        } => {
            let anchors = CertificateDer::pem_file_iter(ca)?.collect::<Result<Vec<_>, _>>()?;
            let tls = TlsClientConfig::new().try_with_server_trust_anchors(anchors)?;
            let endpoint = Endpoint::build(Executor::new())
                .bind_address("0.0.0.0:0".parse::<SocketAddr>()?)
                .await?;
            let client = EasyHttpConnectorBuilder::new()
                .with_http3_connector::<Body>(
                    endpoint.clone(),
                    tls,
                    TlsOptions::default(),
                    Config::default(),
                    Executor::new(),
                )
                .with_default_connection_pool()
                .build_client();
            for _ in 0..count {
                let request = Request::builder()
                    .uri(url.as_str())
                    .version(Version::HTTP_3)
                    .method(if body.is_some() { "POST" } else { "GET" })
                    .body(body.clone().map_or_else(Body::empty, Body::from))?;
                let response =
                    tokio::time::timeout(Duration::from_secs(15), client.serve(request)).await??;
                assert_eq!(response.version(), Version::HTTP_3);
                let status = response.status();
                let received = response.into_body().collect().await?;
                println!("{status}: trailers: {:?}", received.trailers());
                println!("{}", String::from_utf8_lossy(&received.to_bytes()));
            }
            drop(client);
            endpoint.close(0u32, b"example complete");
            endpoint.shutdown().await;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama::extensions::ExtensionsRef as _;
    use rama::http::{HeaderMap, body::Frame};
    use rama::tls::server::GeneratedServerAuthConfig;

    #[tokio::test]
    async fn public_builders_reuse_h3_with_common_bodies_and_trailers() -> Result<(), BoxError> {
        for capture_chain in [false, true] {
            tokio::time::timeout(Duration::from_secs(20), async {
                let auth = ServerAuthData::new_generated(GeneratedServerAuthConfig::default())?;
                let tls = TlsClientConfig::new()
                    .try_with_server_trust_anchors(auth.cert_chain.clone())?
                    .with_store_server_cert_chain(capture_chain);
                let server_tls = TlsServerConfig::new()
                    .with_server_auth(auth)
                    .with_alpn([b"h3".as_slice().into()].into_iter().collect());
                let server = HttpServer::new_http3(Executor::new());
                let mut transport = TransportConfig::default();
                server.http3().configure_transport(&mut transport)?;
                let mut config =
                    ServerConfig::try_from_rama_tls(&server_tls, TlsOptions::default())?;
                config.set_transport_config(Arc::new(transport));
                let endpoint = Endpoint::build(Executor::new())
                    .with_server_config(config)
                    .bind_address("127.0.0.1:0".parse::<SocketAddr>()?)
                    .await?;
                let address = endpoint.local_addr()?;
                let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
                let task = tokio::spawn({
                    let endpoint = endpoint.clone();
                    let accepted = accepted.clone();
                    async move {
                        while let Some(incoming) = endpoint.accept().await {
                            accepted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            let server = server.clone();
                            tokio::spawn(async move {
                                if let Ok(connection) = incoming.await {
                                    let _result = server
                                        .serve_quic(
                                            ServiceInput {
                                                input: connection,
                                                extensions: Extensions::new(),
                                            },
                                            service_fn(async |request: Request| {
                                                assert_eq!(request.version(), Version::HTTP_3);
                                                Ok::<_, Infallible>(Response::new(
                                                    request.into_body(),
                                                ))
                                            }),
                                        )
                                        .await;
                                }
                            });
                        }
                    }
                });
                let client_endpoint = Endpoint::build(Executor::new())
                    .bind_address("127.0.0.1:0".parse::<SocketAddr>()?)
                    .await?;
                let client = EasyHttpConnectorBuilder::new()
                    .with_http3_connector::<Body>(
                        client_endpoint.clone(),
                        tls,
                        TlsOptions::default(),
                        Config::default(),
                        Executor::new(),
                    )
                    .with_default_connection_pool()
                    .build_client()
                    .with_jit_layer(rama::layer::MapInputLayer::new(move |request: Request| {
                        let egress = request
                            .extensions()
                            .get_ref::<rama::extensions::Egress<Extensions>>()
                            .unwrap();
                        let parameters = egress
                            .0
                            .get_ref::<rama::tls::client::NegotiatedTlsParameters>()
                            .unwrap();
                        assert_eq!(
                            parameters
                                .peer_certificate_chain
                                .as_ref()
                                .is_some_and(|chain| !chain.is_empty()),
                            capture_chain
                        );
                        request
                    }));
                for _ in 0..3 {
                    let mut trailers = HeaderMap::new();
                    trailers.insert("x-complete", "yes".parse()?);
                    let body = Body::from_frame_stream(rama::futures::stream::iter([
                        Ok::<_, Infallible>(Frame::data(rama::bytes::Bytes::from_static(
                            b"common body",
                        ))),
                        Ok(Frame::trailers(trailers)),
                    ]));
                    let request = Request::builder()
                        .method("POST")
                        .version(Version::HTTP_3)
                        .uri(format!("https://localhost:{}/echo", address.port()))
                        .body(body)?;
                    let response = client.serve(request).await?;
                    assert_eq!(response.version(), Version::HTTP_3);
                    let received = response.into_body().collect().await?;
                    assert_eq!(
                        received
                            .trailers()
                            .and_then(|h| h.get("x-complete"))
                            .map(|h| h.as_bytes()),
                        Some(b"yes".as_slice())
                    );
                    assert_eq!(received.to_bytes(), "common body");
                }
                assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 1);
                drop(client);
                client_endpoint.close(0u32, b"done");
                endpoint.close(0u32, b"done");
                task.abort();
                tokio::join!(client_endpoint.shutdown(), endpoint.shutdown());
                Ok::<_, BoxError>(())
            })
            .await??;
        }
        Ok(())
    }
}
