//! This example demonstrates how to create a TLS termination proxy, forwarding the
//! plain transport stream to another service.
//!
//! See also the [mtls_tunnel_and_services](./mtls_tunnel_and_services.rs) example for a more complex example
//! of how to use the `TlsAcceptorLayer` and `TlsAcceptorService` to create a mTLS tunnel and services.
//!
//! This proxy is an example of a TLS termination proxy, which is a server that accepts TLS connections,
//! decrypts the TLS and forwards the plain transport stream to another service.
//! You can learn more about this kind of proxy in [the rama book](https://ramaproxy.org/book/) at the [TLS Termination Proxy](https://ramaproxy.org/book/proxies/tls.html) section.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example tls_termination
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:63800`. You can use `curl` to interact with the service:
//!
//! ```sh
//! curl -v https://127.0.0.1:62800
//! curl -k -v https://127.0.0.1:63800
//! ```
//!
//! You should see a response with `HTTP/1.0 200 ok` and the body `Hello world!`.

use pki_types::CertificateDer;
// these dependencies are re-exported by rama for your convenience,
// as to make it easy to use them and ensure that the versions remain compatible
// (given most do not have a stable release yet)
use rama::tls::rustls::dep::{pki_types::PrivatePkcs8KeyDer, rustls::ServerConfig};

// rama provides everything out of the box to build a TLS termination proxy
use rama::{
    service::ServiceBuilder,
    tcp::{server::TcpListener, service::Forwarder},
    tls::rustls::server::{IncomingClientHello, TlsAcceptorLayer, TlsClientConfigHandler},
    utils::graceful::Shutdown,
};
use rcgen::KeyPair;

// everything else is provided by the standard library, community crates or tokio
use std::time::Duration;
use tokio::{io::AsyncWriteExt, net::TcpStream};
use tracing::metadata::LevelFilter;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        )
        .init();

    let shutdown = Shutdown::default();

    // Create an issuer CA cert.
    let alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    let ca_key_pair = KeyPair::generate_for(alg).expect("generate ca key pair");

    let mut ca_params = rcgen::CertificateParams::new(Vec::new()).expect("create ca params");
    ca_params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "Rustls Server Acceptor");
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Example CA");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let ca_cert = ca_params.self_signed(&ca_key_pair).expect("create ca cert");

    // Create a server end entity cert issued by the CA.
    let server_key_pair = KeyPair::generate_for(alg).expect("generate server key pair");
    let mut server_ee_params = rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()])
        .expect("create server ee params");
    server_ee_params.is_ca = rcgen::IsCa::NoCa;
    server_ee_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let server_cert = server_ee_params
        .signed_by(&server_key_pair, &ca_cert, &ca_key_pair)
        .expect("create server cert");
    let server_cert_der: CertificateDer = server_cert.into();
    let server_key_der = PrivatePkcs8KeyDer::from(server_key_pair.serialize_der());

    // create tls proxy
    shutdown.spawn_task_fn(|guard| async move {
        let tls_client_config_handler = TlsClientConfigHandler::default()
            .store_client_hello()
            .server_config_provider(|client_hello: IncomingClientHello| async move {
                tracing::debug!(?client_hello, "client hello");

                // Return None in case you want to use the default acceptor Tls config
                // Usually though when implementing this trait it's because you
                // want to use the client hello to determine which server config to use.
                Ok(None)
            });

        let tls_server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![server_cert_der],
                PrivatePkcs8KeyDer::from(server_key_der.secret_pkcs8_der().to_owned()).into(),
            )
            .expect("create tls server config");

        let tcp_service = ServiceBuilder::new()
            .layer(TlsAcceptorLayer::with_client_config_handler(
                tls_server_config,
                tls_client_config_handler,
            ))
            .service(Forwarder::target("127.0.0.1:62800".parse().unwrap()));

        TcpListener::bind("127.0.0.1:63800")
            .await
            .expect("bind TCP Listener: tls")
            .serve_graceful(guard, tcp_service)
            .await;
    });

    // create http server
    shutdown.spawn_task_fn(|guard| async {
        TcpListener::bind("127.0.0.1:62800")
            .await
            .expect("bind TCP Listener: http")
            .serve_fn_graceful(guard, |mut stream: TcpStream| async move {
                stream
                    .write_all(
                        &b"HTTP/1.0 200 ok\r\n\
                    Connection: close\r\n\
                    Content-length: 12\r\n\
                    \r\n\
                    Hello world!"[..],
                    )
                    .await
                    .expect("write to stream");
                Ok::<_, std::convert::Infallible>(())
            })
            .await;
    });

    shutdown
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}
