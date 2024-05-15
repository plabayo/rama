//! This example demonstrates how to create a mTLS tunnel proxy and a mTLS web service.
//! The mTLS tunnel proxy is a server that accepts mTLS connections, and forwards the mTLS transport stream to another service.
//! The mTLS web service is a server that accepts mTLS connections, and serves a simple web page.
//! You can learn more about this kind of proxy in [the rama book](https://ramaproxy.org/book/) at the [mTLS Tunnel Proxy](https://ramaproxy.org/book/proxies/tls.html) section.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example mtls_tunnel_and_service
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:63014`. You can use `curl` to interact with the service:
//!
//! ```sh
//! curl -k -v https://127.0.0.1:63014
//! ```
//!
//! This won't work as the client is not authorized. You can use `curl` to interact with the service:
//!
//! ```sh
//! curl -v http://127.0.0.1:62014/hello
//! ```
//!
//! You should see a response with `HTTP/1.1 200 OK` and a body with `Hello, authorized client!`.

// these dependencies are re-exported by rama for your convenience,
// as to make it easy to use them and ensure that the versions remain compatible
// (given most do not have a stable release yet)
use rama::tls::rustls::dep::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
    rustls::{server::WebPkiClientVerifier, ClientConfig, KeyLogFile, RootCertStore, ServerConfig},
    tokio_rustls::TlsConnector,
};

// rama provides everything out of the box to build mtls web services and proxies
use rama::{
    error::BoxError,
    http::{
        layer::trace::TraceLayer,
        response::{Html, Redirect},
        server::HttpServer,
        service::web::WebService,
    },
    rt::Executor,
    service::{Context, ServiceBuilder},
    tcp::server::TcpListener,
    tls::rustls::server::TlsAcceptorLayer,
    utils::graceful::Shutdown,
};
use rcgen::KeyPair;

// everything else is provided by the standard library, community crates or tokio
use std::{sync::Arc, time::Duration};
use tokio::net::TcpStream;
use tracing::metadata::LevelFilter;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

const SERVER_DOMAIN: &str = "127.0.0.1";
const SERVER_ADDR: &str = "127.0.0.1:63014";
const TUNNEL_ADDR: &str = "127.0.0.1:62014";

#[derive(Debug)]
struct TunnelState {
    client_config: Arc<ClientConfig>,
}

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

    // generate client mtls cert
    let (client_cert_der, client_key_der) = generate_tls_cert_client();
    let client_cert_der_copy = client_cert_der.clone();

    // generate server cert (client will also verify the server cert)
    let (root_cert_der, server_cert_der, server_key_der) = generate_tls_cert_server();
    let server_cert_der_copy = server_cert_der.clone();

    // create mtls web server
    shutdown.spawn_task_fn(|guard| async move {
        let mut root_cert_storage = RootCertStore::empty();
        root_cert_storage
            .add(client_cert_der_copy)
            .expect("add client cert to root cert storage");
        let cert_verifier = WebPkiClientVerifier::builder(Arc::new(root_cert_storage))
            .build()
            .expect("create webpki client verifier");

        let tls_server_config = ServerConfig::builder()
            .with_client_cert_verifier(cert_verifier)
            .with_single_cert(
                vec![server_cert_der.clone()],
                PrivatePkcs8KeyDer::from(server_key_der.secret_pkcs8_der().to_owned()).into(),
            )
            .expect("create tls server config");

        let executor = Executor::graceful(guard.clone());

        let tcp_service = ServiceBuilder::new()
            .layer(TlsAcceptorLayer::new(tls_server_config))
            .service(
                HttpServer::auto(executor).service(
                    ServiceBuilder::new()
                        .layer(TraceLayer::new_for_http())
                        .service(
                            WebService::default()
                                .get("/", Redirect::temporary("/hello"))
                                .get("/hello", Html("<h1>Hello, authorized client!</h1>")),
                        ),
                ),
            );

        tracing::info!("start mtls (https) web service: {}", SERVER_ADDR);
        TcpListener::bind(SERVER_ADDR)
            .await
            .unwrap_or_else(|e| {
                panic!("bind TCP Listener ({SERVER_ADDR}): mtls (https): web service: {e}")
            })
            .serve_graceful(guard, tcp_service)
            .await;
    });

    // create mtls tunnel proxy
    shutdown.spawn_task_fn(|guard| async move {
        let mut root_cert_storage: RootCertStore = RootCertStore::empty();
        root_cert_storage
            .add(root_cert_der)
            .expect("add root cert to root cert storage");
        root_cert_storage
            .add(server_cert_der_copy)
            .expect("add server cert to root cert storage");

        let mut client_config = ClientConfig::builder()
            .with_root_certificates(root_cert_storage)
            .with_client_auth_cert(vec![client_cert_der], PrivateKeyDer::Pkcs8(client_key_der))
            .expect("build mTLS client config");

        // support key logging
        if std::env::var("SSLKEYLOGFILE").is_ok() {
            client_config.key_log = Arc::new(KeyLogFile::new());
        }

        let client_config = Arc::new(client_config);

        tracing::info!("start mTLS TCP Tunnel Proxys: {}", TUNNEL_ADDR);
        TcpListener::build_with_state(TunnelState { client_config })
            .bind(TUNNEL_ADDR)
            .await
            .expect("bind TCP Listener: mTLS TCP Tunnel Proxys")
            .serve_graceful(
                guard,
                ServiceBuilder::new().trace_err().service_fn(serve_conn),
            )
            .await;
    });

    shutdown
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}

/// generate client Tls certificate and private key.
fn generate_tls_cert_client() -> (CertificateDer<'static>, PrivatePkcs8KeyDer<'static>) {
    // Create a client end entity cert.
    let alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    let client_key_pair = KeyPair::generate_for(alg).expect("generate client key pair");
    let mut client_ee_params = rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()])
        .expect("create client EE Params");
    client_ee_params.is_ca = rcgen::IsCa::NoCa;
    client_ee_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    let client_cert = client_ee_params
        .self_signed(&client_key_pair)
        .expect("create client self-signed cert");
    let client_cert_der = client_cert.into();
    let client_key_der = PrivatePkcs8KeyDer::from(client_key_pair.serialize_der());

    (client_cert_der, client_key_der)
}

/// Generate a server Tls certificate and private key.
fn generate_tls_cert_server() -> (
    CertificateDer<'static>,
    CertificateDer<'static>,
    PrivatePkcs8KeyDer<'static>,
) {
    // Create an issuer CA cert.
    let alg: &rcgen::SignatureAlgorithm = &rcgen::PKCS_ECDSA_P256_SHA256;
    let ca_key_pair = KeyPair::generate_for(alg).expect("generate CA server key pair");
    let mut ca_params =
        rcgen::CertificateParams::new(vec!["Example CA".to_owned()]).expect("create CA Params");
    ca_params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "Rustls Server Acceptor");
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Example CA");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = ca_params
        .self_signed(&ca_key_pair)
        .expect("create ca (server) self-signed cert");
    let ca_cert_der = ca_cert.der().clone();

    // Create a server end entity cert issued by the CA.
    let mut server_ee_params = rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()])
        .expect("create server EE Params");
    server_ee_params.is_ca = rcgen::IsCa::NoCa;
    server_ee_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    server_ee_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Example Server");
    let server_key_pair = KeyPair::generate_for(alg).expect("generate tls server key pair");
    let server_cert = server_ee_params
        .signed_by(&server_key_pair, &ca_cert, &ca_key_pair)
        .expect("create server self-signed cert");
    let server_cert_der = server_cert.into();
    let server_key_der = PrivatePkcs8KeyDer::from(server_key_pair.serialize_der());

    (ca_cert_der, server_cert_der, server_key_der)
}

/// L4 Proxy Service
async fn serve_conn(ctx: Context<TunnelState>, mut source: TcpStream) -> Result<(), BoxError> {
    let state = ctx.state();

    let target = TcpStream::connect(SERVER_ADDR).await?;
    let tls_connector = TlsConnector::from(state.client_config.clone());
    let server_name = ServerName::try_from(SERVER_DOMAIN)
        .expect("parse server name")
        .to_owned();
    let mut target = tls_connector.connect(server_name, target).await?;

    match tokio::io::copy_bidirectional(&mut source, &mut target).await {
        Ok(_) => Ok(()),
        Err(err) => {
            if rama::tcp::utils::is_connection_error(&err) {
                Ok(())
            } else {
                Err(err)
            }
        }
    }?;
    Ok(())
}
