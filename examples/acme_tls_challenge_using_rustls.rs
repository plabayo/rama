//! An example showcasing how to complete an ACME TLS-ALPN-01 challenge using Rama with rustls and Pebble.
//!
//! This sets up a minimal TLS server that responds with a special certificate required
//! to prove domain ownership over an encrypted connection. This method is useful when
//! port 80 is blocked or not preferred, and certificate validation must occur over port 443.
//!
//! The example uses Pebble (a local ACME test server) as the certificate authority and disables
//! TLS verification for simplicity.
//!
//! # Prerequisites
//!
//! - Run Pebble locally (https://github.com/letsencrypt/pebble)
//! - Make sure Pebble is listening on `https://localhost:14000/dir`
//! - Ensure `example.com` resolves to `127.0.0.1` in your `/etc/hosts`
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example acme_tls_challenge_using_rustls --features=http-full,acme,rustls
//! ```
//!
//! # Expected Output
//!
//! The example:
//! - Registers an ACME account
//! - Creates a new order for `example.com`
//! - Serves a TLS certificate over port `5004` with ALPN set to `acme-tls/1`
//! - Completes the TLS-ALPN-01 challenge and downloads a certificate
//!
//! You should see log output indicating progress through each ACME step,
//! and finally the certificate download will complete successfully.
//!
//! ```sh
//! curl -vik --resolve example:5004:127.0.0.1 https://example:5004
//! ```
//! Output
//! ```
//! * Server certificate:
//! *  subject: [NONE]
//! *  start date: Sep 16 19:08:44 2025 GMT
//! *  expire date: Sep 16 19:08:43 2030 GMT
//! *  issuer: CN=Pebble Intermediate CA 4224e8
//! *  SSL certificate verify result: unable to get local issuer certificate (20), continuing anyway.
//! ```
//!
//! TODO: once Rama has an ACME server implementation (https://github.com/plabayo/rama/issues/649) migrate
//! this example to use that instead of Pebble so we can test everything automatically
use rama::{
    Layer, Service,
    crypto::{
        dep::{
            pki_types::{CertificateDer, PrivateKeyDer},
            rcgen::{
                self, CertificateParams, CertificateSigningRequest, DistinguishedName, DnType,
            },
        },
        jose::EcdsaKey,
    },
    graceful,
    http::{client::EasyHttpWebClient, server::HttpServer, service::web::response::IntoResponse},
    layer::ConsumeErrLayer,
    rt::Executor,
    service::service_fn,
    tcp::server::TcpListener,
    telemetry::tracing::{self, level_filters::LevelFilter},
    tls::{
        acme::{
            AcmeClient,
            proto::{
                client::{CreateAccountOptions, NewOrderPayload},
                common::Identifier,
                server::{ChallengeType, OrderStatus},
            },
        },
        rustls::{
            dep::rustls::{
                self,
                crypto::aws_lc_rs::sign::any_ecdsa_type,
                server::{ClientHello as RustlsClientHello, ResolvesServerCert},
                sign::CertifiedKey,
            },
            server::{TlsAcceptorData, TlsAcceptorDataBuilder, TlsAcceptorLayer},
        },
    },
};

use std::{convert::Infallible, sync::Arc, time::Duration};
use tokio::time::sleep;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

// Default directory url of pebble
const TEST_DIRECTORY_URL: &str = "https://localhost:14000/dir";
// Addr on which server will bind to do acme challenge
const ADDR: &str = "0.0.0.0:5004";

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

    let tls_config = rama::tls::rustls::client::TlsConnectorDataBuilder::new()
        .with_env_key_logger()
        .expect("add env keylogger")
        .with_alpn_protocols_http_auto()
        .with_no_cert_verifier()
        .build();

    let client = EasyHttpWebClient::builder()
        .with_default_transport_connector()
        .without_tls_proxy_support()
        .with_proxy_support()
        .with_tls_support_using_rustls(Some(tls_config))
        .build()
        .boxed();

    let client = AcmeClient::new(TEST_DIRECTORY_URL, client)
        .await
        .expect("create acme client");

    let account_key = EcdsaKey::generate().expect("generate key for account");
    let account = client
        .create_or_load_account(
            account_key,
            CreateAccountOptions {
                terms_of_service_agreed: Some(true),
                ..Default::default()
            },
        )
        .await
        .expect("create account");

    let mut order = account
        .new_order(NewOrderPayload {
            identifiers: vec![Identifier::dns("example.com")],
            ..Default::default()
        })
        .await
        .expect("create order");

    let mut authz = order
        .get_authorizations()
        .await
        .expect("get order authorizations");
    let auth = &mut authz[0];

    tracing::info!("running service at: {ADDR}");

    let graceful = crate::graceful::Shutdown::default();

    let challenge = auth
        .challenges
        .iter_mut()
        .find(|challenge| challenge.r#type == ChallengeType::TlsAlpn01)
        .expect("find tls challenge");

    let (pk, cert) = order
        .create_tls_challenge_data(challenge, &auth.identifier)
        .expect("create tls challenge data");

    let pk = PrivateKeyDer::Pkcs8(pk);

    let cert_key = CertifiedKey::new(
        vec![cert.der().clone()],
        any_ecdsa_type(&pk).expect("create certified key"),
    );

    let cert_resolver = Arc::new(ResolvesServerCertAcme::new(cert_key));

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(cert_resolver);

    server_config.alpn_protocols = vec![rama::net::tls::ApplicationProtocol::ACME_TLS.into()];

    let acceptor_data = TlsAcceptorData::from(server_config);

    let challenge_server_handle = graceful.spawn_task_fn(async move |guard| {
        let tcp_service =
            TlsAcceptorLayer::new(acceptor_data).layer(service_fn(internal_tcp_service_fn));

        TcpListener::bind("127.0.0.1:5001")
            .await
            .expect("bind TCP Listener: tls")
            .serve_graceful(guard, tcp_service)
            .await;
    });

    sleep(Duration::from_millis(1000)).await;

    order
        .finish_challenge(challenge)
        .await
        .expect("finish challenge");

    order
        .wait_until_all_authorizations_finished()
        .await
        .expect("wait until all authorizations are finished");

    assert_eq!(order.state().status, OrderStatus::Ready);

    let (key_pair, csr) = create_csr();

    order.finalize(csr.der()).await.expect("finalize order");

    let cert = order
        .download_certificate_as_pem_stack()
        .await
        .expect("download certificate");

    tracing::info!(?cert, "received certificiate");
    challenge_server_handle.abort();

    let cert_chain = cert
        .into_iter()
        .map(|pem| CertificateDer::from(pem.contents))
        .collect();

    let private_key = PrivateKeyDer::Pkcs8(key_pair.serialize_der().into());

    // create https server using the configured certificate

    graceful.spawn_task_fn(async |guard| {
        let exec = Executor::graceful(guard.clone());
        let http_service = HttpServer::auto(exec).service(service_fn(async || {
            Ok::<_, Infallible>("hello".into_response())
        }));

        let acceptor_data = TlsAcceptorDataBuilder::new(cert_chain, private_key)
            .expect("tls acceptor with self signed data")
            .with_env_key_logger()
            .expect("with env key logger")
            .build();

        let tcp_service = (
            ConsumeErrLayer::default(),
            TlsAcceptorLayer::new(acceptor_data),
        )
            .into_layer(http_service);

        TcpListener::bind(ADDR)
            .await
            .expect("bind TCP Listener: http")
            .serve_graceful(guard, tcp_service)
            .await;
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}

#[derive(Debug)]
struct ResolvesServerCertAcme {
    key: Arc<CertifiedKey>,
}

impl ResolvesServerCertAcme {
    pub(crate) fn new(key: CertifiedKey) -> Self {
        Self { key: Arc::new(key) }
    }
}

impl ResolvesServerCert for ResolvesServerCertAcme {
    fn resolve(&self, _client_hello: RustlsClientHello) -> Option<Arc<CertifiedKey>> {
        Some(self.key.clone())
    }
}

async fn internal_tcp_service_fn<S>(_stream: S) -> Result<(), Infallible> {
    Ok(())
}

fn create_csr() -> (rcgen::KeyPair, CertificateSigningRequest) {
    let key_pair = rcgen::KeyPair::generate().expect("create keypair");

    let mut params =
        CertificateParams::new(vec!["example.com".to_owned()]).expect("create certificate params");

    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CountryName, "BE");
    distinguished_name.push(DnType::LocalityName, "Ghent");
    distinguished_name.push(DnType::OrganizationName, "Plabayo");
    distinguished_name.push(DnType::CommonName, "example.com");

    params.distinguished_name = distinguished_name;

    let csr = params
        .serialize_request(&key_pair)
        .expect("create certificate signing request");

    (key_pair, csr)
}
