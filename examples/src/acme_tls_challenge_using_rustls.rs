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
//! - Run Pebble locally (<https://github.com/letsencrypt/pebble>)
//! - Make sure Pebble is listening on `https://localhost:14000/dir`
//! - Ensure `example.com` resolves to `127.0.0.1` in your `/etc/hosts`
//!
//! # Run the example
//!
//! ```sh
//! cargo run -p rama-examples --bin acme_tls_challenge_using_rustls --features=http-full,acme,rustls
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
//! TODO: once Rama has an ACME server implementation (<https://github.com/plabayo/rama/issues/649>) migrate
//! this example to use that instead of Pebble so we can test everything automatically
#![expect(
    clippy::expect_used,
    reason = "example/test/bench: panic-on-error and print-for-output are the standard patterns for demos and harnesses"
)]

use rama::{
    Layer, Service,
    crypto::{
        dep::rcgen::{
            self, CertificateParams, CertificateSigningRequest, DistinguishedName, DnType,
        },
        jose::EcdsaKey,
    },
    graceful,
    http::{client::EasyHttpWebClient, server::HttpServer, service::web::response::IntoResponse},
    layer::ConsumeErrLayer,
    rt::Executor,
    service::service_fn,
    tcp::server::TcpListener,
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
    tls::{
        ApplicationProtocol, KeyLogIntent,
        client::{ServerVerifyMode, TlsClientConfig},
        server::{ServerAuthData, TlsServerConfig},
    },
    tls::{
        acme::{
            AcmeClient,
            proto::{
                client::{CreateAccountOptions, NewOrderPayload},
                common::Identifier,
                server::{ChallengeType, OrderStatus},
            },
        },
        rustls::server::TlsAcceptorLayer,
    },
    utils::collections::smallvec::smallvec,
};

use std::{convert::Infallible, time::Duration};
use tokio::time::sleep;

// Default directory url of pebble
const TEST_DIRECTORY_URL: &str = "https://localhost:14000/dir";
// Addr on which server will bind to do acme challenge
const ADDR: &str = "0.0.0.0:5004";

#[tokio::main]
async fn main() {
    tracing::subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        )
        .init();

    let tls_config = TlsClientConfig::default().with_server_verify(ServerVerifyMode::Disable);

    let graceful = crate::graceful::Shutdown::default();

    let client = EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .with_default_dns_connector()
        .without_tls_proxy_support()
        .with_proxy_support()
        .with_tls_support_using_rustls(tls_config)
        .with_default_http_connector(Executor::graceful(graceful.guard()))
        .build_client()
        .boxed();

    let client = AcmeClient::try_new(TEST_DIRECTORY_URL, client)
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
        .try_new_order(NewOrderPayload {
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

    let challenge = auth
        .challenges
        .iter_mut()
        .find(|challenge| challenge.r#type == ChallengeType::TlsAlpn01)
        .expect("find tls challenge");

    let (pk, cert) = order
        .create_tls_challenge_data(challenge, &auth.identifier)
        .expect("create tls challenge data");

    let acceptor_data = TlsServerConfig::new()
        .with_single_cert(ServerAuthData {
            private_key: pk.into(),
            cert_chain: vec![cert.into()],
            ocsp: None,
        })
        .with_alpn(smallvec![ApplicationProtocol::ACME_TLS]);

    let challenge_server_handle = graceful.spawn_task_fn(async move |guard| {
        let tcp_service =
            TlsAcceptorLayer::new(acceptor_data).layer(service_fn(internal_tcp_service_fn));

        TcpListener::bind_address("127.0.0.1:5001", Executor::graceful(guard))
            .await
            .expect("bind TCP Listener: tls")
            .serve(tcp_service)
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

    let cert_chain = order
        .download_certificate_chain()
        .await
        .expect("download certificate");

    tracing::info!(?cert_chain, "received certificiate");
    challenge_server_handle.abort();

    // create https server using the configured certificate

    graceful.spawn_task_fn(async |guard| {
        let exec = Executor::graceful(guard.clone());
        let http_service = HttpServer::auto(exec.clone()).service(service_fn(async || {
            Ok::<_, Infallible>("hello".into_response())
        }));

        let acceptor_data = TlsServerConfig::new()
            .with_single_cert(ServerAuthData {
                cert_chain,
                private_key: key_pair.into(),
                ocsp: None,
            })
            .with_keylog(KeyLogIntent::Environment);

        let tcp_service = (
            ConsumeErrLayer::default(),
            TlsAcceptorLayer::new(acceptor_data),
        )
            .into_layer(http_service);

        TcpListener::bind_address(ADDR, exec)
            .await
            .expect("bind TCP Listener: http")
            .serve(tcp_service)
            .await;
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
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
