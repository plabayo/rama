//! An example showcasing how to complete an ACME HTTP-01 challenge using Rama and Pebble.
//!
//! This sets up a simple HTTP server that serves the ACME key authorization required
//! to prove domain ownership. It's useful for testing ACME integrations in controlled environments.
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
//! cargo run --example acme_http_challenge --features=http-full,boring,acme
//! ```
//!
//! # Expected Output
//!
//! The example:
//! - Registers an ACME account
//! - Creates a new order for `example.com`
//! - Serves the HTTP-01 challenge response on `0.0.0.0:5002/.well-known/acme-challenge/<token>`
//! - Completes the challenge and downloads a certificate
//!
//! You should see log output indicating progress through each ACME step,
//! and finally the certificate download will complete successfully.
//!
//! ```sh
//! curl -vik --resolve example:5002:127.0.0.1 https://example:5002
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
            aws_lc_rs::rand::SystemRandom,
            rcgen::{
                self, CertificateParams, CertificateSigningRequest, DistinguishedName, DnType,
            },
        },
        jose::EcdsaKey,
    },
    graceful,
    http::{
        client::EasyHttpWebClient,
        headers::ContentType,
        layer::{compression::CompressionLayer, trace::TraceLayer},
        server::HttpServer,
        service::web::WebService,
        service::web::response::{Headers, IntoResponse},
    },
    layer::ConsumeErrLayer,
    net::tls::{
        DataEncoding,
        client::ServerVerifyMode,
        server::{ServerAuth, ServerAuthData, ServerConfig},
    },
    rt::Executor,
    service::service_fn,
    tcp::server::TcpListener,
    telemetry::tracing::{self, level_filters::LevelFilter},
    tls::{
        acme::{
            AcmeClient,
            proto::{
                client::{CreateAccountOptions, KeyAuthorization, NewOrderPayload},
                common::Identifier,
                server::{ChallengeType, OrderStatus},
            },
        },
        boring::{
            client::TlsConnectorDataBuilder,
            server::{TlsAcceptorData, TlsAcceptorLayer},
        },
    },
};

use std::{convert::Infallible, sync::Arc, time::Duration};
use tokio::time::sleep;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

// Default directory url of pebble
const TEST_DIRECTORY_URL: &str = "https://localhost:14000/dir";
// Addr on which server will bind to do acme challenge
const ADDR: &str = "0.0.0.0:5002";

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

    let tls_config = TlsConnectorDataBuilder::new_http_auto()
        .with_server_verify_mode(ServerVerifyMode::Disable)
        .with_keylog_intent(rama::net::tls::KeyLogIntent::Environment)
        .into_shared_builder();

    let client = EasyHttpWebClient::builder()
        .with_default_transport_connector()
        .without_tls_proxy_support()
        .without_proxy_support()
        .with_tls_support_using_boringssl(Some(tls_config))
        .build()
        .boxed();

    let client = AcmeClient::new(TEST_DIRECTORY_URL, client)
        .await
        .expect("create acme client");

    let account = client
        .create_account(CreateAccountOptions {
            terms_of_service_agreed: Some(true),
            ..Default::default()
        })
        .await
        .expect("create account");

    // Export key used by account and save this somewhere external
    let alg = account.key().alg();
    let pkcs8 = account.key().pkcs8_der().expect("create der");

    // Later we can then load the key from the exported pkcs8 so we dont have to create a new account
    let account_key =
        EcdsaKey::from_pkcs8_der(alg, pkcs8.as_ref(), SystemRandom::new()).expect("load from der");

    // Load account associated with the given account key, if acme server doesn't have this account yet this will fail
    let account = client
        .load_account(account_key)
        .await
        .expect("create account");

    let mut order = account
        .new_order(NewOrderPayload {
            identifiers: vec![Identifier::dns("example.com")],
            ..Default::default()
        })
        .await
        .expect("create order");

    let authz = order
        .get_authorizations()
        .await
        .expect("get order authorizations");

    let auth = &authz[0];
    let mut challenge = auth
        .challenges
        .iter()
        .find(|challenge| challenge.r#type == ChallengeType::Http01)
        .expect("find http challenge")
        .to_owned();

    let key_authorization = order
        .create_key_authorization(&challenge)
        .expect("create key authorization");

    let path = format!(".well-known/acme-challenge/{}", challenge.token);

    tracing::info!("running service at: {ADDR}");

    let state = Arc::new(ChallengeState {
        key_authorization: key_authorization.clone(),
    });

    let graceful = graceful::Shutdown::default();

    let challenge_server_handle = graceful.spawn_task_fn(async move |guard| {
        let exec = Executor::graceful(guard.clone());
        HttpServer::auto(exec)
            .listen(
                ADDR,
                (TraceLayer::new_for_http(), CompressionLayer::new()).into_layer(
                    WebService::default().get(&path, move || {
                        let state = state.clone();
                        std::future::ready((
                            Headers::single(ContentType::octet_stream()),
                            state.key_authorization.as_str().to_owned(),
                        ))
                    }),
                ),
            )
            .await
            .expect("http server");
    });

    sleep(Duration::from_millis(1000)).await;

    order
        .finish_challenge(&mut challenge)
        .await
        .expect("finish challenge");

    let state = order
        .wait_until_all_authorizations_finished()
        .await
        .expect("wait until authorizations are finished");

    assert_eq!(state.status, OrderStatus::Ready);

    let (key_pair, csr) = create_csr();

    order.finalize(csr.der()).await.expect("finalize order");

    let cert = order
        .download_certificate_as_pem_stack()
        .await
        .expect("download certificate");

    tracing::info!(?cert, "received certificiate");
    challenge_server_handle.abort();

    let server_auth = ServerAuthData {
        cert_chain: DataEncoding::DerStack(cert.into_iter().map(|pem| pem.contents).collect()),
        private_key: DataEncoding::Der(key_pair.serialize_der()),
        ocsp: None,
    };

    // create https server using the configured certificate

    graceful.spawn_task_fn(async |guard| {
        let exec = Executor::graceful(guard.clone());
        let http_service = HttpServer::auto(exec).service(service_fn(async || {
            Ok::<_, Infallible>("hello".into_response())
        }));

        let tls_server_config = ServerConfig::new(ServerAuth::Single(server_auth));

        let acceptor_data =
            TlsAcceptorData::try_from(tls_server_config).expect("create acceptor data");

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
struct ChallengeState {
    key_authorization: KeyAuthorization,
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
