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
//! TODO: once Rama has an ACME server implementation (https://github.com/plabayo/rama/issues/649) migrate
//! this example to use that instead of Pebble so we can test everything automatically
use rama::{
    Context, Layer, Service,
    crypto::dep::rcgen::{
        self, CertificateParams, CertificateSigningRequest, DistinguishedName, DnType,
    },
    graceful,
    http::{
        Body,
        client::EasyHttpWebClient,
        headers::{ContentType, HeaderMapExt},
        layer::{compression::CompressionLayer, trace::TraceLayer},
        server::HttpServer,
        service::web::WebService,
    },
    net::tls::client::ServerVerifyMode,
    rt::Executor,
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
        boring::client::TlsConnectorDataBuilder,
    },
};
use std::{sync::Arc, time::Duration};
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
        .with_keylog_intent(rama_net::tls::KeyLogIntent::Environment)
        .into_shared_builder();

    let client = EasyHttpWebClient::builder()
        .with_default_transport_connector()
        .without_tls_proxy_support()
        .without_proxy_support()
        .with_tls_support_using_boringssl(Some(tls_config))
        .build()
        .boxed();

    let client = AcmeClient::new(TEST_DIRECTORY_URL, client, Context::default())
        .await
        .expect("create acme client");

    let account = client
        .create_account(
            Context::default(),
            CreateAccountOptions {
                terms_of_service_agreed: Some(true),
                ..Default::default()
            },
        )
        .await
        .expect("create account");

    let mut order = account
        .new_order(
            Context::default(),
            NewOrderPayload {
                identifiers: vec![Identifier::Dns("example.com".into())],
                ..Default::default()
            },
        )
        .await
        .expect("create order");

    let authz = order
        .get_authorizations(Context::default())
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

    graceful.spawn_task_fn(async move |guard| {
        let exec = Executor::graceful(guard.clone());
        HttpServer::auto(exec)
            .listen_with_state(
                state,
                ADDR,
                (TraceLayer::new_for_http(), CompressionLayer::new()).into_layer(
                    WebService::default().get(
                        &path,
                        async move |ctx: Context<Arc<ChallengeState>>| {
                            let mut response = http::Response::new(Body::from(
                                ctx.state().key_authorization.as_str().to_owned(),
                            ));
                            let headers = response.headers_mut();
                            headers.typed_insert(ContentType::octet_stream());
                            response
                        },
                    ),
                ),
            )
            .await
            .expect("http server");
    });

    sleep(Duration::from_millis(1000)).await;

    order
        .finish_challenge(Context::default(), &mut challenge)
        .await
        .expect("finish challenge");

    let state = order
        .wait_until_all_authorizations_finished(Context::default())
        .await
        .expect("wait until authorizations are finished");

    assert_eq!(state.status, OrderStatus::Ready);

    let csr = create_csr();
    order
        .finalize(Context::default(), csr.der())
        .await
        .expect("finalize order");

    let cert = order
        .download_certificate(Context::default())
        .await
        .expect("download certificate");

    tracing::info!(?cert, "received certificiate")
}

#[derive(Debug)]
struct ChallengeState {
    key_authorization: KeyAuthorization,
}

fn create_csr() -> CertificateSigningRequest {
    let key_pair = rcgen::KeyPair::generate().expect("create keypair");

    let params =
        CertificateParams::new(vec!["example.com".to_owned()]).expect("create certificate params");

    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CountryName, "BE");
    distinguished_name.push(DnType::LocalityName, "Ghent");
    distinguished_name.push(DnType::OrganizationName, "Plabayo");
    distinguished_name.push(DnType::CommonName, "example.com");

    params
        .serialize_request(&key_pair)
        .expect("create certificate signing request")
}
