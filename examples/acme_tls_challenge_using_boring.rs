//! An example showcasing how to complete an ACME TLS-ALPN-01 challenge using Rama with boringssl and Pebble.
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
//! cargo run --example acme_tls_challenge_using_boring --features=http-full,acme,boring
//! ```
//!
//! # Expected Output
//!
//! The example:
//! - Registers an ACME account
//! - Creates a new order for `example.com`
//! - Serves a TLS certificate over port `5003` with ALPN set to `acme-tls/1`
//! - Completes the TLS-ALPN-01 challenge and downloads a certificate
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
    error::OpaqueError,
    graceful,
    http::client::EasyHttpWebClient,
    net::{
        address::Host,
        tls::{
            DataEncoding,
            client::{ClientHello, ServerVerifyMode},
            server::{
                CacheKind, DynamicCertIssuer, ServerAuth, ServerAuthData, ServerCertIssuerData,
                ServerConfig,
            },
        },
    },
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
        boring::{
            client::TlsConnectorDataBuilder,
            server::{TlsAcceptorData, TlsAcceptorLayer},
        },
    },
};
use std::{convert::Infallible, time::Duration};
use tokio::time::sleep;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

// Default directory url of pebble
const TEST_DIRECTORY_URL: &str = "https://localhost:14000/dir";
// Addr on which server will bind to do acme challenge
const ADDR: &str = "0.0.0.0:5003";

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
        .with_store_server_certificate_chain(true)
        .with_keylog_intent(rama::net::tls::KeyLogIntent::Environment)
        .into_shared_builder();

    let client = EasyHttpWebClient::builder()
        .with_default_transport_connector()
        .without_tls_proxy_support()
        .with_proxy_support()
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

    let mut authz = order
        .get_authorizations(Context::default())
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

    let auth_data = ServerAuthData {
        private_key: DataEncoding::Der(pk.secret_pkcs8_der().into()),
        cert_chain: DataEncoding::DerStack(vec![cert.der().to_vec()]),
        ocsp: None,
    };

    let issuer = TlsAcmeIssue(auth_data);

    let tls_server_config = ServerConfig {
        server_auth: ServerAuth::CertIssuer(ServerCertIssuerData {
            kind: issuer.into(),
            cache_kind: CacheKind::Disabled,
        }),
        application_layer_protocol_negotiation: Some(vec![
            rama::net::tls::ApplicationProtocol::ACME_TLS,
        ]),
        client_verify_mode: Default::default(),
        expose_server_cert: Default::default(),
        key_logger: Default::default(),
        protocol_versions: Default::default(),
        store_client_certificate_chain: Default::default(),
    };

    let acceptor_data = TlsAcceptorData::try_from(tls_server_config).expect("create acceptor data");

    graceful.spawn_task_fn(async move |guard| {
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
        .finish_challenge(Context::default(), challenge)
        .await
        .expect("finish challenge");

    order
        .wait_until_all_authorizations_finished(Context::default())
        .await
        .expect("wait until all authorizations are finished");

    assert_eq!(order.state().status, OrderStatus::Ready);

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

struct TlsAcmeIssue(ServerAuthData);

impl DynamicCertIssuer for TlsAcmeIssue {
    async fn issue_cert(
        &self,
        _client_hello: ClientHello,
        _server_name: Option<Host>,
    ) -> Result<ServerAuthData, OpaqueError> {
        Ok(self.0.clone())
    }
}

async fn internal_tcp_service_fn<S>(_ctx: Context<()>, _stream: S) -> Result<(), Infallible> {
    Ok(())
}

fn create_csr() -> CertificateSigningRequest {
    let key_pair = rcgen::KeyPair::generate().expect("create keypair");

    let params =
        CertificateParams::new(vec!["example.com".to_owned()]).expect("create certificate paramas");

    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CountryName, "BE");
    distinguished_name.push(DnType::LocalityName, "Ghent");
    distinguished_name.push(DnType::OrganizationName, "Plabayo");
    distinguished_name.push(DnType::CommonName, "example.com");

    params
        .serialize_request(&key_pair)
        .expect("create certificate signing request")
}
