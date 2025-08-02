use rama::{
    Context, Layer, Service,
    crypto::dep::{
        pki_types::PrivateKeyDer,
        rcgen::{self, CertificateParams, CertificateSigningRequest, DistinguishedName, DnType},
    },
    graceful,
    http::client::EasyHttpWebClient,
    service::service_fn,
    tcp::server::TcpListener,
    telemetry::tracing,
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
            server::{TlsAcceptorData, TlsAcceptorLayer},
        },
    },
};

use std::{convert::Infallible, sync::Arc, time::Duration};
use tokio::time::sleep;

// Default directory url of pebble
const TEST_DIRECTORY_URL: &str = "https://localhost:14000/dir";
// Addr on which server will bind to do acme challenge
const ADDR: &str = "0.0.0.0:5004";

#[tokio::main]
async fn main() {
    let tls_config = rama_tls_rustls::client::TlsConnectorDataBuilder::new()
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

    let client = AcmeClient::new(TEST_DIRECTORY_URL, client).await.expect("");
    let account = client
        .create_account(CreateAccountOptions {
            terms_of_service_agreed: Some(true),
            ..Default::default()
        })
        .await
        .expect("create account");

    let mut order = account
        .new_order(NewOrderPayload {
            identifiers: vec![Identifier::Dns("example.com".into())],
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

    server_config.alpn_protocols = vec![rama_net::tls::ApplicationProtocol::ACME_TLS.into()];

    let acceptor_data = TlsAcceptorData::from(server_config);

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
        .notify_challenge_ready(challenge)
        .await
        .expect("notify challenge ready");

    order
        .poll_until_challenge_finished(challenge, Duration::from_secs(30))
        .await
        .expect("wait until challenge is finished");

    order
        .poll_until_all_authorizations_finished(Duration::from_secs(3))
        .await
        .expect("wait until all authorizations are finished");

    assert_eq!(order.state().status, OrderStatus::Ready);

    let csr = create_csr();
    order.finalize(csr.der()).await.expect("finalize order");

    order
        .poll_until_certificate_ready(Duration::from_secs(3))
        .await
        .expect("wait until certificate is ready");

    let _cert = order
        .download_certificate()
        .await
        .expect("download certificate");
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

async fn internal_tcp_service_fn<S>(_ctx: Context<()>, _stream: S) -> Result<(), Infallible> {
    Ok(())
}

fn create_csr() -> CertificateSigningRequest {
    let key_pair = rcgen::KeyPair::generate().expect("");

    let params = CertificateParams::new(vec!["example.com".to_owned()]).expect("");

    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CountryName, "BE");
    distinguished_name.push(DnType::LocalityName, "Ghent");
    distinguished_name.push(DnType::OrganizationName, "Plabayo");
    distinguished_name.push(DnType::CommonName, "example.com");

    params.serialize_request(&key_pair).expect("")
}
