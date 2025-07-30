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
const ADDR: &str = "0.0.0.0:5002";

#[tokio::main]
async fn main() {
    let tls_config = rama_tls_rustls::client::TlsConnectorDataBuilder::new()
        .with_env_key_logger()
        .unwrap()
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

    let client = AcmeClient::new(TEST_DIRECTORY_URL, client).await.unwrap();
    let account = client
        .create_account(CreateAccountOptions {
            terms_of_service_agreed: Some(true),
            contact: None,
            external_account_binding: None,
            only_return_existing: None,
        })
        .await
        .unwrap();

    let mut order = account
        .new_order(NewOrderPayload {
            identifiers: vec![Identifier::Dns("test.dev".into())],
            ..Default::default()
        })
        .await
        .unwrap();

    let mut authz = order.get_authorizations().await.unwrap();
    let auth = &mut authz[0];

    tracing::info!("running service at: {ADDR}");

    let graceful = crate::graceful::Shutdown::default();

    let challenge = auth
        .challenges
        .iter_mut()
        .find(|challenge| challenge.r#type == ChallengeType::TlsAlpn01)
        .unwrap();

    let (pk, cert) = order
        .create_tls_challenge_data(challenge, &auth.identifier)
        .unwrap();

    let pk = PrivateKeyDer::Pkcs8(pk);

    let cert_key = CertifiedKey::new(vec![cert.der().clone()], any_ecdsa_type(&pk).unwrap());

    let cert_resolver = Arc::new(ResolvesServerCertAcme::new(cert_key));

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(cert_resolver);

    server_config.alpn_protocols = vec![rama_net::tls::ApplicationProtocol::ACME_TLS.into()];

    let acceptor_data = TlsAcceptorData::from(server_config);

    graceful.spawn_task_fn(|guard| async move {
        let tcp_service =
            TlsAcceptorLayer::new(acceptor_data).layer(service_fn(internal_tcp_service_fn));

        TcpListener::bind("127.0.0.1:5001")
            .await
            .expect("bind TCP Listener: tls")
            .serve_graceful(guard, tcp_service)
            .await;
    });

    sleep(Duration::from_millis(1000)).await;

    order.notify_challenge_ready(challenge).await.unwrap();

    order
        .poll_until_challenge_finished(challenge, Duration::from_secs(30))
        .await
        .unwrap();

    order
        .poll_until_all_authorizations_finished(Duration::from_secs(3))
        .await
        .unwrap();

    assert_eq!(order.state().status, OrderStatus::Ready);

    let csr = create_csr();
    order.finalize(csr.der()).await.unwrap();

    order
        .poll_until_certificate_ready(Duration::from_secs(3))
        .await
        .unwrap();

    let _cert = order.download_certificate().await.unwrap();
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
    let key_pair = rcgen::KeyPair::generate().unwrap();

    let params = CertificateParams::new(vec!["test.dev".to_owned()]).unwrap();

    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CountryName, "US");
    distinguished_name.push(DnType::StateOrProvinceName, "California");
    distinguished_name.push(DnType::LocalityName, "San Francisco");
    distinguished_name.push(DnType::OrganizationName, "ACME Corporation");
    distinguished_name.push(DnType::CommonName, "example.com");

    params.serialize_request(&key_pair).unwrap()
}
