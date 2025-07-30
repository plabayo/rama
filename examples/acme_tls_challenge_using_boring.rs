use rama::{
    Context, Layer, Service,
    error::OpaqueError,
    graceful,
    service::service_fn,
    tcp::server::TcpListener,
    telemetry::tracing,
    tls::acme::{
        AcmeClient,
        proto::{
            client::{CreateAccountOptions, NewOrderPayload},
            common::Identifier,
            server::{ChallengeType, OrderStatus},
        },
    },
};
use rama_crypto::dep::rcgen::{
    self, CertificateParams, CertificateSigningRequest, DistinguishedName, DnType,
};
use rama_http_backend::client::EasyHttpWebClient;
use rama_net::{
    address::Host,
    tls::{
        DataEncoding,
        client::{ClientHello, ServerVerifyMode},
        server::{
            CacheKind, DynamicCertIssuer, ServerAuth, ServerAuthData, ServerCertIssuerData,
            ServerConfig,
        },
    },
};
use rama_tls_boring::{
    client::TlsConnectorDataBuilder,
    server::{TlsAcceptorData, TlsAcceptorLayer},
};

use std::{convert::Infallible, time::Duration};
use tokio::time::sleep;

// Default directory url of pebble
const TEST_DIRECTORY_URL: &str = "https://localhost:14000/dir";
// Addr on which server will bind to do acme challenge
const ADDR: &str = "0.0.0.0:5002";

#[tokio::main]
async fn main() {
    let tls_config = TlsConnectorDataBuilder::new_http_auto()
        .with_server_verify_mode(ServerVerifyMode::Disable)
        .with_store_server_certificate_chain(true)
        .with_keylog_intent(rama_net::tls::KeyLogIntent::Environment)
        .into_shared_builder();

    let client = EasyHttpWebClient::builder()
        .with_default_transport_connector()
        .without_tls_proxy_support()
        .with_proxy_support()
        .with_tls_support_using_boringssl(Some(tls_config))
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
            rama_net::tls::ApplicationProtocol::ACME_TLS,
        ]),
        client_verify_mode: rama_net::tls::server::ClientVerifyMode::Disable,
        expose_server_cert: false,
        key_logger: rama_net::tls::KeyLogIntent::Environment,
        protocol_versions: None,
        store_client_certificate_chain: false,
    };

    let acceptor_data = TlsAcceptorData::try_from(tls_server_config).expect("create acceptor data");

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

struct TlsAcmeIssue(ServerAuthData);

impl DynamicCertIssuer for TlsAcmeIssue {
    async fn issue_cert(
        &self,
        _client_hello: ClientHello,
        _server_name: Option<Host>,
    ) -> Result<ServerAuthData, OpaqueError> {
        // TODO checks
        Ok(self.0.clone())
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
