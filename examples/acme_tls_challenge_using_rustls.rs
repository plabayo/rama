use rama::{
    Context, Layer, graceful,
    service::service_fn,
    tcp::server::TcpListener,
    tls::{
        acme::{
            AcmeClient,
            proto::{
                client::{CreateAccountOptions, NewOrderPayload},
                common::Identifier,
                server::OrderStatus,
            },
        },
        rustls::{
            dep::rustls::{
                self,
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
    let client = AcmeClient::new(TEST_DIRECTORY_URL).await.unwrap();
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

    let authz = order.get_authorizations().await.unwrap();
    // println!("authz: {:?}", authz);
    // println!("challenges: {:?}", authz[0].challenges);

    let auth = &authz[0];

    tracing::info!("running service at: {ADDR}");

    let graceful = crate::graceful::Shutdown::default();

    let (challenge, cert_key) = order.create_rustls_cert_for_acme_authz(auth).unwrap();
    let mut challenge = challenge.to_owned();

    let cert_resolver = Arc::new(ResolvesServerCertAcme::new(cert_key));

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(cert_resolver);

    server_config.alpn_protocols = vec![rama_net::tls::ApplicationProtocol::ACME_TLS.into()];

    let acceptor_data = TlsAcceptorData::try_from(server_config).expect("create acceptor data");

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

    order.notify_challenge_ready(&challenge).await.unwrap();

    println!("waiting for challenge");
    order
        .poll_until_challenge_finished(&mut challenge, Duration::from_secs(30))
        .await
        .unwrap();

    println!("waiting for order");
    order
        .poll_until_all_authorizations_finished(Duration::from_secs(3))
        .await
        .unwrap();

    println!("new order state: {:?}", order.state());
    assert_eq!(order.state().status, OrderStatus::Ready);
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
        return Some(self.key.clone());
    }
}

async fn internal_tcp_service_fn<S>(_ctx: Context<()>, _stream: S) -> Result<(), Infallible> {
    Ok(())
}
