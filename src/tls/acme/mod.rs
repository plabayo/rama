pub mod proto;

mod client;
#[doc(inline)]
pub use client::{AcmeClient, AcmeProvider};

mod server;
#[doc(inline)]
pub use server::{AcmeServer, DirectoryPaths};

#[cfg(test)]
mod test {
    use std::{convert::Infallible, sync::Arc, time::Duration};

    use crate::tls::acme::proto::{
        client::{CreateAccountOptions, FinalizePayload, KeyAuthorization, NewOrderPayload},
        common::Identifier,
        server::{ChallengeType, OrderStatus},
    };
    use http::HeaderValue;
    use parking_lot::Mutex;
    use rama_core::{Context, Service, error::BoxError};
    use rama_crypto::dep::aws_lc_rs::{
        rand::SystemRandom,
        signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair},
    };
    use rama_http::{Body, Request, Response, service::web::Router};
    use rama_net::client::EstablishedClientConnection;
    use rama_net::test_utils::client::MockConnectorService;
    use rama_tls_rustls::{
        client::{TlsConnector, TlsConnectorDataBuilder},
        dep::{
            rcgen::{self, Certificate, CertificateParams, DistinguishedName, DnType, KeyPair},
            rustls::{
                self, crypto,
                server::{ClientHello, ResolvesServerCert},
                sign::CertifiedKey,
            },
        },
        server::{TlsAcceptorData, TlsAcceptorService},
    };

    use super::*;

    const DIRECTORY_PATHS: server::DirectoryPaths = server::DirectoryPaths {
        directory: "/directory",
        new_nonce: "/nonce",
        key_change: "/key_change",
        new_order: "/new_order",
        new_account: "/new_account",
        new_authz: None,
        revoke_cert: "/revoke_cert",
    };

    #[tokio::test]
    async fn http_test() {
        let key_authz_store = Arc::new(Mutex::new(None));
        let challege_response = ChallengeResponder {
            key_auth: key_authz_store.clone(),
        };

        let http_acme_test_local_server = Router::<()>::new()
            .get("/.well-known/acme-challenge/{token}", challege_response)
            .boxed();

        let acme_server = server::AcmeServer::new("https://test.localhost", &DIRECTORY_PATHS, None)
            .with_http_challenge_client(http_acme_test_local_server)
            .build();

        let test_nonce: u64 = 0;

        let acme_client = AcmeClient::new_with_https_client(
            format!("https://test.localhost{}", DIRECTORY_PATHS.directory).as_str(),
            acme_server.boxed(),
        )
        .await
        .expect("get directory");

        // Should fetch a nonce from server
        let nonce = acme_client.nonce().await.expect("get nonce");
        assert_eq!(nonce, test_nonce.to_string());

        // *acme_client.nonce.lock() = Some(test_nonce.to_string());
        // let nonce = acme_client.nonce().await.unwrap();
        // assert_eq!(nonce, test_nonce.to_string());

        println!("creating account");
        let account = acme_client
            .create_account(CreateAccountOptions {
                terms_of_service_agreed: Some(true),
                contact: None,
                external_account_binding: None,
                only_return_existing: None,
            })
            .await
            .expect("create account");

        println!("creating order");
        let mut order = account
            .new_order(NewOrderPayload {
                identifiers: vec![Identifier::Dns("test.dev".into())],
                ..Default::default()
            })
            .await
            .expect("create order");

        println!("refresh order");
        order.refresh().await.expect("refresh order");

        println!("get authz");
        let authz = order.get_authorizations().await.unwrap();

        let auth = &authz[0];
        println!("authz: {:?}", auth);
        let mut challenge = auth
            .challenges
            .iter()
            .find(|challenge| challenge.r#type == ChallengeType::Http01)
            .unwrap()
            .to_owned();

        let key_authz = order.create_key_authorization(&challenge).unwrap();

        *key_authz_store.lock() = Some(key_authz);

        println!("notifying ready");
        order.notify_challenge_ready(&challenge).await.unwrap();

        println!("waiting for challenge");
        order
            .poll_until_challenge_finished(&mut challenge, Duration::from_secs(1))
            .await
            .unwrap();

        println!("waiting for order");
        let state = order
            .poll_until_all_authorizations_finished(Duration::from_secs(3))
            .await
            .unwrap();

        assert_eq!(state.status, OrderStatus::Ready);

        let csr = create_csr();

        order.finalize(csr).await.unwrap();

        order
            .poll_until_certificate_ready(Duration::from_secs(3))
            .await
            .unwrap();

        let cert = order.download_certificate().await.unwrap();
        println!("got certificate: {cert:?}");
    }

    fn create_csr() -> String {
        let key_pair = rcgen::KeyPair::generate().unwrap();

        let params = CertificateParams::new(vec!["example.com".to_string()]).unwrap();

        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CountryName, "US");
        distinguished_name.push(DnType::StateOrProvinceName, "California");
        distinguished_name.push(DnType::LocalityName, "San Francisco");
        distinguished_name.push(DnType::OrganizationName, "ACME Corporation");
        distinguished_name.push(DnType::CommonName, "example.com");

        let csr_pem = params.serialize_request(&key_pair).unwrap().pem().unwrap();
        csr_pem
    }

    #[tokio::test]
    async fn tls_test() {
        let cert_store = Arc::new(Mutex::new(None));
        let cert_resolver = Arc::new(ResolvesServerCertAcme {
            key: cert_store.clone(),
        });

        let mut server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(cert_resolver);

        server_config.alpn_protocols = vec![rama_net::tls::ApplicationProtocol::ACME_TLS.into()];

        let acceptor_data = TlsAcceptorData::try_from(server_config).expect("create acceptor data");

        let tls_acme_test_local_server = TlsConnector::secure(MockConnectorService::new(|| {
            TlsAcceptorService::new(acceptor_data, DummyConnector, false)
        }))
        .with_connector_data(
            TlsConnectorDataBuilder::new()
                .with_alpn_protocols(&[rama_net::tls::ApplicationProtocol::ACME_TLS])
                .with_no_cert_verifier()
                .with_store_server_certificate_chain(true)
                .build(),
        );

        let acme_server = server::AcmeServer::new("https://test.localhost", &DIRECTORY_PATHS, None)
            .with_tls_challenge_client(tls_acme_test_local_server)
            .build();

        let test_nonce: u64 = 0;

        let acme_client = AcmeClient::new_with_https_client(
            format!("https://test.localhost{}", DIRECTORY_PATHS.directory).as_str(),
            acme_server.boxed(),
        )
        .await
        .unwrap();

        // Should fetch a nonce from server
        let nonce = acme_client.nonce().await.unwrap();
        assert_eq!(nonce, test_nonce.to_string());

        // *acme_client.nonce.lock() = Some(test_nonce.to_string());
        // let nonce = acme_client.nonce().await.unwrap();
        // assert_eq!(nonce, test_nonce.to_string());

        println!("creating account");
        let account = acme_client
            .create_account(CreateAccountOptions {
                terms_of_service_agreed: Some(true),
                contact: None,
                external_account_binding: None,
                only_return_existing: None,
            })
            .await
            .unwrap();

        println!("creating order");
        let mut order = account
            .new_order(NewOrderPayload {
                identifiers: vec![Identifier::Dns("test.dev".into())],
                ..Default::default()
            })
            .await
            .unwrap();

        println!("refresh order");
        order.refresh().await.unwrap();

        println!("get authz");
        let authz = order.get_authorizations().await.unwrap();

        let auth = &authz[0];
        println!("authz: {:?}", auth);
        let challenge = auth
            .challenges
            .iter()
            .find(|challenge| challenge.r#type == ChallengeType::TlsAlpn01)
            .unwrap();

        let cert_key = order
            .create_rustls_cert_for_acme_authz(&challenge, &auth.identifier)
            .unwrap();

        *cert_store.lock() = Some(Arc::new(cert_key));
        println!("challegen: {:?}", challenge);
        let mut challenge = challenge.to_owned();

        order.notify_challenge_ready(&challenge).await.unwrap();

        println!("waiting for challenge");
        order
            .poll_until_challenge_finished(&mut challenge, Duration::from_secs(30))
            .await
            .unwrap();

        println!("waiting for order");
        let state = order
            .poll_until_all_authorizations_finished(Duration::from_secs(3))
            .await
            .unwrap();

        assert_eq!(state.status, OrderStatus::Ready);

        let csr = create_csr();

        order.finalize(csr).await.unwrap();

        order
            .poll_until_certificate_ready(Duration::from_secs(3))
            .await
            .unwrap();

        let cert = order.download_certificate().await.unwrap();
        println!("got certificate: {cert:?}");
    }

    struct ChallengeResponder {
        key_auth: Arc<Mutex<Option<KeyAuthorization>>>,
    }

    impl Service<(), Request> for ChallengeResponder {
        type Response = Response;

        type Error = Infallible;

        async fn serve(
            &self,
            _ctx: Context<()>,
            _req: Request,
        ) -> Result<Self::Response, Self::Error> {
            println!("receving get request from acme server");

            let authz = self.key_auth.lock();
            match authz.as_ref() {
                Some(authz) => {
                    let mut response = http::Response::new(Body::from(authz.as_str().to_owned()));
                    let headers = response.headers_mut();
                    headers.append(
                        "content-type",
                        HeaderValue::from_str("application/octet-stream").unwrap(),
                    );
                    Ok(response)
                }
                None => panic!("otodo"),
            }
        }
    }

    #[derive(Debug)]
    struct ResolvesServerCertAcme {
        key: Arc<Mutex<Option<Arc<CertifiedKey>>>>,
    }

    impl ResolvesServerCert for ResolvesServerCertAcme {
        fn resolve(&self, _client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
            return self.key.lock().clone();
        }
    }

    struct DummyConnector;

    impl<Request> Service<(), Request> for DummyConnector
    where
        Request: Send + 'static,
    {
        type Response = EstablishedClientConnection<(), (), Request>;

        type Error = BoxError;

        async fn serve(
            &self,
            ctx: Context<()>,
            req: Request,
        ) -> Result<Self::Response, Self::Error> {
            Ok(EstablishedClientConnection { ctx, req, conn: () })
        }
    }
}
