use rama::{
    Context, Layer, Service,
    crypto::dep::rcgen::{
        self, CertificateParams, CertificateSigningRequest, DistinguishedName, DnType,
    },
    graceful,
    http::{
        Body, HeaderValue,
        client::EasyHttpWebClient,
        layer::{compression::CompressionLayer, trace::TraceLayer},
        server::HttpServer,
        service::web::WebService,
    },
    net::tls::client::ServerVerifyMode,
    rt::Executor,
    telemetry::tracing,
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

// Default directory url of pebble
const TEST_DIRECTORY_URL: &str = "https://localhost:14000/dir";
// Addr on which server will bind to do acme challenge
const ADDR: &str = "0.0.0.0:5002";

#[tokio::main]
async fn main() {
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
            identifiers: vec![Identifier::Dns("example.com".into())],
            ..Default::default()
        })
        .await
        .unwrap();

    let authz = order.get_authorizations().await.unwrap();

    let auth = &authz[0];
    let mut challenge = auth
        .challenges
        .iter()
        .find(|challenge| challenge.r#type == ChallengeType::Http01)
        .unwrap()
        .to_owned();

    let key_authz = order.create_key_authorization(&challenge).unwrap();

    let path = format!(".well-known/acme-challenge/{}", challenge.token);

    tracing::info!("running service at: {ADDR}");

    let state = Arc::new(ChallengeState {
        key_authz: key_authz.clone(),
    });

    let graceful = graceful::Shutdown::default();

    graceful.spawn_task_fn(|guard| async move {
        let exec = Executor::graceful(guard.clone());
        HttpServer::auto(exec)
            .listen_with_state(
                state,
                ADDR,
                (TraceLayer::new_for_http(), CompressionLayer::new()).layer(
                    WebService::default().get(
                        &path,
                        |ctx: Context<Arc<ChallengeState>>| async move {
                            let mut response = http::Response::new(Body::from(
                                ctx.state().key_authz.as_str().to_owned(),
                            ));
                            let headers = response.headers_mut();
                            headers.append(
                                "content-type",
                                HeaderValue::from_str("application/octet-stream").unwrap(),
                            );
                            response
                        },
                    ),
                ),
            )
            .await
            .unwrap();
    });

    sleep(Duration::from_millis(1000)).await;

    order.notify_challenge_ready(&challenge).await.unwrap();

    order
        .poll_until_challenge_finished(&mut challenge, Duration::from_secs(30))
        .await
        .unwrap();

    let state = order
        .poll_until_all_authorizations_finished(Duration::from_secs(3))
        .await
        .unwrap();

    assert_eq!(state.status, OrderStatus::Ready);

    let csr = create_csr();
    order.finalize(csr.der()).await.unwrap();

    order
        .poll_until_certificate_ready(Duration::from_secs(3))
        .await
        .unwrap();

    let _cert = order.download_certificate().await.unwrap();
}

#[derive(Debug)]
struct ChallengeState {
    key_authz: KeyAuthorization,
}

fn create_csr() -> CertificateSigningRequest {
    let key_pair = rcgen::KeyPair::generate().unwrap();

    let params = CertificateParams::new(vec!["example.com".to_owned()]).unwrap();

    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CountryName, "US");
    distinguished_name.push(DnType::StateOrProvinceName, "California");
    distinguished_name.push(DnType::LocalityName, "San Francisco");
    distinguished_name.push(DnType::OrganizationName, "ACME Corporation");
    distinguished_name.push(DnType::CommonName, "example.com");

    params.serialize_request(&key_pair).unwrap()
}
