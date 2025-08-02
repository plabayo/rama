use rama::{
    Context, Layer, Service,
    crypto::dep::rcgen::{
        self, CertificateParams, CertificateSigningRequest, DistinguishedName, DnType,
    },
    graceful,
    http::{
        Body,
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
use rama_http::headers::{ContentType, HeaderMapExt};

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

    let mut order = account
        .new_order(NewOrderPayload {
            identifiers: vec![Identifier::Dns("example.com".into())],
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
        .notify_challenge_ready(&challenge)
        .await
        .expect("notify challenge is ready");

    order
        .poll_until_challenge_finished(&mut challenge, Duration::from_secs(30))
        .await
        .expect("wait until challenge is finished");

    let state = order
        .poll_until_all_authorizations_finished(Duration::from_secs(3))
        .await
        .expect("wait until authorizations are finished");

    assert_eq!(state.status, OrderStatus::Ready);

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
