use rama::{
    Context, Layer, graceful,
    http::{
        Body, HeaderValue,
        layer::{compression::CompressionLayer, trace::TraceLayer},
        server::HttpServer,
        service::web::WebService,
    },
    rt::Executor,
    tls::acme::{
        AcmeClient,
        proto::{
            client::{CreateAccountOptions, KeyAuthorization, NewOrderPayload},
            common::Identifier,
            server::{ChallengeType, OrderStatus},
        },
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

    let auth = &authz[0];
    let mut challenge = auth
        .challenges
        .iter()
        .find(|challenge| challenge.r#type == ChallengeType::Http01)
        .unwrap()
        .to_owned();

    let key_authz = order.create_key_authorization(&challenge);

    let path = format!(".well-known/acme-challenge/{}", challenge.token);

    println!("localhost:5002/{}", path);
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
                            println!("receving get request");
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
}

#[derive(Debug)]
struct ChallengeState {
    key_authz: KeyAuthorization,
}
