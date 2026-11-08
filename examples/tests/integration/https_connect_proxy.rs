use super::utils;
use rama::{
    Layer,
    graceful::WeakScope,
    http::service::web::response::{IntoResponse, Json},
    http::{BodyExtractExt, Request, headers::Accept, server::HttpServer},
    net::{address::ProxyAddress, client::ProxyRoute},
    service::service_fn,
    telemetry::tracing,
};
use serde_json::{Value, json};

#[cfg(feature = "compression")]
use rama::http::layer::compression::CompressionLayer;

#[tokio::test]
#[ignore = "spawns example processes"]
async fn test_https_connect_proxy() {
    utils::init_tracing();

    tokio::spawn(async {
        HttpServer::auto(WeakScope::detached())
            .listen(
                "127.0.0.1:13002",
                (
                    #[cfg(feature = "compression")]
                    CompressionLayer::new(),
                )
                    .into_layer(service_fn(async |req: Request| {
                        tracing::debug!(url.full = %req.uri(), "serve request");
                        Ok(Json(json!({
                            "method": req.method().as_str(),
                            "path": req.uri().path_or_root(),
                        }))
                        .into_response())
                    })),
            )
            .await
            .unwrap();
    });

    let mut runner = utils::ExampleRunner::interactive(utils::example!("https_connect_proxy"));
    runner.wait_for_tcp(([127, 0, 0, 1], 12016)).await;

    // test regular proxy flow
    let result = runner
        .get("http://127.0.0.1:13002/foo/bar")
        .extension(ProxyRoute::Proxy(
            ProxyAddress::try_from("https://john:secret@127.0.0.1:12016").unwrap(),
        ))
        .typed_header(Accept::json())
        .send()
        .await
        .unwrap()
        .try_into_json::<Value>()
        .await
        .unwrap();
    let expected_value = json!({"method":"GET","path":"/foo/bar"});
    assert_eq!(expected_value, result);
}
