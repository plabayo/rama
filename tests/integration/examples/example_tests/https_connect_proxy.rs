use super::utils;
use rama::{
    Layer,
    http::service::web::response::{IntoResponse, Json},
    http::{BodyExtractExt, Request, headers::Accept, server::HttpServer},
    net::address::ProxyAddress,
    rt::Executor,
    service::service_fn,
    telemetry::tracing,
};
use serde_json::{Value, json};

#[cfg(feature = "compression")]
use rama::http::layer::compression::CompressionLayer;

#[tokio::test]
#[ignore]
async fn test_https_connect_proxy() {
    utils::init_tracing();

    tokio::spawn(async {
        HttpServer::auto(Executor::default())
            .listen(
                "127.0.0.1:63002",
                (
                    #[cfg(feature = "compression")]
                    CompressionLayer::new(),
                )
                    .into_layer(service_fn(async |req: Request| {
                        tracing::debug!(url.full = %req.uri(), "serve request");
                        Ok(Json(json!({
                            "method": req.method().as_str(),
                            "path": req.uri().path(),
                        }))
                        .into_response())
                    })),
            )
            .await
            .unwrap();
    });

    let runner = utils::ExampleRunner::interactive("https_connect_proxy", Some("rustls"));

    // test regular proxy flow
    let result = runner
        .get("http://127.0.0.1:63002/foo/bar")
        .extension(ProxyAddress::try_from("https://john:secret@127.0.0.1:62016").unwrap())
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
