use super::utils;
use rama::{
    http::{
        headers::Accept, layer::compression::CompressionLayer, response::Json, server::HttpServer,
        BodyExtractExt, IntoResponse, Request,
    },
    net::address::ProxyAddress,
    rt::Executor,
    service::{Context, ServiceBuilder},
};
use serde_json::{json, Value};

#[tokio::test]
#[ignore]
async fn test_https_connect_proxy() {
    utils::init_tracing();

    tokio::spawn(async {
        HttpServer::auto(Executor::default())
            .listen(
                "127.0.0.1:63002",
                ServiceBuilder::new()
                    .layer(CompressionLayer::new())
                    .service_fn(|req: Request| async move {
                        tracing::debug!(uri = %req.uri(), "serve request");
                        Ok(Json(json!({
                            "method": req.method().as_str(),
                            "path": req.uri().path(),
                        }))
                        .into_response())
                    }),
            )
            .await
            .unwrap();
    });

    let runner = utils::ExampleRunner::interactive("https_connect_proxy");

    let mut ctx = Context::default();
    ctx.insert(ProxyAddress::try_from("https://john:secret@127.0.0.1:62016").unwrap());

    // test regular proxy flow
    let result = runner
        .get("http://127.0.0.1:63002/foo/bar")
        .typed_header(Accept::json())
        .send(ctx.clone())
        .await
        .unwrap()
        .try_into_json::<Value>()
        .await
        .unwrap();
    let expected_value = json!({"method":"GET","path":"/foo/bar"});
    assert_eq!(expected_value, result);
}
