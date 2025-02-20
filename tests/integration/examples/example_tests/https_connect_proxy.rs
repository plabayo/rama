use super::utils;
use rama::{
    Context, Layer,
    http::{
        BodyExtractExt, IntoResponse, Request, headers::Accept, response::Json, server::HttpServer,
    },
    net::address::ProxyAddress,
    rt::Executor,
    service::service_fn,
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
                    .layer(service_fn(|req: Request| async move {
                        tracing::debug!(uri = %req.uri(), "serve request");
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
