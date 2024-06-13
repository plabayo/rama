use super::utils;
use rama::{
    http::{response::Json, server::HttpServer, BodyExtractExt, Request},
    net::address::ProxyAddress,
    rt::Executor,
    service::{service_fn, Context},
};
use serde_json::{json, Value};

#[tokio::test]
#[ignore]
async fn test_http_connect_proxy() {
    utils::init_tracing();

    tokio::spawn(async {
        HttpServer::auto(Executor::default())
            .listen(
                "127.0.0.1:63002",
                service_fn(|req: Request| async move {
                    Ok(Json(json!({
                        "method": req.method().as_str(),
                        "path": req.uri().path(),
                    })))
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
        .send(ctx.clone())
        .await
        .unwrap()
        .try_into_json::<Value>()
        .await
        .unwrap();
    let expected_value = json!({"method":"GET","path":"/foo/bar"});
    assert_eq!(expected_value, result);
}
