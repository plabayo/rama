use super::utils;
use rama::{
    http::{response::Json, server::HttpServer, BodyExtractExt, Request},
    proxy::http::client::HttpProxyInfo,
    rt::Executor,
    service::{service_fn, Context},
    stream::ServerSocketAddr,
};
use serde_json::{json, Value};

#[tokio::test]
#[ignore]
async fn test_http_connect_proxy() {
    utils::init_tracing();

    tokio::spawn(async {
        HttpServer::auto(Executor::default())
            .listen(
                "127.0.0.1:63001",
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

    let runner = utils::ExampleRunner::interactive("http_connect_proxy");

    let mut ctx = Context::default();
    ctx.insert(HttpProxyInfo {
        proxy: "127.0.0.1:62001".parse().unwrap(),
        credentials: Some(rama::proxy::ProxyCredentials::Basic {
            username: "john".to_owned(),
            password: Some("secret".to_owned()),
        }),
    });

    // test regular proxy flow
    let result = runner
        .get("http://127.0.0.1:63001/foo/bar")
        .send(ctx)
        .await
        .unwrap()
        .try_into_json::<Value>()
        .await
        .unwrap();
    let expected_value = json!({"method":"GET","path":"/foo/bar"});
    assert_eq!(expected_value, result);

    let mut ctx = Context::default();
    // TODO: this should just work correctly over proxy... instead of this hack
    ctx.insert(ServerSocketAddr::new("127.0.0.1:62001".parse().unwrap()));
    // test proxy pseudo API
    let result = runner
        .post("http://echo.example.internal/lucky/42")
        // TODO: once we go over proxy properly, we should not need this...
        .header("Proxy-Authorization", "Basic am9objpzZWNyZXQ=")
        .send(ctx)
        .await
        .unwrap()
        .try_into_json::<Value>()
        .await
        .unwrap();
    let expected_value = json!({"lucky_number": 42});
    assert_eq!(expected_value, result);

    // TODO: test https proxy flow
}
