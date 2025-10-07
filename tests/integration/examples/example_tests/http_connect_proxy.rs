use super::utils;
use rama::{
    http::service::web::response::Json,
    http::{BodyExtractExt, Request, server::HttpServer},
    net::address::ProxyAddress,
    rt::Executor,
    service::service_fn,
};
use serde_json::{Value, json};

#[tokio::test]
#[ignore]
async fn test_http_connect_proxy() {
    utils::init_tracing();

    tokio::spawn(async {
        HttpServer::auto(Executor::default())
            .listen(
                "127.0.0.1:63001",
                service_fn(async |req: Request| {
                    Ok(Json(json!({
                        "method": req.method().as_str(),
                        "path": req.uri().path(),
                    })))
                }),
            )
            .await
            .unwrap();
    });

    let runner = utils::ExampleRunner::interactive("http_connect_proxy", None);

    // test regular proxy flow
    let result = runner
        .get("http://127.0.0.1:63001/foo/bar")
        .extension(ProxyAddress::try_from("http://john:secret@127.0.0.1:62001").unwrap())
        .send()
        .await
        .unwrap()
        .try_into_json::<Value>()
        .await
        .unwrap();
    let expected_value = json!({"method":"GET","path":"/foo/bar"});
    assert_eq!(expected_value, result);

    // test proxy pseudo API
    let result = runner
        .post("http://echo.example.internal/lucky/42")
        .extension(ProxyAddress::try_from("http://john:secret@127.0.0.1:62001").unwrap())
        .send()
        .await
        .unwrap()
        .try_into_json::<Value>()
        .await
        .unwrap();
    let expected_value = json!({"lucky_number": 42});
    assert_eq!(expected_value, result);
}
