use super::utils;
use rama::{
    http::layer::har::{self},
    http::service::web::response::Json,
    http::{BodyExtractExt, Request, StatusCode, server::HttpServer},
    net::address::ProxyAddress,
    rt::Executor,
    service::service_fn,
};

use serde_json::{Value, json};

#[tokio::test]
#[ignore]
async fn test_http_record_har() {
    utils::init_tracing();

    tokio::spawn(async {
        HttpServer::auto(Executor::default())
            .listen(
                "127.0.0.1:63007",
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

    let runner = utils::ExampleRunner::interactive("http_record_har", Some("boring"));

    let proxy_address = ProxyAddress::try_from("http://john:secret@127.0.0.1:62040").unwrap();

    // test regular proxy flow w/o har recording enabled
    let response = runner
        .get("http://127.0.0.1:63007/fetch/1")
        .extension(proxy_address.clone())
        .send()
        .await
        .unwrap();

    assert!(response.headers().get("x-rama-har-file-path").is_none());

    let result = response.try_into_json::<Value>().await.unwrap();
    let expected_value = json!({"method":"GET","path":"/fetch/1"});
    assert_eq!(expected_value, result);

    // toggle har recording on
    let status_code = runner
        .post("http://har.toggle.internal/switch")
        .extension(proxy_address.clone())
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(StatusCode::OK, status_code);

    // test regular proxy flow w har recording enabled

    let response = runner
        .get("http://127.0.0.1:63007/fetch/2")
        .extension(proxy_address.clone())
        .send()
        .await
        .unwrap();

    let file_path = response
        .headers()
        .get("x-rama-har-file-path")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert!(!file_path.is_empty());

    let result = response.try_into_json::<Value>().await.unwrap();
    let expected_value = json!({"method":"GET","path":"/fetch/2"});
    assert_eq!(expected_value, result);

    let response = runner
        .get("http://127.0.0.1:63007/fetch/3")
        .extension(proxy_address.clone())
        .send()
        .await
        .unwrap();

    let file_path_2 = response
        .headers()
        .get("x-rama-har-file-path")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(file_path, file_path_2);

    let result = response.try_into_json::<Value>().await.unwrap();
    let expected_value = json!({"method":"GET","path":"/fetch/3"});
    assert_eq!(expected_value, result);

    // toggle recording off again
    let status_code = runner
        .post("http://har.toggle.internal/switch")
        .extension(proxy_address.clone())
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(StatusCode::OK, status_code);

    // test regular proxy flow once again w/o har recording enabled
    let response = runner
        .get("http://127.0.0.1:63007/fetch/4")
        .extension(proxy_address.clone())
        .send()
        .await
        .unwrap();

    assert!(response.headers().get("x-rama-har-file-path").is_none());

    let result = response.try_into_json::<Value>().await.unwrap();
    let expected_value = json!({"method":"GET","path":"/fetch/4"});
    assert_eq!(expected_value, result);

    // now read file and ensure we have a HAR file as we more or less expect

    let har_file_bytes = tokio::fs::read(file_path).await.unwrap();
    assert!(!har_file_bytes.is_empty());

    let har::spec::LogFile { log } = serde_json::from_slice(&har_file_bytes).unwrap();

    // test metadata
    assert!(log.comment.is_none());
    assert!(log.browser.is_none());
    assert_eq!(log.version, "1.2");
    assert_eq!(log.creator.name, rama::utils::info::NAME);
    assert_eq!(log.creator.version, rama::utils::info::VERSION);
    assert!(log.creator.comment.is_none());
    assert!(log.pages.as_ref().unwrap().is_empty());

    // test entries...
    assert_eq!(2, log.entries.len());
    // ... test entry #1
    // ...... not yet supported
    assert!(log.entries[0].comment.is_none());
    assert!(log.entries[0].connection.is_none());
    assert!(log.entries[0].server_address.is_none());
    assert!(log.entries[0].page_ref.is_none());
    // ...... request
    assert!(log.entries[0].request.comment.is_none());
    assert_eq!("GET", log.entries[0].request.method);
    assert_eq!("http://127.0.0.1:63007/fetch/2", log.entries[0].request.url);
    // ...... response
    assert_eq!(200, log.entries[0].response.as_ref().unwrap().status);
    // ... test entry #2
    // ...... not yet supported
    assert!(log.entries[1].comment.is_none());
    assert!(log.entries[1].connection.is_none());
    assert!(log.entries[1].server_address.is_none());
    assert!(log.entries[1].page_ref.is_none());
    // ...... request
    assert!(log.entries[0].request.comment.is_none());
    assert_eq!("GET", log.entries[1].request.method);
    assert_eq!("http://127.0.0.1:63007/fetch/3", log.entries[1].request.url);
    // ...... response
    assert_eq!(200, log.entries[1].response.as_ref().unwrap().status);
}
