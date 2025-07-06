use super::utils;
use rama::{
    Context,
    http::{
        BodyExtractExt, StatusCode,
        headers::{ContentType, HeaderMapExt, dep::mime},
    },
};

#[tokio::test]
#[ignore]
async fn test_ws_over_h2() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("ws_over_h2", Some("boring"));

    // basic html page sanity checks,
    // to at least give some basic guarantees for the human experience

    let index_response = runner
        .get("https://127.0.0.1:62035")
        .send(Context::default())
        .await
        .unwrap();
    assert_eq!(StatusCode::OK, index_response.status());
    assert!(
        index_response
            .headers()
            .typed_get::<ContentType>()
            .map(|ct| ct.mime().eq(&mime::TEXT_HTML_UTF_8))
            .unwrap_or_default()
    );
    let index_content = index_response.try_into_string().await.unwrap();
    assert!(index_content.contains(r##"new WebSocket("/echo")"##));

    // test the actual ws content

    let mut ws = runner
        .websocket_h2("wss://127.0.0.1:62035/echo")
        .handshake(Context::default())
        .await
        .unwrap();
    ws.send_message("hello world".into())
        .await
        .expect("ws message to be sent");
    assert_eq!(
        "hello world",
        ws.recv_message()
            .await
            .expect("echo ws message to be received")
            .into_text()
            .expect("echo ws message to be a text message")
            .as_str()
    );
}
