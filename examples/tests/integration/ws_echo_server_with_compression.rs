use super::utils;
use rama::{
    extensions::Extensions,
    http::{
        BodyExtractExt, StatusCode,
        headers::{ContentType, HeaderMapExt},
        mime,
        ws::protocol::{PerMessageDeflateConfig, WebSocketConfig},
    },
};

#[tokio::test]
#[ignore]
async fn test_ws_echo_server_with_compression() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("ws_echo_server_with_compression", None);

    // basic html page sanity checks,
    // to at least give some basic guarantees for the human experience

    let index_response = runner.get("http://127.0.0.1:62038").send().await.unwrap();
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

    // test the actual ws content w/ compression

    let mut ws = runner
        .websocket("ws://127.0.0.1:62038/echo")
        .with_config(
            WebSocketConfig::default().with_per_message_deflate(PerMessageDeflateConfig::default()),
        )
        .handshake(Extensions::default())
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

    // test the actual ws content w/o compression

    let mut ws = runner
        .websocket("ws://127.0.0.1:62038/echo")
        .handshake(Extensions::default())
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
