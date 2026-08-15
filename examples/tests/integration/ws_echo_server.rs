use super::utils;
use rama::{
    extensions::Extensions,
    http::{
        BodyExtractExt, StatusCode,
        client::BlockingHttpClient,
        headers::{ContentType, HeaderMapExt},
        mime,
        ws::handshake::client::BlockingHttpClientWebSocketExt as _,
    },
};

#[tokio::test]
#[ignore]
async fn test_ws_echo_server() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("ws_echo_server", None);

    // basic html page sanity checks,
    // to at least give some basic guarantees for the human experience

    let index_response = runner.get("http://127.0.0.1:62032").send().await.unwrap();
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
        .websocket("ws://127.0.0.1:62032/echo")
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

    let blocking_client = BlockingHttpClient::try_new(runner.client.clone()).unwrap();
    std::thread::spawn(move || {
        let mut ws = blocking_client
            .websocket("ws://127.0.0.1:62032/echo")
            .try_handshake()
            .unwrap();
        ws.send_message("hello blocking world".into()).unwrap();
        assert_eq!(
            "hello blocking world",
            ws.recv_message().unwrap().into_text().unwrap().as_str(),
        );
    })
    .join()
    .unwrap();
}
