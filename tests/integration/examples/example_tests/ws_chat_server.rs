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
async fn test_ws_chat_server() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("ws_chat_server", None);

    // basic html page sanity checks,
    // to at least give some basic guarantees for the human experience

    let index_response = runner
        .get("http://127.0.0.1:62033")
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
    assert!(index_content.contains(r##"new WebSocket("/chat")"##));

    // test the actual ws content

    let mut ws_1 = runner
        .websocket("ws://127.0.0.1:62033/chat")
        .handshake(Context::default())
        .await
        .unwrap();
    ws_1.send_message(r##"{"type":"join","name":"john"}"##.into())
        .await
        .expect("ws message to be sent");
    assert_eq!(
        r##"{"type":"system","name":null,"message":"john joined the chat."}"##,
        ws_1.recv_message()
            .await
            .expect("ws message to be received")
            .into_text()
            .expect("ws message to be a text message")
            .as_str()
    );

    let mut ws_2 = runner
        .websocket("ws://127.0.0.1:62033/chat")
        .handshake(Context::default())
        .await
        .unwrap();
    ws_2.send_message(r##"{"type":"join","name":"nick"}"##.into())
        .await
        .expect("ws message to be sent");
    assert_eq!(
        r##"{"type":"system","name":null,"message":"nick joined the chat."}"##,
        ws_2.recv_message()
            .await
            .expect("ws message to be received")
            .into_text()
            .expect("ws message to be a text message")
            .as_str()
    );
    assert_eq!(
        r##"{"type":"system","name":null,"message":"nick joined the chat."}"##,
        ws_1.recv_message()
            .await
            .expect("ws message to be received")
            .into_text()
            .expect("ws message to be a text message")
            .as_str()
    );

    ws_1.send_message(r##"{"type":"chat","message":"hello"}"##.into())
        .await
        .expect("ws message to be sent");
    assert_eq!(
        r##"{"type":"user","name":"john","message":"hello"}"##,
        ws_2.recv_message()
            .await
            .expect("ws message to be received")
            .into_text()
            .expect("ws message to be a text message")
            .as_str()
    );
    assert_eq!(
        r##"{"type":"user","name":"john","message":"hello"}"##,
        ws_1.recv_message()
            .await
            .expect("ws message to be received")
            .into_text()
            .expect("ws message to be a text message")
            .as_str()
    );
}
