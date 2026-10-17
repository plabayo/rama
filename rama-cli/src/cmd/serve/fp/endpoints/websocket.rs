//! One bounded text round trip for the fingerprint page's WebSocket probe.

use std::time::Duration;

use rama::{
    error::{BoxError, BoxErrorExt as _, ErrorContext as _},
    futures::SinkExt as _,
    http::{
        Version,
        ws::{
            AsyncWebSocket, Message,
            protocol::{CloseFrame, frame::coding::CloseCode},
        },
    },
    io::Io,
};
use serde_json::json;

const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(15);

pub(super) async fn exchange<S: Io + Unpin>(
    socket: AsyncWebSocket<S>,
    version: Version,
) -> Result<(), BoxError> {
    tokio::time::timeout(EXCHANGE_TIMEOUT, exchange_messages(socket, version))
        .await
        .context("WebSocket probe timed out")?
}

async fn exchange_messages<S: Io + Unpin>(
    mut socket: AsyncWebSocket<S>,
    version: Version,
) -> Result<(), BoxError> {
    let greeting = json!({
        "initiator": "ws",
        "version": format!("{version:?}"),
        "h3": if version == Version::HTTP_3 {
            "negotiated"
        } else {
            "unsupported_or_not_negotiated"
        },
    });
    socket
        .send_message(greeting.to_string().into())
        .await
        .context("send WebSocket greeting")?;

    // Clients may close after reading the greeting. A browser probe only
    // succeeds after sending text and checking the echoed application bytes.
    loop {
        match socket
            .recv_message()
            .await
            .context("receive WebSocket probe")?
        {
            Message::Text(text) => {
                socket
                    .send_message(Message::Text(text))
                    .await
                    .context("echo WebSocket probe")?;
                break;
            }
            Message::Close(_) => {
                socket.flush().await.context("reply to WebSocket close")?;
                return Ok(());
            }
            Message::Ping(_) | Message::Pong(_) => (),
            _ => return Err(BoxError::from_static_str("WebSocket probe requires text")),
        }
    }

    socket
        .close(Some(CloseFrame {
            code: CloseCode::Normal,
            reason: "finished".into(),
        }))
        .await
        .context("close WebSocket probe")?;
    // The close we sent is flushed; read the peer's reply before dropping IO.
    loop {
        let message = socket
            .recv_message()
            .await
            .context("receive WebSocket close")?;
        if matches!(message, Message::Close(_)) {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama::{ServiceInput, http::ws::protocol::Role};

    #[tokio::test(start_paused = true)]
    async fn text_probe_is_echoed_before_normal_close() {
        for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
            let (client, server) = tokio::io::duplex(4096);
            let server =
                AsyncWebSocket::from_raw_socket(ServiceInput::new(server), Role::Server, None)
                    .await;
            let mut client =
                AsyncWebSocket::from_raw_socket(ServiceInput::new(client), Role::Client, None)
                    .await;
            let server = tokio::spawn(exchange(server, version));
            let Message::Text(greeting) = client.recv_message().await.unwrap() else {
                panic!("greeting")
            };
            let greeting: serde_json::Value = serde_json::from_str(&greeting).unwrap();
            assert_eq!(greeting["version"], format!("{version:?}"));
            let probe = "current request 🐢".repeat(32);
            client
                .send_message(Message::Text(probe.clone().into()))
                .await
                .unwrap();
            assert_eq!(
                client.recv_message().await.unwrap(),
                Message::Text(probe.into())
            );
            let Message::Close(Some(close)) = client.recv_message().await.unwrap() else {
                panic!("close")
            };
            assert_eq!(close.code, CloseCode::Normal);
            client.flush().await.unwrap();
            server.await.unwrap().unwrap();
        }
    }

    #[tokio::test(start_paused = true)]
    async fn client_can_close_after_the_greeting() {
        let (client, server) = tokio::io::duplex(4096);
        let server =
            AsyncWebSocket::from_raw_socket(ServiceInput::new(server), Role::Server, None).await;
        let mut client =
            AsyncWebSocket::from_raw_socket(ServiceInput::new(client), Role::Client, None).await;
        let server = tokio::spawn(exchange(server, Version::HTTP_2));
        assert!(matches!(
            client.recv_message().await.unwrap(),
            Message::Text(_)
        ));
        client.close(None).await.unwrap();
        assert!(matches!(
            client.recv_message().await.unwrap(),
            Message::Close(_)
        ));
        server.await.unwrap().unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn silent_client_cannot_hold_the_probe_open() {
        let (_client, server) = tokio::io::duplex(4096);
        let server =
            AsyncWebSocket::from_raw_socket(ServiceInput::new(server), Role::Server, None).await;
        let start = tokio::time::Instant::now();
        assert!(
            tokio::time::timeout(EXCHANGE_TIMEOUT * 2, exchange(server, Version::HTTP_3))
                .await
                .expect("the exchange enforces its own deadline")
                .unwrap_err()
                .to_string()
                .contains("timed out")
        );
        assert!(start.elapsed() >= EXCHANGE_TIMEOUT);
    }
}
