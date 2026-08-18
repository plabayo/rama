//! rama websocket client

use std::time::Duration;

use rama::{
    Service,
    error::{BoxError, ErrorContext, extra::OpaqueError},
    graceful::{self, Shutdown},
    http::layer::har::recorder::WebSocketCapture,
    http::ws::{WebSocketIo, layer::har::HARWebSocket, protocol::Role},
    http::{Request, Response},
    utils::{collections::NonEmptySmallVec, str::NonEmptyStr},
};
use tokio::sync::oneshot;

mod client;
mod tui;

pub(super) async fn run<C>(
    req: Request,
    client: C,
    protocols: Option<NonEmptySmallVec<3, NonEmptyStr>>,
) -> Result<(), BoxError>
where
    C: Service<Request, Output = Response, Error = OpaqueError>,
{
    let title = format!("  rama-ws @ {}", req.uri());
    let socket = client::connect(req, client, protocols)
        .await
        .context("establish WebSocket connection")?;
    let capture = socket
        .response()
        .extensions
        .get_ref::<WebSocketCapture>()
        .cloned();
    if let Some(capture) = capture {
        run_app(tui::App::new(title, with_har_capture(socket, capture))).await
    } else {
        run_app(tui::App::new(title, socket)).await
    }
}

fn with_har_capture<S>(
    socket: rama::http::ws::handshake::client::ClientWebSocket<S>,
    capture: WebSocketCapture,
) -> rama::http::ws::handshake::client::ClientWebSocket<HARWebSocket<S>> {
    socket.map_socket(move |socket| HARWebSocket::new(socket, Role::Client, Some(capture)))
}

async fn run_app<S: WebSocketIo>(app: tui::App<S>) -> Result<(), BoxError> {
    let (tx, rx) = oneshot::channel();
    let (tx_final, rx_final) = oneshot::channel();

    let shutdown = Shutdown::new(async move {
        tokio::select! {
            _ = graceful::default_signal() => {
                _ = tx_final.send(Ok(()));
            }
            result = rx => {
                match result {
                    Ok(result) => {
                        _ = tx_final.send(result);
                    }
                    Err(_) => {
                        _ = tx_final.send(Ok(()));
                    }
                }
            }
        }
    });

    shutdown.spawn_task_fn(async move |guard| {
        let mut app = app;
        let result = app.run(guard).await;
        _ = tx.send(result);
    });

    _ = shutdown.shutdown_with_limit(Duration::from_secs(1)).await;

    rx_final.await?
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama::{
        ServiceInput,
        http::layer::har::{
            recorder::WebSocketCaptureRecorder,
            spec::{WebSocketMessage, WebSocketMessageType},
        },
        http::ws::{Message, handshake::client::ClientWebSocket, runtime::AsyncWebSocket},
        http::{Body, Response},
    };
    use std::sync::Arc;
    use tokio::sync::Mutex;

    struct CollectMessages(Arc<Mutex<Vec<WebSocketMessage>>>);

    impl WebSocketCaptureRecorder for CollectMessages {
        async fn record(&self, message: WebSocketMessage) -> Result<(), BoxError> {
            self.0.lock().await.push(message);
            Ok(())
        }
    }

    #[tokio::test]
    async fn cli_websocket_capture_wraps_both_message_directions() {
        let messages = Arc::new(Mutex::new(Vec::new()));
        let capture = WebSocketCapture::new(CollectMessages(messages.clone()), || {});
        let (client_io, server_io) = tokio::io::duplex(1024);
        let client_socket =
            AsyncWebSocket::from_raw_socket(ServiceInput::new(client_io), Role::Client, None).await;
        let (response, _) = Response::new(Body::empty()).into_parts();
        let client = ClientWebSocket {
            socket: client_socket,
            response,
            accepted_protocol: None,
        };
        let mut client = with_har_capture(client, capture);
        let server = tokio::spawn(async move {
            let mut server =
                AsyncWebSocket::from_raw_socket(ServiceInput::new(server_io), Role::Server, None)
                    .await;
            assert_eq!(server.recv_message().await.unwrap(), Message::text("sent"));
            server
                .send_message(Message::text("received"))
                .await
                .unwrap();
        });

        client.send_message(Message::text("sent")).await.unwrap();
        assert_eq!(
            client.recv_message().await.unwrap(),
            Message::text("received")
        );
        server.await.unwrap();

        let messages = messages.lock().await;
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].r#type, WebSocketMessageType::Send);
        assert_eq!(messages[0].data.as_str(), "sent");
        assert_eq!(messages[1].r#type, WebSocketMessageType::Receive);
        assert_eq!(messages[1].data.as_str(), "received");
    }
}
