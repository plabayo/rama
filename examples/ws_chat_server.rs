//! A WebSocket example server which facilitates a little chat application.
//! This is obviously not a production-ready chat application, so don't try to copy paste it as one.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example ws_chat_server --features=http-full
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62033`.
//! Open it in the browser to see it in action or use `rama ws` cli client to test it.
//!
//! Try it with some friends over a local network,
//! or with yourself using different browsers or browser tabs :)

use rama::{
    Context,
    http::{
        server::HttpServer,
        service::web::{Router, response::Html},
        ws::{
            Message, ProtocolError,
            handshake::server::{ServerWebSocket, WebSocketAcceptor},
        },
    },
    service::service_fn,
    tcp::server::TcpListener,
    telemetry::tracing::{debug, error, info, level_filters::LevelFilter, warn},
};

use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::sync::broadcast;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        )
        .init();

    let graceful = rama::graceful::Shutdown::default();

    graceful.spawn_task_fn(async |guard| {
        let server = HttpServer::http1().service(Router::new().get("/", Html(INDEX)).get(
            "/chat",
            WebSocketAcceptor::new().into_service(service_fn(
                async |ctx: Context<State>, mut ws: ServerWebSocket| {
                    let state = ctx.into_parts().state;
                    let mut handler = WsHandler {
                        nickname: None,
                        broadcast_tx: state.broadcast_tx,
                    };
                    let mut broadcast_rx = state.broadcast_rx;

                    loop {
                        tokio::select! {
                            result = ws.recv_message() => {
                                if handler.handle_inc_ws_message(result).await {
                                    return Ok(());
                                }
                            }
                            result = broadcast_rx.recv() => {
                                match result {
                                    Ok(BroadcastMessage::User { name, message }) => {
                                        match serde_json::to_string(&ChatMessage {
                                            r#type: "user",
                                            name: Some(name.as_ref()),
                                            message: Some(message.as_ref()),
                                        }) {
                                            Ok(text) => {
                                                if let Err(err) = ws.send_message(text.into()).await {
                                                    warn!("failed to send user message via WS socket: {err}");
                                                }
                                            }
                                            Err(err) => {
                                                warn!("failed to json serialize user message: {err}");
                                            }
                                        }
                                    }
                                    Ok(BroadcastMessage::System(message)) => {
                                        match serde_json::to_string(&ChatMessage {
                                            r#type: "system",
                                            name: None,
                                            message: Some(message.as_ref()),
                                        }) {
                                            Ok(text) => {
                                                if let Err(err) = ws.send_message(text.into()).await {
                                                    warn!("failed to send system message via WS socket: {err}");
                                                }
                                            }
                                            Err(err) => {
                                                warn!("failed to json serialize system message: {err}");
                                            }
                                        }
                                    }
                                    Err(err) => {
                                        warn!("failed to receive broadcast message: {err}");
                                    }
                                }
                            }
                        }
                    }
                },
            )),
        ));
        info!("open mini web chat @ http://127.0.0.1:62033");
        info!("or connect directly to ws://127.0.0.1:62033/chat (via 'rama ws')");
        TcpListener::bind("127.0.0.1:62033")
            .await
            .expect("bind TCP Listener")
            .with_state(State::default())
            .serve_graceful(guard, server)
            .await;
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}

#[derive(Debug)]
struct WsHandler {
    nickname: Option<String>,
    broadcast_tx: broadcast::Sender<BroadcastMessage>,
}

impl WsHandler {
    async fn handle_inc_ws_message(&mut self, result: Result<Message, ProtocolError>) -> bool {
        match result {
            Ok(Message::Text(msg)) => match serde_json::from_str::<ChatMessage>(msg.as_str()) {
                Ok(chat_msg) => {
                    let msg_type = chat_msg.r#type.trim();
                    if msg_type.eq_ignore_ascii_case("join") {
                        match chat_msg.name {
                            Some("") | None => warn!("ignore invalid join msg: {chat_msg:?}"),
                            Some(name) => {
                                self.nickname = Some(name.to_owned());
                                if let Err(err) = self.broadcast_tx.send(BroadcastMessage::System(
                                    format!("{name} joined the chat."),
                                )) {
                                    warn!(
                                        "failed to broadcast join message (nickname: {name}): {err}"
                                    );
                                }
                            }
                        }
                    } else if msg_type.eq_ignore_ascii_case("chat") {
                        match (chat_msg.message, self.nickname.as_deref()) {
                            (Some(msg), Some(name)) => {
                                if let Err(err) = self.broadcast_tx.send(BroadcastMessage::User {
                                    name: name.to_owned(),
                                    message: msg.to_owned(),
                                }) {
                                    warn!("failed to broadcast message ({chat_msg:?}): {err}");
                                }
                            }
                            (None, _) => {
                                warn!(
                                    "ws sent chat message without content: drop msg: {chat_msg:?}"
                                )
                            }
                            (_, None) => {
                                warn!(
                                    "ws sent chat message without advertising nickname first: drop msg: {chat_msg:?}"
                                );
                            }
                        }
                    } else {
                        warn!("ignore invalid incoming json message: {chat_msg:?}");
                    }
                }
                Err(err) => {
                    warn!("failed to json-decode incoming message ({msg}): {err}");
                }
            },
            Ok(msg @ Message::Binary(_)) => {
                warn!("ignore binary message: {msg}");
            }
            Ok(
                msg @ (Message::Close(_) | Message::Ping(_) | Message::Frame(_) | Message::Pong(_)),
            ) => {
                debug!("ignore meta message: {msg}");
            }
            Err(err) => {
                if err.is_connection_error()
                    || matches!(err, ProtocolError::ResetWithoutClosingHandshake)
                {
                    debug!("websocket connection dropped: {err}");
                } else {
                    error!("websocket connection failed with fatal error: {err}")
                }
                if let Some(name) = self.nickname.as_deref()
                    && let Err(err) = self
                        .broadcast_tx
                        .send(BroadcastMessage::System(format!("{name} left the chat.")))
                {
                    warn!("failed to broadcast exit message (nickname: {name}): {err}");
                }
                return true;
            }
        }

        false
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ChatMessage<'a> {
    r#type: &'a str,
    name: Option<&'a str>,
    message: Option<&'a str>,
}

#[derive(Debug, Clone)]
enum BroadcastMessage {
    User { name: String, message: String },
    System(String),
}

#[derive(Debug)]
struct State {
    broadcast_rx: broadcast::Receiver<BroadcastMessage>,
    broadcast_tx: broadcast::Sender<BroadcastMessage>,
}

impl Clone for State {
    fn clone(&self) -> Self {
        Self {
            broadcast_rx: self.broadcast_tx.subscribe(),
            broadcast_tx: self.broadcast_tx.clone(),
        }
    }
}

impl State {
    fn new() -> Self {
        let (tx, rx) = broadcast::channel(16);
        Self {
            broadcast_rx: rx,
            broadcast_tx: tx,
        }
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

const INDEX: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Simple WebSocket Chatroom</title>
  <style>
    body { font-family: sans-serif; background: #eef2f3; padding: 2rem; }
    #chat { max-width: 600px; margin: auto; background: white; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); display: flex; flex-direction: column; height: 80vh; }
    #messages { flex: 1; padding: 1rem; overflow-y: auto; border-bottom: 1px solid #ddd; }
    .message { margin: 0.3rem 0; }
    .system { font-style: italic; color: #555; }
    .user { color: #333; }
    .self { color: #1976d2; text-align: right; }
    #form { display: flex; }
    #input { flex: 1; padding: 1rem; border: none; font-size: 1rem; }
    #send { padding: 1rem; background: #1976d2; color: white; border: none; cursor: pointer; }
    #send:hover { background: #125ea3; }
    #loginModal {
      position: fixed; inset: 0;
      background: rgba(0,0,0,0.5);
      display: flex; align-items: center; justify-content: center;
    }
    #loginModal form {
      background: white; padding: 2rem; border-radius: 8px;
      box-shadow: 0 0 10px rgba(0,0,0,0.2);
    }
  </style>
</head>
<body>
  <div id="loginModal">
    <form id="loginForm">
      <label for="name">Enter your nickname:</label><br/>
      <input id="name" required autofocus /><br/><br/>
      <button type="submit">Join Chat</button>
    </form>
  </div>

  <div id="chat" style="display: none;">
    <div id="messages"></div>
    <form id="form">
      <input id="input" autocomplete="off" placeholder="Type a message..." />
      <button id="send" type="submit">Send</button>
    </form>
  </div>

  <script>
    let ws;
    let nickname = "";

    const chatBox = document.getElementById("chat");
    const messages = document.getElementById("messages");
    const form = document.getElementById("form");
    const input = document.getElementById("input");
    const loginModal = document.getElementById("loginModal");
    const loginForm = document.getElementById("loginForm");

    loginForm.addEventListener("submit", (e) => {
      e.preventDefault();
      nickname = document.getElementById("name").value;
      loginModal.style.display = "none";
      chatBox.style.display = "flex";
      startWebSocket();
    });

    function startWebSocket() {
      ws = new WebSocket("/chat");

      ws.onopen = () => {
        ws.send(JSON.stringify({ type: "join", name: nickname }));
      };

      ws.onmessage = (event) => {
        const msg = JSON.parse(event.data);
        if (msg.type === "system") {
          addMessage(msg.message, "system");
        } else if (msg.type === "user") {
          const className = msg.name === nickname ? "self" : "user";
          addMessage(`${msg.name}: ${msg.message}`, className);
        }
      };

      form.addEventListener("submit", (e) => {
        e.preventDefault();
        const message = input.value;
        if (message && ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: "chat", message }));
          input.value = "";
        }
      });
    }

    function addMessage(text, className) {
      const div = document.createElement("div");
      div.textContent = text;
      div.className = `message ${className}`;
      messages.appendChild(div);
      messages.scrollTop = messages.scrollHeight;
    }
  </script>
</body>
</html>
"##;
