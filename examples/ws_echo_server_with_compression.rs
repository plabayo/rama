//! Example clone of `ws_echo_server.rs` but with compression enabled and supported.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example ws_echo_server_with_compression --features=http-full
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62038`.
//! Open it in the browser to see it in action or use `rama` cli client to test it.

use rama::{
    Layer,
    http::{
        server::HttpServer,
        service::web::{Router, response::Html},
        ws::handshake::server::WebSocketAcceptor,
    },
    layer::ConsumeErrLayer,
    rt::Executor,
    tcp::server::TcpListener,
    telemetry::tracing::{
        self, Level, info,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
};

use std::{sync::Arc, time::Duration};

#[tokio::main]
async fn main() {
    tracing::subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        )
        .init();

    let graceful = rama::graceful::Shutdown::default();

    graceful.spawn_task_fn(async |guard| {
        let server = HttpServer::http1(Executor::graceful(guard.clone())).service(Arc::new(
            Router::new().with_get("/", Html(INDEX)).with_get(
                "/echo",
                ConsumeErrLayer::trace(Level::DEBUG).into_layer(
                    WebSocketAcceptor::new()
                        .with_per_message_deflate_overwrite_extensions()
                        .into_echo_service(),
                ),
            ),
        ));
        info!("open web echo chat @ http://127.0.0.1:62038");
        info!("or connect directly to ws://127.0.0.1:62038/echo (via 'rama')");
        TcpListener::bind("127.0.0.1:62038", Executor::graceful(guard))
            .await
            .expect("bind TCP Listener")
            .serve(server)
            .await;
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}

const INDEX: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>WebSocket Echo Chat</title>
  <style>
    body {
      font-family: sans-serif;
      background: #f5f5f5;
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 2rem;
    }
    #chat {
      width: 100%;
      max-width: 600px;
      background: white;
      border: 1px solid #ccc;
      border-radius: 8px;
      overflow: hidden;
      box-shadow: 0 2px 10px rgba(0,0,0,0.1);
      display: flex;
      flex-direction: column;
    }
    #messages {
      flex: 1;
      padding: 1rem;
      overflow-y: auto;
      height: 300px;
      border-bottom: 1px solid #ddd;
    }
    .message {
      margin: 0.5rem 0;
    }
    .message.you {
      text-align: right;
      color: #1976d2;
    }
    .message.server {
      text-align: left;
      color: #388e3c;
    }
    #form {
      display: flex;
      border-top: 1px solid #ddd;
    }
    #input {
      flex: 1;
      padding: 1rem;
      border: none;
      font-size: 1rem;
    }
    #send {
      padding: 1rem;
      background: #1976d2;
      color: white;
      border: none;
      cursor: pointer;
    }
    #send:hover {
      background: #0d47a1;
    }
  </style>
</head>
<body>
  <h2>WebSocket Echo Client</h2>
  <div id="chat">
    <div id="messages"></div>
    <form id="form">
      <input id="input" autocomplete="off" placeholder="Type a message..." />
      <button id="send" type="submit">Send</button>
    </form>
  </div>

  <script>
    const ws = new WebSocket("/echo");
    const messages = document.getElementById("messages");
    const form = document.getElementById("form");
    const input = document.getElementById("input");

    ws.onmessage = (event) => {
      addMessage(event.data, "server");
    };

    form.addEventListener("submit", (e) => {
      e.preventDefault();
      const msg = input.value;
      if (msg && ws.readyState === WebSocket.OPEN) {
        ws.send(msg);
        addMessage(msg, "you");
        input.value = "";
      }
    });

    function addMessage(text, type) {
      const div = document.createElement("div");
      div.textContent = text;
      div.className = `message ${type}`;
      messages.appendChild(div);
      messages.scrollTop = messages.scrollHeight;
    }
  </script>
</body>
</html>
"##;
