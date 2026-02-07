//! A minimal WebSocket example similar to the `ws_tls_server` example
//! with the only difference that it uses h2 instead of HTTP/1.1, and as such is reached via
//! the `wss://` scheme instead of the plain text `ws://` one.
//!
//! > While technically you can run h2 without TLS, it is not supported (out of the box)
//! > by most major User Agents.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example ws_over_h2 --features=http-full,boring
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62035`.
//! Open it in the browser to see it in action or use `rama` cli client to test it.
//!
//! Note that firefox does not support h2 bootstrapping of WebSockets,
//! Chrome does support it.

use rama::{
    Layer,
    http::{
        server::HttpServer,
        service::web::{Router, response::Html},
        ws::handshake::server::WebSocketAcceptor,
    },
    layer::ConsumeErrLayer,
    net::tls::{
        ApplicationProtocol,
        server::{SelfSignedData, ServerAuth, ServerConfig},
    },
    rt::Executor,
    tcp::server::TcpListener,
    telemetry::tracing::{
        self, info,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
    tls::boring::server::{TlsAcceptorData, TlsAcceptorLayer},
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

    let tls_server_config = ServerConfig {
        application_layer_protocol_negotiation: Some(vec![ApplicationProtocol::HTTP_2]),
        ..ServerConfig::new(ServerAuth::SelfSigned(SelfSignedData::default()))
    };
    let acceptor_data = TlsAcceptorData::try_from(tls_server_config).expect("create acceptor data");

    graceful.spawn_task_fn(async |guard| {
        let mut h2 = HttpServer::h2(Executor::graceful(guard.clone()));
        h2.h2_mut().set_enable_connect_protocol(); // required for WS sockets
        let server = h2.service(Arc::new(
            Router::new().with_get("/", Html(INDEX)).with_connect(
                "/echo",
                ConsumeErrLayer::trace_as_debug()
                    .into_layer(WebSocketAcceptor::new().into_echo_service()),
            ),
        ));

        let tls_server = TlsAcceptorLayer::new(acceptor_data).into_layer(server);

        info!("open web echo chat @ https://127.0.0.1:62035");
        info!("or connect directly to wss://127.0.0.1:62035/echo (via 'rama')");
        TcpListener::bind("127.0.0.1:62035", Executor::graceful(guard))
            .await
            .expect("bind TCP Listener")
            .serve(tls_server)
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
    #warning {
      background: #ffcc00;
      color: #000;
      padding: 1rem;
      border: 1px solid #f5a623;
      border-radius: 5px;
      margin-bottom: 1rem;
      display: none;
      max-width: 600px;
      text-align: center;
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
  <div id="warning">
    Your browser does not appear to be Chromium-based. H2 bootstrap for WebSocket is not supported. Please try again using a Chromium browser like Chrome, Edge, or Brave.
  </div>
  <div id="chat">
    <div id="messages"></div>
    <form id="form">
      <input id="input" autocomplete="off" placeholder="Type a message..." />
      <button id="send" type="submit">Send</button>
    </form>
  </div>

  <script>
    // Detect non-Chromium browsers
    const isChromium = /Chrome/.test(navigator.userAgent) && /Google Inc/.test(navigator.vendor);
    if (!isChromium) {
      document.getElementById("warning").style.display = "block";
    }

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
