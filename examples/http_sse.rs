//! SSE Example, showcasing how to support a SSE API endpoint
//! in a Rama webstack using regular text data.
//!
//! See `http_sse_json` for an example on how to do so with Json data.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example http_sse --features=http-full
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62027`. You open the url in your browser to easily interact:
//!
//! ```sh
//! open http://127.0.0.1:62027
//! ```
//!
//! This will open a web page which should populate a table with events
//! as they are being received from (this) server.

use rama::{
    Layer,
    error::{ErrorContext, OpaqueError},
    futures::async_stream::stream_fn,
    http::{
        headers::LastEventId,
        layer::trace::TraceLayer,
        server::HttpServer,
        service::web::{
            Router,
            extract::TypedHeader,
            response::{Html, IntoResponse, Sse},
        },
        sse::{
            self,
            server::{KeepAlive, KeepAliveStream},
        },
    },
    net::address::SocketAddress,
    rt::Executor,
    tcp::server::TcpListener,
    telemetry::tracing::{self, level_filters::LevelFilter},
};

use std::{sync::Arc, time::Duration};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

async fn api_events_endpoint(last_id: Option<TypedHeader<LastEventId>>) -> impl IntoResponse {
    let mut id: u64 = last_id
        .and_then(|id| id.as_str().parse().ok())
        .unwrap_or_default();

    let mut next_event = move || {
        let mut id_buffer = itoa::Buffer::new();
        let event = sse::Event::new()
            .with_data(EXAMPLE_EVENTS[(id as usize) % EXAMPLE_EVENTS.len()].to_owned())
            .try_with_id(id_buffer.format(id))
            .context("set next event's id")?;
        id += 1;
        Ok::<_, OpaqueError>(event)
    };

    Sse::new(KeepAliveStream::new(
        KeepAlive::new(),
        stream_fn(move |mut yielder| async move {
            for i in 0..42 {
                // emulate random delays :P
                tokio::time::sleep(Duration::from_millis((i % 7) * 5)).await;

                // NOTE that in a realistic service this data most likely
                // comes from an async service or channel.
                yielder.yield_item(next_event()).await;
            }
        }),
    ))
}

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

    let listener = TcpListener::bind(SocketAddress::default_ipv4(62027))
        .await
        .expect("tcp port to be bound");
    let bind_address = listener.local_addr().expect("retrieve bind address");

    tracing::info!(
        network.local.address = %bind_address.ip(),
        network.local.port = %bind_address.port(),
        "http's tcp listener ready to serve",
    );
    tracing::info!("open http://{bind_address} in your browser to see the service in action");

    graceful.spawn_task_fn(async |guard| {
        let exec = Executor::graceful(guard.clone());
        let app = (TraceLayer::new_for_http()).into_layer(Arc::new(
            Router::new()
                .get("/", Html(INDEX_CONTENT))
                .get("/api/events", api_events_endpoint),
        ));
        listener
            .serve_graceful(guard, HttpServer::auto(exec).service(app))
            .await;
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}

const EXAMPLE_EVENTS: [&str; 17] = [
    "User alice logged in",
    "New order placed: #84329",
    "CPU usage exceeded 90%",
    "Chat message received from bob",
    "File upload completed: report.pdf",
    "Sensor #12 disconnected",
    "New comment on blog post: \"SSE Deep Dive\"",
    "User session expired for carol",
    "System reboot scheduled at 03:00 UTC",
    "Order #84329 shipped",
    "Alert: Unauthorized login attempt",
    "Build #2025.04.22 passed",
    "Meeting reminder: Engineering sync @ 10am",
    "User david changed password",
    "Service latency spike detected",
    "API rate limit exceeded",
    "Email verification link clicked",
];

const INDEX_CONTENT: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Rama SSE Example</title>
  <style>
    body {
      font-family: sans-serif;
      padding: 20px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 1rem;
    }
    th, td {
      padding: 0.5rem;
      border: 1px solid #ccc;
      text-align: left;
    }
    th {
      background: #f2f2f2;
    }
  </style>
</head>
<body>

  <h1>Live Event Stream</h1>
  <table id="event-table">
    <thead>
      <tr>
        <th>Received At</th>
        <th>Message</th>
      </tr>
    </thead>
    <tbody>
      <!-- New rows will be appended here -->
    </tbody>
  </table>

  <script>
    let eventCount = 0;

    const tableBody = document.querySelector('#event-table tbody');
    const source = new EventSource('/api/events');

    source.onmessage = function (event) {
      const row = document.createElement('tr');

      const timestamp = new Date().toLocaleTimeString();
      const timeCell = document.createElement('td');
      const dataCell = document.createElement('td');

      timeCell.textContent = timestamp;
      dataCell.textContent = event.data;

      row.appendChild(timeCell);
      row.appendChild(dataCell);
      tableBody.appendChild(row);

      eventCount += 1;
      if (eventCount >= 500) {
        source.close();
      }
    };

    source.onerror = function (err) {
      console.error('EventSource error:', err);
    };
  </script>

</body>
</html>
"##;
