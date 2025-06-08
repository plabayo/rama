//! SSE Example, showcasing a very simple datastar example,
//! which is supported by rama both on the client as well as the server side.
//!
//! Datastar helps you build reactive web applications with the simplicity
//! of server-side rendering and the power of a full-stack SPA framework.
//!
//! It's the combination of a small js library which makes use of SSE among other utilities,
//! this module implements the event data types used from the server-side to send to the client,
//! which makes use of this JS library.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example http_sse_datastar_hello --features=http-full
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62031`. You open the url in your browser to easily interact:
//!
//! ```sh
//! open http://127.0.0.1:62031
//! ```
//!
//! This will open a web page which will be a simple hello world data app.

use rama::{
    Layer,
    error::{ErrorContext, OpaqueError},
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
            self, JsonEventData,
            server::{KeepAlive, KeepAliveStream},
        },
    },
    net::address::SocketAddress,
    rt::Executor,
    tcp::server::TcpListener,
};

use async_stream::stream;
use serde::Serialize;
use std::{sync::Arc, time::Duration};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

async fn api_events_endpoint(last_id: Option<TypedHeader<LastEventId>>) -> impl IntoResponse {
    let mut id: u64 = last_id
        .and_then(|id| id.as_str().parse().ok())
        .unwrap_or_default();

    let mut next_event = move || {
        let mut id_buffer = itoa::Buffer::new();
        let event = sse::Event::new()
            .with_data(JsonEventData(
                SAMPLE_ORDERS[(id as usize) % SAMPLE_ORDERS.len()].clone(),
            ))
            .try_with_id(id_buffer.format(id))
            .context("set next event's id")?;
        id += 1;
        Ok::<_, OpaqueError>(event)
    };

    Sse::new(KeepAliveStream::new(
        KeepAlive::new(),
        stream! {
            for i in 0..42 {
                // emulate random delays :P
                tokio::time::sleep(Duration::from_millis((i % 7) * 5)).await;

                // NOTE that in a realistic service this data most likely
                // comes from an async service or channel.
                yield next_event();
            }
        },
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

    let listener = TcpListener::bind(SocketAddress::default_ipv4(62028))
        .await
        .expect("tcp port to be bound");
    let bind_address = listener.local_addr().expect("retrieve bind address");

    tracing::info!(%bind_address, "http's tcp listener ready to serve");
    tracing::info!(
        "open http://{} in your browser to see the service in action",
        bind_address
    );

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

#[derive(Debug, Clone, Serialize)]
pub struct OrderEvent {
    pub item: &'static str,
    pub quantity: u32,
    pub prepaid: bool,
}

pub const SAMPLE_ORDERS: [OrderEvent; 21] = [
    OrderEvent {
        item: "Apple Watch Series 9",
        quantity: 2,
        prepaid: true,
    },
    OrderEvent {
        item: "Gaming Mousepad XL",
        quantity: 1,
        prepaid: false,
    },
    OrderEvent {
        item: "Noise Cancelling Headphones",
        quantity: 3,
        prepaid: true,
    },
    OrderEvent {
        item: "Ergonomic Chair",
        quantity: 1,
        prepaid: true,
    },
    OrderEvent {
        item: "LED Monitor 27\"",
        quantity: 4,
        prepaid: false,
    },
    OrderEvent {
        item: "Smartphone Stand",
        quantity: 6,
        prepaid: false,
    },
    OrderEvent {
        item: "Mechanical Keyboard",
        quantity: 2,
        prepaid: true,
    },
    OrderEvent {
        item: "Laptop Sleeve 15.6\"",
        quantity: 3,
        prepaid: false,
    },
    OrderEvent {
        item: "USB-C Docking Station",
        quantity: 1,
        prepaid: true,
    },
    OrderEvent {
        item: "Wireless Presenter",
        quantity: 1,
        prepaid: false,
    },
    OrderEvent {
        item: "Foldable Desk Lamp",
        quantity: 5,
        prepaid: true,
    },
    OrderEvent {
        item: "Portable SSD 1TB",
        quantity: 2,
        prepaid: true,
    },
    OrderEvent {
        item: "Webcam Cover Slide",
        quantity: 10,
        prepaid: false,
    },
    OrderEvent {
        item: "Bluetooth Speaker",
        quantity: 2,
        prepaid: false,
    },
    OrderEvent {
        item: "Fitness Tracker Band",
        quantity: 4,
        prepaid: true,
    },
    OrderEvent {
        item: "Laser Pointer",
        quantity: 1,
        prepaid: false,
    },
    OrderEvent {
        item: "Conference Mic",
        quantity: 2,
        prepaid: true,
    },
    OrderEvent {
        item: "Noise-Absorbing Panels",
        quantity: 12,
        prepaid: false,
    },
    OrderEvent {
        item: "Desk Organizer Set",
        quantity: 1,
        prepaid: true,
    },
    OrderEvent {
        item: "Whiteboard Eraser Pack",
        quantity: 6,
        prepaid: false,
    },
    OrderEvent {
        item: "Travel Power Adapter",
        quantity: 2,
        prepaid: true,
    },
];

const INDEX_CONTENT: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Rama SSE — Incoming Orders</title>
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

  <h1>Incoming Orders</h1>
  <table id="order-table">
    <thead>
      <tr>
        <th>Received At</th>
        <th>Item</th>
        <th>Quantity</th>
        <th>Prepaid</th>
      </tr>
    </thead>
    <tbody>
      <!-- Orders will be appended here -->
    </tbody>
  </table>

  <script>
    let eventCount = 0;

    const tableBody = document.querySelector('#order-table tbody');
    const source = new EventSource('/api/events');

    source.onmessage = function (event) {
      let order;
      try {
        order = JSON.parse(event.data);
      } catch (e) {
        console.error('Invalid JSON:', event.data);
        return;
      }

      const row = document.createElement('tr');

      const timestamp = new Date().toLocaleTimeString();
      const timeCell = document.createElement('td');
      const itemCell = document.createElement('td');
      const qtyCell = document.createElement('td');
      const prepaidCell = document.createElement('td');

      timeCell.textContent = timestamp;
      itemCell.textContent = order.item;
      qtyCell.textContent = order.quantity;
      prepaidCell.textContent = order.prepaid ? "Yes" : "No";

      row.appendChild(timeCell);
      row.appendChild(itemCell);
      row.appendChild(qtyCell);
      row.appendChild(prepaidCell);

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
