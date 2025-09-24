//! ndjson example showcasing how to stream
//! Newline Delimited JSON objects over a TCP Stream. See the test
//! for this example to see how it looks like from the client side.
//!
//! # json stream
//!
//! While this example transports the data over TCP, it is important to highlight
//! that this kind of NDJson streaming works over any async stream. As such this can also
//! be done over UDP, Unix, SOCKS5 and so on...
//!
//! Given how bare-bones ndjson is however it is recommended to
//! utilise ndjson over a transport layer which ensures all packets arive
//! correctly and in order. Otherwise you'll run into errors or if unlucky,
//! hard to debug issues.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example tcp_nd_json --features=tcp
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62042`.
//! With a utility like `socat`, `nc` or `telnet you can talk to your server:
//!
//! ```sh
//! socat - TCP:127.0.0.1:62042
//! ```
//!
//! You should see the items coming through and could also pipe it to
//! some other tool or directly into your clipboard or a file.

use rama::{
    error::{ErrorContext as _, OpaqueError},
    futures::SinkExt,
    net::address::SocketAddress,
    service::service_fn,
    stream::{codec::FramedWrite, json::JsonEncoder},
    tcp::{TcpStream, server::TcpListener},
    telemetry::tracing::{self, level_filters::LevelFilter},
};

use serde::Serialize;
use std::time::Duration;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

async fn serve_stream(stream: TcpStream) -> Result<(), OpaqueError> {
    let mut writer = FramedWrite::new(stream, JsonEncoder::new());
    for (i, item) in SAMPLE_ORDERS.into_iter().enumerate() {
        tokio::time::sleep(Duration::from_millis(((i as u64) % 7) * 5)).await;
        tracing::info!("return item #{i}");
        writer
            .send(item)
            .await
            .map_err(OpaqueError::from_boxed)
            .context("write item to stream")?;
        if i % 3 == 0 {
            tracing::info!("return extra item @ #{i}");
            writer
                .send(OrderEvent {
                    item: "extra item",
                    quantity: (i * 2) as u32,
                    prepaid: i % 6 == 0,
                })
                .await
                .map_err(OpaqueError::from_boxed)
                .context("write extra item to stream")?;
        }
    }

    writer
        .close()
        .await
        .map_err(OpaqueError::from_boxed)
        .context("close the writer")?;

    Ok(())
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

    let listener = TcpListener::bind(SocketAddress::default_ipv4(62042))
        .await
        .expect("tcp port to be bound");
    let bind_address = listener.local_addr().expect("retrieve bind address");

    tracing::info!(
        network.local.address = %bind_address.ip(),
        network.local.port = %bind_address.port(),
        "tcp listener ready to serve",
    );
    tracing::info!(
        "establish a (client) tcp connection to {bind_address} to see the service in action"
    );

    graceful.spawn_task_fn(async |guard| {
        listener
            .serve_graceful(guard, service_fn(serve_stream))
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

// same events as the SSE examples, lazy coder be lazy
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
