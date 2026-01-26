//! ndjson example showcasing how to stream
//! a Newline Delimited JSON body. See the test
//! for this example to see how it looks like from the client side.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example http_nd_json --features=http-full
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62041`. You open the url in your browser to easily interact:
//!
//! ```sh
//! open http://127.0.0.1:62041/orders
//! ```
//!
//! Your browser will show the text in raw format.
//! Best to use this however with a client that supports ndjson (e.g. rama).

use rama::{
    Layer,
    futures::{StreamExt as _, async_stream::stream_fn},
    http::{
        Body,
        headers::ContentType,
        layer::trace::TraceLayer,
        server::HttpServer,
        service::web::{
            Router,
            response::{Headers, IntoResponse},
        },
    },
    net::address::SocketAddress,
    rt::Executor,
    stream::json::JsonWriteStream,
    tcp::server::TcpListener,
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
};

use serde::Serialize;
use std::{borrow::Cow, convert::Infallible, sync::Arc, time::Duration};

async fn api_json_events_endpoint() -> impl IntoResponse {
    (
        Headers::single(ContentType::ndjson()),
        Body::from_stream(JsonWriteStream::new(
            stream_fn(move |mut yielder| async move {
                for (i, item) in SAMPLE_ORDERS.iter().enumerate() {
                    // emulate random delays :P
                    tokio::time::sleep(Duration::from_millis(((i as u64) % 7) * 5)).await;

                    yielder.yield_item(Cow::Borrowed(item)).await;

                    if i % 3 == 0 {
                        yielder
                            .yield_item(Cow::Owned(OrderEvent {
                                item: "extra item",
                                quantity: (i * 2) as u32,
                                prepaid: i % 6 == 0,
                            }))
                            .await;
                    }
                }
            })
            .map(Ok::<_, Infallible>),
        )),
    )
}

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
    let exec = Executor::graceful(graceful.guard());

    let listener = TcpListener::bind(SocketAddress::default_ipv4(62041), exec.clone())
        .await
        .expect("tcp port to be bound");
    let bind_address = listener.local_addr().expect("retrieve bind address");

    tracing::info!(
        network.local.address = %bind_address.ip(),
        network.local.port = %bind_address.port(),
        "http's tcp listener ready to serve",
    );
    tracing::info!(
        "open http://{bind_address}/orders in your browser to see the service in action"
    );

    graceful.spawn_task(async {
        let app = (TraceLayer::new_for_http()).into_layer(Arc::new(
            Router::new().with_get("/orders", api_json_events_endpoint),
        ));
        listener.serve(HttpServer::auto(exec).service(app)).await;
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
