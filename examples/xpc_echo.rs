//! XPC echo — an end-to-end demonstration of Apple XPC using an anonymous channel.
//!
//! Two tokio tasks run in-process: a **server** task that echoes every incoming message
//! back to the sender, and a **client** task that exercises three XPC patterns:
//!
//! 1. Fire-and-forget send (`XpcConnection::send`)
//! 2. Request-reply (`XpcConnection::send_request` / `ReceivedXpcMessage::reply`)
//! 3. Shutdown via connection cancel
//!
//! The channel is created with `XpcEndpoint::anonymous_channel`, which requires no
//! launchd registration and no installed plist — making this example fully self-contained.
//!
//! > **Apple-only.** XPC is available exclusively on macOS/iOS/tvOS/watchOS. On other
//! > platforms the binary prints a notice and exits immediately.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example xpc_echo --features=net-apple-xpc
//! ```
//!
//! # Expected output
//!
//! ```text
//! [server] ready, waiting for events
//! [client] sending ping (fire-and-forget)
//! [server] received fire-and-forget: {"kind": "ping"}
//! [client] sending echo request
//! [server] received request, replying: {"text": "hello xpc"}
//! [client] got reply: {"text": "hello xpc"}
//! [client] done, cancelling connection
//! [server] connection closed (Interrupted), shutting down
//! ```

#![cfg_attr(
    target_vendor = "apple",
    expect(
        clippy::expect_used,
        reason = "example: panic-on-error is the standard pattern for demos"
    )
)]

#[cfg(not(target_vendor = "apple"))]
fn main() {
    eprintln!("xpc_echo: XPC is only available on Apple platforms.");
}

#[cfg(target_vendor = "apple")]
#[tokio::main]
async fn main() {
    use std::{collections::BTreeMap, convert::Infallible, time::Duration};

    use tokio::sync::oneshot;

    use rama::{
        graceful::Shutdown,
        net::apple::xpc::{XpcEndpoint, XpcMessage, XpcServer},
        rt::Executor,
        service::service_fn,
        telemetry::tracing::{
            self, error, info,
            level_filters::LevelFilter,
            subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
        },
    };

    tracing::subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        )
        .init();

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let graceful = Shutdown::new(async { drop(shutdown_rx.await) });

    // Create anonymous channel: server connection + endpoint for the client.
    let (server_conn, endpoint) = XpcEndpoint::anonymous_channel(None).expect("anonymous_channel");

    let server = XpcServer::new(service_fn(async |message: XpcMessage| {
        let reply = match message {
            XpcMessage::Dictionary(values) if values.contains_key("text") => {
                Some(XpcMessage::Dictionary(values))
            }
            _ => None,
        };
        Ok::<_, Infallible>(reply)
    }));

    // Server task: serve the anonymous listener through the higher-level XpcServer
    // adapter, which accepts the peer connection and dispatches message handling to
    // the Rama service above.
    let server_task = graceful.spawn_task_fn(async move |guard| {
        info!(target: "xpc_echo::server", "ready, waiting for peer connection");
        if let Err(err) = server
            .serve_connection(server_conn, Executor::graceful(guard))
            .await
        {
            error!(target: "xpc_echo::server", %err, "server error");
        }
        info!(target: "xpc_echo::server", "server stopped");
    });

    // Client task: connect via endpoint, send fire-and-forget then a request.
    let client_task = graceful.spawn_task(async move {
        let client_conn = endpoint.into_connection().expect("into_connection");

        // 1. Fire-and-forget ping.
        info!(target: "xpc_echo::client", "sending ping (fire-and-forget)");
        let mut ping = BTreeMap::new();
        ping.insert("kind".to_owned(), XpcMessage::String("ping".to_owned()));
        client_conn
            .send(XpcMessage::Dictionary(ping))
            .expect("send ping");

        // Small yield so the server gets a chance to print the fire-and-forget before
        // we start the request — not required for correctness.
        tokio::task::yield_now().await;

        // 2. Request-reply echo.
        info!(target: "xpc_echo::client", "sending echo request");
        let mut req = BTreeMap::new();
        req.insert(
            "text".to_owned(),
            XpcMessage::String("hello xpc".to_owned()),
        );
        match client_conn.send_request(XpcMessage::Dictionary(req)).await {
            Ok(reply) => info!(target: "xpc_echo::client", ?reply, "got reply"),
            Err(err) => error!(target: "xpc_echo::client", %err, "request error"),
        }

        // 3. Cancel to signal the server we're done.
        info!(target: "xpc_echo::client", "done, cancelling connection");
        client_conn.cancel();
        _ = shutdown_tx.send(());
    });

    _ = tokio::join!(server_task, client_task);

    graceful
        .shutdown_with_limit(Duration::from_secs(5))
        .await
        .expect("graceful shutdown");
}
