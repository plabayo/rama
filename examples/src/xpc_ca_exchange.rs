//! XPC CA exchange — a service-style request/reply example mirroring a container app/extension
//! control plane.
//!
//! This example demonstrates the first practical use case for `rama-net-apple-xpc`:
//! using XPC request/reply to fetch CA material from a more-privileged container app process,
//! instead of pushing private key material through some unrelated opaque config blob.
//!
//! It intentionally uses an anonymous XPC endpoint so the example stays self-contained
//! and testable without launchd or plist setup. In a real container app and Network Extension sysext
//! deployment you would typically:
//!
//! - bind a named Mach service
//! - gate it with `PeerSecurityRequirement`
//! - return the CA certificate and key only to the signed extension process
//!
//! Run with:
//!
//! ```sh
//! cargo run -p rama-examples --bin xpc_ca_exchange --features=net-apple-xpc
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
    eprintln!("xpc_ca_exchange: XPC is only available on Apple platforms.");
}

#[cfg(target_vendor = "apple")]
#[tokio::main]
async fn main() {
    use std::{collections::BTreeMap, convert::Infallible, time::Duration};

    use tokio::sync::oneshot;

    use rama::{
        graceful::Scope,
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
    let scope = Scope::new()
        .with_grace(Duration::from_secs(5))
        .with_signal(async { drop(shutdown_rx.await) });

    let (server_conn, endpoint) =
        XpcEndpoint::anonymous_channel(Some("org.rama.example.xpc-ca-exchange"))
            .expect("anonymous_channel");

    let server = XpcServer::new(service_fn(async |message: XpcMessage| {
        let response = match message {
            XpcMessage::Dictionary(mut values) => match values.remove("op") {
                Some(XpcMessage::String(op)) if op == "get_ca_material" => {
                    let mut reply = BTreeMap::new();
                    reply.insert(
                        "ca_cert_pem".to_owned(),
                        XpcMessage::String(
                            "-----BEGIN CERTIFICATE-----\nMIIB...demo...\n-----END CERTIFICATE-----"
                                .to_owned(),
                        ),
                    );
                    reply.insert(
                        "ca_key_pem".to_owned(),
                        XpcMessage::String(
                            "-----BEGIN PRIVATE KEY-----\nMIIE...demo...\n-----END PRIVATE KEY-----"
                                .to_owned(),
                        ),
                    );
                    reply.insert("rotated".to_owned(), XpcMessage::Bool(false));
                    Some(XpcMessage::Dictionary(reply))
                }
                _ => {
                    let mut reply = BTreeMap::new();
                    reply.insert(
                        "error".to_owned(),
                        XpcMessage::String("unsupported request".to_owned()),
                    );
                    Some(XpcMessage::Dictionary(reply))
                }
            },
            _ => None,
        };

        Ok::<_, Infallible>(response)
    }));

    let exec = Executor::from(scope.clone());
    let server_task = exec.clone().into_spawn_task(async move {
        info!(target: "xpc_ca_exchange::server", "ready");
        if let Err(err) = server.serve_connection(server_conn, exec).await {
            error!(target: "xpc_ca_exchange::server", %err, "server error");
        }
        info!(target: "xpc_ca_exchange::server", "stopped");
    });

    let client_task = Executor::from(scope.clone()).into_spawn_task(async move {
        let client_conn = endpoint.into_connection().expect("into_connection");

        let mut request = BTreeMap::new();
        request.insert(
            "op".to_owned(),
            XpcMessage::String("get_ca_material".to_owned()),
        );

        info!(
            target: "xpc_ca_exchange::client",
            "requesting CA material over xpc"
        );
        match client_conn
            .send_request(XpcMessage::Dictionary(request))
            .await
        {
            Ok(reply) => info!(target: "xpc_ca_exchange::client", ?reply, "received reply"),
            Err(err) => error!(target: "xpc_ca_exchange::client", %err, "request error"),
        }

        client_conn.cancel();
        _ = shutdown_tx.send(());
    });

    _ = tokio::join!(server_task, client_task);

    scope.join().await.expect("graceful shutdown");
}
