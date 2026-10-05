use std::{
    net::{IpAddr, SocketAddr},
    pin::pin,
};

use rama_core::{
    Service,
    extensions::ExtensionsRef as _,
    futures::{StreamExt as _, stream::FuturesUnordered},
    rt::Executor,
    telemetry::tracing::{self, Instrument as _},
};
use rama_net::{address::SocketAddress, stream::SocketInfo};

use super::Endpoint;
use crate::driver::connection::Connection;

impl Endpoint {
    /// Serve incoming connections with `service`, each in its own task spawned on `exec`.
    ///
    /// The handshake runs in that task, so a slow peer never delays the next accept.
    /// Each established [`Connection`] carries its [`SocketInfo`] in its extensions.
    ///
    /// Once the guard of a graceful `exec` is cancelled, new connection attempts are refused
    /// while served connections keep running, so their protocol can drain (HTTP/3 sends
    /// GOAWAY and finishes in-flight requests). When the last one ends, the endpoint is
    /// closed and shut down. Build the endpoint on an executor without that guard: one that
    /// carries it closes every connection as soon as shutdown starts.
    ///
    /// Returns when the endpoint is closed, or after cancellation once served connections ended.
    pub async fn serve<S>(self, exec: Executor, service: S)
    where
        S: Service<Connection> + Clone,
    {
        let guard = exec.guard().cloned();
        let mut cancelled = pin!(async move {
            match guard {
                Some(guard) => guard.cancelled().await,
                None => std::future::pending().await,
            }
        });
        let bound = self.local_addr().ok();
        let mut served = FuturesUnordered::new();

        loop {
            tokio::select! {
                () = cancelled.as_mut() => {
                    tracing::trace!("signal received: initiate graceful shutdown");
                    break;
                }
                Some(served) = served.next(), if !served.is_empty() => log_join(served),
                incoming = self.accept() => {
                    let Some(incoming) = incoming else {
                        break;
                    };
                    let service = service.clone();
                    let peer_addr = incoming.remote_address();
                    let local_addr = known_local_address(bound, incoming.local_ip());
                    let trace_local_addr =
                        local_addr.unwrap_or_else(|| SocketAddress::default_ipv4(0));
                    let span = tracing::trace_root_span!(
                        "quic::serve_graceful",
                        otel.kind = "server",
                        network.local.port = trace_local_addr.port,
                        network.local.address = %trace_local_addr.ip_addr,
                        network.peer.port = %peer_addr.port(),
                        network.peer.address = %peer_addr.ip(),
                        network.protocol.name = "quic",
                    );
                    served.push(exec.spawn_task(
                        async move {
                            let connection = match incoming.await {
                                Ok(connection) => connection,
                                Err(error) => {
                                    tracing::debug!(%error, "QUIC handshake failed");
                                    return;
                                }
                            };
                            connection
                                .extensions()
                                .insert(SocketInfo::new(local_addr, peer_addr.into()));
                            _ = service.serve(connection).await;
                        }
                        .instrument(span),
                    ));
                }
            }
        }

        // Refuse new attempts, so their clients fall back at once, while served connections drain.
        while !served.is_empty() {
            tokio::select! {
                Some(served) = served.next() => log_join(served),
                Some(incoming) = self.accept() => incoming.refuse(),
            }
        }

        _ = self.shutdown().await;
    }
}

fn log_join(served: Result<(), tokio::task::JoinError>) {
    if let Err(error) = served
        && error.is_panic()
    {
        tracing::error!(%error, "QUIC connection service panicked");
    }
}

// A wildcard bind is not a connection's local address. Packet metadata may
// identify the actual interface; otherwise the address stays unknown.
fn known_local_address(
    bound: Option<SocketAddr>,
    observed: Option<IpAddr>,
) -> Option<SocketAddress> {
    let bound = bound?;
    let ip = observed
        .filter(|ip| !ip.is_unspecified())
        .or_else(|| (!bound.ip().is_unspecified()).then_some(bound.ip()))?;
    Some(SocketAddr::new(ip, bound.port()).into())
}
