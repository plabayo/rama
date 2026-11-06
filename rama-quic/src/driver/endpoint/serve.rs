use std::pin::pin;

use rama_core::{
    Service,
    extensions::ExtensionsRef as _,
    futures::{StreamExt as _, stream::FuturesUnordered},
    graceful::attach_scope,
    rt::Executor,
    telemetry::tracing::{self, Instrument as _},
};
use rama_net::address::SocketAddress;

use super::Endpoint;
use crate::driver::{connection::Connection, incoming::IncomingOutcome};

impl Endpoint {
    /// Serve incoming connections with `service`, each in its own task spawned on `exec`.
    ///
    /// The handshake runs in that task, so a slow peer never delays the next accept; see
    /// [`Incoming::accept_or_retry`](crate::Incoming::accept_or_retry) for when it starts
    /// with a Retry. Each established [`Connection`] carries its [`SocketInfo`](rama_net::stream::SocketInfo)
    /// in its extensions, and runs in the [`Scope`](rama_core::graceful::Scope) of `exec`.
    ///
    /// Once the scope of `exec` is cancelled, new connection attempts are refused, and so are
    /// attempts still in their handshake, while established connections keep running, so
    /// their protocol can drain (HTTP/3 sends GOAWAY and finishes in-flight requests). When
    /// the last one ends, or once the scope is aborted, the endpoint is closed and shut down.
    /// Build the endpoint on an executor outside that scope: an endpoint closes every
    /// connection as soon as the scope of its own executor is cancelled.
    ///
    /// Returns when the endpoint is closed, or after cancellation once served connections ended
    /// or the scope was aborted. The task of each served connection ends at the hard phase, and
    /// none outlives this call.
    pub async fn serve<S>(self, exec: Executor, service: S)
    where
        S: Service<Connection> + Clone,
    {
        // Accepting holds the scope, so every connection accepted until the cancel is admitted.
        let Some(scope) = exec.scope().to_scope() else {
            tracing::debug!("executor scope closed: not serving");
            _ = self.shutdown_now().await;
            return;
        };
        let mut cancelled = pin!(exec.cancelled());
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
                    let local_addr = incoming.local_address().map(SocketAddress::from);
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
                    // A handshake has nothing to drain: one still running when shutdown begins
                    // is refused, as a new attempt is, instead of holding the shutdown until the
                    // client finishes or the attempt times out.
                    let shutting_down = exec.cancelled();
                    let connection_scope = scope.clone();
                    // Ended at the hard phase, whatever the service does by then.
                    served.push(scope.spawn_abortable_task(
                        async move {
                            let outcome = incoming.accept_or_retry_until(shutting_down).await;
                            let connection = match outcome {
                                Ok(IncomingOutcome::Accepted(connection)) => connection,
                                Ok(IncomingOutcome::Retried) => {
                                    tracing::trace!("QUIC: Retry sent");
                                    return;
                                }
                                Err(error) => {
                                    tracing::debug!(%error, "QUIC handshake failed");
                                    return;
                                }
                            };
                            attach_scope(connection.extensions(), &connection_scope);
                            _ = service.serve(connection).await;
                        }
                        .instrument(span),
                    ));
                }
            }
        }

        // Served connections hold the scope from here on.
        drop(scope);

        // Refuse new attempts, so their clients fall back at once, while served connections
        // drain; the hard phase ends the drain and the shutdown below closes them.
        let mut aborted = pin!(exec.aborted());
        while !served.is_empty() {
            tokio::select! {
                Some(served) = served.next() => log_join(served),
                Some(incoming) = self.accept() => incoming.refuse(),
                () = aborted.as_mut() => break,
            }
        }

        // The endpoint's own budget is for a graceful stop: the hard phase of `exec` ends it too.
        let hard = exec.aborted();
        tokio::select! {
            biased;
            () = hard => {
                _ = self.shutdown_now().await;
            }
            _ = self.shutdown() => {}
        }
        // Each task ends at the hard phase: reaped, so none outlives this call.
        while let Some(served) = served.next().await {
            log_join(served);
        }
    }
}

fn log_join(served: Result<Option<()>, tokio::task::JoinError>) {
    if let Err(error) = served
        && error.is_panic()
    {
        tracing::error!(%error, "QUIC connection service panicked");
    }
}
