use std::{convert::Infallible, fmt};

use rama_core::{
    Layer, Service,
    error::{BoxError, ErrorContext as _},
    extensions::ExtensionsMut,
    futures::{self, GracefulStream, StreamExt},
    graceful::{Shutdown, ShutdownGuard},
    rt::Executor,
    service::service_fn,
    stream::{Stream, wrappers::ReceiverStream},
    telemetry::tracing,
};
use rama_http::{Body, Request, Response, StatusCode, service::web::response::IntoResponse};
use rama_http_core::server::conn::auto::{Builder, Http1Builder, Http2Builder};
use rama_net::{client::EstablishedClientConnection, proxy::StreamBridge};
use rama_utils::macros::generate_set_and_with;

use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::{CancellationToken, DropGuard};

use crate::{
    client::{HttpClientService, http_connect},
    server::HttpServer,
};

/// A utility that can be used by MITM services such as transparent proxies,
/// in order to relay HTTP requests and responses between a client and server,
/// as part of a deep protocol inspection protocol (DPI) flow.
///
/// Useful if you have a fairly standard MITM http flow and already
/// have pre-established ingress and egress connections (e.g. because
/// you already MITM'd the <L7 layers, such as SOCKS5 MITM'ng, TLS, ...).
pub struct HttpMitmRelay<M = ()> {
    http_server: HttpServer<Builder>,
    graceful: Shutdown,
    drop_guard: DropGuard,
    relay_buffer: Option<usize>,
    middleware: M,
}

impl<M: fmt::Debug> fmt::Debug for HttpMitmRelay<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpMitmRelay")
            .field("http_server", &self.http_server)
            .field("graceful", &"Shutdown")
            .field("middleware", &self.middleware)
            .finish()
    }
}

impl HttpMitmRelay {
    #[inline(always)]
    #[must_use]
    /// Create a new [`HttpMitmRelay`], ready to serve.
    pub fn new(exec: Executor) -> Self {
        let token = CancellationToken::new();
        let cancelled = token.clone().cancelled_owned();
        let graceful = Shutdown::new(async move {
            if let Some(guard) = exec.into_guard() {
                let _ = futures::join!(cancelled, guard.cancelled());
            } else {
                let _ = cancelled.await;
            }
        });

        Self {
            http_server: HttpServer::auto(Executor::graceful(graceful.guard())),
            graceful,
            relay_buffer: None,
            drop_guard: token.drop_guard(),
            middleware: (),
        }
    }

    /// Set HTTP middleware to use between server and client.
    ///
    /// By default the identity middleware `()` is used,
    /// which preserves the requests and responses as is...
    pub fn with_http_middleware<M>(self, middleware: M) -> HttpMitmRelay<M> {
        HttpMitmRelay {
            http_server: self.http_server,
            graceful: self.graceful,
            relay_buffer: self.relay_buffer,
            drop_guard: self.drop_guard,
            middleware,
        }
    }
}

impl<M> HttpMitmRelay<M> {
    #[inline(always)]
    /// Http1 server configuration.
    pub fn server_http_mut(&mut self) -> Http1Builder<'_> {
        self.http_server.http1_mut()
    }

    /// H2 server configuration.
    #[inline(always)]
    pub fn server_h2_mut(&mut self) -> Http2Builder<'_> {
        self.http_server.h2_mut()
    }

    generate_set_and_with! {
        /// Set an explicit buffer size for the relay buffer.
        ///
        /// By default, or in case the value is `None` or `Some(0)`,
        /// it will use the value of the h2 server settings its max streams.
        pub fn relay_buffer(mut self, n: Option<usize>) -> Self {
            self.relay_buffer = n;
            self
        }
    }
}

impl<M> HttpMitmRelay<M>
where
    M: Layer<HttpClientService<Body>> + Send + 'static,
    M::Service: Service<Request, Output = Response, Error = Infallible> + Clone,
{
    pub async fn serve<Ingress, Egress>(
        self,
        StreamBridge {
            left: ingress_stream,
            right: egress_stream,
        }: StreamBridge<Ingress, Egress>,
    ) -> Result<(), BoxError>
    where
        Ingress: Stream + Unpin + ExtensionsMut,
        Egress: Stream + Unpin + ExtensionsMut,
    {
        let Self {
            mut http_server,
            graceful,
            drop_guard,
            relay_buffer,
            middleware,
        } = self;

        let (req_tx, req_rx) = tokio::sync::mpsc::channel(
            relay_buffer
                .unwrap_or_else(|| http_server.h2_mut().max_concurrent_streams() as usize)
                .max(1),
        );

        graceful.spawn_task_fn(async move |guard| {
            let _drop_guard = drop_guard;
            http_relay_service_egress(egress_stream, guard, req_rx, middleware).await;
            tracing::trace!("http_relay_service_egress = done");
        });

        drop(graceful);
        http_server
            .serve(
                ingress_stream,
                service_fn(move |req: Request| {
                    let req_tx = req_tx.clone();
                    async move {
                        let (tx, rx) = tokio::sync::oneshot::channel();
                        if let Err(err) = req_tx.send(ReqJob { req, reply: tx }).await {
                            tracing::debug!("failed to schedule http request for MITM relay: {err}");
                            return Ok(StatusCode::BAD_GATEWAY.into_response());
                        }
                        match rx.await {
                            Ok(resp) => Ok(resp),
                            Err(err) => {
                                tracing::debug!(
                                    "failed to receive http response from MITM relay executor: {err}"
                                );
                                Ok(StatusCode::BAD_GATEWAY.into_response())
                            }
                        }
                    }
                }),
            )
            .await
            .context("serve HTTP MITM relay")
    }
}

#[derive(Debug)]
struct ReqJob {
    req: Request,
    reply: oneshot::Sender<Response>,
}

async fn http_relay_service_egress<Egress, Middleware>(
    egress_stream: Egress,
    guard: ShutdownGuard,
    req_rx: mpsc::Receiver<ReqJob>,
    middleware: Middleware,
) where
    Egress: Stream + Unpin + ExtensionsMut,
    Middleware: Layer<HttpClientService<Body>>,
    Middleware::Service: Service<Request, Output = Response, Error = Infallible> + Clone,
{
    let cancelled = std::pin::pin!(guard.clone_weak().into_cancelled());
    let mut req_stream = GracefulStream::new(cancelled, ReceiverStream::new(req_rx));

    let Some(ReqJob { req, reply }) = req_stream.next().await else {
        tracing::debug!("failed to receive initial request for HTTP MITM relay... return early");
        return;
    };

    let (req, core_client) = match http_connect(egress_stream, req, Executor::graceful(guard)).await
    {
        Ok(EstablishedClientConnection { input, conn }) => (input, conn),
        Err(err) => {
            tracing::debug!("failed to establish egress HTTP connection: {err}");
            if reply.send(StatusCode::BAD_GATEWAY.into_response()).is_err() {
                tracing::trace!("failed to send BAD_GATEWAY response (svc error: {err})");
            }
            return;
        }
    };

    let client = middleware.into_layer(core_client);

    let mut job_req = req;
    let mut job_reply = reply;

    tracing::debug!("egress http side ready; HTTP MITM relay loop ready and starting");

    loop {
        let client = client.clone();
        tokio::spawn(async move {
            let Ok(resp) = client.serve(job_req).await;
            if job_reply.send(resp).is_err() {
                tracing::trace!("failed to send received response");
            }
        });

        let Some(job) = req_stream.next().await else {
            tracing::debug!("(ingress) request stream exhausted; abort relay loop");
            return;
        };

        job_req = job.req;
        job_reply = job.reply;
    }
}
