use std::convert::Infallible;

use rama_core::{
    Layer, Service,
    error::{BoxError, ErrorContext as _},
    extensions::ExtensionsMut,
    futures::{GracefulStream, StreamExt},
    graceful::{Shutdown, ShutdownGuard},
    io::{BridgeIo, Io},
    layer::{
        ArcLayer, ConsumeErrLayer,
        consume_err::{StaticOutput, Trace},
    },
    rt::Executor,
    service::service_fn,
    stream::wrappers::ReceiverStream,
    telemetry::tracing,
};
use rama_http::{
    Body, HeaderName, HeaderValue, Request, Response, StatusCode,
    service::web::response::IntoResponse,
};
use rama_http_core::server::conn::auto::Builder as AutoConnBuilder;
use rama_http_core::server::conn::http1::Builder as Http1ConnBuilder;
use rama_http_core::server::conn::http2::Builder as H2ConnBuilder;
use rama_net::client::EstablishedClientConnection;
use rama_utils::macros::generate_set_and_with;

use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use crate::{
    client::{HttpClientService, http_connect},
    server::HttpServer,
};

#[derive(Debug, Clone, Copy, Default)]
/// Default [`Response`] used in case the inner (egress)
/// client of the [`HttpMitmRelay`] is erroring.
pub struct DefaultErrorResponse;

impl DefaultErrorResponse {
    #[inline(always)]
    pub fn new() -> Self {
        Self
    }

    #[inline(always)]
    fn response() -> Response {
        (
            [
                (
                    HeaderName::from_static("x-proxy-framework-name"),
                    HeaderValue::from_static(rama_utils::info::NAME),
                ),
                (
                    HeaderName::from_static("x-proxy-framework-version"),
                    HeaderValue::from_static(rama_utils::info::VERSION),
                ),
            ],
            StatusCode::BAD_GATEWAY,
        )
            .into_response()
    }
}

impl From<DefaultErrorResponse> for Response {
    #[inline(always)]
    fn from(_: DefaultErrorResponse) -> Self {
        DefaultErrorResponse::response()
    }
}

/// Default middleware used by [`HttpMitmRelay`],
/// most likely you'll want to overwrite it with custom middleware,
/// unless you do not require MITM middleware.
pub type DefaultMiddleware = (
    ConsumeErrLayer<Trace, StaticOutput<DefaultErrorResponse>>,
    ArcLayer,
);

#[derive(Debug, Clone)]
/// A utility that can be used by MITM services such as transparent proxies,
/// in order to relay HTTP requests and responses between a client and server,
/// as part of a deep protocol inspection protocol (DPI) flow.
///
/// Useful if you have a fairly standard MITM http flow and already
/// have pre-established ingress and egress connections (e.g. because
/// you already MITM'd the <L7 layers, such as SOCKS5 MITM'ng, TLS, ...).
pub struct HttpMitmRelay<M = DefaultMiddleware> {
    http_server: HttpServer<AutoConnBuilder>,
    relay_buffer: Option<usize>,
    middleware: M,
    exec: Executor,
}

impl HttpMitmRelay {
    #[inline(always)]
    #[must_use]
    /// Create a new [`HttpMitmRelay`], ready to serve.
    pub fn new(exec: Executor) -> Self {
        Self {
            http_server: HttpServer::auto(exec.clone()),
            relay_buffer: None,
            middleware: (
                ConsumeErrLayer::trace_as_debug().with_response(DefaultErrorResponse),
                ArcLayer::new(),
            ),
            exec,
        }
    }

    /// Set HTTP middleware to use between server and client.
    ///
    /// By default the identity middleware `()` is used,
    /// which preserves the requests and responses as is...
    pub fn with_http_middleware<M>(self, middleware: M) -> HttpMitmRelay<M> {
        HttpMitmRelay {
            http_server: self.http_server,
            relay_buffer: self.relay_buffer,
            middleware,
            exec: self.exec,
        }
    }
}

impl<M> HttpMitmRelay<M> {
    #[inline(always)]
    /// Http1 builder.
    pub fn http1(&self) -> &Http1ConnBuilder {
        self.http_server.http1()
    }

    #[inline(always)]
    /// Http1 mutable builder.
    pub fn http1_mut(&mut self) -> &mut Http1ConnBuilder {
        self.http_server.http1_mut()
    }

    #[inline(always)]
    /// H2 builder.
    pub fn h2(&self) -> &H2ConnBuilder {
        self.http_server.h2()
    }

    #[inline(always)]
    /// H2 mutable builder.
    pub fn h2_mut(&mut self) -> &mut H2ConnBuilder {
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

impl<Ingress, Egress, M> Service<BridgeIo<Ingress, Egress>> for HttpMitmRelay<M>
where
    Ingress: Io + Unpin + ExtensionsMut,
    Egress: Io + Unpin + ExtensionsMut,
    M: Layer<HttpClientService<Body>> + Send + Sync + 'static + Clone,
    M::Service: Service<Request, Output = Response, Error = Infallible> + Clone,
{
    type Output = ();
    type Error = BoxError;

    async fn serve(
        &self,
        BridgeIo(ingress_stream, egress_stream): BridgeIo<Ingress, Egress>,
    ) -> Result<Self::Output, Self::Error> {
        let token = CancellationToken::new();
        let cancelled = token.clone().cancelled_owned();

        // TODO: see if <https://github.com/plabayo/rama/issues/830>,
        // warrants this logic to change also slightly, relating to the graceful setup...

        let graceful_guard = self.exec.guard().cloned();
        let graceful = Shutdown::new(async move {
            if let Some(guard) = graceful_guard {
                tokio::select! {
                    _ = cancelled => {
                        tracing::trace!("HTTP MITM Relay: Shutdown: cancelation token");
                    },
                    _ = guard.cancelled() => {
                        tracing::trace!("HTTP MITM Relay: Shutdown: parent guard cancellation");
                    },
                }
            } else {
                let _ = cancelled.await;
            }
        });

        let _cancel_guard = token.drop_guard();

        let (req_tx, req_rx) = tokio::sync::mpsc::channel(
            self.relay_buffer
                .unwrap_or_else(|| self.http_server.h2().max_concurrent_streams() as usize)
                .max(1),
        );

        let middleware = self.middleware.clone();
        graceful.spawn_task_fn(async move |guard| {
            http_relay_service_egress(egress_stream, guard, req_rx, middleware).await;
            tracing::trace!("http_relay_service_egress = done");
        });

        let graceful_shutdown_fut = graceful.shutdown();

        let result = self.http_server
            .serve(
                ingress_stream,
                service_fn(move |req: Request| {
                    let req_tx = req_tx.clone();
                    async move {
                        let (tx, rx) = tokio::sync::oneshot::channel();
                        if let Err(err) = req_tx.send(ReqJob { req, reply: tx }).await {
                            tracing::debug!("failed to schedule http request for MITM relay: {err}");
                            return Ok(DefaultErrorResponse::response());
                        }
                        match rx.await {
                            Ok(resp) => Ok(resp),
                            Err(err) => {
                                tracing::debug!(
                                    "failed to receive http response from MITM relay executor: {err}"
                                );
                                Ok(DefaultErrorResponse::response())
                            }
                        }
                    }
                }),
            )
            .await
            .context("serve HTTP MITM relay");

        graceful_shutdown_fut.await;
        result
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
    Egress: Io + Unpin + ExtensionsMut,
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
            if reply.send(DefaultErrorResponse::response()).is_err() {
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
