use std::convert::TryFrom;

use rama_core::{
    Layer, Service,
    error::{BoxError, ErrorContext as _, ErrorExt as _},
    extensions::ExtensionsMut,
    futures::{self, GracefulStream, StreamExt},
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
    Body, HeaderName, HeaderValue, Request, Response, StatusCode, Version,
    service::web::response::IntoResponse,
};
use rama_http_core::server::conn::{
    auto::Builder as AutoConnBuilder, http1::Builder as Http1ConnBuilder,
    http2::Builder as H2ConnBuilder,
};
use rama_net::client::EstablishedClientConnection;
use rama_utils::macros::generate_set_and_with;

use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;
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

    #[inline(always)]
    fn response_for_version(version: Version) -> Response {
        let mut response = Self::response();
        if matches!(
            version,
            Version::HTTP_09 | Version::HTTP_10 | Version::HTTP_11
        ) {
            response.headers_mut().insert(
                HeaderName::from_static("connection"),
                HeaderValue::from_static("close"),
            );
        }
        response
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
    M::Service: Service<Request, Output = Response> + Clone,
    <M::Service as Service<Request>>::Error: Into<BoxError>,
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

        let _cancel_guard = token.clone().drop_guard();

        let (req_tx, req_rx) = tokio::sync::mpsc::channel(
            self.relay_buffer
                .unwrap_or_else(|| self.http_server.h2().max_concurrent_streams() as usize)
                .max(1),
        );

        let middleware = self.middleware.clone();
        let close_ingress = token.clone();
        graceful.spawn_task_fn(async move |guard| {
            http_relay_service_egress(egress_stream, guard, req_rx, middleware, close_ingress)
                .await;
            tracing::trace!("http_relay_service_egress = done");
        });

        let graceful_shutdown_fut = graceful.shutdown();

        let result = self.http_server
            .serve(
                ingress_stream,
                service_fn(move |req: Request| {
                    let req_tx = req_tx.clone();
                    let close_ingress = token.clone();
                    async move {
                        let version = req.version();
                        let (tx, rx) = tokio::sync::oneshot::channel();
                        if let Err(err) = req_tx.send(ReqJob { req, reply: tx }).await {
                            tracing::debug!("failed to schedule http request for MITM relay: {err}");
                            close_ingress.cancel();
                            return Ok(DefaultErrorResponse::response_for_version(version));
                        }
                        match rx.await {
                            Ok(resp) => Ok(resp),
                            Err(err) => {
                                tracing::debug!(
                                    "failed to receive http response from MITM relay executor: {err}"
                                );
                                close_ingress.cancel();
                                Ok(DefaultErrorResponse::response_for_version(version))
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

#[derive(Debug, Clone, Copy)]
enum RelayMode {
    Http1,
    Http2,
}

impl RelayMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Http1 => "http1",
            Self::Http2 => "http2",
        }
    }
}

impl TryFrom<Version> for RelayMode {
    type Error = BoxError;

    fn try_from(version: Version) -> Result<Self, Self::Error> {
        match version {
            Version::HTTP_2 => Ok(Self::Http2),
            Version::HTTP_09 | Version::HTTP_10 | Version::HTTP_11 => Ok(Self::Http1),
            version => Err(BoxError::from("unsupported request version for MITM relay")
                .context_debug_field("version", version)),
        }
    }
}

async fn http_relay_service_egress<Egress, Middleware>(
    egress_stream: Egress,
    guard: ShutdownGuard,
    req_rx: mpsc::Receiver<ReqJob>,
    middleware: Middleware,
    close_ingress: CancellationToken,
) where
    Egress: Io + Unpin + ExtensionsMut,
    Middleware: Layer<HttpClientService<Body>>,
    Middleware::Service: Service<Request, Output = Response, Error: Into<BoxError>> + Clone,
{
    let cancelled = std::pin::pin!(guard.clone_weak().into_cancelled());
    let mut req_stream = GracefulStream::new(cancelled, ReceiverStream::new(req_rx));

    let Some(first_job @ ReqJob { .. }) = req_stream.next().await else {
        tracing::debug!("failed to receive initial request for HTTP MITM relay... return early");
        return;
    };

    let first_request_version = first_job.req.version();
    let relay_mode = match RelayMode::try_from(first_request_version) {
        Ok(mode) => mode,
        Err(err) => {
            tracing::debug!("failed to derive relay mode from initial request version: {err}");
            close_ingress.cancel();
            let _ = first_job
                .reply
                .send(DefaultErrorResponse::response_for_version(
                    first_request_version,
                ));
            return;
        }
    };
    let ReqJob { req, reply } = first_job;
    let req_version = req.version();

    let (req, core_client) = match http_connect(egress_stream, req, Executor::graceful(guard)).await
    {
        Ok(EstablishedClientConnection { input, conn }) => (input, conn),
        Err(err) => {
            tracing::debug!("failed to establish egress HTTP connection: {err}");
            close_ingress.cancel();
            if reply
                .send(DefaultErrorResponse::response_for_version(req_version))
                .is_err()
            {
                tracing::trace!("failed to send BAD_GATEWAY response (svc error: {err})");
            }
            return;
        }
    };

    let client = middleware.into_layer(core_client);

    tracing::debug!("egress http side ready; HTTP MITM relay loop ready and starting");
    tracing::debug!(
        mode = relay_mode.as_str(),
        ?first_request_version,
        "http mitm relay selected upstream driver mode"
    );

    let first_job = ReqJob { req, reply };

    match relay_mode {
        RelayMode::Http1 => {
            run_http1_relay_loop(req_stream, client, first_job, close_ingress).await;
        }
        RelayMode::Http2 => {
            run_http2_relay_loop(req_stream, client, first_job, close_ingress).await;
        }
    }
}

async fn run_http1_relay_loop<Stream, Client>(
    mut req_stream: Stream,
    client: Client,
    mut job: ReqJob,
    close_ingress: CancellationToken,
) where
    Stream: futures::Stream<Item = ReqJob> + Unpin,
    Client: Service<Request, Output = Response, Error: Into<BoxError>>,
{
    let mut request_id = 0_u64;

    loop {
        if !serve_relay_job(&client, job, request_id, close_ingress.clone()).await {
            tracing::debug!(
                mode = RelayMode::Http1.as_str(),
                relay.request_id = request_id,
                "stopping HTTP/1 MITM relay loop after upstream failure"
            );
            return;
        }
        request_id += 1;

        let Some(next_job) = req_stream.next().await else {
            tracing::debug!(
                mode = RelayMode::Http1.as_str(),
                "request stream exhausted; HTTP MITM relay loop finished"
            );
            return;
        };

        job = next_job;
    }
}

async fn run_http2_relay_loop<Stream, Client>(
    mut req_stream: Stream,
    client: Client,
    first_job: ReqJob,
    close_ingress: CancellationToken,
) where
    Stream: rama_core::futures::Stream<Item = ReqJob> + Unpin,
    Client: Service<Request, Output = Response> + Clone + Send + 'static,
    Client::Error: Into<BoxError> + Send,
{
    let mut tasks = JoinSet::new();
    let mut request_id = 0_u64;

    spawn_relay_job(
        &mut tasks,
        client.clone(),
        first_job,
        request_id,
        close_ingress.clone(),
    );
    request_id += 1;

    while let Some(job) = req_stream.next().await {
        if close_ingress.is_cancelled() {
            tracing::debug!(
                mode = RelayMode::Http2.as_str(),
                "ingress shutdown already requested; stop scheduling new HTTP/2 relay jobs"
            );
            break;
        }

        spawn_relay_job(
            &mut tasks,
            client.clone(),
            job,
            request_id,
            close_ingress.clone(),
        );
        request_id += 1;
    }

    tracing::debug!(
        mode = RelayMode::Http2.as_str(),
        in_flight = tasks.len(),
        "request stream exhausted; draining in-flight HTTP MITM relay tasks"
    );

    while let Some(join_result) = tasks.join_next().await {
        if let Err(err) = join_result {
            tracing::debug!("http2 relay task failed to join cleanly: {err}");
        }
    }
}

fn spawn_relay_job<Client>(
    tasks: &mut JoinSet<()>,
    client: Client,
    job: ReqJob,
    request_id: u64,
    close_ingress: CancellationToken,
) where
    Client: Service<Request, Output = Response, Error: Into<BoxError> + Send> + Send + 'static,
{
    tasks.spawn(async move {
        let _ = serve_relay_job(&client, job, request_id, close_ingress).await;
    });
}

async fn serve_relay_job<Client>(
    client: &Client,
    job: ReqJob,
    request_id: u64,
    close_ingress: CancellationToken,
) -> bool
where
    Client: Service<Request, Output = Response, Error: Into<BoxError>>,
{
    let ReqJob { req, reply } = job;
    let method = req.method().clone();
    let uri = req.uri().clone();
    let version = req.version();

    tracing::trace!(
        relay.request_id = request_id,
        http.request.method = %method,
        url.full = %uri,
        ?version,
        "dispatching request on MITM relay egress"
    );

    let resp = match client.serve(req).await {
        Ok(resp) => resp,
        Err(err) => {
            let err = err.into();
            tracing::debug!(
                relay.request_id = request_id,
                http.request.method = %method,
                url.full = %uri,
                ?version,
                "upstream MITM relay request failed: {err}"
            );
            close_ingress.cancel();
            if reply
                .send(DefaultErrorResponse::response_for_version(version))
                .is_err()
            {
                tracing::trace!(
                    relay.request_id = request_id,
                    http.request.method = %method,
                    url.full = %uri,
                    ?version,
                    "failed to send fallback response after upstream MITM relay failure"
                );
            }
            return false;
        }
    };

    tracing::trace!(
        relay.request_id = request_id,
        http.request.method = %method,
        url.full = %uri,
        ?version,
        http.response.status_code = resp.status().as_u16(),
        "received response from MITM relay egress"
    );

    if reply.send(resp).is_err() {
        tracing::trace!(
            relay.request_id = request_id,
            http.request.method = %method,
            url.full = %uri,
            ?version,
            "failed to send received response back to ingress"
        );
    }

    true
}
