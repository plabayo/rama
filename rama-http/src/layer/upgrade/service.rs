//! upgrade service to handle branching into http upgrade services
//!
//! See [`UpgradeService`] for more details.

use super::Upgraded;
use crate::opentelemetry::version_as_protocol_version;
use rama_core::Layer;
use rama_core::error::{BoxError, ErrorExt as _};
use rama_core::error_sink::ErrorSink;
use rama_core::extensions::{Extension, ExtensionsRef};
use rama_core::layer::{ConsumeErrLayer, MapOutputLayer};
use rama_core::rt::Executor;
use rama_core::telemetry::tracing::{self, Instrument};
use rama_core::{Service, extensions::Extensions, matcher::Matcher, service::BoxService};
use rama_http_types::Request;
use rama_utils::macros::define_inner_service_accessors;
use std::{convert::Infallible, fmt, future::Future, pin::Pin, sync::Arc};

/// Upgrade service can be used to handle the possibility of upgrading a request,
/// after which it will pass down the transport RW to the attached upgrade service.
pub struct UpgradeService<S, O> {
    handlers: Vec<Arc<UpgradeHandler<O>>>,
    inner: S,
    exec: Executor,
    error_sink: Arc<dyn ErrorSink>,
}

/// Handshake response produced by the responder in a
/// [`UpgradeLayer::new_with_services`](super::UpgradeLayer::new_with_services)
/// configuration.
///
/// Call [`Self::with_handler`] to attach a response-local continuation and turn
/// it into the [`UpgradeOutput`] expected by [`UpgradeLayer::new`](super::UpgradeLayer::new).
#[derive(Clone, Debug)]
pub struct UpgradeResponse<I, O> {
    /// Response that should be returned
    pub response: O,
    /// Request that caused this upgrade
    pub request: I,
    /// Extensions which will be applied to the [`Upgraded`] io
    /// if the upgrade was successful
    pub extensions: Extensions,
}

impl<I, O> UpgradeResponse<I, O> {
    /// Create an upgrade response without extra extensions.
    #[must_use]
    pub fn new(request: I, response: O) -> Self {
        Self {
            response,
            request,
            extensions: Extensions::new(),
        }
    }

    /// Add an extension which will be applied to the [`Upgraded`] I/O.
    #[must_use]
    pub fn with_extension<T: Extension>(self, extension: T) -> Self {
        self.extensions.insert(extension);
        self
    }

    /// Attach a response-local, one-shot handler for the upgraded connection.
    ///
    /// The returned [`UpgradeOutput`] is accepted by [`UpgradeLayer::new`](super::UpgradeLayer::new).
    /// The handler can own resources established while producing this response,
    /// such as an egress connection, without storing them in [`Extensions`].
    pub fn with_handler<F, Fut, T, E>(self, handler: F) -> UpgradeOutput<I, O>
    where
        F: FnOnce(Upgraded) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, E>> + Send + 'static,
        E: Into<BoxError>,
    {
        UpgradeOutput {
            response: self.response,
            request: self.request,
            extensions: self.extensions,
            handler: Box::new(move |upgraded| {
                Box::pin(async move { handler(upgraded).await.map(drop).map_err(Into::into) })
            }),
        }
    }
}

pub(crate) type UpgradeHandlerFuture =
    Pin<Box<dyn Future<Output = Result<(), BoxError>> + Send + 'static>>;
pub(crate) type ResponseUpgradeHandler =
    Box<dyn FnOnce(Upgraded) -> UpgradeHandlerFuture + Send + 'static>;

/// Complete output of a service registered with [`UpgradeLayer::new`](super::UpgradeLayer::new).
///
/// Besides the handshake response, it contains a response-local handler which
/// owns everything needed to serve the upgraded connection.
#[must_use]
pub struct UpgradeOutput<I, O> {
    /// Response that should be returned.
    pub response: O,
    /// Request that caused this upgrade.
    pub request: I,
    /// Extensions which will be applied to the [`Upgraded`] I/O.
    pub extensions: Extensions,
    pub(crate) handler: ResponseUpgradeHandler,
}

impl<I, O> fmt::Debug for UpgradeOutput<I, O>
where
    I: fmt::Debug,
    O: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpgradeOutput")
            .field("response", &self.response)
            .field("request", &self.request)
            .field("extensions", &self.extensions)
            .finish_non_exhaustive()
    }
}

/// UpgradeHandler is a helper struct used internally to create an upgrade service.
pub struct UpgradeHandler<O> {
    matcher: Box<dyn Matcher<Request>>,
    kind: UpgradeHandlerKind<O>,
    _phantom: std::marker::PhantomData<fn(O) -> ()>,
}

enum UpgradeHandlerKind<O> {
    ResponseLocal {
        responder: BoxService<Request, UpgradeOutput<Request, O>, O>,
        handler_error_sink: Arc<dyn ErrorSink>,
    },
    SeparateServices {
        responder: BoxService<Request, UpgradeResponse<Request, O>, O>,
        handler: BoxService<Upgraded, (), Infallible>,
    },
}

enum UpgradeContinuation {
    ResponseLocal {
        handler: ResponseUpgradeHandler,
        error_sink: Arc<dyn ErrorSink>,
    },
    Service(BoxService<Upgraded, (), Infallible>),
}

struct PreparedUpgrade<O> {
    response: O,
    request: Request,
    extensions: Extensions,
    continuation: UpgradeContinuation,
}

impl<O: Send + 'static> UpgradeHandler<O> {
    /// Register one service which returns its response-local upgrade handler.
    pub(crate) fn new<M, R, Sink>(matcher: M, responder: R, sink: Sink) -> Self
    where
        M: Matcher<Request>,
        R: Service<Request, Output = UpgradeOutput<Request, O>, Error = O> + Clone,
        Sink: ErrorSink,
    {
        Self {
            matcher: Box::new(matcher),
            kind: UpgradeHandlerKind::ResponseLocal {
                responder: responder.boxed(),
                handler_error_sink: Arc::new(sink),
            },
            _phantom: std::marker::PhantomData,
        }
    }

    /// Register separate responder and upgraded-connection services.
    pub(crate) fn new_with_services<M, R, H, Sink>(
        matcher: M,
        responder: R,
        handler: H,
        sink: Sink,
    ) -> Self
    where
        M: Matcher<Request>,
        R: Service<Request, Output = UpgradeResponse<Request, O>, Error = O> + Clone,
        H: Service<Upgraded> + Clone,
        Sink: ErrorSink<H::Error>,
    {
        let sink = Arc::new(sink);
        let handler = (
            ConsumeErrLayer::new(move |err| sink.sink_error(err)),
            MapOutputLayer::new(drop),
        )
            .into_layer(handler)
            .boxed();

        Self {
            matcher: Box::new(matcher),
            kind: UpgradeHandlerKind::SeparateServices {
                responder: responder.boxed(),
                handler,
            },
            _phantom: std::marker::PhantomData,
        }
    }

    async fn prepare(&self, request: Request) -> Result<PreparedUpgrade<O>, O> {
        match &self.kind {
            UpgradeHandlerKind::ResponseLocal {
                responder,
                handler_error_sink,
            } => responder.serve(request).await.map(
                |UpgradeOutput {
                     response,
                     request,
                     extensions,
                     handler,
                 }| PreparedUpgrade {
                    response,
                    request,
                    extensions,
                    continuation: UpgradeContinuation::ResponseLocal {
                        handler,
                        error_sink: handler_error_sink.clone(),
                    },
                },
            ),
            UpgradeHandlerKind::SeparateServices { responder, handler } => {
                responder.serve(request).await.map(
                    |UpgradeResponse {
                         response,
                         request,
                         extensions,
                     }| PreparedUpgrade {
                        response,
                        request,
                        extensions,
                        continuation: UpgradeContinuation::Service(handler.clone()),
                    },
                )
            }
        }
    }
}

impl<S, O> UpgradeService<S, O> {
    /// Create a new [`UpgradeService`].
    pub fn new(
        handlers: Vec<Arc<UpgradeHandler<O>>>,
        inner: S,
        exec: Executor,
        error_sink: Arc<dyn ErrorSink>,
    ) -> Self {
        Self {
            handlers,
            inner,
            exec,
            error_sink,
        }
    }

    define_inner_service_accessors!();
}

impl<S, O> fmt::Debug for UpgradeService<S, O>
where
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpgradeService")
            .field("handlers", &self.handlers)
            .field("inner", &self.inner)
            .field("exec", &self.exec)
            .finish()
    }
}

impl<S, O> Clone for UpgradeService<S, O>
where
    S: Clone,
{
    fn clone(&self) -> Self {
        Self {
            handlers: self.handlers.clone(),
            inner: self.inner.clone(),
            exec: self.exec.clone(),
            error_sink: self.error_sink.clone(),
        }
    }
}

impl<S, O> Service<Request> for UpgradeService<S, O>
where
    S: Service<Request, Output = O>,
    O: Send + 'static,
{
    type Output = O;
    type Error = S::Error;

    async fn serve(&self, req: Request) -> Result<Self::Output, Self::Error> {
        for handler in &self.handlers {
            let ext = Extensions::new();
            if !handler.matcher.matches(Some(&ext), &req) {
                continue;
            }
            req.extensions().extend(&ext);

            return match handler.prepare(req).await {
                Ok(PreparedUpgrade {
                    response,
                    request,
                    extensions,
                    continuation,
                }) => {
                    let upgrade_error_sink = self.error_sink.clone();

                    let span = tracing::trace_root_span!(
                        "upgrade::serve",
                        otel.kind = "server",
                        http.request.method = %request.method().as_str(),
                        url.full = %request.request_uri(),
                        url.path = %request.uri().path_or_root().as_ref(),
                        url.query = %request.uri().query_or_empty().as_ref(),
                        url.scheme = %request.uri().scheme_str().unwrap_or_default(),
                        network.protocol.name = "http",
                        network.protocol.version = version_as_protocol_version(request.version()),
                    );

                    self.exec.spawn_task(
                        async move {
                            match crate::io::upgrade::handle_upgrade(request).await {
                                Ok(upgraded) => {
                                    upgraded.extensions().extend(&extensions);
                                    match continuation {
                                        UpgradeContinuation::ResponseLocal {
                                            handler,
                                            error_sink,
                                        } => {
                                            if let Err(err) = handler(upgraded).await {
                                                error_sink.sink_error(err);
                                            }
                                        }
                                        UpgradeContinuation::Service(handler) => {
                                            _ = handler.serve(upgraded).await;
                                        }
                                    }
                                }
                                Err(err) => {
                                    // The HTTP upgrade itself failed (before the handler
                                    // ran): route it to the layer's upgrade error sink.
                                    upgrade_error_sink.sink_error(
                                        err.context("http upgrade failed before handler"),
                                    );
                                }
                            }
                        }
                        .instrument(span),
                    );
                    Ok(response)
                }
                Err(e) => Ok(e),
            };
        }

        self.inner.serve(req).await
    }
}

impl<O> fmt::Debug for UpgradeHandler<O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpgradeHandler").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::upgrade::{Upgraded, pending};
    use crate::layer::upgrade::UpgradeLayer;
    use rama_core::Layer;
    use rama_core::ServiceInput;
    use rama_core::bytes::Bytes;
    use rama_core::error::{BoxError, BoxErrorExt as _};
    use rama_core::service::service_fn;
    use rama_http_types::{Body, Response};
    use std::time::Duration;
    use std::{cell::Cell, convert::Infallible};
    use tokio::sync::mpsc;
    use tokio_test::io::Builder;

    #[derive(Debug)]
    struct ResponseLocalMarker;

    impl Extension for ResponseLocalMarker {}

    #[derive(Clone)]
    struct SendOnlyOutputResponder;

    impl Service<Request> for SendOnlyOutputResponder {
        type Output = UpgradeOutput<Request, Cell<u8>>;
        type Error = Cell<u8>;

        async fn serve(&self, req: Request) -> Result<Self::Output, Self::Error> {
            Ok(UpgradeResponse::new(req, Cell::new(1))
                .with_handler(|_upgraded| async { Ok::<_, BoxError>(()) }))
        }
    }

    #[derive(Clone)]
    struct SendOnlyInner;

    impl Service<Request> for SendOnlyInner {
        type Output = Cell<u8>;
        type Error = Cell<u8>;

        async fn serve(&self, _req: Request) -> Result<Self::Output, Self::Error> {
            Err(Cell::new(2))
        }
    }

    #[tokio::test]
    async fn output_and_error_need_not_be_sync() {
        let service = UpgradeLayer::new(Executor::default(), false, SendOnlyOutputResponder)
            .into_layer(SendOnlyInner);

        let error = service
            .serve(Request::new(Body::empty()))
            .await
            .unwrap_err();

        assert_eq!(error.get(), 2);
    }

    #[tokio::test]
    async fn response_local_handler_runs_after_upgrade() {
        let (handled_tx, mut handled_rx) = mpsc::unbounded_channel();
        let (pending_upgrade, on_upgrade) = pending();
        let req = Request::new(Body::empty());
        req.extensions().insert(on_upgrade);

        let service = service_fn(move |req: Request| {
            let handled_tx = handled_tx.clone();
            async move {
                Ok::<_, Response>(
                    UpgradeResponse::new(req, Response::new(Body::empty()))
                        .with_extension(ResponseLocalMarker)
                        .with_handler(move |upgraded| async move {
                            assert!(upgraded.extensions().contains::<ResponseLocalMarker>());
                            _ = handled_tx.send(());
                            Ok::<_, BoxError>(())
                        }),
                )
            }
        });
        let inner =
            service_fn(
                |_req: Request| async move { Ok::<_, Infallible>(Response::new(Body::empty())) },
            );
        let svc = UpgradeLayer::new(Executor::default(), true, service).into_layer(inner);

        let _response = svc.serve(req).await.expect("upgrade response");
        assert!(handled_rx.try_recv().is_err());

        pending_upgrade.fulfill(Upgraded::new(
            ServiceInput::new(Builder::default().build()),
            Bytes::new(),
        ));
        tokio::time::timeout(Duration::from_secs(5), handled_rx.recv())
            .await
            .expect("response-local handler should run")
            .expect("handler notification");
    }

    #[tokio::test]
    async fn response_local_handler_error_is_routed_to_sink() {
        let (error_tx, mut error_rx) = mpsc::unbounded_channel();
        let (pending_upgrade, on_upgrade) = pending();
        let req = Request::new(Body::empty());
        req.extensions().insert(on_upgrade);

        let service = service_fn(|req: Request| async move {
            Ok::<_, Response>(
                UpgradeResponse::new(req, Response::new(Body::empty())).with_handler(
                    |_upgraded| async move {
                        Err::<(), _>(BoxError::from_static_str("response-local handler boom"))
                    },
                ),
            )
        });
        let inner =
            service_fn(
                |_req: Request| async move { Ok::<_, Infallible>(Response::new(Body::empty())) },
            );
        let svc = UpgradeLayer::new_with_error_sink(
            Executor::default(),
            true,
            service,
            move |err: BoxError| {
                _ = error_tx.send(format!("{err:?}"));
            },
        )
        .into_layer(inner);

        let _response = svc.serve(req).await.expect("upgrade response");
        pending_upgrade.fulfill(Upgraded::new(
            ServiceInput::new(Builder::default().build()),
            Bytes::new(),
        ));

        let reported = tokio::time::timeout(Duration::from_secs(5), error_rx.recv())
            .await
            .expect("handler error should reach sink")
            .expect("handler error notification");
        assert!(reported.contains("response-local handler boom"));
    }

    // Regression for #1014: a failing upgrade handler must hand its error to its
    // per-handler [`ErrorSink`] instead of being silently swallowed.
    #[tokio::test]
    async fn upgrade_handler_error_is_routed_to_sink() {
        // mpsc so the (sync) sink can report out of the detached upgrade task.
        let (tx, mut rx) = mpsc::unbounded_channel::<String>();

        // The request carries an `OnUpgrade` extension, as the http server sets.
        let (pending_upgrade, on_upgrade) = pending();
        let req = Request::new(Body::empty());
        req.extensions().insert(on_upgrade);

        // Responder echoes the request back (so `handle_upgrade` can find the
        // `OnUpgrade`) and yields a response.
        let responder = service_fn(|req: Request| async move {
            Ok::<_, Response>(UpgradeResponse {
                response: Response::new(Body::empty()),
                request: req,
                extensions: Extensions::new(),
            })
        });

        // Handler that always fails — previously this had to be `Infallible`.
        let handler = service_fn(|_upgraded: Upgraded| async move {
            Err::<(), BoxError>(BoxError::from_static_str("handler boom"))
        });

        // Fallthrough inner service (not reached: matcher is `true`).
        let inner =
            service_fn(
                |_req: Request| async move { Ok::<_, Infallible>(Response::new(Body::empty())) },
            );

        // The handler keeps its own error type; its (raw) error is routed to
        // the per-handler sink given here.
        let svc = UpgradeLayer::new_with_services_and_error_sink(
            Executor::default(),
            true,
            responder,
            handler,
            move |err: BoxError| {
                _ = tx.send(format!("{err:?}"));
            },
        )
        .into_layer(inner);

        // Serving spawns the detached upgrade task (which awaits the upgrade).
        let _resp = svc.serve(req).await.expect("upgrade match -> Ok(response)");

        // Fulfill the pending upgrade so the handler runs and then fails.
        let upgraded = Upgraded::new(ServiceInput::new(Builder::default().build()), Bytes::new());
        pending_upgrade.fulfill(upgraded);

        // The handler error must reach the sink (not be swallowed).
        let reported = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("sink should be called within timeout")
            .expect("sink channel should yield the error");
        assert!(
            reported.contains("handler boom"),
            "unexpected sink message: {reported}"
        );
    }
}
