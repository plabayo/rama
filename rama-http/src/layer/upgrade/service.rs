//! upgrade service to handle branching into http upgrade services
//!
//! See [`UpgradeService`] for more details.

use super::Upgraded;
use crate::opentelemetry::version_as_protocol_version;
use rama_core::error::ErrorExt as _;
use rama_core::error_sink::ErrorSink;
use rama_core::extensions::ExtensionsRef;
use rama_core::layer::ConsumeErr;
use rama_core::rt::Executor;
use rama_core::telemetry::tracing::{self, Instrument};
use rama_core::{Service, extensions::Extensions, matcher::Matcher, service::BoxService};
use rama_http_types::Request;
use rama_utils::macros::define_inner_service_accessors;
use std::{convert::Infallible, fmt, sync::Arc};

/// Upgrade service can be used to handle the possibility of upgrading a request,
/// after which it will pass down the transport RW to the attached upgrade service.
pub struct UpgradeService<S, O> {
    handlers: Vec<Arc<UpgradeHandler<O>>>,
    inner: S,
    exec: Executor,
    error_sink: Arc<dyn ErrorSink>,
}

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

/// UpgradeHandler is a helper struct used internally to create an upgrade service.
pub struct UpgradeHandler<O> {
    matcher: Box<dyn Matcher<Request>>,
    responder: BoxService<Request, UpgradeResponse<Request, O>, O>,
    // The handler's own error (any type `E`) is consumed by its [`ErrorSink`]
    // inside this boxed unit, so nothing remains to propagate (`Infallible`).
    handler: BoxService<Upgraded, (), Infallible>,
    _phantom: std::marker::PhantomData<fn(O) -> ()>,
}

impl<O> UpgradeHandler<O> {
    /// Create a new upgrade handler whose own errors (of any type `E`) are
    /// routed to the given [`ErrorSink`].
    pub(crate) fn new<M, R, H, Sink>(matcher: M, responder: R, handler: H, sink: Sink) -> Self
    where
        M: Matcher<Request>,
        R: Service<Request, Output = UpgradeResponse<Request, O>, Error = O> + Clone,
        H: Service<Upgraded, Output = ()> + Clone,
        Sink: ErrorSink<H::Error>,
    {
        let sink = Arc::new(sink);
        // Consume the handler's error in place via its sink, so the boxed
        // handler is `Infallible` regardless of the handler's error type.
        let handler = ConsumeErr::new(handler, move |err| sink.sink_error(err)).boxed();
        Self {
            matcher: Box::new(matcher),
            responder: responder.boxed(),
            handler,
            _phantom: std::marker::PhantomData,
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

impl<S, O, E> Service<Request> for UpgradeService<S, O>
where
    S: Service<Request, Output = O, Error = E>,
    O: Send + Sync + 'static,
    E: Send + Sync + 'static,
{
    type Output = O;
    type Error = E;

    async fn serve(&self, req: Request) -> Result<Self::Output, Self::Error> {
        for handler in &self.handlers {
            let ext = Extensions::new();
            if !handler.matcher.matches(Some(&ext), &req) {
                continue;
            }
            req.extensions().extend(&ext);

            return match handler.responder.serve(req).await {
                Ok(UpgradeResponse {
                    response,
                    request,
                    extensions,
                }) => {
                    let handler = handler.handler.clone();
                    let error_sink = self.error_sink.clone();

                    let span = tracing::trace_root_span!(
                        "upgrade::serve",
                        otel.kind = "server",
                        http.request.method = %request.method().as_str(),
                        url.full = %request.request_uri(),
                        url.path = %request.uri().path_or_root(),
                        url.query = request.uri().query_or_empty(),
                        url.scheme = %request.uri().scheme_str().unwrap_or_default(),
                        network.protocol.name = "http",
                        network.protocol.version = version_as_protocol_version(request.version()),
                    );

                    self.exec.spawn_task(
                        async move {
                            match crate::io::upgrade::handle_upgrade(request).await {
                                Ok(upgraded) => {
                                    upgraded.extensions().extend(&extensions);
                                    // The handler's own error (if any) was already
                                    // consumed by its per-handler [`ErrorSink`]; the
                                    // boxed handler is `Infallible` here.
                                    _ = handler.serve(upgraded).await;
                                }
                                Err(err) => {
                                    // The HTTP upgrade itself failed (before the handler
                                    // ran): route it to the layer's upgrade error sink.
                                    error_sink.sink_error(
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
    use std::convert::Infallible;
    use std::time::Duration;
    use tokio::sync::mpsc;
    use tokio_test::io::Builder;

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
        let svc = UpgradeLayer::new_with_error_sink(
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
