use crate::io::upgrade::Upgraded;

use super::UpgradeResponse;

use super::{UpgradeService, service::UpgradeHandler};
use rama_core::error::BoxError;
use rama_core::error_sink::{DropErrorSink, ErrorSink, TracingErrorSink};
use rama_core::{Layer, Service, matcher::Matcher, rt::Executor};
use rama_http_types::Request;
use std::{fmt, sync::Arc};

/// UpgradeLayer is a middleware that can be used to upgrade a request.
///
/// See [`UpgradeService`] for more details.
///
/// [`UpgradeService`]: crate::layer::upgrade::UpgradeService
pub struct UpgradeLayer<O> {
    handlers: Vec<Arc<UpgradeHandler<O>>>,
    exec: Executor,
    error_sink: Arc<dyn ErrorSink>,
}

impl<O> UpgradeLayer<O> {
    /// Create a new upgrade layer whose handler's errors are routed to the
    /// default [`ErrorSink`] ([`TracingErrorSink::default`], DEBUG level).
    ///
    /// Use [`UpgradeLayer::new_with_error_sink`] to give the handler a custom
    /// sink (which also lifts the `Error: Into<BoxError>` requirement, allowing
    /// any handler error type).
    pub fn new<M, R, H>(exec: Executor, matcher: M, responder: R, handler: H) -> Self
    where
        M: Matcher<Request>,
        R: Service<Request, Output = UpgradeResponse<Request, O>, Error = O> + Clone,
        H: Service<Upgraded, Output = (), Error: Into<BoxError>> + Clone,
    {
        Self::new_with_error_sink(
            exec,
            matcher,
            responder,
            handler,
            TracingErrorSink::default(),
        )
    }

    /// Create a new upgrade layer, routing the handler's errors (of any type)
    /// to the given [`ErrorSink`].
    pub fn new_with_error_sink<M, R, H, Sink>(
        exec: Executor,
        matcher: M,
        responder: R,
        handler: H,
        sink: Sink,
    ) -> Self
    where
        M: Matcher<Request>,
        R: Service<Request, Output = UpgradeResponse<Request, O>, Error = O> + Clone,
        H: Service<Upgraded, Output = ()> + Clone,
        Sink: ErrorSink<H::Error>,
    {
        Self {
            handlers: vec![Arc::new(UpgradeHandler::new(
                matcher, responder, handler, sink,
            ))],
            exec,
            error_sink: Arc::new(TracingErrorSink::default()),
        }
    }

    /// Create a new upgrade layer whose handler's errors (of any type) are
    /// silently dropped ([`DropErrorSink`]). Use this for handlers whose errors
    /// are neither actionable nor traceable.
    pub fn new_dropping_errors<M, R, H>(
        exec: Executor,
        matcher: M,
        responder: R,
        handler: H,
    ) -> Self
    where
        M: Matcher<Request>,
        R: Service<Request, Output = UpgradeResponse<Request, O>, Error = O> + Clone,
        H: Service<Upgraded, Output = ()> + Clone,
    {
        Self::new_with_error_sink(exec, matcher, responder, handler, DropErrorSink::new())
    }

    /// Add an extra upgrade handler, routing its errors to the default
    /// [`ErrorSink`] ([`TracingErrorSink::default`], DEBUG level).
    #[must_use]
    pub fn on<M, R, H>(self, matcher: M, responder: R, handler: H) -> Self
    where
        M: Matcher<Request>,
        R: Service<Request, Output = UpgradeResponse<Request, O>, Error = O> + Clone,
        H: Service<Upgraded, Output = (), Error: Into<BoxError>> + Clone,
    {
        self.on_with_error_sink(matcher, responder, handler, TracingErrorSink::default())
    }

    /// Add an extra upgrade handler whose errors (of any type) are silently
    /// dropped ([`DropErrorSink`]).
    #[must_use]
    pub fn on_dropping_errors<M, R, H>(self, matcher: M, responder: R, handler: H) -> Self
    where
        M: Matcher<Request>,
        R: Service<Request, Output = UpgradeResponse<Request, O>, Error = O> + Clone,
        H: Service<Upgraded, Output = ()> + Clone,
    {
        self.on_with_error_sink(matcher, responder, handler, DropErrorSink::new())
    }

    /// Add an extra upgrade handler, routing its errors (of any type) to the
    /// given [`ErrorSink`].
    #[must_use]
    pub fn on_with_error_sink<M, R, H, Sink>(
        mut self,
        matcher: M,
        responder: R,
        handler: H,
        sink: Sink,
    ) -> Self
    where
        M: Matcher<Request>,
        R: Service<Request, Output = UpgradeResponse<Request, O>, Error = O> + Clone,
        H: Service<Upgraded, Output = ()> + Clone,
        Sink: ErrorSink<H::Error>,
    {
        self.handlers.push(Arc::new(UpgradeHandler::new(
            matcher, responder, handler, sink,
        )));
        self
    }

    /// Set the [`ErrorSink`] used for errors that occur while *establishing*
    /// the upgraded connection (i.e. the HTTP upgrade itself fails, before any
    /// handler runs). Per-handler errors are routed to their own sink instead;
    /// see [`UpgradeLayer::on_with_error_sink`].
    ///
    /// Defaults to [`TracingErrorSink::default`] (traces at DEBUG level).
    #[must_use]
    pub fn with_upgrade_error_sink(mut self, sink: impl ErrorSink) -> Self {
        self.error_sink = Arc::new(sink);
        self
    }
}

impl<O> fmt::Debug for UpgradeLayer<O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpgradeLayer")
            .field("handlers", &self.handlers)
            .finish()
    }
}

impl<O> Clone for UpgradeLayer<O> {
    fn clone(&self) -> Self {
        Self {
            handlers: self.handlers.clone(),
            exec: self.exec.clone(),
            error_sink: self.error_sink.clone(),
        }
    }
}

impl<S, O> Layer<S> for UpgradeLayer<O> {
    type Service = UpgradeService<S, O>;

    fn layer(&self, inner: S) -> Self::Service {
        UpgradeService::new(
            self.handlers.clone(),
            inner,
            self.exec.clone(),
            self.error_sink.clone(),
        )
    }

    fn into_layer(self, inner: S) -> Self::Service {
        UpgradeService::new(self.handlers, inner, self.exec, self.error_sink)
    }
}
