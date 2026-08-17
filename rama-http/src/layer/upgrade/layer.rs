use crate::io::upgrade::Upgraded;

use super::{UpgradeOutput, UpgradeResponse};

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

impl<O: Send + 'static> UpgradeLayer<O> {
    /// Create a new upgrade layer from one service.
    ///
    /// The service responds to the upgrade request with an [`UpgradeOutput`]
    /// containing the response-local handler for the upgraded connection. This
    /// lets that handler directly own resources established before the response.
    /// Use [`Self::new_with_services`] when the responder and handler are separate.
    pub fn new<M, R>(exec: Executor, matcher: M, service: R) -> Self
    where
        M: Matcher<Request>,
        R: Service<Request, Output = UpgradeOutput<Request, O>, Error = O> + Clone,
    {
        Self::new_with_error_sink(exec, matcher, service, TracingErrorSink::default())
    }

    /// Create a single-service upgrade layer with a custom handler error sink.
    pub fn new_with_error_sink<M, R, Sink>(
        exec: Executor,
        matcher: M,
        service: R,
        sink: Sink,
    ) -> Self
    where
        M: Matcher<Request>,
        R: Service<Request, Output = UpgradeOutput<Request, O>, Error = O> + Clone,
        Sink: ErrorSink,
    {
        Self {
            handlers: vec![Arc::new(UpgradeHandler::new(matcher, service, sink))],
            exec,
            error_sink: Arc::new(TracingErrorSink::default()),
        }
    }

    /// Create a single-service upgrade layer which silently drops handler errors.
    pub fn new_dropping_errors<M, R>(exec: Executor, matcher: M, service: R) -> Self
    where
        M: Matcher<Request>,
        R: Service<Request, Output = UpgradeOutput<Request, O>, Error = O> + Clone,
    {
        Self::new_with_error_sink(exec, matcher, service, DropErrorSink::new())
    }

    /// Create an upgrade layer with separate responder and handler services.
    ///
    /// This is useful when the handshake can be acknowledged independently and
    /// the upgraded-connection service performs any deferred setup itself.
    pub fn new_with_services<M, R, H>(exec: Executor, matcher: M, responder: R, handler: H) -> Self
    where
        M: Matcher<Request>,
        R: Service<Request, Output = UpgradeResponse<Request, O>, Error = O> + Clone,
        H: Service<Upgraded, Error: Into<BoxError>> + Clone,
    {
        Self::new_with_services_and_error_sink(
            exec,
            matcher,
            responder,
            handler,
            TracingErrorSink::default(),
        )
    }

    /// Create a separate-services upgrade layer with a custom handler error sink.
    pub fn new_with_services_and_error_sink<M, R, H, Sink>(
        exec: Executor,
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
        Self {
            handlers: vec![Arc::new(UpgradeHandler::new_with_services(
                matcher, responder, handler, sink,
            ))],
            exec,
            error_sink: Arc::new(TracingErrorSink::default()),
        }
    }

    /// Create a separate-services upgrade layer which silently drops handler errors.
    pub fn new_with_services_dropping_errors<M, R, H>(
        exec: Executor,
        matcher: M,
        responder: R,
        handler: H,
    ) -> Self
    where
        M: Matcher<Request>,
        R: Service<Request, Output = UpgradeResponse<Request, O>, Error = O> + Clone,
        H: Service<Upgraded> + Clone,
    {
        Self::new_with_services_and_error_sink(
            exec,
            matcher,
            responder,
            handler,
            DropErrorSink::new(),
        )
    }

    /// Add a single-service upgrade handler.
    #[must_use]
    pub fn on<M, R>(self, matcher: M, service: R) -> Self
    where
        M: Matcher<Request>,
        R: Service<Request, Output = UpgradeOutput<Request, O>, Error = O> + Clone,
    {
        self.on_with_error_sink(matcher, service, TracingErrorSink::default())
    }

    /// Add a single-service upgrade handler with a custom handler error sink.
    #[must_use]
    pub fn on_with_error_sink<M, R, Sink>(mut self, matcher: M, service: R, sink: Sink) -> Self
    where
        M: Matcher<Request>,
        R: Service<Request, Output = UpgradeOutput<Request, O>, Error = O> + Clone,
        Sink: ErrorSink,
    {
        self.handlers
            .push(Arc::new(UpgradeHandler::new(matcher, service, sink)));
        self
    }

    /// Add a single-service upgrade handler which silently drops handler errors.
    #[must_use]
    pub fn on_dropping_errors<M, R>(self, matcher: M, service: R) -> Self
    where
        M: Matcher<Request>,
        R: Service<Request, Output = UpgradeOutput<Request, O>, Error = O> + Clone,
    {
        self.on_with_error_sink(matcher, service, DropErrorSink::new())
    }

    /// Add separate responder and upgraded-connection services.
    #[must_use]
    pub fn on_with_services<M, R, H>(self, matcher: M, responder: R, handler: H) -> Self
    where
        M: Matcher<Request>,
        R: Service<Request, Output = UpgradeResponse<Request, O>, Error = O> + Clone,
        H: Service<Upgraded, Error: Into<BoxError>> + Clone,
    {
        self.on_with_services_and_error_sink(
            matcher,
            responder,
            handler,
            TracingErrorSink::default(),
        )
    }

    /// Add separate services with a custom handler error sink.
    #[must_use]
    pub fn on_with_services_and_error_sink<M, R, H, Sink>(
        mut self,
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
        self.handlers
            .push(Arc::new(UpgradeHandler::new_with_services(
                matcher, responder, handler, sink,
            )));
        self
    }

    /// Add separate services while silently dropping handler errors.
    #[must_use]
    pub fn on_with_services_dropping_errors<M, R, H>(
        self,
        matcher: M,
        responder: R,
        handler: H,
    ) -> Self
    where
        M: Matcher<Request>,
        R: Service<Request, Output = UpgradeResponse<Request, O>, Error = O> + Clone,
        H: Service<Upgraded> + Clone,
    {
        self.on_with_services_and_error_sink(matcher, responder, handler, DropErrorSink::new())
    }

    /// Set the [`ErrorSink`] used for errors that occur while *establishing*
    /// the upgraded connection (i.e. the HTTP upgrade itself fails, before any
    /// handler runs). Per-handler errors are routed to their own sink instead;
    /// see [`Self::on_with_error_sink`] and
    /// [`Self::on_with_services_and_error_sink`].
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
