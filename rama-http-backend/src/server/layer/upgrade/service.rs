//! upgrade service to handle branching into http upgrade services
//!
//! See [`UpgradeService`] for more details.

use super::Upgraded;
use rama_core::extensions::{ExtensionsMut, ExtensionsRef};
use rama_core::rt::Executor;
use rama_core::telemetry::tracing::{self, Instrument};
use rama_core::{Service, extensions::Extensions, matcher::Matcher, service::BoxService};
use rama_http::opentelemetry::version_as_protocol_version;
use rama_http_types::Request;
use rama_utils::macros::define_inner_service_accessors;
use std::{convert::Infallible, fmt, sync::Arc};

/// Upgrade service can be used to handle the possibility of upgrading a request,
/// after which it will pass down the transport RW to the attached upgrade service.
pub struct UpgradeService<S, O> {
    handlers: Vec<Arc<UpgradeHandler<O>>>,
    inner: S,
}

/// UpgradeHandler is a helper struct used internally to create an upgrade service.
pub struct UpgradeHandler<O> {
    matcher: Box<dyn Matcher<Request>>,
    responder: BoxService<Request, (O, Request), O>,
    handler: Arc<BoxService<Upgraded, (), Infallible>>,
    _phantom: std::marker::PhantomData<fn(O) -> ()>,
}

impl<O> UpgradeHandler<O> {
    /// Create a new upgrade handler.
    pub(crate) fn new<M, R, H>(matcher: M, responder: R, handler: H) -> Self
    where
        M: Matcher<Request>,
        R: Service<Request, Response = (O, Request), Error = O> + Clone,
        H: Service<Upgraded, Response = (), Error = Infallible> + Clone,
    {
        Self {
            matcher: Box::new(matcher),
            responder: responder.boxed(),
            handler: Arc::new(handler.boxed()),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<S, O> UpgradeService<S, O> {
    /// Create a new [`UpgradeService`].
    pub const fn new(handlers: Vec<Arc<UpgradeHandler<O>>>, inner: S) -> Self {
        Self { handlers, inner }
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
        }
    }
}

impl<S, O, E> Service<Request> for UpgradeService<S, O>
where
    S: Service<Request, Response = O, Error = E>,
    O: Send + Sync + 'static,
    E: Send + Sync + 'static,
{
    type Response = O;
    type Error = E;

    async fn serve(&self, mut req: Request) -> Result<Self::Response, Self::Error> {
        let mut ext = Extensions::new();
        for handler in &self.handlers {
            if !handler.matcher.matches(Some(&mut ext), &req) {
                ext.clear();
                continue;
            }
            req.extensions_mut().extend(ext);
            let exec = req
                .extensions()
                .get::<Executor>()
                .cloned()
                .unwrap_or_default();

            return match handler.responder.serve(req).await {
                Ok((resp, mut req)) => {
                    let handler = handler.handler.clone();

                    let span = tracing::trace_root_span!(
                        "upgrade::serve",
                        otel.kind = "server",
                        http.request.method = %req.method().as_str(),
                        url.full = %req.uri(),
                        url.path = %req.uri().path(),
                        url.query = req.uri().query().unwrap_or_default(),
                        url.scheme = %req.uri().scheme().map(|s| s.as_str()).unwrap_or_default(),
                        network.protocol.name = "http",
                        network.protocol.version = version_as_protocol_version(req.version()),
                    );

                    exec.spawn_task(
                        async move {
                            match rama_http::io::upgrade::on(&mut req).await {
                                Ok(mut upgraded) => {
                                    upgraded.extensions_mut().extend(req.take_extensions());
                                    let _ = handler.serve(upgraded).await;
                                }
                                Err(e) => {
                                    // TODO: do we need to allow the user to hook into this?
                                    tracing::error!("upgrade error: {e:?}");
                                }
                            }
                        }
                        .instrument(span),
                    );
                    Ok(resp)
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
