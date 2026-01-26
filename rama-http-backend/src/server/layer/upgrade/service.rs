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
    exec: Executor,
}

/// UpgradeHandler is a helper struct used internally to create an upgrade service.
pub struct UpgradeHandler<O> {
    matcher: Box<dyn Matcher<Request>>,
    responder: BoxService<Request, (O, Request), O>,
    handler: BoxService<Upgraded, (), Infallible>,
    _phantom: std::marker::PhantomData<fn(O) -> ()>,
}

impl<O> UpgradeHandler<O> {
    /// Create a new upgrade handler.
    pub(crate) fn new<M, R, H>(matcher: M, responder: R, handler: H) -> Self
    where
        M: Matcher<Request>,
        R: Service<Request, Output = (O, Request), Error = O> + Clone,
        H: Service<Upgraded, Output = (), Error = Infallible> + Clone,
    {
        Self {
            matcher: Box::new(matcher),
            responder: responder.boxed(),
            handler: handler.boxed(),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<S, O> UpgradeService<S, O> {
    /// Create a new [`UpgradeService`].
    pub fn new(handlers: Vec<Arc<UpgradeHandler<O>>>, inner: S, exec: Executor) -> Self {
        Self {
            handlers,
            inner,
            exec,
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

    async fn serve(&self, mut req: Request) -> Result<Self::Output, Self::Error> {
        for handler in &self.handlers {
            let mut ext = Extensions::new();
            if !handler.matcher.matches(Some(&mut ext), &req) {
                continue;
            }
            req.extensions_mut().extend(ext);

            return match handler.responder.serve(req).await {
                Ok((resp, req)) => {
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

                    self.exec.spawn_task(
                        async move {
                            match rama_http::io::upgrade::handle_upgrade(&req).await {
                                Ok(mut upgraded) => {
                                    upgraded.extensions_mut().extend(req.extensions().clone());
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
