//! upgrade service to handle branching into http upgrade services
//!
//! See [`UpgradeService`] for more details.

use super::Upgraded;
use crate::{
    http::Request,
    service::{context::Extensions, BoxService, Context, Matcher, Service},
};
use std::{convert::Infallible, fmt, sync::Arc};

/// Upgrade service can be used to handle the possibility of upgrading a request,
/// after which it will pass down the transport RW to the attached upgrade service.
pub struct UpgradeService<S, State, O> {
    handlers: Vec<Arc<UpgradeHandler<State, O>>>,
    inner: S,
}

/// UpgradeHandler is a helper struct used internally to create an upgrade service.
pub struct UpgradeHandler<S, O> {
    matcher: Box<dyn Matcher<S, Request>>,
    responder: BoxService<S, Request, (O, Context<S>, Request), O>,
    handler: Arc<BoxService<S, Upgraded, (), Infallible>>,
    _phantom: std::marker::PhantomData<fn(S, O) -> ()>,
}

impl<S, O> UpgradeHandler<S, O> {
    /// Create a new upgrade handler.
    pub(crate) fn new<M, R, H>(matcher: M, responder: R, handler: H) -> Self
    where
        M: Matcher<S, Request>,
        R: Service<S, Request, Response = (O, Context<S>, Request), Error = O> + Clone,
        H: Service<S, Upgraded, Response = (), Error = Infallible> + Clone,
    {
        Self {
            matcher: Box::new(matcher),
            responder: responder.boxed(),
            handler: Arc::new(handler.boxed()),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<S, State, O> UpgradeService<S, State, O> {
    /// Create a new [`UpgradeService`].
    pub fn new(handlers: Vec<Arc<UpgradeHandler<State, O>>>, inner: S) -> Self {
        Self { handlers, inner }
    }

    define_inner_service_accessors!();
}

impl<S, State, O> fmt::Debug for UpgradeService<S, State, O>
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

impl<S, State, O> Clone for UpgradeService<S, State, O>
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

impl<S, State, O, E> Service<State, Request> for UpgradeService<S, State, O>
where
    State: Send + Sync + 'static,
    S: Service<State, Request, Response = O, Error = E>,
    O: Send + Sync + 'static,
    E: Send + Sync + 'static,
{
    type Response = O;
    type Error = E;

    async fn serve(
        &self,
        mut ctx: Context<State>,
        req: Request,
    ) -> Result<Self::Response, Self::Error> {
        let mut ext = Extensions::new();
        for handler in &self.handlers {
            if !handler.matcher.matches(Some(&mut ext), &ctx, &req) {
                ext.clear();
                continue;
            }
            ctx.extend(ext);
            let exec = ctx.executor().clone();
            return match handler.responder.serve(ctx, req).await {
                Ok((resp, ctx, mut req)) => {
                    let handler = handler.handler.clone();
                    exec.spawn_task(async move {
                        match hyper::upgrade::on(&mut req).await {
                            Ok(upgraded) => {
                                let upgraded = Upgraded::new(upgraded);
                                let _ = handler.serve(ctx, upgraded).await;
                            }
                            Err(e) => {
                                // TODO: do we need to allow the user to hook into this?
                                tracing::error!(error = %e, "upgrade error");
                            }
                        }
                    });
                    Ok(resp)
                }
                Err(e) => Ok(e),
            };
        }
        self.inner.serve(ctx, req).await
    }
}

impl<S, O> fmt::Debug for UpgradeHandler<S, O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpgradeHandler").finish()
    }
}
