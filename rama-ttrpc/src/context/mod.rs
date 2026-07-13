use std::fmt::Debug;
use std::future::Future;
use std::ops::Deref;
use std::sync::Arc;

pub(crate) mod metadata;
pub(crate) mod timeout;

use metadata::Metadata;
use timeout::Timeout;
use tokio::task::futures::TaskLocalFuture;

use crate::ServerController;

#[derive(Default, Clone, Debug)]
pub struct Context {
    pub metadata: Metadata,
    pub timeout: Timeout,
}

#[derive(Clone)]
pub struct ServerContext {
    pub server: ServerController,
    context: Arc<Context>,
}

impl Debug for ServerContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.context.fmt(f)
    }
}

impl Deref for ServerContext {
    type Target = Context;

    fn deref(&self) -> &Self::Target {
        &self.context
    }
}

tokio::task_local! {
    static CONTEXT: ServerContext;
}

/// The current call's [`ServerContext`], or `None` when called outside a running method handler
/// (e.g. from an independently spawned task).
#[must_use]
pub fn get_context() -> Option<ServerContext> {
    CONTEXT.try_with(Clone::clone).ok()
}

/// The current call's [`ServerController`], or `None` outside a running method handler.
#[must_use]
pub fn get_server() -> Option<ServerController> {
    get_context().map(|ctx| ctx.server)
}

pub(crate) trait WithContext: Future {
    fn with_context(
        self,
        ctx: impl Into<Arc<Context>>,
        server: ServerController,
    ) -> TaskLocalFuture<ServerContext, Self>
    where
        Self: Sized,
    {
        CONTEXT.scope(
            ServerContext {
                server,
                context: ctx.into(),
            },
            self,
        )
    }
}

impl<F: Future> WithContext for F {}

#[cfg(test)]
mod tests {
    use super::{get_context, get_server};

    #[tokio::test]
    async fn accessors_return_none_outside_a_handler() {
        // Called outside any running method handler (no `with_context` scope): the accessors
        // must return `None`, not panic.
        assert!(get_context().is_none());
        assert!(get_server().is_none());
    }
}
