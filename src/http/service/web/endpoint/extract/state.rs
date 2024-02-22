use super::FromRequestParts;
use crate::http::dep::http::request::Parts;
use crate::service::Context;
use std::convert::Infallible;
use std::ops::Deref;
use std::sync::Arc;

/// Extractor to get a Arc::clone of the state from the context.
#[derive(Debug, Default)]
pub struct State<S>(pub Arc<S>);

impl<S> Clone for State<S> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<S> FromRequestParts<S> for State<S>
where
    S: Send + Sync + 'static,
{
    type Rejection = Infallible;

    async fn from_request_parts(ctx: &Context<S>, _parts: &Parts) -> Result<Self, Self::Rejection> {
        Ok(Self(ctx.state_clone()))
    }
}

impl<S> Deref for State<S> {
    type Target = S;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
