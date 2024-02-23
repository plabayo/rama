use super::FromRequestParts;
use crate::http::{dep::http::request::Parts, StatusCode};
use crate::service::Context;
use std::ops::{Deref, DerefMut};

/// Extractor to get an Extension from the context (e.g. a shared Database).
pub struct Extension<T>(pub T);

impl<T: std::fmt::Debug> std::fmt::Debug for Extension<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Extension").field(&self.0).finish()
    }
}

impl<T: Clone> Clone for Extension<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<S, T> FromRequestParts<S> for Extension<T>
where
    S: Send + Sync + 'static,
    T: Clone + Send + Sync + 'static,
{
    type Rejection = StatusCode;

    async fn from_request_parts(ctx: &Context<S>, _parts: &Parts) -> Result<Self, Self::Rejection> {
        match ctx.get::<T>() {
            Some(value) => Ok(Self(value.clone())),
            None => Err(StatusCode::INTERNAL_SERVER_ERROR),
        }
    }
}

impl<T> Deref for Extension<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for Extension<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
