use super::FromRequestParts;
use crate::http::service::web::matcher::UriParams;
use crate::http::{dep::http::request::Parts, StatusCode};
use crate::service::Context;
use serde::de::DeserializeOwned;
use std::ops::{Deref, DerefMut};

/// Extractor to get a Arc::clone of the state from the context.
#[derive(Debug, Default)]
pub struct Path<T>(pub T);

impl<T: Clone> Clone for Path<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> FromRequestParts<T> for Path<T>
where
    T: DeserializeOwned + Send + Sync + 'static,
{
    type Rejection = StatusCode;

    async fn from_request_parts(ctx: &Context<T>, _parts: &Parts) -> Result<Self, Self::Rejection> {
        match ctx.get::<UriParams>() {
            Some(params) => match params.deserialize::<T>() {
                Ok(value) => Ok(Self(value)),
                Err(_) => Err(StatusCode::BAD_REQUEST),
            },
            None => Err(StatusCode::BAD_REQUEST),
        }
    }
}

impl<T> Deref for Path<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for Path<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
