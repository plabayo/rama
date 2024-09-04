use super::FromRequestParts;
use crate::dep::http::request::Parts;
use rama_core::Context;
use std::convert::Infallible;
use std::ops::Deref;

#[derive(Debug, Clone)]
/// Extractor to get a clone of the [`Dns`] from the [`Context`].
///
/// [`Dns`]: crate::dns::Dns
/// [`Context`]: rama_core::Context
pub struct Dns(pub rama_core::dns::Dns);

impl<T> FromRequestParts<T> for Dns
where
    T: Send + Sync + 'static,
{
    type Rejection = Infallible;

    async fn from_request_parts(ctx: &Context<T>, _parts: &Parts) -> Result<Self, Self::Rejection> {
        Ok(Self(ctx.dns().clone()))
    }
}

impl Deref for Dns {
    type Target = rama_core::dns::Dns;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
