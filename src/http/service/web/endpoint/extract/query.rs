use super::FromRequestParts;
use crate::http::dep::http::request::Parts;
use crate::service::Context;
use serde::de::DeserializeOwned;

/// Extractor that deserializes query strings into some type.
///
/// `T` is expected to implement [`serde::Deserialize`].
pub struct Query<T>(pub T);

crate::__define_http_rejection! {
    #[status = BAD_REQUEST]
    #[body = "Failed to deserialize query string"]
    /// Rejection type used if the [`Query`] extractor is unable to
    /// deserialize the query string into the target type.
    pub struct FailedToDeserializeQueryString(Error);
}

impl<T: std::fmt::Debug> std::fmt::Debug for Query<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Query").field(&self.0).finish()
    }
}

impl<T: Clone> Clone for Query<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T, S> FromRequestParts<S> for Query<T>
where
    T: DeserializeOwned + Send + Sync + 'static,
    S: Send + Sync + 'static,
{
    type Rejection = FailedToDeserializeQueryString;

    async fn from_request_parts(_ctx: &Context<S>, parts: &Parts) -> Result<Self, Self::Rejection> {
        let query = parts.uri.query().unwrap_or_default();
        let params =
            serde_html_form::from_str(query).map_err(FailedToDeserializeQueryString::from_err)?;
        Ok(Query(params))
    }
}
