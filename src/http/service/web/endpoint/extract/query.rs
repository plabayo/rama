use super::FromRequestParts;
use crate::http::{dep::http::request::Parts, StatusCode, Uri};
use crate::service::Context;
use serde::de::DeserializeOwned;

/// Extractor that deserializes query strings into some type.
///
/// `T` is expected to implement [`serde::Deserialize`].
#[derive(Debug, Clone, Copy, Default)]
pub struct Query<T>(pub T);

impl<T, S> FromRequestParts<S> for Query<T>
where
    T: DeserializeOwned + Send + Sync + 'static,
    S: Send + Sync + 'static,
{
    type Rejection = StatusCode;

    async fn from_request_parts(_ctx: &Context<S>, parts: &Parts) -> Result<Self, Self::Rejection> {
        match Self::try_from_uri(&parts.uri) {
            Some(query) => Ok(query),
            None => Err(StatusCode::BAD_REQUEST),
        }
    }
}

impl<T> Query<T>
where
    T: DeserializeOwned,
{
    /// Attempts to construct a [`Query`] from a reference to a [`Uri`].
    ///
    /// # Example
    /// ```
    /// use rama::http::service::web::extract::Query;
    /// use rama::http::Uri;
    /// use serde::Deserialize;
    ///
    /// #[derive(Deserialize)]
    /// struct ExampleParams {
    ///     foo: String,
    ///     bar: u32,
    /// }
    ///
    /// let uri: Uri = "http://example.com/path?foo=hello&bar=42".parse().unwrap();
    /// let result: Query<ExampleParams> = Query::try_from_uri(&uri).unwrap();
    /// assert_eq!(result.foo, String::from("hello"));
    /// assert_eq!(result.bar, 42);
    /// ```
    pub fn try_from_uri(value: &Uri) -> Option<Self> {
        let query = value.query().unwrap_or_default();
        let params = serde_urlencoded::from_str(query).ok()?;
        Some(Query(params))
    }
}

__impl_deref!(Query);
