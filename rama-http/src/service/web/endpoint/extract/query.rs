//! Module in function of the [`Query`] extractor.

use super::{FromPartsStateRefPair, OptionalFromPartsStateRefPair};
use crate::Uri;
use crate::request::Parts;
use crate::utils::macros::define_http_rejection;
use serde::de::DeserializeOwned;

/// Extractor that deserializes query strings into some type.
///
/// `T` is expected to implement [`serde::Deserialize`].
#[derive(Debug, Clone)]
pub struct Query<T>(pub T);

define_http_rejection! {
    #[status = BAD_REQUEST]
    #[body = "Failed to deserialize query string"]
    /// Rejection type used if the [`Query`] extractor is unable to
    /// deserialize the query string into the target type.
    pub struct FailedToDeserializeQueryString(Error);
}

impl<T> Query<T>
where
    T: DeserializeOwned + Send + Sync + 'static,
{
    /// Attempts to construct a [`Query`] from a reference to a [`Uri`].
    #[inline(always)]
    pub fn try_from_uri(value: &Uri) -> Result<Self, FailedToDeserializeQueryString> {
        let query = value.query().unwrap_or_default();
        Self::parse_query_str(query)
    }

    /// Create a `Query<T>` directly from the query str,
    /// can be useful to combine this method as part of another extractor
    /// or otherwise impossible combination.
    pub fn parse_query_str(query: &str) -> Result<Self, FailedToDeserializeQueryString> {
        let params =
            serde_html_form::from_str(query).map_err(FailedToDeserializeQueryString::from_err)?;
        Ok(Self(params))
    }
}

impl<T, State> FromPartsStateRefPair<State> for Query<T>
where
    T: DeserializeOwned + Send + Sync + 'static,
    State: Send + Sync,
{
    type Rejection = FailedToDeserializeQueryString;

    async fn from_parts_state_ref_pair(
        parts: &Parts,
        _state: &State,
    ) -> Result<Self, Self::Rejection> {
        let query = parts.uri.query().unwrap_or_default();
        Self::parse_query_str(query)
    }
}

impl<T, State> OptionalFromPartsStateRefPair<State> for Query<T>
where
    T: DeserializeOwned + Send + Sync + 'static,
    State: Send + Sync,
{
    type Rejection = FailedToDeserializeQueryString;

    async fn from_parts_state_ref_pair(
        parts: &Parts,
        _state: &State,
    ) -> Result<Option<Self>, Self::Rejection> {
        match parts.uri.query() {
            Some(query) => {
                let params = serde_html_form::from_str(query)
                    .map_err(FailedToDeserializeQueryString::from_err)?;
                Ok(Some(Self(params)))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[test]
    fn test_try_from_uri() {
        #[derive(Deserialize)]
        struct TestQueryParams {
            foo: Vec<String>,
            bar: u32,
        }
        let uri: Uri = "http://example.com/path?foo=hello&bar=42&foo=goodbye"
            .parse()
            .unwrap();
        let Query(TestQueryParams { foo, bar }) = Query::try_from_uri(&uri).unwrap();
        assert_eq!(foo, [String::from("hello"), String::from("goodbye")]);
        assert_eq!(bar, 42);
    }

    #[test]
    fn test_try_from_uri_with_invalid_query() {
        #[derive(Deserialize)]
        struct TestQueryParams {
            _foo: String,
            _bar: u32,
        }
        let uri: Uri = "http://example.com/path?foo=hello&bar=invalid"
            .parse()
            .unwrap();
        let result: Result<Query<TestQueryParams>, _> = Query::try_from_uri(&uri);

        assert!(result.is_err());
    }
}
