use super::{IntoResponse, IntoResponseParts, ResponseParts, TryIntoHeaderError};
use crate::{HeaderName, HeaderValue};
use rama_http_types::Response;
use rama_utils::macros::impl_deref;
use std::fmt;

/// Append headers to a response.
///
/// Returning something like `[("content-type", "foo=bar")]` from a handler will override any
/// existing `content-type` headers. If instead you want to append headers, use `AppendHeaders`:
///
/// ```rust
/// use rama_http_types::header::SET_COOKIE;
/// use rama_http::service::web::response::{AppendHeaders, IntoResponse};
///
/// async fn handler() -> impl IntoResponse {
///     // something that sets the `set-cookie` header
///     let set_some_cookies = /* ... */
///     # rama_http_types::HeaderMap::new();
///
///     (
///         set_some_cookies,
///         // append two `set-cookie` headers to the response
///         // without overriding the ones added by `set_some_cookies`
///         AppendHeaders([
///             (SET_COOKIE, "foo=bar"),
///             (SET_COOKIE, "baz=qux"),
///         ])
///     )
/// }
/// ```
#[derive(Debug, Clone)]
pub struct AppendHeaders<I>(pub I);

impl_deref!(AppendHeaders);

impl<I, K, V> IntoResponse for AppendHeaders<I>
where
    I: IntoIterator<Item = (K, V)>,
    K: TryInto<HeaderName, Error: fmt::Display>,
    V: TryInto<HeaderValue, Error: fmt::Display>,
{
    fn into_response(self) -> Response {
        (self, ()).into_response()
    }
}

impl<I, K, V> IntoResponseParts for AppendHeaders<I>
where
    I: IntoIterator<Item = (K, V)>,
    K: TryInto<HeaderName, Error: fmt::Display>,
    V: TryInto<HeaderValue, Error: fmt::Display>,
{
    type Error = TryIntoHeaderError<K::Error, V::Error>;

    fn into_response_parts(self, mut res: ResponseParts) -> Result<ResponseParts, Self::Error> {
        for (key, value) in self.0 {
            let key = key.try_into().map_err(TryIntoHeaderError::key)?;
            let value = value.try_into().map_err(TryIntoHeaderError::value)?;
            res.headers_mut().append(key, value);
        }

        Ok(res)
    }
}
