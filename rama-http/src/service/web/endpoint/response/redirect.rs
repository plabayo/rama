use std::borrow::Cow;

use super::IntoResponse;
use crate::{HeaderValue, Response, StatusCode, header};

#[derive(Debug, Clone)]
/// Utility struct to easily create a redirect response.
pub struct Redirect {
    loc: HeaderValue,
    status: StatusCode,
}

pub trait IntoRedirectLoc: private::IntoRedirectLocSeal {}
impl<T: private::IntoRedirectLocSeal> IntoRedirectLoc for T {}

mod private {
    use rama_http_types::{HeaderName, HeaderValue};

    pub trait IntoRedirectLocSeal {
        #[must_use]
        fn into_redirect_loc(self) -> HeaderValue;
    }

    impl IntoRedirectLocSeal for &'static str {
        fn into_redirect_loc(self) -> HeaderValue {
            HeaderValue::from_static(self)
        }
    }

    impl IntoRedirectLocSeal for HeaderName {
        fn into_redirect_loc(self) -> HeaderValue {
            HeaderValue::from_name(self)
        }
    }

    impl IntoRedirectLocSeal for HeaderValue {
        fn into_redirect_loc(self) -> HeaderValue {
            self
        }
    }
}

impl Redirect {
    /// Create a new [`Redirect`] that uses a [`303 See Other`][mdn] status code.
    ///
    /// This redirect instructs the client to change the method to GET for the subsequent request
    /// to the given location, which is useful after successful form submission, file upload or when
    /// you generally don't want the redirected-to page to observe the original request method and
    /// body (if non-empty). If you want to preserve the request method and body,
    /// [`Redirect::temporary`] should be used instead.
    ///
    /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/303
    pub fn to(loc: impl IntoRedirectLoc) -> Self {
        Self::with_status_code(StatusCode::SEE_OTHER, loc)
    }

    /// Create a new found (302) redirect response.
    ///
    /// Can be useful in flows where the resource was legit and found,
    /// but a pre-requirement such as authentication wasn't met.
    pub fn found(loc: impl IntoRedirectLoc) -> Self {
        Self::with_status_code(StatusCode::FOUND, loc)
    }

    /// Create a new temporary (307) redirect response.
    pub fn temporary(loc: impl IntoRedirectLoc) -> Self {
        Self::with_status_code(StatusCode::TEMPORARY_REDIRECT, loc)
    }

    /// Create a new permanent (308) redirect response.
    pub fn permanent(loc: impl IntoRedirectLoc) -> Self {
        Self::with_status_code(StatusCode::PERMANENT_REDIRECT, loc)
    }

    // This is intentionally not public since other kinds of redirects might not
    // use the `Location` header, namely `304 Not Modified`.
    //
    // We're open to adding more constructors upon request, if they make sense :)
    fn with_status_code(status: StatusCode, loc: impl IntoRedirectLoc) -> Self {
        assert!(status.is_redirection(), "not a redirection status code");
        Self {
            status,
            loc: loc.into_redirect_loc(),
        }
    }

    /// Returns the HTTP status code of the `Redirect`.
    #[must_use]
    pub fn status_code(&self) -> StatusCode {
        self.status
    }

    /// Returns the `Redirect`'s URI
    #[must_use]
    pub fn location(&self) -> &HeaderValue {
        &self.loc
    }

    /// Returns the `Redirect`'s URI as a lossy-utf-8 str
    #[must_use]
    pub fn location_str(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(self.loc.as_bytes())
    }
}

impl IntoResponse for Redirect {
    fn into_response(self) -> Response {
        ([(header::LOCATION, self.loc)], self.status).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::Redirect;
    use rama_http_types::{HeaderValue, StatusCode};

    const EXAMPLE_URL: HeaderValue = HeaderValue::from_static("https://example.com");

    // Tests to make sure Redirect has the correct status codes
    // based on the way it was constructed.
    #[test]
    fn correct_status() {
        assert_eq!(
            StatusCode::SEE_OTHER,
            Redirect::to(EXAMPLE_URL).status_code()
        );

        assert_eq!(
            StatusCode::FOUND,
            Redirect::found(EXAMPLE_URL).status_code()
        );

        assert_eq!(
            StatusCode::TEMPORARY_REDIRECT,
            Redirect::temporary(EXAMPLE_URL).status_code()
        );

        assert_eq!(
            StatusCode::PERMANENT_REDIRECT,
            Redirect::permanent(EXAMPLE_URL).status_code()
        );
    }

    #[test]
    fn correct_location() {
        assert_eq!(EXAMPLE_URL, Redirect::permanent(EXAMPLE_URL).location());

        assert_eq!(
            "/redirect",
            Redirect::permanent(HeaderValue::from_static("/redirect")).location_str()
        )
    }
}
