use super::IntoResponse;
use crate::{HeaderValue, Response, StatusCode, header};

#[derive(Debug, Clone)]
/// Utility struct to easily create a redirect response.
pub struct Redirect {
    loc: HeaderValue,
    status: StatusCode,
}

impl Redirect {
    /// Create a new temporary (307) redirect response.
    ///
    /// # Panics
    ///
    /// This function panics if the `loc` argument contains invalid header value characters.
    pub fn temporary(loc: impl AsRef<str>) -> Self {
        Self {
            loc: HeaderValue::from_str(loc.as_ref()).unwrap(),
            status: StatusCode::TEMPORARY_REDIRECT,
        }
    }

    /// Create a new permanent (308) redirect response.
    ///
    /// # Panics
    ///
    /// This function panics if the `loc` argument contains invalid header value characters.
    pub fn permanent(loc: impl AsRef<str>) -> Self {
        Self {
            loc: HeaderValue::from_str(loc.as_ref()).unwrap(),
            status: StatusCode::PERMANENT_REDIRECT,
        }
    }
}

impl IntoResponse for Redirect {
    fn into_response(self) -> Response {
        ([(header::LOCATION, self.loc)], self.status).into_response()
    }
}
