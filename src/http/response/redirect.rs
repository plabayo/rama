use super::IntoResponse;
use crate::http::{header, HeaderValue, Response, StatusCode};

#[derive(Debug, Clone)]
/// Utility struct to easily create a redirect response.
pub struct Redirect {
    loc: HeaderValue,
    status: StatusCode,
}

impl Redirect {
    /// Create a new temporary (307) redirect response.
    pub fn temporary(loc: impl Into<HeaderValue>) -> Self {
        Redirect {
            loc: loc.into(),
            status: StatusCode::TEMPORARY_REDIRECT,
        }
    }

    /// Create a new permanent (308) redirect response.
    pub fn permanent(loc: impl Into<HeaderValue>) -> Self {
        Redirect {
            loc: loc.into(),
            status: StatusCode::PERMANENT_REDIRECT,
        }
    }
}

impl IntoResponse for Redirect {
    fn into_response(self) -> Response {
        ([(header::LOCATION, self.loc)], self.status).into_response()
    }
}
