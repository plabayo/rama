//! Http Response utilities for Rama Http Services.

use super::Response;

/// Trait for generating responses.
///
/// Types that implement IntoResponse can be returned from handlers.
pub trait IntoResponse {
    /// Create a response.
    fn into_response(self) -> Response;
}

impl IntoResponse for Response {
    fn into_response(self) -> Response {
        self
    }
}
