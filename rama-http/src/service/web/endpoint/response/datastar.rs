use super::{IntoResponse, Script};
use rama_http_types::Response;

#[derive(Debug, Clone, Copy)]
/// Datastar script ready to be served.
///
/// Embedded version of a recent enough datastar frontend script
/// compatible with the datastar support embedded in rama.
///
/// Learn more about datastar at <https://data-star.dev/>
/// or in the book: <https://ramaproxy.org/book/web_servers.html#datastar>.
pub struct DatastarScript(Script<&'static str>);

impl Default for DatastarScript {
    fn default() -> Self {
        Self(Script(include_str!("./datastar.js")))
    }
}

impl DatastarScript {
    #[inline]
    /// Create a new [`DatastarScript`] ready to be served.
    #[must_use]
    pub fn new() -> Self {
        Default::default()
    }
}

impl IntoResponse for DatastarScript {
    #[inline]
    fn into_response(self) -> Response {
        self.0.into_response()
    }
}
