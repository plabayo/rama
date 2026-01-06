use super::{IntoResponse, Script};
use rama_http_types::{
    Response,
    header::{CONTENT_TYPE, HeaderValue},
};

#[derive(Debug, Clone, Copy)]
/// Datastar script ready to be served.
///
/// Embedded version of a recent enough datastar frontend script
/// compatible with the datastar support embedded in rama.
///
/// Source: <https://cdn.jsdelivr.net/gh/starfederation/datastar@1.0.0-RC.7/bundles/datastar.js>
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

#[derive(Debug, Clone, Copy)]
/// Datastar source map ready to be served.
///
/// Embedded version of the datastar source map file
/// for improved debugging experience.
///
/// Source: <https://cdn.jsdelivr.net/gh/starfederation/datastar@1.0.0-RC.7/bundles/datastar.js.map>
///
/// Learn more about datastar at <https://data-star.dev/>
/// or in the book: <https://ramaproxy.org/book/web_servers.html#datastar>.
pub struct DatastarSourceMap(&'static str);

impl Default for DatastarSourceMap {
    fn default() -> Self {
        Self(include_str!("./datastar.js.map"))
    }
}

impl DatastarSourceMap {
    #[inline]
    /// Create a new [`DatastarSourceMap`] ready to be served.
    #[must_use]
    pub fn new() -> Self {
        Default::default()
    }
}

impl IntoResponse for DatastarSourceMap {
    #[inline]
    fn into_response(self) -> Response {
        let mut response = Response::new(self.0.into());
        response
            .headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        response
    }
}
