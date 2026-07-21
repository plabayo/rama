//! Native host objects for Rama HTTP requests and responses.
//!
//! Message bodies and extensions remain entirely Rust-owned. The JavaScript
//! API exposes only method, URI, status, version, and header metadata.
//!
//! Request objects expose mutable `method`, `uri`, and `version` properties;
//! response objects expose mutable `status` and `version` properties. Both
//! provide `header`, `headers`, `headerNames`, `containsHeader`, `setHeader`,
//! `appendHeader`, and `removeHeader` methods. Text access rejects header
//! values which cannot be represented as strings without loss.

mod middleware;
mod shared;

use rama_http_types::{Method, StatusCode, request, response};
use rama_net::uri::Uri;

use crate::{JsError, JsHostClass, JsHostHandle, JsHostObject, JsStr};

use self::shared::http_message_class;

pub use middleware::{JsHttpError, JsHttpLayer, JsHttpScriptProvider, JsHttpService};

/// Build the reusable native-object class used for HTTP requests.
pub fn request_host_class() -> JsHostClass<request::Parts> {
    http_message_class()
        .getter("method", |parts: &request::Parts| {
            JsStr::new(parts.method.as_str())
        })
        .setter(
            "method",
            |parts: &mut request::Parts, method: JsStr| -> Result<(), JsError> {
                parts.method = Method::from_bytes(method.as_bytes()).map_err(|err| {
                    JsError::conversion(format!("invalid HTTP method `{method}`: {err}"))
                })?;
                Ok(())
            },
        )
        .getter("uri", |parts: &request::Parts| {
            JsStr::from(parts.uri.as_str())
        })
        .setter(
            "uri",
            |parts: &mut request::Parts, uri: JsStr| -> Result<(), JsError> {
                parts.uri = uri.as_str().parse::<Uri>().map_err(|err| {
                    JsError::conversion(format!("invalid HTTP URI `{uri}`: {err}"))
                })?;
                Ok(())
            },
        )
        .build()
}

/// Wrap one HTTP request head in its default native-object class.
pub fn request_host(
    parts: request::Parts,
) -> (JsHostObject<request::Parts>, JsHostHandle<request::Parts>) {
    request_host_class().bind(parts)
}

/// Build the reusable native-object class used for HTTP responses.
pub fn response_host_class() -> JsHostClass<response::Parts> {
    http_message_class()
        .getter("status", |parts: &response::Parts| parts.status.as_u16())
        .setter(
            "status",
            |parts: &mut response::Parts, status: u16| -> Result<(), JsError> {
                parts.status = StatusCode::from_u16(status).map_err(|err| {
                    JsError::conversion(format!("invalid HTTP status `{status}`: {err}"))
                })?;
                Ok(())
            },
        )
        .build()
}

/// Wrap one HTTP response head in its default native-object class.
pub fn response_host(
    parts: response::Parts,
) -> (JsHostObject<response::Parts>, JsHostHandle<response::Parts>) {
    response_host_class().bind(parts)
}
