use std::borrow::Cow;

use ahash::{HashMap, HashMapExt as _};
use rama_core::{Service, error::BoxError, telemetry::tracing};
use rama_utils::str::arcstr::arcstr;
use serde::{Serialize, de::DeserializeOwned};

use crate::{XpcError, XpcMessage, xpc_serde::from_xpc_message};

mod raw_adapter;
mod typed_adapter;

use self::{raw_adapter::RawAdapter, typed_adapter::TypedAdapter};

// Reply key for Xpc router handler
const RESULT_KEY: &str = "$result";
// Reply key for a structured error envelope produced instead of a `$result`.
const ERROR_KEY: &str = "$error";

/// Error code for a selector with no registered route and no fallback.
pub const ERROR_CODE_UNKNOWN_SELECTOR: i64 = 1;
/// Error code for a message that is not a well-formed call (missing/invalid `$selector`).
pub const ERROR_CODE_INVALID_MESSAGE: i64 = 2;
/// Error code for a registered handler that returned an error.
pub const ERROR_CODE_HANDLER_FAILED: i64 = 3;

/// Build an error reply `{"$error": {"code": <code>, "message": <message>}}`,
/// returned in place of a `$result` so a failed call gets a definite reply
/// instead of a hang. [`extract_result`] surfaces it as [`XpcError::Remote`].
pub fn error_envelope(code: i64, message: impl Into<String>) -> XpcMessage {
    let mut inner = std::collections::BTreeMap::new();
    inner.insert("code".to_owned(), XpcMessage::Int64(code));
    inner.insert("message".to_owned(), XpcMessage::String(message.into()));
    let mut outer = std::collections::BTreeMap::new();
    outer.insert(ERROR_KEY.to_owned(), XpcMessage::Dictionary(inner));
    XpcMessage::Dictionary(outer)
}

/// `Some((code, message))` when `reply` is an `{"$error": …}` envelope.
fn parse_error_envelope(reply: &XpcMessage) -> Option<(i64, String)> {
    let XpcMessage::Dictionary(map) = reply else {
        return None;
    };
    let XpcMessage::Dictionary(inner) = map.get(ERROR_KEY)? else {
        return None;
    };
    let code = match inner.get("code") {
        Some(XpcMessage::Int64(c)) => *c,
        Some(XpcMessage::Uint64(c)) => i64::try_from(*c).unwrap_or(i64::MAX),
        _ => 0,
    };
    let message = match inner.get("message") {
        Some(XpcMessage::String(s)) => s.clone(),
        _ => String::new(),
    };
    Some((code, message))
}

/// A type-erased, clone-able service that processes an [`XpcMessage`] and
/// optionally returns a reply [`XpcMessage`].
type BoxedRoute = rama_core::service::BoxService<XpcMessage, Option<XpcMessage>, BoxError>;

/// A selector-based [`XpcMessage`] router.
///
/// `XpcMessageRouter` implements [`Service<XpcMessage>`] and dispatches incoming
/// messages to registered handlers based on the `$selector` key in the decoded
/// [`crate::XpcCall`].
///
/// # Wire format
///
/// Incoming messages must follow the NSXPC-inspired format:
///
/// ```json
/// { "$selector": "methodName:withReply:", "$arguments": [ … ] }
/// ```
///
/// # Handler types
///
/// Two kinds of handlers can be registered:
///
/// - **Typed handlers** (via [`with_typed_route`](Self::with_typed_route) /
///   [`set_typed_route`](Self::set_typed_route)) — accept a [`DeserializeOwned`]
///   request type and return a [`Serialize`] response.  The router deserializes
///   the first `$arguments` entry as `Req` and wraps the result in
///   `{"$result": <value>}`.
///
/// - **Raw handlers** (via [`with_route`](Self::with_route) /
///   [`set_route`](Self::set_route)) — accept the raw [`XpcMessage`] (the full
///   call dictionary) and return `Option<XpcMessage>`.  The router does not
///   modify the reply.
///
/// # Fallback
///
/// An optional fallback service handles any selector with no registered route.
/// Without one, an unknown or malformed selector resolves to an [`error_envelope`]
/// reply (not an `Err`), so one bad request never tears down the peer connection.
#[derive(Clone)]
pub struct XpcMessageRouter {
    routes: HashMap<Cow<'static, str>, BoxedRoute>,
    fallback: Option<BoxedRoute>,
}

impl std::fmt::Debug for XpcMessageRouter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XpcMessageRouter")
            .field("route_count", &self.routes.len())
            .field("has_fallback", &self.fallback.is_some())
            .finish()
    }
}

impl Default for XpcMessageRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl XpcMessageRouter {
    /// Create a new empty router.
    pub fn new() -> Self {
        Self {
            routes: HashMap::new(),
            fallback: None,
        }
    }

    /// Register a typed handler for `selector`, consuming `self` (builder pattern).
    ///
    /// The service receives a deserialized `Req` (from the first `$arguments`
    /// entry) and its `Res` return value is serialized into `{"$result": <value>}`.
    #[must_use]
    pub fn with_typed_route<Req, Res, S>(
        mut self,
        selector: impl Into<Cow<'static, str>>,
        service: S,
    ) -> Self
    where
        Req: DeserializeOwned + Send + 'static,
        Res: Serialize + Send + 'static,
        S: Service<Req, Output = Res, Error: Into<BoxError>> + 'static,
    {
        self.set_typed_route(selector, service);
        self
    }

    /// Register a typed handler for `selector` in place.
    pub fn set_typed_route<Req, Res, S>(
        &mut self,
        selector: impl Into<Cow<'static, str>>,
        service: S,
    ) -> &mut Self
    where
        Req: DeserializeOwned + Send + 'static,
        Res: Serialize + Send + 'static,
        S: Service<Req, Output = Res, Error: Into<BoxError>> + 'static,
    {
        let boxed = BoxedRoute::new(TypedAdapter::new(service));
        self.routes.insert(selector.into(), boxed);
        self
    }

    /// Register a raw handler for `selector`, consuming `self` (builder pattern).
    ///
    /// The service receives the full incoming [`XpcMessage`] (the whole call
    /// dictionary) and returns `Option<XpcMessage>`.
    #[must_use]
    pub fn with_route<S>(mut self, selector: impl Into<Cow<'static, str>>, service: S) -> Self
    where
        S: Service<XpcMessage, Output = Option<XpcMessage>, Error: Into<BoxError>> + 'static,
    {
        self.set_route(selector, service);
        self
    }

    /// Register a raw handler for `selector` in place.
    pub fn set_route<S>(&mut self, selector: impl Into<Cow<'static, str>>, service: S) -> &mut Self
    where
        S: Service<XpcMessage, Output = Option<XpcMessage>, Error: Into<BoxError>> + 'static,
    {
        let boxed = BoxedRoute::new(RawAdapter(service));
        self.routes.insert(selector.into(), boxed);
        self
    }

    /// Set a fallback service that handles selectors with no registered route,
    /// consuming `self` (builder pattern).
    #[must_use]
    pub fn with_fallback<S>(mut self, service: S) -> Self
    where
        S: Service<XpcMessage, Output = Option<XpcMessage>, Error: Into<BoxError>> + 'static,
    {
        self.set_fallback(service);
        self
    }

    /// Set a fallback service in place.
    pub fn set_fallback<S>(&mut self, service: S) -> &mut Self
    where
        S: Service<XpcMessage, Output = Option<XpcMessage>, Error: Into<BoxError>> + 'static,
    {
        self.fallback = Some(BoxedRoute::new(RawAdapter(service)));
        self
    }

    /// Remove the fallback service.
    #[must_use]
    pub fn without_fallback(mut self) -> Self {
        self.fallback = None;
        self
    }
}

impl Service<XpcMessage> for XpcMessageRouter {
    type Output = Option<XpcMessage>;
    type Error = BoxError;

    async fn serve(&self, input: XpcMessage) -> Result<Self::Output, Self::Error> {
        // Malformed calls answer with an error envelope, never an `Err`.
        let XpcMessage::Dictionary(map) = &input else {
            tracing::warn!("xpc router: message is not a Dictionary");
            return Ok(Some(error_envelope(
                ERROR_CODE_INVALID_MESSAGE,
                "XpcMessageRouter: expected a Dictionary",
            )));
        };
        let Some(XpcMessage::String(selector)) = map.get("$selector") else {
            tracing::warn!("xpc router: missing or non-string '$selector'");
            return Ok(Some(error_envelope(
                ERROR_CODE_INVALID_MESSAGE,
                "XpcMessageRouter: missing or non-string '$selector'",
            )));
        };
        let selector = selector.as_str();

        if let Some(handler) = self.routes.get(selector) {
            tracing::info!(selector, "xpc router dispatching selector");
            return handler.serve(input).await;
        }

        if let Some(fallback) = &self.fallback {
            tracing::warn!(selector, "xpc router using fallback for unknown selector");
            return fallback.serve(input).await;
        }

        tracing::warn!(selector, "xpc router missing selector");
        Ok(Some(error_envelope(
            ERROR_CODE_UNKNOWN_SELECTOR,
            format!("XpcMessageRouter: no route registered for selector '{selector}'"),
        )))
    }
}

/// Extract and deserialize the `$result` field from a router reply.
///
/// Used on the client side after [`crate::XpcConnection::request_selector`] to decode
/// the reply returned by a typed server handler.
pub fn extract_result<T: DeserializeOwned>(reply: XpcMessage) -> Result<T, XpcError> {
    if let Some((code, message)) = parse_error_envelope(&reply) {
        return Err(XpcError::Remote {
            code,
            message: message.into(),
        });
    }
    let XpcMessage::Dictionary(mut map) = reply else {
        return Err(XpcError::InvalidMessage(arcstr!(
            "router reply: expected a Dictionary"
        )));
    };
    let result = map
        .remove(RESULT_KEY)
        .ok_or_else(|| XpcError::InvalidMessage(arcstr!("router reply: missing '$result' key")))?;
    from_xpc_message(result)
}

#[cfg(test)]
mod tests;
