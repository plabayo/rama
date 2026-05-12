use std::borrow::Cow;

use ahash::{HashMap, HashMapExt as _};
use rama_core::{
    Service,
    error::{BoxError, ErrorExt, extra::OpaqueError},
};
use rama_utils::str::arcstr::arcstr;
use serde::{Serialize, de::DeserializeOwned};

use crate::{XpcError, XpcMessage, xpc_serde::from_xpc_message};

mod raw_adapter;
mod typed_adapter;

use self::{raw_adapter::RawAdapter, typed_adapter::TypedAdapter};

// Reply key for Xpc router handler
const RESULT_KEY: &str = "$result";

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
/// An optional fallback service handles any selector that has no registered
/// route.  Without a fallback, unknown selectors are silently ignored (returning
/// `Ok(None)`).
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
        // Peek at the selector without consuming the message.
        let selector = match &input {
            XpcMessage::Dictionary(map) => match map.get("$selector") {
                Some(XpcMessage::String(s)) => s.as_str(),
                _ => {
                    return Err(BoxError::from(XpcError::InvalidMessage(arcstr!(
                        "XpcMessageRouter: missing or non-string '$selector'"
                    ))));
                }
            },
            _ => {
                return Err(BoxError::from(XpcError::InvalidMessage(arcstr!(
                    "XpcMessageRouter: expected a Dictionary"
                ))));
            }
        };

        if let Some(handler) = self.routes.get(selector) {
            return handler.serve(input).await;
        }

        if let Some(fallback) = &self.fallback {
            return fallback.serve(input).await;
        }

        Err(OpaqueError::from_static_str(
            "XpcMessageRouter: no matching router found and no fallback defined",
        )
        .into_box_error())
    }
}

/// Extract and deserialize the `$result` field from a router reply.
///
/// Used on the client side after [`crate::XpcConnection::request_selector`] to decode
/// the reply returned by a typed server handler.
pub fn extract_result<T: DeserializeOwned>(reply: XpcMessage) -> Result<T, XpcError> {
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
