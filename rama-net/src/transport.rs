//! transport net logic
//!
//! See [`TransportContext`] for the centerpiece of this module.

use crate::http::RequestContext;
use crate::{Protocol, address::Authority};
use rama_core::error::OpaqueError;
use rama_core::extensions::ExtensionsRef;
use rama_http_types::request::Parts;
use rama_http_types::{Request, Version};

#[derive(Debug, Clone, PartialEq, Eq)]
/// The context as relevant to the transport layer,
/// often used when operating on Tcp/Udp/Tls.
pub struct TransportContext {
    /// the protocol used on the transport layer. One of the infamous two.
    pub protocol: TransportProtocol,

    /// The [`Protocol`] of the application layer, if known.
    pub app_protocol: Option<Protocol>,

    /// The [`Version`] if the application layer is http.
    pub http_version: Option<Version>,

    /// The authority of the target,
    /// from where this comes depends on the kind of
    /// request it originates from.
    pub authority: Authority,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// The protocol used for the transport layer.
pub enum TransportProtocol {
    /// The `tcp` protocol.
    Tcp,
    /// The `udp` protocol.
    Udp,
}

/// Utility trait to support trait bounds where you wish
/// to turn combined types into a [`TransportContext`],
/// not expressible with [`Into`].
///
/// e.g. `&Request: Into<TransportContext>` would not work if it needs also [`Context`] and be a ref.
pub trait TryRefIntoTransportContext {
    /// The error that can happen when trying to turn the self reference into the TransportContext.
    type Error;

    /// Try to turn the reference to self within the given context into the TransportContext.
    fn try_ref_into_transport_ctx(&self) -> Result<TransportContext, Self::Error>;
}

impl TryFrom<&Parts> for TransportContext {
    type Error = OpaqueError;

    fn try_from(parts: &Parts) -> Result<Self, Self::Error> {
        Ok(
            if let Some(req_ctx) = parts.extensions().get::<RequestContext>() {
                req_ctx.into()
            } else {
                let req_ctx = RequestContext::try_from(parts)?;
                req_ctx.into()
            },
        )
    }
}

impl<Body> TryFrom<&Request<Body>> for TransportContext {
    type Error = OpaqueError;

    fn try_from(req: &Request<Body>) -> Result<Self, Self::Error> {
        Ok(
            if let Some(req_ctx) = req.extensions().get::<RequestContext>() {
                req_ctx.into()
            } else {
                let req_ctx = RequestContext::try_from(req)?;
                req_ctx.into()
            },
        )
    }
}
