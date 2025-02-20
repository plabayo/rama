//! transport net logic
//!
//! See [`TransportContext`] for the centerpiece of this module.

use crate::http::RequestContext;
use crate::{Protocol, address::Authority};
use rama_core::{Context, error::OpaqueError};
use rama_http_types::{Request, Version, dep::http::request::Parts as HttpParts};

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
pub trait TryRefIntoTransportContext<State> {
    /// The error that can happen when trying to turn the self reference into the TransportContext.
    type Error;

    /// Try to turn the reference to self within the given context into the TransportContext.
    fn try_ref_into_transport_ctx(
        &self,
        ctx: &Context<State>,
    ) -> Result<TransportContext, Self::Error>;
}

impl<State, Body> TryFrom<(&Context<State>, &Request<Body>)> for TransportContext {
    type Error = OpaqueError;

    fn try_from(
        (ctx, req): (&Context<State>, &Request<Body>),
    ) -> Result<TransportContext, Self::Error> {
        Ok(match ctx.get::<RequestContext>() {
            Some(req_ctx) => req_ctx.into(),
            None => {
                let req_ctx = RequestContext::try_from((ctx, req))?;
                req_ctx.into()
            }
        })
    }
}

impl<State> TryFrom<(&Context<State>, &HttpParts)> for TransportContext {
    type Error = OpaqueError;

    fn try_from(
        (ctx, parts): (&Context<State>, &HttpParts),
    ) -> Result<TransportContext, Self::Error> {
        Ok(match ctx.get::<RequestContext>() {
            Some(req_ctx) => req_ctx.into(),
            None => {
                let req_ctx = RequestContext::try_from((ctx, parts))?;
                req_ctx.into()
            }
        })
    }
}
