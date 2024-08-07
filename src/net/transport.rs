//! transport net logic
//!
//! See [`TransportContext`] for the centerpiece of this module.

use http::Version;

use crate::{
    error::OpaqueError,
    http::RequestContext,
    net::{address::Authority, Protocol},
    service::Context,
};

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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// The protocol used for the transport layer.
pub enum TransportProtocol {
    /// The `tcp` protocol.
    Tcp,
    /// The `udp` protocol.
    Udp,
}

impl From<RequestContext> for TransportContext {
    fn from(value: RequestContext) -> Self {
        Self {
            protocol: if value.http_version == Version::HTTP_3 {
                TransportProtocol::Udp
            } else {
                TransportProtocol::Tcp
            },
            app_protocol: Some(value.protocol),
            http_version: Some(value.http_version),
            authority: value.authority,
        }
    }
}

impl From<&RequestContext> for TransportContext {
    fn from(value: &RequestContext) -> Self {
        Self {
            protocol: if value.http_version == Version::HTTP_3 {
                TransportProtocol::Udp
            } else {
                TransportProtocol::Tcp
            },
            app_protocol: Some(value.protocol.clone()),
            http_version: Some(value.http_version),
            authority: value.authority.clone(),
        }
    }
}

impl<State, Body> TryFrom<(&Context<State>, &crate::http::Request<Body>)> for TransportContext {
    type Error = OpaqueError;

    fn try_from(
        (ctx, req): (&Context<State>, &crate::http::Request<Body>),
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

impl<State> TryFrom<(&Context<State>, &crate::http::dep::http::request::Parts)>
    for TransportContext
{
    type Error = OpaqueError;

    fn try_from(
        (ctx, parts): (&Context<State>, &crate::http::dep::http::request::Parts),
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

impl<State, Body> TryRefIntoTransportContext<State> for crate::http::Request<Body> {
    type Error = OpaqueError;

    fn try_ref_into_transport_ctx(
        &self,
        ctx: &Context<State>,
    ) -> Result<TransportContext, Self::Error> {
        (ctx, self).try_into()
    }
}

impl<State> TryRefIntoTransportContext<State> for crate::http::dep::http::request::Parts {
    type Error = OpaqueError;

    fn try_ref_into_transport_ctx(
        &self,
        ctx: &Context<State>,
    ) -> Result<TransportContext, Self::Error> {
        (ctx, self).try_into()
    }
}
