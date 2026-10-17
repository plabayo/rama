//! Reusable CLI [`Service`]s.
//!
//! These services are used by rama's binary
//! distribution and that can be added to your own rama-driven CLI application as well.
//!
//! [`Service`]: crate::Service

pub mod echo;
pub mod fs;
pub mod geo;
pub mod http_security;
pub mod ip;

use crate::{
    cli::ForwardKind,
    combinators::Either7,
    http::{
        headers::forwarded::{
            CFConnectingIp, ClientIp, TrueClientIp, XClientIp, XForwardedFor, XRealIp,
        },
        layer::forwarded::GetForwardedHeaderLayer,
    },
};

/// The HTTP/3 half of a service pair built for both TCP and QUIC.
///
/// With the `quic` feature this is a [`Service`] for accepted QUIC connections;
/// without it, it carries no bound, so the TCP half can be built from one code path.
#[cfg(feature = "quic")]
trait MaybeHttp3Service:
    crate::Service<crate::quic::Connection, Output = (), Error = std::convert::Infallible>
{
}

#[cfg(feature = "quic")]
impl<S> MaybeHttp3Service for S where
    S: crate::Service<crate::quic::Connection, Output = (), Error = std::convert::Infallible>
{
}

#[cfg(not(feature = "quic"))]
trait MaybeHttp3Service {}

#[cfg(not(feature = "quic"))]
impl<S> MaybeHttp3Service for S {}

/// The forwarded-header extraction layer selected by a [`ForwardKind`].
///
/// `None` means no extraction: the default, and `HaProxy` (which forwards at
/// the transport layer instead).
type HttpForwardedLayer = Option<
    Either7<
        GetForwardedHeaderLayer,
        GetForwardedHeaderLayer<XForwardedFor>,
        GetForwardedHeaderLayer<XClientIp>,
        GetForwardedHeaderLayer<ClientIp>,
        GetForwardedHeaderLayer<XRealIp>,
        GetForwardedHeaderLayer<CFConnectingIp>,
        GetForwardedHeaderLayer<TrueClientIp>,
    >,
>;

/// Build the HTTP forwarded-header extraction layer selected by `forward`,
/// shared by the echo and fs CLI services.
pub(super) fn http_forwarded_layer(forward: Option<&ForwardKind>) -> HttpForwardedLayer {
    match forward {
        None | Some(ForwardKind::HaProxy) => None,
        Some(ForwardKind::Forwarded) => Some(Either7::A(GetForwardedHeaderLayer::forwarded())),
        Some(ForwardKind::XForwardedFor) => {
            Some(Either7::B(GetForwardedHeaderLayer::x_forwarded_for()))
        }
        Some(ForwardKind::XClientIp) => {
            Some(Either7::C(GetForwardedHeaderLayer::<XClientIp>::new()))
        }
        Some(ForwardKind::ClientIp) => Some(Either7::D(GetForwardedHeaderLayer::<ClientIp>::new())),
        Some(ForwardKind::XRealIp) => Some(Either7::E(GetForwardedHeaderLayer::<XRealIp>::new())),
        Some(ForwardKind::CFConnectingIp) => {
            Some(Either7::F(GetForwardedHeaderLayer::<CFConnectingIp>::new()))
        }
        Some(ForwardKind::TrueClientIp) => {
            Some(Either7::G(GetForwardedHeaderLayer::<TrueClientIp>::new()))
        }
    }
}
