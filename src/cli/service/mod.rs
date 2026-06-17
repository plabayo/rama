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
