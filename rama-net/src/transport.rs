//! transport net logic
//!
//! See [`TransportContext`] for the centerpiece of this module.

use crate::Protocol;
use crate::address::{HostWithOptPort, HostWithPort};

#[derive(Debug, Clone, PartialEq, Eq)]
/// The context as relevant to the transport layer,
/// often used when operating on Tcp/Udp/Tls.
pub struct TransportContext {
    /// the protocol used on the transport layer. One of the infamous two.
    pub protocol: TransportProtocol,

    /// The [`Protocol`] of the application layer, if known.
    pub app_protocol: Option<Protocol>,

    /// The authority of the target,
    /// from where this comes depends on the kind of
    /// request it originates from.
    pub authority: HostWithOptPort,
}

impl TransportContext {
    #[must_use]
    pub fn host_with_port(&self) -> Option<HostWithPort> {
        let port = self
            .authority
            .port
            .as_u16()
            .or_else(|| self.app_protocol.as_ref().and_then(|p| p.default_port()))?;
        let host = self.authority.host.clone();
        Some(HostWithPort { host, port })
    }
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
/// e.g. `&Request: Into<TransportContext>` would not work if it needs also [`Extensions`] and be a ref.
///
/// [`Extensions`]: rama_core::extensions::Extensions
pub trait TryRefIntoTransportContext {
    /// The error that can happen when trying to turn the self reference into the TransportContext.
    type Error;

    /// Try to turn the reference to self within the given context into the TransportContext.
    fn try_ref_into_transport_ctx(&self) -> Result<TransportContext, Self::Error>;
}
