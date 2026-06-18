//! Small, single-concern accessor traits for reading routing/transport
//! properties off a service input (an http request, a connect target, …).
//!
//! These replace the monolithic `RequestContext`/`TransportContext`: instead of
//! a fallible build that resolves protocol + authority + version up front, each
//! concern is its own trait and most callers want exactly one piece.
//!
//! Design (matching [`ClientIp`](crate::ClientIp)): each trait is **plain** —
//! no [`ExtensionsRef`](rama_core::extensions::ExtensionsRef) bound and no
//! blanket impl — so every input type opts in with the resolution that fits it
//! (the http `Request`/`Parts` impls in `rama-http-types` walk the
//! uri → `ProxyTarget` → TLS SNI → `Forwarded` → `Host` fallback chain; a
//! transport target resolves its authority directly).
//!
//! The return type *is* the fallibility contract: an `Option` may be absent (a
//! caller that requires it does `.ok_or_else(|| …)?` with its own error);
//! [`transport_protocol`](TransportProtocolInputExt::transport_protocol) is
//! always known, so it returns a bare value.

use crate::Protocol;
use crate::address::HostWithOptPort;
use crate::http::Version;
use crate::transport::TransportProtocol;

/// Read the routing **authority** (`host[:port]`) of a service input.
///
/// This is the HTTP routing authority — the `:authority` pseudo-header / `Host`
/// header target — so it is a [`HostWithOptPort`], **not** the RFC-3986
/// [`Authority`](crate::address::Authority) type (userinfo is never used for
/// routing). Returns `None` when no authority can be resolved.
pub trait AuthorityInputExt {
    /// The routing authority (`host[:port]`), or `None` if none is resolvable.
    fn authority(&self) -> Option<HostWithOptPort>;
}

/// Read the application-layer [`Protocol`] (scheme) of a service input.
pub trait ProtocolInputExt {
    /// The application protocol, or `None` if it can't be determined.
    fn protocol(&self) -> Option<Protocol>;
}

/// Read the negotiated HTTP [`Version`] of a service input.
///
/// Explicitly HTTP-named: it is `None` for non-HTTP inputs (e.g. a raw
/// transport target).
pub trait HttpVersionInputExt {
    /// The HTTP version, or `None` for non-HTTP inputs.
    fn http_version(&self) -> Option<Version>;
}

/// Read the transport-layer [`TransportProtocol`] (TCP/UDP) of a service input.
///
/// Always known, so this is infallible.
pub trait TransportProtocolInputExt {
    /// The transport protocol (TCP or UDP).
    fn transport_protocol(&self) -> TransportProtocol;
}
