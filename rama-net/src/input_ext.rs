//! Small, single-concern accessor traits for reading routing/transport
//! properties off a service input (an http request, a connect target, …).
//!
//! Each concern (authority, protocol, http version, transport) is its own small
//! trait, so a caller reads exactly the piece it needs instead of building a
//! combined context up front.
//!
//! Design (matching [`ClientIp`](crate::ClientIp)): each *resolution* trait has
//! no [`ExtensionsRef`](rama_core::extensions::ExtensionsRef) bound and is never
//! blanket-derived from another trait — every input type opts in with the
//! resolution that fits it (the http `Request`/`Parts` impls in `rama-http-types`
//! walk the uri → `ProxyTarget` → TLS SNI → `Forwarded` → `Host` fallback chain;
//! a transport target resolves its authority directly). The only blanket impls
//! are the trivial reference-forwarding ones and the composed
//! [`TransportAddressInputExt`], whose method is purely derived.
//!
//! The return type *is* the fallibility contract: an `Option` may be absent (a
//! caller that requires it does `.ok_or_else(|| …)?` with its own error);
//! [`transport_protocol`](TransportProtocolInputExt::transport_protocol) is
//! always known, so it returns a bare value.
//!
//! Each resolution trait also carries **default methods** built on its one
//! required accessor (e.g. [`AuthorityInputExt::host_as_domain`]), so callers
//! get ergonomic projections without re-writing the same closure chains.

use crate::Protocol;
use crate::address::{Domain, Host, HostWithOptPort, HostWithPort};
use crate::http::Version;
use crate::transport::TransportProtocol;
use crate::uri::Uri;

/// Read the [`Uri`] of a service input that carries one.
///
/// Unlike the other `*InputExt` traits (which return an `Option` because they
/// *resolve* a property that may be absent), this is a structural **capability**:
/// a type implements it only when it always has a URI, so `uri()` returns a
/// `&Uri` directly. Plenty of inputs besides http requests carry a URI (a bare
/// [`Uri`], a redirect target, a url-keyed config, …), which is why this lives
/// next to the http request impls rather than being tied to them.
///
/// Note: a `UriInputExt` is **not** automatically an [`AuthorityInputExt`] /
/// [`ProtocolInputExt`] — an http request, for instance, resolves its authority
/// from more than just its URI (proxy target, TLS SNI, `Forwarded`, `Host`), so
/// those impls are deliberately per-type rather than blanket-derived from here.
pub trait UriInputExt {
    /// The [`Uri`] this input carries.
    fn uri(&self) -> &Uri;
}

impl UriInputExt for Uri {
    fn uri(&self) -> &Uri {
        self
    }
}

/// Read the routing **authority** (`host[:port]`) of a service input.
///
/// This is the HTTP routing authority — the `:authority` pseudo-header / `Host`
/// header target — so it is a [`HostWithOptPort`], **not** the RFC-3986
/// [`Authority`](crate::address::Authority) type (userinfo is never used for
/// routing). Returns `None` when no authority can be resolved.
pub trait AuthorityInputExt {
    /// The routing authority (`host[:port]`), or `None` if none is resolvable.
    fn authority(&self) -> Option<HostWithOptPort>;

    /// The authority [`Host`], dropping any port.
    fn host(&self) -> Option<Host> {
        self.authority().map(|a| a.host)
    }

    /// The authority host as a [`Domain`], or `None` if absent or not a domain
    /// (e.g. an IP literal).
    fn host_as_domain(&self) -> Option<Domain> {
        self.authority().and_then(|a| a.host.try_into_domain().ok())
    }

    /// The authority port, if one is set explicitly.
    fn port(&self) -> Option<u16> {
        self.authority().and_then(|a| a.port_u16())
    }
}

impl<T: AuthorityInputExt + ?Sized> AuthorityInputExt for &T {
    fn authority(&self) -> Option<HostWithOptPort> {
        (**self).authority()
    }
}

/// Read the application-layer [`Protocol`] (scheme) of a service input.
pub trait ProtocolInputExt {
    /// The application protocol, or `None` if it can't be determined.
    fn protocol(&self) -> Option<Protocol>;

    /// The default port of the resolved [`Protocol`] (e.g. 443 for HTTPS), or
    /// `None` if the protocol is unknown or portless.
    fn protocol_default_port(&self) -> Option<u16> {
        self.protocol().and_then(|p| p.default_port())
    }
}

impl<T: ProtocolInputExt + ?Sized> ProtocolInputExt for &T {
    fn protocol(&self) -> Option<Protocol> {
        (**self).protocol()
    }
}

/// Read the negotiated HTTP [`Version`] of a service input.
///
/// Explicitly HTTP-named: it is `None` for non-HTTP inputs (e.g. a raw
/// transport target).
pub trait HttpVersionInputExt {
    /// The HTTP version, or `None` for non-HTTP inputs.
    fn http_version(&self) -> Option<Version>;
}

impl<T: HttpVersionInputExt + ?Sized> HttpVersionInputExt for &T {
    fn http_version(&self) -> Option<Version> {
        (**self).http_version()
    }
}

/// Read the transport-layer [`TransportProtocol`] (TCP/UDP) of a service input.
///
/// Always known, so this is infallible.
pub trait TransportProtocolInputExt {
    /// The transport protocol (TCP or UDP).
    fn transport_protocol(&self) -> TransportProtocol;
}

impl<T: TransportProtocolInputExt + ?Sized> TransportProtocolInputExt for &T {
    fn transport_protocol(&self) -> TransportProtocol {
        (**self).transport_protocol()
    }
}

mod private {
    use super::{AuthorityInputExt, ProtocolInputExt};

    /// Seals [`TransportAddressInputExt`](super::TransportAddressInputExt): it is
    /// purely derived from [`AuthorityInputExt`] + [`ProtocolInputExt`], so it must
    /// never be implemented by hand.
    pub trait Sealed {}
    impl<T: AuthorityInputExt + ProtocolInputExt + ?Sized> Sealed for T {}
}

/// Resolve the **transport address** (`host:port`) to connect to: the routing
/// [`authority`](AuthorityInputExt::authority) with the application
/// [`protocol`](ProtocolInputExt::protocol)'s default port as the port fallback.
///
/// Auto-implemented (and sealed) for every input that is both an
/// [`AuthorityInputExt`] and a [`ProtocolInputExt`]; it yields the typed
/// `host:port` a connector needs, and is never implemented by hand.
pub trait TransportAddressInputExt: AuthorityInputExt + ProtocolInputExt + private::Sealed {
    /// The `host:port` to connect to: the authority's port if set, else the
    /// protocol's default port. `None` when no host (or no port) resolves.
    fn host_with_port(&self) -> Option<HostWithPort> {
        self.authority()
            .and_then(|a| a.into_host_with_port(self.protocol_default_port()))
    }

    /// Like [`host_with_port`](Self::host_with_port) but with `default_port` as
    /// the ultimate fallback (authority port → protocol default → `default_port`),
    /// so it yields `Some` whenever an authority resolves at all.
    fn host_with_port_or(&self, default_port: u16) -> Option<HostWithPort> {
        self.authority()
            .map(|a| a.into_host_with_port_or(self.protocol_default_port().unwrap_or(default_port)))
    }
}

impl<T: AuthorityInputExt + ProtocolInputExt + ?Sized> TransportAddressInputExt for T {}
