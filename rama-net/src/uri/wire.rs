//! HTTP-context wire writers for [`Uri`].
//!
//! HTTP/1.1 defines four mutually-exclusive request-target forms
//! (RFC 9112 §3.2); HTTP/2 / HTTP/3 split the target across the
//! `:scheme` / `:authority` / `:path` pseudo-headers (RFC 9113 §8.3.1).
//! Each form strips a different subset of URI components — for example,
//! fragments are never on the wire (RFC 9110 §7.1) and userinfo is
//! forbidden in any URI sent inside an HTTP message (RFC 9110 §4.2.4).
//!
//! These writers serialize a [`Uri`] into a caller-provided buffer
//! according to the rules for each form. They're HTTP-context — other
//! URI consumers should use [`Display`](std::fmt::Display) for the
//! canonical full form.

use std::net::IpAddr;

use rama_core::bytes::BytesMut;

use crate::address::HostRef;

use super::{Uri, UriInner};

/// Error returned when a wire-form contract can't be honoured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// The URI is the HTTP asterisk-form (`*`), but the requested wire
    /// form requires a richer URI (`write_http_origin_form` / `_absolute_form`
    /// / `_authority_form`, or the H2 `:scheme` / `:authority` pseudos).
    AsteriskMismatch,
    /// The requested form requires a scheme but the URI has none.
    NoScheme,
    /// The requested form requires an authority but the URI has none.
    NoAuthority,
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AsteriskMismatch => {
                f.write_str("asterisk-form URI cannot be serialised in the requested wire form")
            }
            Self::NoScheme => f.write_str("requested wire form requires a scheme"),
            Self::NoAuthority => f.write_str("requested wire form requires an authority"),
        }
    }
}

impl std::error::Error for WireError {}

impl Uri {
    /// HTTP/1.1 origin-form request-target: `/path[?query]`.
    ///
    /// Used for normal requests to an origin server (the common case).
    /// Empty path is normalised to `/`. Scheme, authority, and fragment
    /// are stripped — origin-form carries only the path-and-query.
    ///
    /// Errors with [`WireError::AsteriskMismatch`] if the URI is `*` —
    /// asterisk-form is its own request-target form (write `*` directly,
    /// it's a one-byte literal).
    pub fn write_http_origin_form(&self, buf: &mut BytesMut) -> Result<(), WireError> {
        if matches!(self.inner, UriInner::Asterisk) {
            return Err(WireError::AsteriskMismatch);
        }
        write_path_query(self, buf);
        Ok(())
    }

    /// HTTP/1.1 absolute-form request-target:
    /// `scheme:[//authority]path[?query]`.
    ///
    /// Used by clients sending through a forward proxy. Userinfo and
    /// fragment are stripped (RFC 9110 §§4.2.4, 7.1).
    pub fn write_http_absolute_form(&self, buf: &mut BytesMut) -> Result<(), WireError> {
        if matches!(self.inner, UriInner::Asterisk) {
            return Err(WireError::AsteriskMismatch);
        }
        let Some(scheme) = self.scheme() else {
            return Err(WireError::NoScheme);
        };
        buf.extend_from_slice(scheme.as_str().as_bytes());
        buf.extend_from_slice(b":");
        if self.authority().is_some() {
            buf.extend_from_slice(b"//");
            write_host_port(self, buf);
        }
        write_path_query(self, buf);
        Ok(())
    }

    /// HTTP/1.1 authority-form request-target: `host[:port]`.
    ///
    /// Only used for `CONNECT`. Userinfo, scheme, path, query, and
    /// fragment are all stripped.
    pub fn write_http_authority_form(&self, buf: &mut BytesMut) -> Result<(), WireError> {
        if matches!(self.inner, UriInner::Asterisk) {
            return Err(WireError::AsteriskMismatch);
        }
        if self.authority().is_none() {
            return Err(WireError::NoAuthority);
        }
        write_host_port(self, buf);
        Ok(())
    }

    /// HTTP/2 / HTTP/3 `:path` pseudo-header content.
    ///
    /// Same shape as origin-form (empty path → `/`), with one exception:
    /// asterisk-form requests carry `*` in `:path` per RFC 9113 §8.3.1,
    /// so this method writes `*` for an asterisk URI rather than
    /// erroring.
    pub fn write_h2_path(&self, buf: &mut BytesMut) {
        if matches!(self.inner, UriInner::Asterisk) {
            buf.extend_from_slice(b"*");
            return;
        }
        write_path_query(self, buf);
    }

    /// HTTP/2 / HTTP/3 `:authority` pseudo-header content: `host[:port]`.
    ///
    /// Userinfo is omitted per RFC 9113 §8.3.1.
    pub fn write_h2_authority(&self, buf: &mut BytesMut) -> Result<(), WireError> {
        if matches!(self.inner, UriInner::Asterisk) {
            return Err(WireError::AsteriskMismatch);
        }
        if self.authority().is_none() {
            return Err(WireError::NoAuthority);
        }
        write_host_port(self, buf);
        Ok(())
    }

    /// HTTP/2 / HTTP/3 `:scheme` pseudo-header content (e.g. `https`).
    pub fn write_h2_scheme(&self, buf: &mut BytesMut) -> Result<(), WireError> {
        if matches!(self.inner, UriInner::Asterisk) {
            return Err(WireError::AsteriskMismatch);
        }
        let Some(scheme) = self.scheme() else {
            return Err(WireError::NoScheme);
        };
        buf.extend_from_slice(scheme.as_str().as_bytes());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Write `host[:port]` to `buf`. IPv6 addresses are bracketed per
/// RFC 3986 §3.2.2 (`IP-literal = "[" IPv6address "]"`). Userinfo is
/// intentionally skipped (HTTP messages MUST NOT carry it).
fn write_host_port(uri: &Uri, buf: &mut BytesMut) {
    if let Some(host) = uri.host() {
        match host {
            HostRef::Name(d) => buf.extend_from_slice(d.as_bytes()),
            HostRef::Address(IpAddr::V4(v4)) => {
                // `IpAddr::to_string` allocates a small `String` (max 15
                // bytes for IPv4). HTTP wire writing happens once per
                // request — fine.
                buf.extend_from_slice(v4.to_string().as_bytes());
            }
            HostRef::Address(IpAddr::V6(v6)) => {
                buf.extend_from_slice(b"[");
                buf.extend_from_slice(v6.to_string().as_bytes());
                buf.extend_from_slice(b"]");
            }
            HostRef::Uninterpreted(host) => {
                // Wire-fidelity: emit the preserved bytes exactly as
                // received. `UninterpretedHost` stores bracketed
                // IP-literal bodies without the surrounding `[...]`,
                // so we add them back here to match URI authority syntax.
                if host.is_bracketed() {
                    buf.extend_from_slice(b"[");
                    buf.extend_from_slice(host.as_bytes());
                    buf.extend_from_slice(b"]");
                } else {
                    buf.extend_from_slice(host.as_bytes());
                }
            }
        }
    }
    if let Some(port) = uri.port() {
        buf.extend_from_slice(b":");
        let mut itoa = itoa::Buffer::new();
        buf.extend_from_slice(itoa.format(port).as_bytes());
    }
}

/// Write `path[?query]` to `buf`. Empty path is normalised to `/`.
/// Fragment is intentionally skipped (HTTP forbids it in request-targets).
fn write_path_query(uri: &Uri, buf: &mut BytesMut) {
    let path_bytes = uri.path().map_or(&[][..], |p| p.as_bytes());
    if path_bytes.is_empty() {
        buf.extend_from_slice(b"/");
    } else {
        buf.extend_from_slice(path_bytes);
    }
    if let Some(q) = uri.query() {
        buf.extend_from_slice(b"?");
        buf.extend_from_slice(q.as_bytes());
    }
}
