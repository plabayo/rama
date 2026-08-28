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
//! according to the rules for each form. Most are HTTP-context; protocol
//! gateways can use [`Uri::write_absolute_form_with_overrides`] to translate
//! a scheme or port without reconstructing the URI themselves.

use super::{Uri, UriInner};
use crate::{Protocol, address::OptPort};

use rama_core::bytes::BytesMut;

/// Error returned when a wire-form contract can't be honoured.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WireError {
    /// The URI is the HTTP asterisk-form (`*`), but the requested wire
    /// form requires a richer URI (`write_http_origin_form` / `_absolute_form`
    /// / `_authority_form`, or the H2 `:scheme` / `:authority` pseudos).
    AsteriskMismatch,
    /// The requested form requires a scheme but the URI has none.
    NoScheme,
    /// The requested form requires an authority but the URI has none.
    NoAuthority,
    /// The supplied text writer rejected output.
    Output,
}

impl core::fmt::Display for WireError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AsteriskMismatch => {
                f.write_str("asterisk-form URI cannot be serialised in the requested wire form")
            }
            Self::NoScheme => f.write_str("requested wire form requires a scheme"),
            Self::NoAuthority => f.write_str("requested wire form requires an authority"),
            Self::Output => f.write_str("URI wire-form output failed"),
        }
    }
}

impl core::error::Error for WireError {}

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
        if let Some(authority) = self.authority() {
            buf.extend_from_slice(b"//");
            let result = authority.write_address_with_port(&mut BytesMutWriter(buf), self.port());
            debug_assert!(result.is_ok(), "BytesMutWriter is infallible");
        }
        write_path_query(self, buf);
        Ok(())
    }

    /// Write an absolute-form URI while replacing its scheme and authority
    /// port.
    ///
    /// The URI supplies the complete authority, path, and query. The fragment
    /// is omitted. Unlike [`write_http_absolute_form`](Self::write_http_absolute_form),
    /// this protocol-neutral projection preserves userinfo because some URI
    /// schemes, including ICAP, define it as part of the service identity.
    /// An empty path remains empty. [`OptPort::Unset`] omits the port,
    /// [`OptPort::Empty`] emits a trailing `:`, and [`OptPort::Set`] emits its
    /// numeric value.
    pub fn write_absolute_form_with_overrides(
        &self,
        scheme: &Protocol,
        port: OptPort,
        writer: &mut impl core::fmt::Write,
    ) -> Result<(), WireError> {
        if matches!(self.inner, UriInner::Asterisk) {
            return Err(WireError::AsteriskMismatch);
        }
        write_absolute_form(self, scheme, port, writer).map_err(|_error| WireError::Output)
    }

    /// HTTP/1.1 authority-form request-target: `host[:port]`.
    ///
    /// Only used for `CONNECT`. Userinfo, scheme, path, query, and
    /// fragment are all stripped.
    ///
    /// **Wire fidelity**: an [`OptPort::Empty`] port emits a bare trailing `:`
    /// (e.g. `example.com:`), mirroring
    /// the parser. RFC 3986 §3.2.3 grammar permits this; some peers
    /// may reject. Call [`Uri::canonicalize`](Self::canonicalize)
    /// first if you want the empty marker normalized away.
    pub fn write_http_authority_form(&self, buf: &mut BytesMut) -> Result<(), WireError> {
        if matches!(self.inner, UriInner::Asterisk) {
            return Err(WireError::AsteriskMismatch);
        }
        if self.authority().is_none() {
            return Err(WireError::NoAuthority);
        }
        write_host_port(self, buf)?;
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
    ///
    /// **Wire fidelity**: see [`write_http_authority_form`](Self::write_http_authority_form)
    /// for the `OptPort::Empty` round-trip behavior.
    pub fn write_h2_authority(&self, buf: &mut BytesMut) -> Result<(), WireError> {
        if matches!(self.inner, UriInner::Asterisk) {
            return Err(WireError::AsteriskMismatch);
        }
        if self.authority().is_none() {
            return Err(WireError::NoAuthority);
        }
        write_host_port(self, buf)?;
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
///
/// IP-address rendering streams through a `fmt::Write` adapter into
/// `buf` — no `to_string()` allocation per request.
fn write_host_port(uri: &Uri, buf: &mut BytesMut) -> Result<(), WireError> {
    let authority = uri.authority().ok_or(WireError::NoAuthority)?;
    let result = authority.write_address(&mut BytesMutWriter(buf));
    debug_assert!(result.is_ok(), "BytesMutWriter is infallible");
    Ok(())
}

fn write_absolute_form(
    uri: &Uri,
    scheme: &Protocol,
    port: OptPort,
    writer: &mut impl core::fmt::Write,
) -> core::fmt::Result {
    writer.write_str(scheme.as_str())?;
    writer.write_str(":")?;
    if let Some(authority) = uri.authority() {
        writer.write_str("//")?;
        if let Some(value) = authority.userinfo() {
            writer.write_str(value.as_str())?;
            writer.write_str("@")?;
        }
        authority.write_address_with_port(writer, port)?;
    }
    write_path_query_fmt(uri, writer)
}

/// [`fmt::Write`] adapter that pushes formatted bytes straight into a
/// [`BytesMut`]. Used by [`write_host_port`] to stream `Ipv4Addr` /
/// `Ipv6Addr` Display output into the request buffer with no
/// intermediate `String`.
struct BytesMutWriter<'a>(&'a mut BytesMut);

impl core::fmt::Write for BytesMutWriter<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.0.extend_from_slice(s.as_bytes());
        Ok(())
    }
}

/// Write `path[?query]` to `buf`. Empty path is normalised to `/`.
/// Fragment is intentionally skipped (HTTP forbids it in request-targets).
fn write_path_query(uri: &Uri, buf: &mut BytesMut) {
    if let Some(path) = uri.path().filter(|p| !p.is_empty()) {
        path.write_encoded_to(buf);
    } else {
        buf.extend_from_slice(b"/");
    }
    if let Some(q) = uri.query() {
        buf.extend_from_slice(b"?");
        q.write_encoded_to(buf);
    }
}

fn write_path_query_fmt(uri: &Uri, writer: &mut impl core::fmt::Write) -> core::fmt::Result {
    if let Some(path) = uri.path().filter(|path| !path.is_empty()) {
        writer.write_fmt(format_args!("{path}"))?;
    }
    if let Some(query) = uri.query() {
        writer.write_str("?")?;
        writer.write_fmt(format_args!("{query}"))?;
    }
    Ok(())
}
