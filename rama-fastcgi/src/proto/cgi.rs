//! CGI parameter name constants used in FastCGI `FCGI_PARAMS` and
//! `FCGI_GET_VALUES` records.
//!
//! FastCGI carries name-value pairs whose *meaning* is defined by the CGI
//! specification (RFC 3875 §4) and a set of de-facto extensions popularised
//! by nginx and php-fpm. Both are vendored under `rama-fastcgi/specifications/`.
//!
//! Use these constants instead of `Bytes::from_static(b"REQUEST_METHOD")`
//! literals: they're zero-cost (each is a `const` [`Bytes`] backed by a
//! `&'static [u8]`), they catch typos at compile time, and they keep the
//! spec reference one click away in IDE hover-docs.
//!
//! Examples:
//!
//! ```
//! use rama_fastcgi::proto::cgi;
//! use rama_fastcgi::FastCgiClientRequest;
//! use rama_core::bytes::Bytes;
//!
//! let mut req = FastCgiClientRequest::new(vec![]);
//! req.push_param(cgi::REQUEST_METHOD, Bytes::from_static(b"GET"));
//! req.push_param(cgi::SCRIPT_FILENAME, "/var/www/index.php");
//! ```

use rama_core::bytes::Bytes;

// ── RFC 3875 §4: CGI/1.1 standard request meta-variables ──────────────────

/// `AUTH_TYPE` — the protocol-specific authentication scheme. RFC 3875 §4.1.1.
pub const AUTH_TYPE: Bytes = Bytes::from_static(b"AUTH_TYPE");
/// `CONTENT_LENGTH` — the size of the request body, in bytes. RFC 3875 §4.1.2.
pub const CONTENT_LENGTH: Bytes = Bytes::from_static(b"CONTENT_LENGTH");
/// `CONTENT_TYPE` — the media type of the request body. RFC 3875 §4.1.3.
pub const CONTENT_TYPE: Bytes = Bytes::from_static(b"CONTENT_TYPE");
/// `GATEWAY_INTERFACE` — the dialect of CGI being used (e.g. `CGI/1.1`).
/// RFC 3875 §4.1.4.
pub const GATEWAY_INTERFACE: Bytes = Bytes::from_static(b"GATEWAY_INTERFACE");
/// `PATH_INFO` — extra path information after the script identifier.
/// RFC 3875 §4.1.5.
pub const PATH_INFO: Bytes = Bytes::from_static(b"PATH_INFO");
/// `PATH_TRANSLATED` — the filesystem-mapped form of `PATH_INFO`.
/// RFC 3875 §4.1.6.
pub const PATH_TRANSLATED: Bytes = Bytes::from_static(b"PATH_TRANSLATED");
/// `QUERY_STRING` — the URL-encoded query component. RFC 3875 §4.1.7.
pub const QUERY_STRING: Bytes = Bytes::from_static(b"QUERY_STRING");
/// `REMOTE_ADDR` — the network address of the client. RFC 3875 §4.1.8.
pub const REMOTE_ADDR: Bytes = Bytes::from_static(b"REMOTE_ADDR");
/// `REMOTE_HOST` — the fully-qualified hostname of the client, when known.
/// RFC 3875 §4.1.9.
pub const REMOTE_HOST: Bytes = Bytes::from_static(b"REMOTE_HOST");
/// `REMOTE_IDENT` — the RFC 1413 ident user, when available. RFC 3875 §4.1.10.
pub const REMOTE_IDENT: Bytes = Bytes::from_static(b"REMOTE_IDENT");
/// `REMOTE_USER` — the authenticated user identity. RFC 3875 §4.1.11.
pub const REMOTE_USER: Bytes = Bytes::from_static(b"REMOTE_USER");
/// `REQUEST_METHOD` — the HTTP method (e.g. `GET`, `POST`). RFC 3875 §4.1.12.
pub const REQUEST_METHOD: Bytes = Bytes::from_static(b"REQUEST_METHOD");
/// `SCRIPT_NAME` — the URL path component identifying the script.
/// RFC 3875 §4.1.13.
pub const SCRIPT_NAME: Bytes = Bytes::from_static(b"SCRIPT_NAME");
/// `SERVER_NAME` — the hostname/IP the server is using for self-reference.
/// RFC 3875 §4.1.14.
pub const SERVER_NAME: Bytes = Bytes::from_static(b"SERVER_NAME");
/// `SERVER_PORT` — the TCP port on which the request was received.
/// RFC 3875 §4.1.15.
pub const SERVER_PORT: Bytes = Bytes::from_static(b"SERVER_PORT");
/// `SERVER_PROTOCOL` — the name/version of the protocol carrying the request
/// (`HTTP/1.1`, `HTTP/2`, …). RFC 3875 §4.1.16.
pub const SERVER_PROTOCOL: Bytes = Bytes::from_static(b"SERVER_PROTOCOL");
/// `SERVER_SOFTWARE` — name and version of the gateway. RFC 3875 §4.1.17.
pub const SERVER_SOFTWARE: Bytes = Bytes::from_static(b"SERVER_SOFTWARE");

// ── Spec-defined values for common CGI variables ──────────────────────────

/// Canonical value of [`GATEWAY_INTERFACE`] when speaking CGI/1.1, which is
/// what nginx and php-fpm hard-require.
pub const GATEWAY_INTERFACE_CGI_1_1: Bytes = Bytes::from_static(b"CGI/1.1");

/// Value of [`REDIRECT_STATUS`] meaning "no preceding redirect / safe to run".
/// php-fpm with `--enable-force-cgi-redirect` (the upstream default) refuses
/// to dispatch when this isn't set; `"200"` is the conventional value.
pub const REDIRECT_STATUS_OK: Bytes = Bytes::from_static(b"200");

/// Value of [`HTTPS`] for a TLS-protected request. Frameworks (Laravel,
/// WordPress, …) read this for URL generation.
pub const HTTPS_ON: Bytes = Bytes::from_static(b"on");

// ── nginx / php-fpm de-facto extensions ───────────────────────────────────

/// `SCRIPT_FILENAME` — absolute filesystem path of the script (the
/// front-controller). **Required by php-fpm** — it refuses to run without
/// one. Not defined by RFC 3875.
pub const SCRIPT_FILENAME: Bytes = Bytes::from_static(b"SCRIPT_FILENAME");
/// `DOCUMENT_ROOT` — absolute filesystem path of the directory containing
/// the script. Nginx convention; php-fpm reads it via `$_SERVER`.
pub const DOCUMENT_ROOT: Bytes = Bytes::from_static(b"DOCUMENT_ROOT");
/// `DOCUMENT_URI` — the URL path that addressed the resource (after
/// rewrites). Nginx convention.
pub const DOCUMENT_URI: Bytes = Bytes::from_static(b"DOCUMENT_URI");
/// `REQUEST_URI` — the raw URI (path + query) the server received,
/// pre-rewrite. Nginx convention; frameworks like Laravel/Symfony read this
/// for routing.
pub const REQUEST_URI: Bytes = Bytes::from_static(b"REQUEST_URI");
/// `REQUEST_SCHEME` — `http` or `https`. Nginx convention.
pub const REQUEST_SCHEME: Bytes = Bytes::from_static(b"REQUEST_SCHEME");
/// `HTTPS` — set to `on` when the connection is TLS-protected. Read by many
/// PHP frameworks for URL generation. Nginx convention.
pub const HTTPS: Bytes = Bytes::from_static(b"HTTPS");
/// `REDIRECT_STATUS` — required by php-fpm when PHP was built with
/// `--enable-force-cgi-redirect` (the upstream default). Typically `200`.
pub const REDIRECT_STATUS: Bytes = Bytes::from_static(b"REDIRECT_STATUS");
/// `REMOTE_PORT` — the TCP source port of the client. Nginx convention.
pub const REMOTE_PORT: Bytes = Bytes::from_static(b"REMOTE_PORT");
/// `SERVER_ADDR` — the IP address the server bound to. Nginx convention.
pub const SERVER_ADDR: Bytes = Bytes::from_static(b"SERVER_ADDR");

// ── FastCGI management names (§4.1) ───────────────────────────────────────

/// `FCGI_MAX_CONNS` — max number of concurrent transport connections the
/// application accepts. FastCGI spec §4.1.
pub const FCGI_MAX_CONNS: Bytes = Bytes::from_static(b"FCGI_MAX_CONNS");
/// `FCGI_MAX_REQS` — max number of concurrent requests the application
/// accepts. FastCGI spec §4.1.
pub const FCGI_MAX_REQS: Bytes = Bytes::from_static(b"FCGI_MAX_REQS");
/// `FCGI_MPXS_CONNS` — `1` if the application multiplexes requests on a
/// single connection, `0` otherwise. FastCGI spec §4.1.
pub const FCGI_MPXS_CONNS: Bytes = Bytes::from_static(b"FCGI_MPXS_CONNS");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants_are_bytes_views_into_static_strings() {
        // Sanity: the bytes don't allocate (Bytes::from_static path) and the
        // values match the canonical names verbatim.
        assert_eq!(&REQUEST_METHOD[..], b"REQUEST_METHOD");
        assert_eq!(&SCRIPT_FILENAME[..], b"SCRIPT_FILENAME");
        assert_eq!(&HTTPS[..], b"HTTPS");
        assert_eq!(&FCGI_MPXS_CONNS[..], b"FCGI_MPXS_CONNS");
    }

    #[test]
    fn test_constants_clone_is_cheap() {
        // Bytes::clone of a static-backed value is a refcount no-op; this
        // documents the intended usage pattern. We compare pointers to
        // assert that no buffer copy happened.
        #[expect(
            clippy::redundant_clone,
            reason = "we explicitly want to call .clone() to observe its zero-copy behaviour"
        )]
        let cloned = SCRIPT_FILENAME.clone();
        assert_eq!(cloned.as_ptr(), SCRIPT_FILENAME.as_ptr());
    }

    #[test]
    fn test_value_constants_match_canonical_strings() {
        assert_eq!(&GATEWAY_INTERFACE_CGI_1_1[..], b"CGI/1.1");
        assert_eq!(&REDIRECT_STATUS_OK[..], b"200");
        assert_eq!(&HTTPS_ON[..], b"on");
    }
}
