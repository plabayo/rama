# `rama-fastcgi` specifications

Vendored copies of the specifications and de-facto conventions this crate
implements. Provenance and short rationale for each file:

| File | What | Provenance |
|---|---|---|
| `fastcgi_spec.txt` | FastCGI 1.0 — Mark R. Brown, Open Market, 29 April 1996. The authoritative protocol document. | <https://fastcgi-archives.github.io/FastCGI_Specification.html> (mirror of the original fastcgi.com/devkit/doc/fcgi-spec.html) |
| `rfc3875_cgi_v1.1.txt` | RFC 3875 — Common Gateway Interface (CGI) 1.1. Defines the semantics of the name-value pairs FastCGI carries (REQUEST_METHOD, SCRIPT_NAME, PATH_INFO, HTTP_* mapping, etc.). | <https://www.rfc-editor.org/rfc/rfc3875.txt> |
| `nginx_fastcgi_params.md` | Curated guide to the de-facto FastCGI parameter set used by nginx, Apache, and php-fpm. | This crate |

## Why all three?

The FastCGI spec is intentionally narrow — it defines record framing and the
name-value encoding only. The *meaning* of variables (`SCRIPT_NAME` vs
`PATH_INFO`, the `HTTPS=on` convention, php-fpm's `REDIRECT_STATUS`
requirement, the `SCRIPT_FILENAME` extension) is split between RFC 3875 and
the de-facto nginx/php-fpm contract. All three are needed to build a
spec-correct *and* interop-correct implementation.

## Interop philosophy

`rama-fastcgi` is **proxy-first**: it parses leniently by default (graceful
over strict) and lets servers opt into stricter behaviour via
`ServerOptions` knobs. See the module documentation in
[`src/server/types.rs`](../src/server/types.rs)
and [`src/client/types.rs`](../src/client/types.rs) for what's configurable.
