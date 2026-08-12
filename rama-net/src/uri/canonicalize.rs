//! RFC 3986 §6.2.2 syntax-based URI normalization.
//!
//! Drives [`crate::uri::Uri::canonicalize`]. Applies, in order:
//!
//! 1. **Host promotion** — [`Host::Uninterpreted`] that decodes to an IP
//!    or a typed [`Domain`] gets replaced with the typed variant.
//!    Sub-delim reg-names and IPvFuture stay `Uninterpreted` (no
//!    canonical typed form exists for them).
//! 2. **Host case + pct normalization** (§6.2.2.1 + §6.2.2.2) — host
//!    bytes are ASCII-lowercased; for un-promoted `Uninterpreted` bodies
//!    pct-encoded octets are also normalised (decode unreserved,
//!    uppercase remaining hex). `Host::Address` is already canonical
//!    via the std `Display` impls.
//! 3. **Default-port drop** — when the scheme has a registered default
//!    port and the URI's port matches it, the port is omitted.
//! 4. **Pct-encoding normalization** (§6.2.2.2) on path, query,
//!    fragment — `%XX` octets that map to an unreserved character are
//!    decoded in place; pct-encoded octets that stay encoded get their
//!    hex digits uppercased (§6.2.2.1 case normalization).
//! 5. **Empty path** (§6.2.3) — when an authority is present and the
//!    path is empty, the canonical form has the path as `/`.
//! 6. **Dot-segment removal** (§6.2.2.3) — `.` and `..` segments are
//!    collapsed. Routed through [`super::resolve`]'s graceful
//!    [`remove_dot_segments_graceful`] so this code path can't error.
//!
//! Wire-fidelity preservation at parse time is intentional (see
//! [`crate::address::UninterpretedHost`]); `canonicalize` is opt-in,
//! for callers (typically clients building URIs from user input) who
//! want a normalised form.

use super::owned::OwnedUriRef;
use super::resolve::remove_dot_segments_graceful;
use super::{Uri, UriInner};
use crate::normalize::normalize_pct;

use rama_core::bytes::BytesMut;

/// Top-level entry — apply RFC 3986 §6.2.2 normalization to `uri`.
///
/// Always allocates one `OwnedUriRef`. No "already canonical?"
/// pre-scan: empirically, byte-walking to detect the no-op case costs
/// more than the allocation it would avoid on typical inputs
/// (`parse_canonical(user_input)` rarely receives already-canonical
/// bytes). If a future benchmark shows the idempotent-canonicalize
/// case dominates, revisit then.
pub(super) fn canonicalize_uri(uri: Uri) -> Uri {
    // Asterisk-form has no components — never needs work.
    if matches!(uri.inner, UriInner::Asterisk) {
        return uri;
    }
    let owned = uri.as_owned_components();
    let canonical = canonicalize_owned(owned);
    Uri {
        inner: UriInner::Owned(crate::std::sync::Arc::new(canonical)),
    }
}

/// Apply RFC 3986 §6.2.2 syntax-based normalization to `owned` in
/// place. See the module docs for the full ordering.
fn canonicalize_owned(mut owned: OwnedUriRef) -> OwnedUriRef {
    // 0. Scheme case (§6.2.2.1).
    if let Some(scheme) = owned.scheme.take() {
        owned.scheme = Some(scheme.canonicalize());
    }

    // 1. Host promotion + host case/pct normalization (§6.2.2.1).
    if let Some(authority) = &mut owned.authority {
        authority.address = authority.address.clone().canonicalize();

        // 2. Default-port drop. Empty (`host:`) also normalises to Unset
        // since canonicalization is the explicit opt-in to dropping
        // wire trivia.
        if let Some(scheme) = &owned.scheme
            && let Some(default) = scheme.default_port()
            && authority.address.port == crate::address::OptPort::Set(default)
        {
            authority.address.port = crate::address::OptPort::Unset;
        }
        if authority.address.port == crate::address::OptPort::Empty {
            authority.address.port = crate::address::OptPort::Unset;
        }
    }

    // 3. Pct-encoding normalization on path / query / fragment.
    normalize_pct(&mut owned.path);
    if let Some(q) = &mut owned.query {
        normalize_pct(&mut q.bytes);
    }
    if let Some(f) = &mut owned.fragment {
        normalize_pct(&mut f.bytes);
    }

    // 5. Dot-segment removal (done before the empty-path fixup so
    // segments like `.` / `..` that collapse to empty still get the
    // `/` rewrite below).
    owned.path = remove_dot_segments_graceful(&owned.path);

    // 4. Empty path → `/` when authority is present (§6.2.3).
    if owned.authority.is_some() && owned.path.is_empty() {
        owned.path = BytesMut::from(&b"/"[..]);
    }

    owned
}
