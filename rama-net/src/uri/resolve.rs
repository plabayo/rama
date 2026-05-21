//! RFC 3986 §5.2 reference resolution.
//!
//! Resolve a reference URI against a base URI to produce a target URI.

use std::sync::Arc;

use rama_core::bytes::BytesMut;

use super::owned::OwnedUriRef;
use super::parser::MAX_URI_LEN;
use super::{Uri, UriInner};

/// Errors from [`Uri::resolve`](super::Uri::resolve) / [`Uri::resolve_strict`](super::Uri::resolve_strict).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// The base URI has no scheme. RFC 3986 §5.2.1 requires the base
    /// to be an absolute URI.
    BaseHasNoScheme,
    /// The base or reference is the asterisk-form (`*`), which is an
    /// HTTP request-target and has no meaning as a URI base or
    /// reference.
    AsteriskNotResolvable,
    /// The resolved URI exceeds the parser's length cap.
    ResultTooLong { len: usize },
    /// (Strict only) A `..` segment would pop past the path root.
    /// Graceful mode silently clamps at root.
    DotSegmentTraversalPastRoot,
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BaseHasNoScheme => f.write_str("base URI has no scheme"),
            Self::AsteriskNotResolvable => {
                f.write_str("asterisk-form URI cannot be used as a base or reference")
            }
            Self::ResultTooLong { len } => write!(f, "resolved URI is {len} bytes — exceeds cap"),
            Self::DotSegmentTraversalPastRoot => {
                f.write_str("`..` segment would traverse past path root (strict mode)")
            }
        }
    }
}

impl std::error::Error for ResolveError {}

/// Resolution mode. Internal — the public API exposes `resolve` (graceful)
/// and `resolve_strict`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ResolveMode {
    /// Browser-compatible: apply the §5.2.2 scheme-matching loophole;
    /// silently clamp excess `..` at root.
    Graceful,
    /// RFC §5.2.2 strict: no scheme-matching loophole; reject `..`
    /// traversal past root.
    Strict,
}

/// Entry point. `Uri::resolve` / `Uri::resolve_strict` funnel through here.
pub(super) fn resolve(base: &Uri, reference: &Uri, mode: ResolveMode) -> Result<Uri, ResolveError> {
    // ---- input validation -----------------------------------------------

    if matches!(base.inner, UriInner::Asterisk) || matches!(reference.inner, UriInner::Asterisk) {
        return Err(ResolveError::AsteriskNotResolvable);
    }
    if base.scheme().is_none() {
        return Err(ResolveError::BaseHasNoScheme);
    }

    // Materialise both inputs into Owned snapshots. Cheap when the source
    // is already Owned (Arc-clone); copies the component bytes for Lazy.
    // Destructure so the branches below can move fields without cloning.
    let OwnedUriRef {
        scheme: b_scheme,
        authority: b_authority,
        path: b_path,
        query: b_query,
        fragment: _,
    } = base.as_owned_components();
    let OwnedUriRef {
        scheme: r_scheme,
        authority: r_authority,
        path: r_path,
        query: r_query,
        fragment: r_fragment,
    } = reference.as_owned_components();

    // ---- scheme-matching loophole (§5.2.2 non-strict) -------------------
    //
    // In graceful mode, if R has a scheme equal to B's, treat R as if it
    // had no scheme. Strict mode skips this and keeps R.scheme.
    let r_has_effective_scheme = match (mode, &r_scheme, &b_scheme) {
        (ResolveMode::Graceful, Some(r_s), Some(b_s)) if r_s == b_s => false,
        _ => r_scheme.is_some(),
    };

    // ---- recompose target components per §5.2.2 -------------------------

    let (t_scheme, t_authority, t_path, t_query) = if r_has_effective_scheme {
        // Branch 1: R has scheme — use R verbatim (path is dot-removed).
        (
            r_scheme,
            r_authority,
            remove_dot_segments(&r_path, mode)?,
            r_query.map(|q| q.bytes),
        )
    } else if r_authority.is_some() {
        // Branch 2: R has authority but no scheme — inherit B's scheme.
        (
            b_scheme,
            r_authority,
            remove_dot_segments(&r_path, mode)?,
            r_query.map(|q| q.bytes),
        )
    } else if r_path.is_empty() {
        // Branch 3: same-document / query-only / fragment-only reference.
        // Inherit B's authority and path. Query: R's if defined, else B's.
        let query = r_query
            .map(|q| q.bytes)
            .or_else(|| b_query.map(|q| q.bytes));
        (b_scheme, b_authority, b_path, query)
    } else {
        // Branch 4: R has a non-empty relative path.
        let raw_path = if r_path.starts_with(b"/") {
            // 4a: R.path is absolute-path → use as-is.
            r_path
        } else {
            // 4b: merge with B.path, then dot-remove.
            merge_paths(b_authority.is_some(), &b_path, &r_path)
        };
        (
            b_scheme,
            b_authority,
            remove_dot_segments(&raw_path, mode)?,
            r_query.map(|q| q.bytes),
        )
    };

    // Fragment always comes from the reference (§5.2.2).
    let t_fragment = r_fragment.map(|f| f.bytes);

    let owned = OwnedUriRef {
        scheme: t_scheme,
        authority: t_authority,
        path: t_path,
        query: t_query.map(|bytes| super::Query { bytes }),
        fragment: t_fragment.map(|bytes| super::Fragment { bytes }),
    };

    // Cap the result so it can round-trip through the parser (which uses
    // u16 offsets internally).
    let total = serialized_len(&owned);
    if total > MAX_URI_LEN {
        return Err(ResolveError::ResultTooLong { len: total });
    }

    Ok(Uri {
        inner: UriInner::Owned(Arc::new(owned)),
    })
}

// ---------------------------------------------------------------------------
// §5.2.3 merge_paths
// ---------------------------------------------------------------------------

/// Combine base path with a relative reference path per RFC 3986 §5.2.3.
fn merge_paths(b_has_authority: bool, b_path: &[u8], r_path: &[u8]) -> BytesMut {
    if b_has_authority && b_path.is_empty() {
        // Special case: empty base path with authority — prepend "/".
        let mut out = BytesMut::with_capacity(1 + r_path.len());
        out.extend_from_slice(b"/");
        out.extend_from_slice(r_path);
        return out;
    }
    // "B.path up to and including the last `/`" — empty if no `/`.
    let cutoff = memchr::memrchr(b'/', b_path).map_or(0, |i| i + 1);
    let mut out = BytesMut::with_capacity(cutoff + r_path.len());
    out.extend_from_slice(&b_path[..cutoff]);
    out.extend_from_slice(r_path);
    out
}

// ---------------------------------------------------------------------------
// §5.2.4 remove_dot_segments
// ---------------------------------------------------------------------------

/// Walk `input` once, applying the §5.2.4 dot-segment removal rules to
/// produce a normalised path.
fn remove_dot_segments(input: &[u8], mode: ResolveMode) -> Result<BytesMut, ResolveError> {
    let mut output = BytesMut::with_capacity(input.len());
    let mut i = 0;

    while i < input.len() {
        let rest = &input[i..];

        // 2A: drop leading "../" or "./".
        if rest.starts_with(b"../") {
            i += 3;
            continue;
        }
        if rest.starts_with(b"./") {
            i += 2;
            continue;
        }

        // 2B: "/./"  → "/"  (advance past "/.", leaving "/" at position i+2)
        if rest.starts_with(b"/./") {
            i += 2;
            continue;
        }
        // 2B: "/."   → "/"  (end of input — emit "/" and finish)
        if rest == b"/." {
            output.extend_from_slice(b"/");
            break;
        }

        // 2C: "/../" → "/" (pop last output segment, advance past "/..")
        if rest.starts_with(b"/../") {
            pop_last_segment(&mut output, mode)?;
            i += 3;
            continue;
        }
        // 2C: "/.."  → "/" (end of input — pop then emit "/")
        if rest == b"/.." {
            pop_last_segment(&mut output, mode)?;
            output.extend_from_slice(b"/");
            break;
        }

        // 2D: input is exactly "." or ".." → drop.
        if rest == b"." || rest == b".." {
            break;
        }

        // 2E: move the first path segment to output. The segment is
        // (optional leading `/`) + (chars up to next `/` or end).
        let seg_end = if rest[0] == b'/' {
            // Find next `/` after the leading one, or end of input.
            memchr::memchr(b'/', &rest[1..]).map_or(rest.len(), |p| p + 1)
        } else {
            memchr::memchr(b'/', rest).unwrap_or(rest.len())
        };
        output.extend_from_slice(&rest[..seg_end]);
        i += seg_end;
    }

    Ok(output)
}

/// Remove the last segment and its preceding `/` from `output`. Empty
/// output is a no-op under graceful mode; under strict, it's an error.
fn pop_last_segment(output: &mut BytesMut, mode: ResolveMode) -> Result<(), ResolveError> {
    if let Some(last_slash) = memchr::memrchr(b'/', output) {
        output.truncate(last_slash);
        return Ok(());
    }
    if !output.is_empty() {
        // Single segment with no leading `/` — clear it.
        output.clear();
        return Ok(());
    }
    // Output is empty.
    match mode {
        ResolveMode::Strict => Err(ResolveError::DotSegmentTraversalPastRoot),
        ResolveMode::Graceful => Ok(()),
    }
}

// ---------------------------------------------------------------------------
/// Apply RFC 3986 §5.2.4 dot-segment removal to a standalone path,
/// graceful mode (`..` past root is silently clamped). Returned buffer
/// is always representable; the underlying machinery only ever errors
/// under strict mode, which this wrapper hard-pins to graceful.
///
/// Used by [`crate::uri::canonicalize`] for §6.2.2.3 path-segment
/// normalization.
pub(super) fn remove_dot_segments_graceful(input: &[u8]) -> BytesMut {
    // Graceful mode never errors — `pop_last_segment` is the only error
    // site and it only fires under `ResolveMode::Strict`.
    remove_dot_segments(input, ResolveMode::Graceful).unwrap_or_else(|_| {
        // Defence-in-depth: any future change that would let graceful
        // mode error trips here loudly rather than silently returning
        // an empty path.
        debug_assert!(false, "graceful remove_dot_segments must not error");
        BytesMut::from(input)
    })
}

// ---------------------------------------------------------------------------
// Size estimation for the cap check
// ---------------------------------------------------------------------------

/// Estimate the serialized byte length of `owned` (matches what `Display`
/// would emit). Used to enforce the [`MAX_URI_LEN`] cap on the resolved
/// URI without an extra `to_string()` allocation.
fn serialized_len(owned: &OwnedUriRef) -> usize {
    let mut n = 0;
    if let Some(scheme) = &owned.scheme {
        n += scheme.as_str().len() + 1; // ":" suffix
    }
    if let Some(auth) = &owned.authority {
        n += 2; // "//"
        if let Some(ui) = &auth.user_info {
            n += ui.as_bytes().len() + 1; // "@" suffix
        }
        // Host: use the existing Display path. Fast enough for size calc;
        // not a hot path.
        n += auth.address.host.to_string().len();
        if let Some(port) = auth.address.port {
            n += 1; // ":"
            n += port_decimal_len(port);
        }
    }
    n += owned.path.len();
    if let Some(q) = &owned.query {
        n += 1 + q.bytes.len(); // "?" + bytes
    }
    if let Some(f) = &owned.fragment {
        n += 1 + f.bytes.len(); // "#" + bytes
    }
    n
}

#[inline]
fn port_decimal_len(port: u16) -> usize {
    match port {
        0..=9 => 1,
        10..=99 => 2,
        100..=999 => 3,
        1000..=9999 => 4,
        _ => 5,
    }
}
