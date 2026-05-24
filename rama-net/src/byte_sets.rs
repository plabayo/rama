//! Byte-set lookup tables and `is_*` predicates, single-sourced for the
//! whole crate.
//!
//! `matches!` and `b < 0x20 || b == 0x7F`-style checks compile to
//! compare-chains whose shape is up to LLVM. Validators on the hot path
//! (URI parsing, DNS-label validation, …) run these on every byte of every
//! input, so we precompute `[bool; 256]` tables: one byte load per check,
//! no branches, no surprises across compiler versions.
//!
//! Lives at the crate root so any module — `address`, `uri`, future
//! grammars — can consume the same primitives and tables without one
//! module taking ownership of another's grammar. Module visibility is
//! `pub(crate)`; nothing here is part of rama-net's public API.

// --- Table-building primitives ---------------------------------------------

/// Mark every byte in `[lo, hi_exclusive)` as `true`. const-evaluable.
pub(crate) const fn set_range(mut t: [bool; 256], lo: u8, hi_exclusive: u8) -> [bool; 256] {
    let mut i = lo;
    while i < hi_exclusive {
        t[i as usize] = true;
        i += 1;
    }
    t
}

/// Mark every byte present in `bytes` as `true`. const-evaluable.
pub(crate) const fn set_each(mut t: [bool; 256], bytes: &[u8]) -> [bool; 256] {
    let mut j = 0;
    while j < bytes.len() {
        t[bytes[j] as usize] = true;
        j += 1;
    }
    t
}

/// Convenience: ASCII alphanumerics (`0-9 A-Z a-z`) — the unreserved
/// alphabet that shows up in nearly every URI byte set.
pub(crate) const fn set_ascii_alphanum(t: [bool; 256]) -> [bool; 256] {
    let t = set_range(t, b'0', b'9' + 1);
    let t = set_range(t, b'A', b'Z' + 1);
    set_range(t, b'a', b'z' + 1)
}

/// ASCII alpha range A-Z and a-z (no digits). Used by the scheme-first table.
const fn set_ascii_alpha(t: [bool; 256]) -> [bool; 256] {
    let t = set_range(t, b'A', b'Z' + 1);
    set_range(t, b'a', b'z' + 1)
}

// --- Concrete byte sets ----------------------------------------------------

/// `b < 0x20 || b == 0x7F` as a single load.
const CONTROL_BYTE_SET: [bool; 256] = set_each(set_range([false; 256], 0, 0x20), &[0x7F]);

/// Strict RFC 3986 path byte set: pchar ∪ `/`. pchar = unreserved /
/// pct-encoded / sub-delims / `:` / `@`. `%` is allowed as the lead byte
/// of a percent-escape (the `%XX` triple is checked separately).
const PATH_BYTE_SET: [bool; 256] = set_each(
    set_ascii_alphanum([false; 256]),
    // unreserved extras + sub-delims + pchar extras + path delimiter + `%`
    b"-._~!$&'()*+,;=:@/%",
);

/// Strict RFC 3986 query / fragment byte set: pchar ∪ `/` ∪ `?`.
const QUERY_FRAGMENT_BYTE_SET: [bool; 256] =
    set_each(set_ascii_alphanum([false; 256]), b"-._~!$&'()*+,;=:@/%?");

/// RFC 3986 §3.1: a scheme's first byte must be ASCII alpha.
const SCHEME_FIRST_BYTE_SET: [bool; 256] = set_ascii_alpha([false; 256]);

/// RFC 3986 §3.1: a scheme's subsequent bytes are ALPHA / DIGIT / "+" / "-" / ".".
const SCHEME_REST_BYTE_SET: [bool; 256] = set_each(set_ascii_alphanum([false; 256]), b"+-.");

/// RFC 3986 §3.2.1: userinfo bytes are unreserved / pct-encoded / sub-delims /
/// `:`. Note that `@` is **not** in the set — `@` is the userinfo terminator,
/// so its raw presence inside the userinfo bytes (which can only happen if
/// the *last*-`@` split logic finds an inner `@`) is a strict violation.
/// Per RFC 3986, such an `@` MUST be percent-encoded as `%40`.
const USERINFO_BYTE_SET: [bool; 256] =
    set_each(set_ascii_alphanum([false; 256]), b"-._~!$&'()*+,;=:%");

/// RFC 3986 §2.3 `unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"`.
/// Used by [`crate::uri::canonicalize`] to decide whether a pct-encoded
/// octet can be decoded back to its literal form (§6.2.2.2).
const UNRESERVED_BYTE_SET: [bool; 256] = set_each(set_ascii_alphanum([false; 256]), b"-._~");

/// RFC 3986 §3.2.2 `reg-name = *( unreserved / pct-encoded / sub-delims )`.
/// ASCII subset of the byte set; non-ASCII is allowed in graceful mode under
/// the IRI `ireg-name` extension (handled inline at the validator).
/// `%` is the pct-escape lead — the `%XX` triple is checked separately.
const REG_NAME_BYTE_SET: [bool; 256] =
    set_each(set_ascii_alphanum([false; 256]), b"-._~!$&'()*+,;=%");

/// RFC 3986 §3.2.2 IPvFuture tail: `1*( unreserved / sub-delims / ":" )`.
/// The leading `v`, hex digits, and `.` separator are validated separately
/// at the start of the literal. No pct-encoding inside IPvFuture.
const IPVFUTURE_TAIL_BYTE_SET: [bool; 256] =
    set_each(set_ascii_alphanum([false; 256]), b"-._~!$&'()*+,;=:");

/// DNS-label byte class: `ALPHA / DIGIT / "_" / "-"`. RFC 1035 §2.3.1 grammar
/// plus the `_` extension widely used in SRV / TXT / DKIM / `_acme-challenge`
/// records. Consumed by [`crate::address::domain`]'s label validator.
const LABEL_BYTE_SET: [bool; 256] = set_each(set_ascii_alphanum([false; 256]), b"_-");

// --- Predicates (single-load hot path) -------------------------------------

#[inline(always)]
pub(crate) const fn is_control_byte(b: u8) -> bool {
    CONTROL_BYTE_SET[b as usize]
}

/// `Some(b)` when `%h1h2` pct-decodes to a control byte `b` (smuggling
/// vector). `None` for non-hex inputs or non-control decodes.
#[inline(always)]
pub(crate) const fn pct_decoded_control_byte(h1: u8, h2: u8) -> Option<u8> {
    match rama_utils::hex::decode_pair(h1, h2) {
        Some(b) if is_control_byte(b) => Some(b),
        _ => None,
    }
}

#[inline(always)]
pub(crate) const fn is_path_byte(b: u8) -> bool {
    PATH_BYTE_SET[b as usize]
}

#[inline(always)]
pub(crate) const fn is_query_fragment_byte(b: u8) -> bool {
    QUERY_FRAGMENT_BYTE_SET[b as usize]
}

#[inline(always)]
pub(crate) const fn is_scheme_first_byte(b: u8) -> bool {
    SCHEME_FIRST_BYTE_SET[b as usize]
}

#[inline(always)]
pub(crate) const fn is_scheme_rest_byte(b: u8) -> bool {
    SCHEME_REST_BYTE_SET[b as usize]
}

#[inline(always)]
pub(crate) const fn is_userinfo_byte(b: u8) -> bool {
    USERINFO_BYTE_SET[b as usize]
}

#[inline(always)]
pub(crate) const fn is_unreserved_byte(b: u8) -> bool {
    UNRESERVED_BYTE_SET[b as usize]
}

#[inline(always)]
pub(crate) const fn is_reg_name_byte(b: u8) -> bool {
    REG_NAME_BYTE_SET[b as usize]
}

#[inline(always)]
pub(crate) const fn is_ipvfuture_tail_byte(b: u8) -> bool {
    IPVFUTURE_TAIL_BYTE_SET[b as usize]
}

#[inline(always)]
pub(crate) const fn is_label_byte(b: u8) -> bool {
    LABEL_BYTE_SET[b as usize]
}
