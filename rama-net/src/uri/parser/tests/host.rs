//! Host-component coverage for the authority parser.
//!
//! Most general parser coverage lives in `absolute_form.rs` and
//! `authority_form.rs`; this file is for tests that target the host
//! component specifically — IP-literal shapes, reg-name edge cases,
//! and the layering between strict / graceful / IDN handling.

use super::parse_strict;

// ----------------------------------------------------------------------
// Pct-encoded reg-name + IPvFuture — RFC 3986 §3.2.2 legal host shapes
// that the current ASCII-via-`Domain::try_from` host fast path rejects.
// Fix lands in a follow-up commit (pct-decode-and-reroute through the
// existing IP / Domain cascade; IPvFuture gets a typed "not supported"
// or basic acceptance).
// ----------------------------------------------------------------------

#[test]
#[ignore = "fix pending in follow-up commit (pct-decode reg-name)"]
fn pct_encoded_reg_name_accepted_in_strict() {
    // `%6D` is the pct-encoded `m`, so `exa%6Dple.com` is the spec-legal
    // wire form of `example.com`. RFC 3986 reg-name allows pct-encoded
    // segments; we currently reject this because `Domain::try_from`
    // doesn't decode pct.
    parse_strict("http://exa%6Dple.com/")
        .expect("strict mode must accept pct-encoded reg-name per RFC 3986");
}

#[test]
#[ignore = "fix pending in follow-up commit (IPvFuture support)"]
fn ipvfuture_literal_accepted_in_strict() {
    // `[v1.fe80::a]` — IPvFuture, RFC 3986 §3.2.2. Today we only
    // bracket-parse IPv6. No `vN.X` IPvFuture form is registered with
    // IANA as of 2026 (real-world dead), but the spec-compliant
    // expectation is to accept it.
    parse_strict("http://[v1.fe80::a]/").expect("strict mode must accept IPvFuture per RFC 3986");
}
