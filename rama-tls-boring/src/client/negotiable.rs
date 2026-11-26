//! Which listed values the native engine can negotiate.
//!
//! Fidelity paths (profile replay and relays) filter the rest out of an offer.
//! Each answer comes from the engine, so values it gains stop being filtered.

use std::{ops::RangeInclusive, sync::LazyLock};

use rama_boring::{
    nid::Nid,
    ssl::{SslCipher, SslCipherRef, SslCurve, SslSignatureAlgorithm},
};
use rama_core::conversion::RamaTryInto as _;
use rama_tls::{CipherSuite, ProtocolVersion, SignatureScheme, SupportedGroup};

/// Every version the engine negotiates.
pub(crate) const ALL_VERSIONS: RangeInclusive<u16> = 0x0301..=0x0304;

/// The renegotiation SCSV is a signal, not a suite, so it is never filtered.
pub(crate) fn cipher_supported(value: u16, versions: RangeInclusive<u16>) -> bool {
    value == u16::from(CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
        || cipher_negotiable(value, versions)
}

/// Whether the engine negotiates suite `value` at one of `versions`.
pub(crate) fn cipher_negotiable(value: u16, versions: RangeInclusive<u16>) -> bool {
    // Built once: describing a suite allocates, and offers are compiled per connection.
    static SUITES: LazyLock<Box<[(u16, u16, u16)]>> = LazyLock::new(|| {
        (0..=u16::MAX)
            .filter_map(|value| {
                let cipher = SslCipher::from_value(value)?;
                // The client has no PSK callback to authenticate these suites.
                if cipher.cipher_auth_nid() == Some(Nid::AUTH_PSK) {
                    return None;
                }
                let (min, max) = cipher_versions(&cipher);
                Some((value, min, max))
            })
            .collect()
    });
    SUITES
        .binary_search_by_key(&value, |&(suite, _, _)| suite)
        .is_ok_and(|index| {
            let (_, min, max) = SUITES[index];
            min <= *versions.end() && *versions.start() <= max
        })
}

// The engine's own description names the suite's key exchange and MAC: GENERIC key
// exchange is TLS 1.3 only, and suites without a SHA-1 MAC need TLS 1.2's PRF.
fn cipher_versions(cipher: &SslCipherRef) -> (u16, u16) {
    let description = cipher.description();
    if description.contains("Kx=GENERIC") {
        (0x0304, 0x0304)
    } else if description.contains("Mac=SHA1") {
        (0x0300, 0x0303)
    } else {
        (0x0303, 0x0303)
    }
}

/// The engine uses finite-field groups (RFC 7919) only as TLS 1.3 key shares.
#[cfg_attr(not(feature = "ua"), expect(dead_code))]
pub(crate) fn group_supported(value: u16, tls13: bool) -> bool {
    let curve: Result<SslCurve, _> = SupportedGroup::from(value).rama_try_into();
    curve.is_ok() && (tls13 || !(0x0100..=0x01ff).contains(&value))
}

#[cfg_attr(not(feature = "ua"), expect(dead_code))]
pub(crate) fn scheme_supported(value: u16) -> bool {
    let algorithm: Result<SslSignatureAlgorithm, _> = SignatureScheme::from(value).rama_try_into();
    algorithm.is_ok()
}

/// The engine still implements TLS 1.1 and 1.0; its default minimum is only a default.
pub(crate) fn version_supported(value: u16) -> bool {
    matches!(
        ProtocolVersion::from(value),
        ProtocolVersion::TLSv1_0
            | ProtocolVersion::TLSv1_1
            | ProtocolVersion::TLSv1_2
            | ProtocolVersion::TLSv1_3
    )
}
