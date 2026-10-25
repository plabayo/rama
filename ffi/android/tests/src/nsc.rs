//! Only run by APK instrumentation: app_process cannot install NSC policy.
use crate::harness::{Test, ensure};
use rama_crypto::{
    pki_types::CertificateDer,
    platform_verifier::{PlatformVerifier, PlatformVerifyErrorKind},
};
use rama_net::address::Host;
use std::time::SystemTime;

pub(crate) static TESTS: &[Test] = &[
    (
        "matching_pin_and_domain_anchor",
        matching_pin_and_domain_anchor,
    ),
    ("mismatching_pin_is_rejected", mismatching_pin_is_rejected),
    (
        "duplicate_extra_root_cannot_bypass_pin",
        duplicate_extra_root_cannot_bypass_pin,
    ),
    (
        "domain_anchor_does_not_leak_to_other_domains",
        domain_anchor_does_not_leak_to_other_domains,
    ),
];

fn verify(
    host: &'static str,
    extra: bool,
) -> Result<(), rama_crypto::platform_verifier::PlatformVerifyError> {
    let verifier = if extra {
        PlatformVerifier::try_with_extra_roots([CertificateDer::from(
            include_bytes!("../fixtures/ca.der").to_vec(),
        )])
        .unwrap()
    } else {
        PlatformVerifier::new()
    };
    verifier
        .verify_server_chain(
            &CertificateDer::from(include_bytes!("../fixtures/leaf.der").as_slice()),
            &[],
            &Host::from_static(host),
            None,
            SystemTime::now(),
        )
        .map(drop)
}

fn matching_pin_and_domain_anchor() -> Result<(), String> {
    verify("good.rama.test", false).map_err(|e| format!("{e:?}"))
}
fn mismatching_pin_is_rejected() -> Result<(), String> {
    let result = verify("bad.rama.test", false);
    ensure(
        result.is_err_and(|e| e.kind() != PlatformVerifyErrorKind::UnknownIssuer),
        "NSC pin rejection lost or classified as missing trust anchor",
    )
}
fn duplicate_extra_root_cannot_bypass_pin() -> Result<(), String> {
    let result = verify("bad.rama.test", true);
    ensure(
        result.is_err_and(|e| e.kind() != PlatformVerifyErrorKind::UnknownIssuer),
        "duplicated additional anchor bypassed NSC pins",
    )
}
fn domain_anchor_does_not_leak_to_other_domains() -> Result<(), String> {
    ensure(
        verify("plain.rama.test", false)
            .is_err_and(|e| e.kind() == PlatformVerifyErrorKind::UnknownIssuer),
        "NSC domain anchor trusted outside its domain",
    )
}
