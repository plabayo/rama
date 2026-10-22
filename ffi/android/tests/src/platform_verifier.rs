//! `rama_crypto::platform_verifier` against the platform `X509TrustManager`.

use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
    time::{Duration, SystemTime},
};

use rama_crypto::{
    cert::{CertificateIdentity, GeneratedServerAuthConfig, generate_server_auth},
    pki_types::CertificateDer,
    platform_verifier::{PlatformVerifier, PlatformVerifyErrorKind},
};
use rama_net::address::{Domain, Host};

use crate::harness::{Test, ensure};

pub(crate) static TESTS: &[Test] = &[
    ("a_private_ca_is_not_trusted", a_private_ca_is_not_trusted),
    (
        "extra_roots_trust_a_private_ca",
        extra_roots_trust_a_private_ca,
    ),
    ("the_server_name_must_match", the_server_name_must_match),
    ("ip_identities_match_ip_names", ip_identities_match_ip_names),
    ("an_expired_leaf_is_rejected", an_expired_leaf_is_rejected),
    (
        "a_malformed_certificate_leaves_the_verifier_usable",
        a_malformed_certificate_leaves_the_verifier_usable,
    ),
    ("overlong_chains_are_refused", overlong_chains_are_refused),
    ("threads_verify_concurrently", threads_verify_concurrently),
];

const NAME: &str = "leaf.rama.test";

/// A leaf for `identity` and the CA that issued it.
fn chain(identity: impl Into<CertificateIdentity>) -> Result<[CertificateDer<'static>; 2], String> {
    let (chain, _) = generate_server_auth(GeneratedServerAuthConfig::generated_ca_for(identity))
        .map_err(|err| err.to_string())?;
    match <[_; 2]>::try_from(chain) {
        Ok(chain) => Ok(chain),
        Err(chain) => Err(format!(
            "expected leaf and CA, got {} certificates",
            chain.len()
        )),
    }
}

fn trusting(ca: &CertificateDer<'static>) -> Result<PlatformVerifier, String> {
    PlatformVerifier::try_with_extra_roots([ca.clone()]).map_err(|err| err.to_string())
}

fn rejected_with(
    outcome: Result<
        Vec<CertificateDer<'static>>,
        rama_crypto::platform_verifier::PlatformVerifyError,
    >,
    expected: PlatformVerifyErrorKind,
) -> Result<(), String> {
    match outcome {
        Ok(_) => Err(format!("accepted, expected {expected:?}")),
        Err(err) if err.kind() == expected => Ok(()),
        Err(err) => Err(format!(
            "rejected with {:?} ({err}), expected {expected:?}",
            err.kind()
        )),
    }
}

fn a_private_ca_is_not_trusted() -> Result<(), String> {
    let [leaf, _ca] = chain(Domain::from_static(NAME))?;
    rejected_with(
        PlatformVerifier::new().verify_server_chain(
            &leaf,
            &[],
            &Host::from_static(NAME),
            None,
            SystemTime::now(),
        ),
        PlatformVerifyErrorKind::UnknownIssuer,
    )
}

fn extra_roots_trust_a_private_ca() -> Result<(), String> {
    let [leaf, ca] = chain(Domain::from_static(NAME))?;
    let verified = trusting(&ca)?
        .verify_server_chain(
            &leaf,
            &[],
            &Host::from_static(NAME),
            None,
            SystemTime::now(),
        )
        .map_err(|err| err.to_string())?;
    ensure(
        verified == [leaf, ca],
        format!(
            "built chain of {} certificates is not leaf then CA",
            verified.len()
        ),
    )
}

fn the_server_name_must_match() -> Result<(), String> {
    let [leaf, ca] = chain(Domain::from_static(NAME))?;
    rejected_with(
        trusting(&ca)?.verify_server_chain(
            &leaf,
            &[],
            &Host::from_static("other.rama.test"),
            None,
            SystemTime::now(),
        ),
        PlatformVerifyErrorKind::NotValidForName,
    )
}

fn ip_identities_match_ip_names() -> Result<(), String> {
    let ip = IpAddr::from(Ipv4Addr::LOCALHOST);
    let [leaf, ca] = chain(ip)?;
    let verifier = trusting(&ca)?;
    verifier
        .verify_server_chain(&leaf, &[], &Host::from(ip), None, SystemTime::now())
        .map_err(|err| err.to_string())?;
    rejected_with(
        verifier.verify_server_chain(
            &leaf,
            &[],
            &Host::from(IpAddr::from(Ipv4Addr::new(127, 0, 0, 2))),
            None,
            SystemTime::now(),
        ),
        PlatformVerifyErrorKind::NotValidForName,
    )
}

fn an_expired_leaf_is_rejected() -> Result<(), String> {
    let [leaf, ca] = chain(Domain::from_static(NAME))?;
    // Generated leaves live 90 days.
    let later = SystemTime::now() + Duration::from_hours(365 * 24);
    rejected_with(
        trusting(&ca)?.verify_server_chain(&leaf, &[], &Host::from_static(NAME), None, later),
        PlatformVerifyErrorKind::Expired,
    )
}

fn a_malformed_certificate_leaves_the_verifier_usable() -> Result<(), String> {
    let [leaf, ca] = chain(Domain::from_static(NAME))?;
    let verifier = trusting(&ca)?;
    rejected_with(
        verifier.verify_server_chain(
            &CertificateDer::from(vec![0x30, 0x03, 0x02, 0x01, 0x00]),
            &[],
            &Host::from_static(NAME),
            None,
            SystemTime::now(),
        ),
        PlatformVerifyErrorKind::BadEncoding,
    )?;
    // A cleared Java exception must not poison later calls.
    verifier
        .verify_server_chain(
            &leaf,
            &[],
            &Host::from_static(NAME),
            None,
            SystemTime::now(),
        )
        .map(drop)
        .map_err(|err| format!("verification after a malformed certificate failed: {err}"))
}

fn overlong_chains_are_refused() -> Result<(), String> {
    let [leaf, ca] = chain(Domain::from_static(NAME))?;
    let intermediates = vec![ca.clone(); 17];
    rejected_with(
        trusting(&ca)?.verify_server_chain(
            &leaf,
            &intermediates,
            &Host::from_static(NAME),
            None,
            SystemTime::now(),
        ),
        PlatformVerifyErrorKind::BadEncoding,
    )
}

fn threads_verify_concurrently() -> Result<(), String> {
    let [leaf, ca] = chain(Domain::from_static(NAME))?;
    let verifier = Arc::new(trusting(&ca)?);
    let workers: Vec<_> = (0..8)
        .map(|_| {
            let (verifier, leaf) = (verifier.clone(), leaf.clone());
            std::thread::spawn(move || {
                verifier
                    .verify_server_chain(
                        &leaf,
                        &[],
                        &Host::from_static(NAME),
                        None,
                        SystemTime::now(),
                    )
                    .map(drop)
                    .map_err(|err| err.to_string())
            })
        })
        .collect();
    for worker in workers {
        worker
            .join()
            .map_err(|_| "a verifying thread panicked".to_owned())??;
    }
    Ok(())
}
