use rama_core::error::{BoxError, BoxErrorExt as _, ErrorExt as _};
use rama_net::{
    Protocol,
    http::Version,
    tls::{AlpnPolicy, ApplicationProtocol},
};

/// Resolve an explicit target HTTP version to an ALPN offer override.
///
/// Non-HTTP protocols ignore the target. An absent application protocol still
/// allows an explicit target; an absent target leaves the existing offer alone.
/// Pass only an explicit target, not a fallback HTTP version. The caller applies
/// the offer and any backend-specific settings coupled to it, such as ALPS.
pub fn http_alpn_override(
    application_protocol: Option<&Protocol>,
    target_version: Option<Version>,
) -> Result<Option<ApplicationProtocol>, BoxError> {
    if application_protocol.is_some_and(|protocol| !protocol.is_http_based()) {
        return Ok(None);
    }
    target_version
        .map(ApplicationProtocol::try_from)
        .transpose()
}

/// Interpret negotiated ALPN for HTTP and validate the version policy.
///
/// An explicit target must match negotiated ALPN. The fallback is used only when
/// ALPN is absent: strict policy requires ALPN if the target, or otherwise the
/// fallback, selects HTTP/2 or HTTP/3. Without a policy override, only an explicit
/// HTTP/3 target requires ALPN. Out-of-band agreement permits missing ALPN.
///
/// Returns `None` for absent ALPN without fabricating negotiated metadata, and
/// for absent or non-HTTP application protocols. Unknown HTTP ALPN is rejected.
/// The caller decides where to publish the returned version; a proxy tunnel's
/// negotiated version must not become the origin's HTTP version.
pub fn negotiated_http_version(
    application_protocol: Option<&Protocol>,
    target_version: Option<Version>,
    fallback_version: Option<Version>,
    negotiated_alpn: Option<&ApplicationProtocol>,
    policy: Option<AlpnPolicy>,
) -> Result<Option<Version>, BoxError> {
    if !application_protocol.is_some_and(Protocol::is_http_based) {
        return Ok(None);
    }
    let Some(alpn) = negotiated_alpn else {
        let required_version = match policy {
            Some(AlpnPolicy::Require) => target_version.or(fallback_version),
            Some(AlpnPolicy::OutOfBandAgreement) => None,
            None => target_version.filter(|version| *version == Version::HTTP_3),
        };
        if matches!(required_version, Some(Version::HTTP_2 | Version::HTTP_3)) {
            return Err(BoxError::from_static_str(
                "target HTTP version requires TLS ALPN negotiation",
            )
            .context_debug_field("target_version", required_version));
        }
        return Ok(None);
    };
    let negotiated_version: Version = alpn.try_into()?;
    if let Some(target_version) = target_version
        && target_version != negotiated_version
    {
        return Err(BoxError::from_static_str(
            "target http version not compatible with negotiated tls alpn version",
        )
        .context_debug_field("target_version", target_version)
        .context_debug_field("negotiated_version", negotiated_version));
    }
    Ok(Some(negotiated_version))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_targets_override_http_offers_even_without_a_protocol() {
        for protocol in [None, Some(&Protocol::HTTPS), Some(&Protocol::WSS)] {
            for (version, alpn) in [
                (Version::HTTP_11, ApplicationProtocol::HTTP_11),
                (Version::HTTP_2, ApplicationProtocol::HTTP_2),
                (Version::HTTP_3, ApplicationProtocol::HTTP_3),
            ] {
                assert_eq!(
                    http_alpn_override(protocol, Some(version)).unwrap(),
                    Some(alpn)
                );
            }
            assert_eq!(http_alpn_override(protocol, None).unwrap(), None);
        }
        assert_eq!(
            http_alpn_override(Some(&Protocol::ICAPS), Some(Version::HTTP_2)).unwrap(),
            None,
        );
    }

    #[test]
    fn negotiated_http_alpn_must_match_an_explicit_target() {
        for protocol in [Protocol::HTTPS, Protocol::WSS] {
            for (version, alpn) in [
                (Version::HTTP_11, ApplicationProtocol::HTTP_11),
                (Version::HTTP_2, ApplicationProtocol::HTTP_2),
                (Version::HTTP_3, ApplicationProtocol::HTTP_3),
            ] {
                for target in [None, Some(version)] {
                    assert_eq!(
                        negotiated_http_version(Some(&protocol), target, None, Some(&alpn), None)
                            .unwrap(),
                        Some(version),
                    );
                }
            }
        }
        negotiated_http_version(
            Some(&Protocol::HTTPS),
            Some(Version::HTTP_11),
            None,
            Some(&ApplicationProtocol::HTTP_2),
            None,
        )
        .expect_err("negotiated version must match the explicit target");
    }

    #[test]
    fn absent_alpn_does_not_infer_a_version_from_the_target() {
        for target in [None, Some(Version::HTTP_10), Some(Version::HTTP_11)] {
            assert_eq!(
                negotiated_http_version(Some(&Protocol::HTTPS), target, None, None, None).unwrap(),
                None,
            );
        }
    }

    #[test]
    fn missing_alpn_policy_matrix() {
        for protocol in [Protocol::HTTPS, Protocol::WSS] {
            for target in [
                None,
                Some(Version::HTTP_11),
                Some(Version::HTTP_2),
                Some(Version::HTTP_3),
            ] {
                for policy in [
                    None,
                    Some(AlpnPolicy::Require),
                    Some(AlpnPolicy::OutOfBandAgreement),
                ] {
                    let rejected = matches!(
                        (target, policy),
                        (
                            Some(Version::HTTP_2 | Version::HTTP_3),
                            Some(AlpnPolicy::Require)
                        ) | (Some(Version::HTTP_3), None)
                    );
                    let result =
                        negotiated_http_version(Some(&protocol), target, None, None, policy);
                    assert_eq!(
                        result.is_err(),
                        rejected,
                        "{protocol:?} {target:?} {policy:?}"
                    );
                    if !rejected {
                        assert_eq!(result.unwrap(), None, "do not invent negotiated metadata");
                    }
                    if let Some(target) = target {
                        let conflicting = if target == Version::HTTP_11 {
                            ApplicationProtocol::HTTP_2
                        } else {
                            ApplicationProtocol::HTTP_11
                        };
                        negotiated_http_version(
                            Some(&protocol),
                            Some(target),
                            None,
                            Some(&conflicting),
                            policy,
                        )
                        .expect_err("a conflicting negotiated protocol is always rejected");
                    }
                }
            }
        }
    }

    #[test]
    fn targets_and_fallbacks_have_distinct_alpn_requirements() {
        // Errors are listed for default, strict, and out-of-band policy, respectively.
        let cases = [
            (None, None, None, [false, false, false]),
            (None, Some(Version::HTTP_11), None, [false, false, false]),
            (None, Some(Version::HTTP_2), None, [false, true, false]),
            (None, Some(Version::HTTP_3), None, [false, true, false]),
            (
                Some(Version::HTTP_11),
                Some(Version::HTTP_2),
                None,
                [false, false, false],
            ),
            (
                Some(Version::HTTP_2),
                Some(Version::HTTP_11),
                None,
                [false, true, false],
            ),
            (
                Some(Version::HTTP_3),
                Some(Version::HTTP_11),
                None,
                [true, true, false],
            ),
            (
                None,
                Some(Version::HTTP_2),
                Some(Version::HTTP_11),
                [false, false, false],
            ),
            (
                None,
                Some(Version::HTTP_11),
                Some(Version::HTTP_2),
                [false, false, false],
            ),
            (
                Some(Version::HTTP_2),
                Some(Version::HTTP_11),
                Some(Version::HTTP_11),
                [true, true, true],
            ),
            (
                Some(Version::HTTP_2),
                Some(Version::HTTP_11),
                Some(Version::HTTP_2),
                [false, false, false],
            ),
            (
                Some(Version::HTTP_11),
                Some(Version::HTTP_2),
                Some(Version::HTTP_2),
                [true, true, true],
            ),
        ];
        for (target, fallback, negotiated, errors) in cases {
            let alpn = negotiated.map(|version| ApplicationProtocol::try_from(version).unwrap());
            for (policy, reject) in [
                None,
                Some(AlpnPolicy::Require),
                Some(AlpnPolicy::OutOfBandAgreement),
            ]
            .into_iter()
            .zip(errors)
            {
                let result = negotiated_http_version(
                    Some(&Protocol::HTTPS),
                    target,
                    fallback,
                    alpn.as_ref(),
                    policy,
                );
                assert_eq!(
                    result.is_err(),
                    reject,
                    "target={target:?}, fallback={fallback:?}, negotiated={negotiated:?}, policy={policy:?}"
                );
                if !reject {
                    assert_eq!(
                        result.unwrap(),
                        negotiated,
                        "fallback must not become negotiated metadata"
                    );
                }
            }
        }
    }

    #[test]
    fn multiplexed_http_targets_require_alpn() {
        for protocol in [Protocol::HTTPS, Protocol::WSS] {
            for version in [Version::HTTP_2, Version::HTTP_3] {
                negotiated_http_version(
                    Some(&protocol),
                    Some(version),
                    None,
                    None,
                    Some(AlpnPolicy::Require),
                )
                .expect_err("strict TLS HTTP/2 and HTTP/3 require ALPN");
            }
        }
    }

    #[test]
    fn only_http_connections_interpret_negotiated_alpn() {
        let unknown = ApplicationProtocol::from(b"custom");
        for alpn in [&unknown, &ApplicationProtocol::HTTP_2] {
            for protocol in [None, Some(&Protocol::ICAPS)] {
                assert_eq!(
                    negotiated_http_version(
                        protocol,
                        Some(Version::HTTP_11),
                        None,
                        Some(alpn),
                        None
                    )
                    .unwrap(),
                    None,
                );
            }
        }
        negotiated_http_version(Some(&Protocol::HTTPS), None, None, Some(&unknown), None)
            .expect_err("HTTP requires a recognized negotiated protocol");
    }
}
