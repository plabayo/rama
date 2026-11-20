use super::*;
use std::time::Duration;

#[test]
fn helpers_reject_non_platform_and_unresolved_platform_policies() {
    let custom = TlsServerTrust::custom(
        TlsServerTrustAnchors::try_new([CertificateDer::from(vec![1])]).unwrap(),
    );
    let unresolved = TlsServerTrust::new(ServerTrustSource::Platform(
        PlatformTrustPolicy::new().with_max_age(Duration::ZERO),
    ));
    for trust in [custom, TlsServerTrust::webpki_roots(), unresolved] {
        assert!(shared_platform_verifier(&trust).is_none());
        drop(build_platform_verifier(&trust).unwrap_err());
    }
}

#[test]
fn unavailable_platform_cannot_use_static_platform_helpers() {
    if !PlatformVerifier::IS_AVAILABLE {
        let trust = TlsServerTrust::platform_verifier();
        assert!(shared_platform_verifier(&trust).is_none());
        drop(build_platform_verifier(&trust).unwrap_err());
    }
}

#[test]
fn a_prepared_handle_retains_the_verifier_and_requires_the_exact_policy() {
    let trust = TlsServerTrust::platform_verifier();
    let verifier = Arc::new(PlatformVerifier::new());
    let weak = Arc::downgrade(&verifier);
    let prepared = PreparedPlatformVerifier(Arc::new(PreparedVerifier {
        trust: trust.clone(),
        verifier,
    }));
    let held = resolve_platform_verifier(&trust, Some(&prepared), |_| {
        panic!("a prepared verifier does not require the cache")
    })
    .unwrap();
    assert!(Arc::ptr_eq(&held, &weak.upgrade().unwrap()));
    let different = trust
        .try_with_additional_anchors([CertificateDer::from(vec![1])])
        .unwrap();
    assert!(prepared.for_trust(&different).is_none());
}
