use super::*;

#[test]
fn header_ownership_preserves_browser_fields_and_binds_message_values() {
    let mut input = headers(&[
        ("User-Agent", "reference/1"),
        ("Accept", "text/html"),
        ("Accept-Language", "en"),
        ("Accept-Encoding", "gzip"),
        ("Sec-CH-UA", "reference"),
        ("Upgrade-Insecure-Requests", "1"),
        ("Priority", "u=1"),
        ("DNT", "1"),
        ("Sec-Fetch-User", "?1"),
        ("Sec-Fetch-Mode", "navigate"),
        ("X-App-Mode", "full"),
        ("Cookie", "cookie-canary"),
        ("Authorization", "auth-canary"),
        ("Proxy-Authorization", "proxy-canary"),
        ("Host", "private.example"),
        ("Sec-WebSocket-Key", "nonce-canary"),
        ("Origin", "https://private.example"),
        ("Referer", "https://private.example/account"),
        ("Content-Length", "18"),
        (
            "Content-Type",
            "multipart/form-data; boundary=boundary-canary",
        ),
        ("If-None-Match", "validator-canary"),
        ("Range", "bytes=0-1"),
    ]);
    let mut secret = HeaderValue::from_static("custom-canary");
    secret.set_sensitive(true);
    input.append("x-secret", secret);
    let policy = HeaderCapturePolicy::default();
    let capture = policy
        .capture(
            ProfileCaptureCompleteness::Complete,
            Version::HTTP_11,
            &input,
            None,
        )
        .unwrap();
    for (index, field) in capture.fields.iter().enumerate() {
        assert_eq!(
            matches!(field.value, HeaderValueSource::Profile(_)),
            index < 11,
            "{}",
            field.name
        );
    }
    let value = capture.canonical(&policy).unwrap();
    for canary in [
        "cookie-canary",
        "auth-canary",
        "proxy-canary",
        "private.example",
        "nonce-canary",
        "boundary-canary",
        "validator-canary",
        "custom-canary",
    ] {
        assert!(
            !value
                .bytes
                .windows(canary.len())
                .any(|v| v == canary.as_bytes()),
            "{canary}"
        );
    }
    let decoded = HeaderCapture::from_canonical(&value, &policy).unwrap();
    assert_eq!(decoded.canonical(&policy).unwrap().id, value.id);
}

#[test]
fn request_nonces_and_body_lengths_do_not_create_profile_variants() {
    let mut ids = BTreeSet::new();
    for number in 0..1000 {
        ids.insert(
            encode(&headers(&[
                ("User-Agent", "reference/1"),
                ("Sec-WebSocket-Key", &format!("key-{number}")),
                ("Content-Length", &number.to_string()),
                (
                    "Content-Type",
                    &format!("multipart/form-data; boundary=nonce-{number}"),
                ),
            ]))
            .id,
        );
    }
    assert_eq!(ids.len(), 1);
    let absent = encode(&headers(&[("User-Agent", "reference/1")]));
    let present = encode(&headers(&[
        ("User-Agent", "reference/1"),
        ("Cookie", "secret"),
    ]));
    let changed = encode(&headers(&[
        ("User-Agent", "reference/1"),
        ("Cookie", "another"),
    ]));
    assert_ne!(absent.id, present.id);
    assert_eq!(present.id, changed.id);
}

#[test]
fn header_import_overrides_cannot_retain_protocol_or_sensitive_values() {
    let mut policy = HeaderCapturePolicy::default();
    for name in [
        "cookie",
        "authorization",
        "content-length",
        "content-type",
        "sec-websocket-key",
        "host",
        "origin",
        "referer",
    ] {
        policy.overrides = vec![HeaderOwnershipOverride {
            name: HeaderName::from_bytes(name.as_bytes()).unwrap(),
            ownership: HeaderOwnership::Profile,
        }]
        .into();
        policy
            .capture(
                ProfileCaptureCompleteness::Complete,
                Version::HTTP_11,
                &headers(&[(name, "1")]),
                None,
            )
            .unwrap_err();
    }
    policy.overrides = vec![HeaderOwnershipOverride {
        name: HeaderName::from_static("x-app"),
        ownership: HeaderOwnership::Profile,
    }]
    .into();
    let input = headers(&[("X-App", "capture-safe")]);
    let capture = policy
        .capture(
            ProfileCaptureCompleteness::Complete,
            Version::HTTP_11,
            &input,
            None,
        )
        .unwrap();
    assert!(
        matches!(&capture.fields[0].value, HeaderValueSource::Profile(value) if &**value == b"capture-safe")
    );
    policy.overrides[0].ownership = HeaderOwnership::Request;
    assert!(matches!(
        policy
            .capture(
                ProfileCaptureCompleteness::Complete,
                Version::HTTP_11,
                &input,
                None
            )
            .unwrap()
            .fields[0]
            .value,
        HeaderValueSource::Request(RequestBinding::Custom)
    ));
    policy.overrides[0].ownership = HeaderOwnership::Profile;
    let mut input = input;
    input.get_mut("x-app").unwrap().set_sensitive(true);
    policy
        .capture(
            ProfileCaptureCompleteness::Complete,
            Version::HTTP_11,
            &input,
            None,
        )
        .unwrap_err();
    let input = headers(&[("Connection", "x-app"), ("X-App", "connection-secret")]);
    policy
        .capture(
            ProfileCaptureCompleteness::Complete,
            Version::HTTP_11,
            &input,
            None,
        )
        .unwrap_err();
    policy.overrides = Box::default();
    let capture = policy
        .capture(
            ProfileCaptureCompleteness::Complete,
            Version::HTTP_11,
            &input,
            None,
        )
        .unwrap();
    assert!(matches!(
        capture.fields[1].value,
        HeaderValueSource::Request(RequestBinding::Connection)
    ));
}

#[test]
fn forwarding_identifiers_proofs_and_body_fields_never_become_profile_values() {
    let names = [
        ("forwarded", RequestBinding::Forwarding),
        ("x-forwarded-for", RequestBinding::Forwarding),
        ("x-forwarded-host", RequestBinding::Forwarding),
        ("x-forwarded-proto", RequestBinding::Forwarding),
        ("x-forwarded-port", RequestBinding::Forwarding),
        ("x-real-ip", RequestBinding::Forwarding),
        ("via", RequestBinding::Forwarding),
        ("alt-used", RequestBinding::Authority),
        ("traceparent", RequestBinding::PerRequestId),
        ("tracestate", RequestBinding::PerRequestId),
        ("baggage", RequestBinding::PerRequestId),
        ("x-request-id", RequestBinding::PerRequestId),
        ("request-id", RequestBinding::PerRequestId),
        ("x-correlation-id", RequestBinding::PerRequestId),
        ("correlation-id", RequestBinding::PerRequestId),
        ("idempotency-key", RequestBinding::PerRequestId),
        ("dpop", RequestBinding::Proof),
        ("sec-websocket-protocol", RequestBinding::WebSocketProtocol),
        ("expect", RequestBinding::BodyMetadata),
        ("signature", RequestBinding::Proof),
        ("signature-input", RequestBinding::Proof),
        ("last-event-id", RequestBinding::PerRequestId),
        ("ping-from", RequestBinding::Referer),
        ("ping-to", RequestBinding::Referer),
        ("cdn-loop", RequestBinding::Forwarding),
        ("max-forwards", RequestBinding::Forwarding),
        ("early-data", RequestBinding::Connection),
        ("http2-settings", RequestBinding::Connection),
        ("content-language", RequestBinding::BodyMetadata),
        ("content-location", RequestBinding::BodyMetadata),
        ("content-custom", RequestBinding::BodyMetadata),
    ];
    let secret = "private-binding-canary";
    let policy = HeaderCapturePolicy::default();
    for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
        for (name, binding) in names {
            let captured = policy
                .capture(
                    ProfileCaptureCompleteness::Complete,
                    version,
                    &headers(&[(name, secret)]),
                    None,
                )
                .unwrap();
            assert!(
                matches!(captured.fields[0].value, HeaderValueSource::Request(value) if value == binding)
            );
            let value = captured.canonical(&policy).unwrap();
            assert!(
                !value
                    .bytes
                    .windows(secret.len())
                    .any(|bytes| bytes == secret.as_bytes())
            );
            let changed = policy
                .capture(
                    ProfileCaptureCompleteness::Complete,
                    version,
                    &headers(&[(name, "another-request")]),
                    None,
                )
                .unwrap()
                .canonical(&policy)
                .unwrap();
            assert_eq!(changed.id, value.id);
            assert_eq!(
                HeaderCapture::from_canonical(&value, &policy)
                    .unwrap()
                    .canonical(&policy)
                    .unwrap()
                    .id,
                value.id
            );
            let mut bucket = CountedObservationBucket::new(
                CanonicalDomain::Headers,
                ValueId([2; 32]),
                [3; 32],
                ProfileBucketLimits::default(),
            )
            .unwrap();
            bucket
                .observe(
                    ObservationId {
                        run: [1; 16],
                        sequence: 1,
                    },
                    &value,
                )
                .unwrap();
            let numeric = serde_json::to_string(secret.as_bytes()).unwrap();
            let debug_numeric = format!("{:?}", secret.as_bytes());
            for output in [
                serde_json::to_string(&captured).unwrap(),
                serde_json::to_string(&bucket.snapshot()).unwrap(),
            ] {
                assert!(!output.contains(secret));
                assert!(!output.contains(&numeric[1..numeric.len() - 1]));
            }
            for output in [format!("{captured:?}"), format!("{:?}", bucket.snapshot())] {
                assert!(!output.contains(secret));
                assert!(!output.contains(&debug_numeric[1..debug_numeric.len() - 1]));
            }
            let mut forged = captured;
            forged.fields[0].value = HeaderValueSource::Profile(secret.as_bytes().into());
            forged.canonical(&policy).unwrap_err();
            let mut override_policy = policy.clone();
            override_policy.overrides = vec![HeaderOwnershipOverride {
                name: HeaderName::from_bytes(name.as_bytes()).unwrap(),
                ownership: HeaderOwnership::Profile,
            }]
            .into();
            override_policy
                .capture(
                    ProfileCaptureCompleteness::Complete,
                    version,
                    &headers(&[(name, secret)]),
                    None,
                )
                .unwrap_err();
        }
    }
}

#[test]
fn canonical_and_decoded_imports_enforce_explicit_ownership_overrides() {
    let mut policy = HeaderCapturePolicy::default();
    let input = headers(&[("x-app", "capture-safe")]);
    let captured = policy
        .capture(
            ProfileCaptureCompleteness::Complete,
            Version::HTTP_11,
            &input,
            None,
        )
        .unwrap();
    let encoded = captured.canonical(&policy).unwrap();
    policy.overrides = vec![HeaderOwnershipOverride {
        name: HeaderName::from_static("x-app"),
        ownership: HeaderOwnership::Request,
    }]
    .into();
    captured.canonical(&policy).unwrap_err();
    HeaderCapture::from_canonical(&encoded, &policy).unwrap_err();
    let safe = policy
        .capture(
            ProfileCaptureCompleteness::Complete,
            Version::HTTP_11,
            &input,
            None,
        )
        .unwrap();
    safe.canonical(&policy).unwrap();
    policy.overrides[0].ownership = HeaderOwnership::Profile;
    assert_eq!(captured.canonical(&policy).unwrap().id, encoded.id);
    policy.overrides = vec![policy.overrides[0].clone(); 2].into();
    captured.canonical(&policy).unwrap_err();
    HeaderCapture::from_canonical(&encoded, &policy).unwrap_err();
    policy.overrides = vec![HeaderOwnershipOverride {
        name: HeaderName::from_static("cookie"),
        ownership: HeaderOwnership::Profile,
    }]
    .into();
    let cookies = HeaderCapturePolicy::default()
        .capture(
            ProfileCaptureCompleteness::Complete,
            Version::HTTP_11,
            &headers(&[("cookie", "excluded")]),
            None,
        )
        .unwrap();
    cookies.canonical(&policy).unwrap_err();
}

#[test]
fn custom_credential_and_trace_defaults_require_explicit_capture_safe_values() {
    let names = [
        "sentry-trace",
        "b3",
        "x-b3-traceid",
        "x-amzn-trace-id",
        "x-cloud-trace-context",
        "x-datadog-parent-id",
        "uber-trace-id",
        "newrelic",
        "true-client-ip",
        "x-client-ip",
        "client-ip",
        "x-cluster-client-ip",
        "cf-connecting-ip",
        "fastly-client-ip",
        "x-csrf-token",
        "x-xsrf-token",
        "x-api-key",
        "api-key",
        "x-apikey",
        "x-auth",
        "x-authorization",
        "password",
        "x-credential",
        "x-bearer",
        "x-jwt",
        "sec-private-state-token-crypto-version",
        "x-auth-token",
        "x-access-token",
        "x-amz-security-token",
        "my-secret",
        "session-key",
        "request-signature",
    ];
    let secret = "custom-private-canary";
    for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
        for name in names {
            let mut policy = HeaderCapturePolicy::default();
            let input = headers(&[(name, secret)]);
            let captured = policy
                .capture(ProfileCaptureCompleteness::Complete, version, &input, None)
                .unwrap();
            assert!(matches!(
                captured.fields[0].value,
                HeaderValueSource::Request(_)
            ));
            let canonical = captured.canonical(&policy).unwrap();
            assert!(
                !canonical
                    .bytes
                    .windows(secret.len())
                    .any(|part| part == secret.as_bytes())
            );
            let mut bucket = CountedObservationBucket::new(
                CanonicalDomain::Headers,
                ValueId([2; 32]),
                [3; 32],
                ProfileBucketLimits::default(),
            )
            .unwrap();
            bucket
                .observe(
                    ObservationId {
                        run: [1; 16],
                        sequence: 1,
                    },
                    &canonical,
                )
                .unwrap();
            let numeric = serde_json::to_string(secret.as_bytes()).unwrap();
            let debug_numeric = format!("{:?}", secret.as_bytes());
            for output in [
                serde_json::to_string(&captured).unwrap(),
                serde_json::to_string(&bucket.snapshot()).unwrap(),
                format!("{captured:?}"),
                format!("{:?}", bucket.snapshot()),
            ] {
                assert!(!output.contains(secret));
                assert!(!output.contains(&numeric[1..numeric.len() - 1]));
                assert!(!output.contains(&debug_numeric[1..debug_numeric.len() - 1]));
            }
            let mut forged = captured;
            forged.fields[0].value = HeaderValueSource::Profile(secret.as_bytes().into());
            forged.canonical(&policy).unwrap_err();
            policy.overrides = vec![HeaderOwnershipOverride {
                name: HeaderName::from_bytes(name.as_bytes()).unwrap(),
                ownership: HeaderOwnership::Profile,
            }]
            .into();
            let safe = policy
                .capture(
                    ProfileCaptureCompleteness::Complete,
                    version,
                    &headers(&[(name, "fixed-safe-mode")]),
                    None,
                )
                .unwrap();
            assert!(matches!(
                safe.fields[0].value,
                HeaderValueSource::CaptureSafeProfile(_)
            ));
            let value = safe.canonical(&policy).unwrap();
            // The explicit importer assertion survives storage/structural validation.
            value.validated_domain(policy.bytes).unwrap();
            safe.structural(&HeaderCapturePolicy::default()).unwrap();
            assert_eq!(
                HeaderCapture::from_canonical(&value, &HeaderCapturePolicy::default())
                    .unwrap()
                    .canonical(&HeaderCapturePolicy::default())
                    .unwrap()
                    .id,
                value.id
            );
            let mut flagged = HeaderValue::from_static("never-safe");
            flagged.set_sensitive(true);
            let mut sensitive = HeaderMap::new();
            sensitive.insert(HeaderName::from_bytes(name.as_bytes()).unwrap(), flagged);
            policy
                .capture(
                    ProfileCaptureCompleteness::Complete,
                    version,
                    &sensitive,
                    None,
                )
                .unwrap_err();
        }
    }
}

#[test]
fn explicit_capture_safe_literals_cannot_override_protocol_or_sensitive_bindings() {
    let policy = HeaderCapturePolicy::default();
    for name in [
        "authorization",
        "cookie",
        "signature",
        "content-location",
        "forwarded",
    ] {
        let mut captured = policy
            .capture(
                ProfileCaptureCompleteness::Complete,
                Version::HTTP_11,
                &headers(&[(name, "private-canary")]),
                None,
            )
            .unwrap();
        captured.fields[0].value =
            HeaderValueSource::CaptureSafeProfile(b"private-canary".as_slice().into());
        captured.canonical(&policy).unwrap_err();
    }
}
