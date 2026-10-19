use super::*;

#[test]
fn default_request_selects_fresh_navigation_across_quic_token_states() {
    for token_present in [false, true] {
        let observed_context = ConnectionContext {
            resumption: ResumptionContext::Fresh,
            early_data: Some(false),
            token_present: Some(token_present),
            ip_family: Some(ConnectionIpFamily::V6),
        };
        let mut captured = profile("browser", h3_capabilities(), observed_context.clone());
        set_request_flow(
            &mut captured,
            FlowKey::Http {
                version: Version::HTTP_3,
                method: Method::GET,
                initiator: Some(RequestInitiator::Navigate),
                fetch: Some(FetchContext {
                    mode: Some("navigate".into()),
                    site: Some("none".into()),
                    destination: Some("document".into()),
                    user_activation: Some("?1".into()),
                }),
                connection: observed_context,
            },
        );
        let database: UserAgentDatabase = [captured].into_iter().collect();
        let request = request(ConnectionContext::default());

        let selected = database
            .select(&request, ProfileSeed([50; 32]), DrawKey([51; 32]))
            .unwrap();
        selected
            .connection(
                &ConnectionContext::default(),
                ProfileSeed([50; 32]),
                DrawKey([52; 32]),
            )
            .unwrap();
    }
}

#[test]
fn request_shape_selects_cookie_variant_and_ignores_unobserved_caller_fields() {
    let context = ConnectionContext::default();
    let empty = request_variant();
    let cookie = request_variant_with_headers(
        Version::HTTP_3,
        (0..2)
            .map(|occurrence| HeaderOccurrence {
                name: HeaderName::from_static("cookie"),
                occurrence,
                sensitive: true,
                representation: None,
                value: HeaderValueSource::Request(RequestBinding::Cookie),
            })
            .collect(),
    );
    let mut captured = profile("browser", h3_capabilities(), context.clone());
    let analysis = Arc::make_mut(captured.captured.as_mut().unwrap());
    let scope = analysis
        .scopes
        .iter_mut()
        .find(|scope| scope.context.flow.is_some())
        .unwrap();
    scope.observations.counts = counts(2);
    scope.observations.retained_samples = 2;
    scope.observations.sample_values = Box::new([empty.id, cookie.id]);
    scope.observations.variants = Box::new([
        AnalyzedCaptureVariant {
            value: empty.clone(),
            weight: AnalyzedOrderWeight::Counted(ObservationWeight::Exact(1)),
        },
        AnalyzedCaptureVariant {
            value: cookie.clone(),
            weight: AnalyzedOrderWeight::Counted(ObservationWeight::Exact(1)),
        },
    ]);

    let database: UserAgentDatabase = [captured].into_iter().collect();
    let selected = database
        .select(
            &request(context.clone()),
            ProfileSeed([53; 32]),
            DrawKey([54; 32]),
        )
        .unwrap();
    let connection = selected
        .connection(&context, ProfileSeed([53; 32]), DrawKey([55; 32]))
        .unwrap();
    let flow = flow(context.clone(), Version::HTTP_3);

    let selected_empty = selected
        .request(
            &connection,
            &flow,
            &HeaderMap::new(),
            ProfileSeed([53; 32]),
            DrawKey([56; 32]),
        )
        .unwrap();
    assert_eq!(selected_empty.variant, empty.id);

    let mut cookie_headers = HeaderMap::new();
    cookie_headers.insert(
        "cookie",
        HeaderValue::from_static("session=secret; other=value"),
    );
    let selected_cookie = selected
        .request(
            &connection,
            &flow,
            &cookie_headers,
            ProfileSeed([53; 32]),
            DrawKey([57; 32]),
        )
        .unwrap();
    assert_eq!(selected_cookie.variant, cookie.id);
    let replayed = selected_cookie.replay_request(&cookie_headers).unwrap();
    assert!(replayed.report.is_exact());
    let headers = replayed.headers.unwrap();
    assert_eq!(
        headers
            .get_all("cookie")
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect::<Vec<_>>(),
        ["session=secret", "other=value"]
    );

    let mut caller_headers = HeaderMap::new();
    caller_headers.insert("authorization", HeaderValue::from_static("Bearer secret"));
    let selected_caller = selected
        .request(
            &connection,
            &flow,
            &caller_headers,
            ProfileSeed([53; 32]),
            DrawKey([58; 32]),
        )
        .unwrap();
    assert_eq!(selected_caller.variant, empty.id);

    let mut pinned_request = request(context.clone());
    pinned_request.pins.request = Some(cookie.id);
    let pinned = database
        .select(&pinned_request, ProfileSeed([53; 32]), DrawKey([59; 32]))
        .unwrap();
    let pinned_connection = pinned
        .connection(&context, ProfileSeed([53; 32]), DrawKey([60; 32]))
        .unwrap();
    // A pin without a matching request shape still replays its variant.
    let pinned = pinned
        .request(
            &pinned_connection,
            &flow,
            &HeaderMap::new(),
            ProfileSeed([53; 32]),
            DrawKey([61; 32]),
        )
        .unwrap();
    assert_eq!(pinned.variant, cookie.id);
    assert!(
        !pinned
            .replay_request(&HeaderMap::new())
            .unwrap()
            .report
            .is_exact()
    );
}

#[test]
fn equal_protocol_classifiers_derive_the_same_request_key_across_profiles() {
    let context = ConnectionContext::default();
    let database: UserAgentDatabase = [profile("complete", h3_capabilities(), context.clone())]
        .into_iter()
        .collect();
    let selected = database
        .select(&request(context), ProfileSeed([31; 32]), DrawKey([32; 32]))
        .unwrap();
    let mut other = selected.clone();
    other.id = ValueId([77; 32]);
    let first = Arc::new(selected).emulation_context(
        ProfileSeed([31; 32]),
        DrawKey([34; 32]),
        DrawKey([35; 32]),
    );
    let second = Arc::new(other).emulation_context(
        ProfileSeed([31; 32]),
        DrawKey([34; 32]),
        DrawKey([35; 32]),
    );
    let policies = [
        ProfileConnectionReuse::new(&first, Version::HTTP_3, &Extensions::new()),
        ProfileConnectionReuse::new(&second, Version::HTTP_3, &Extensions::new()),
    ];
    assert_eq!(policies[0].classifier(), policies[1].classifier());
    assert_ne!(policies[0].connection_key(), policies[1].connection_key());
    for context in [first, second] {
        let input = Extensions::new();
        context.publish(&input);
        assert!(policies[0].request_key(&input).is_some());
        assert_eq!(
            policies[0].request_key(&input),
            policies[1].request_key(&input)
        );
    }
}

#[test]
fn repeated_profile_selection_shares_lazy_request_shape_cache() {
    let context = ConnectionContext::default();
    let database: UserAgentDatabase = [profile("complete", h3_capabilities(), context.clone())]
        .into_iter()
        .collect();
    let request = request(context);
    let first = database
        .select(&request, ProfileSeed([41; 32]), DrawKey([42; 32]))
        .unwrap();
    let second = database
        .select(&request, ProfileSeed([43; 32]), DrawKey([44; 32]))
        .unwrap();

    assert!(Arc::ptr_eq(&first.request_shapes, &second.request_shapes));
    assert!(!first.request_shapes.is_initialized());
    let analysis = first.profile.captured.as_ref().unwrap();
    let scope = analysis
        .scopes
        .iter()
        .position(|scope| scope.context.flow.is_some())
        .unwrap();
    let first_shape = first
        .request_shapes
        .shape(analysis, scope, 0, Version::HTTP_3)
        .unwrap();
    let second_shape = second
        .request_shapes
        .shape(analysis, scope, 0, Version::HTTP_3)
        .unwrap();
    assert!(ptr::eq(first_shape, second_shape));
    assert!(first.request_shapes.is_initialized());
}

#[test]
fn request_shape_cache_does_not_alias_distinct_values_with_the_same_supplied_id() {
    let mut profile = profile("complete", h3_capabilities(), ConnectionContext::default());
    let analysis = Arc::make_mut(profile.captured.as_mut().unwrap());
    let scope = analysis
        .scopes
        .iter()
        .position(|scope| scope.context.flow.is_some())
        .unwrap();
    let valid = analysis.scopes[scope].observations.variants[0].clone();
    let mut invalid = valid.clone();
    invalid.value.bytes[0] ^= 1;
    analysis.scopes[scope].observations.variants = vec![invalid, valid].into();

    let cache = RequestShapeCache::default();
    cache
        .shape(analysis, scope, 0, Version::HTTP_3)
        .unwrap_err();
    cache.shape(analysis, scope, 1, Version::HTTP_3).unwrap();
}

#[test]
fn cookie_crumb_count_is_request_owned_but_other_occurrences_remain_exact() {
    for version in [Version::HTTP_2, Version::HTTP_3] {
        for name in ["cookie", "set-cookie"] {
            let capture = |count| {
                request_variant_with_headers(
                    version,
                    (0..count)
                        .map(|occurrence| HeaderOccurrence {
                            name: HeaderName::from_static(name),
                            occurrence,
                            sensitive: true,
                            representation: None,
                            value: HeaderValueSource::Request(RequestBinding::Cookie),
                        })
                        .collect(),
                )
            };
            let one = request_header_shape(&capture(1)).unwrap();
            let two = request_header_shape(&capture(2)).unwrap();
            assert_eq!(one.fields == two.fields, name == "cookie");
        }
    }
}

#[test]
fn cookie_layout_evidence_uses_other_variants_without_crossing_protocols() {
    let mut profile = profile("complete", h3_capabilities(), ConnectionContext::default());
    let analysis = Arc::make_mut(profile.captured.as_mut().unwrap());
    let scope = analysis
        .scopes
        .iter()
        .position(|scope| scope.context.flow.is_some())
        .unwrap();
    let mut one = analysis.scopes[scope].observations.variants[0].clone();
    let capture = |count| {
        request_variant_with_headers(
            Version::HTTP_3,
            (0..count)
                .map(|occurrence| HeaderOccurrence {
                    name: COOKIE,
                    occurrence,
                    sensitive: true,
                    representation: None,
                    value: HeaderValueSource::Request(RequestBinding::Cookie),
                })
                .collect(),
        )
    };
    one.value = capture(1);
    analysis.scopes[scope].observations.variants = vec![one.clone()].into();
    assert_eq!(
        RequestShapeCache::default().cookie_layout(analysis, Version::HTTP_3),
        CookieLayoutEvidence::Unknown
    );

    let mut two = one.clone();
    two.value = capture(2);
    analysis.scopes[scope].observations.variants = vec![one, two].into();
    let cache = RequestShapeCache::default();
    assert_eq!(
        cache.cookie_layout(analysis, Version::HTTP_3),
        CookieLayoutEvidence::Split
    );
    assert_eq!(
        cache.cookie_layout(analysis, Version::HTTP_2),
        CookieLayoutEvidence::Unknown
    );
    assert_eq!(
        cache.cookie_layout(analysis, Version::HTTP_11),
        CookieLayoutEvidence::Unknown
    );
}

#[test]
fn pinned_single_cookie_variant_uses_other_capture_layout_evidence() {
    let context = ConnectionContext::default();
    let capture = |count| {
        request_variant_with_headers(
            Version::HTTP_3,
            (0..count)
                .map(|occurrence| HeaderOccurrence {
                    name: COOKIE,
                    occurrence,
                    sensitive: true,
                    representation: None,
                    value: HeaderValueSource::Request(RequestBinding::Cookie),
                })
                .collect(),
        )
    };
    let one = capture(1);
    let two = capture(2);
    let mut captured = profile("browser", h3_capabilities(), context.clone());
    let analysis = Arc::make_mut(captured.captured.as_mut().unwrap());
    let scope = analysis
        .scopes
        .iter_mut()
        .find(|scope| scope.context.flow.is_some())
        .unwrap();
    scope.observations.counts = counts(2);
    scope.observations.retained_samples = 2;
    scope.observations.sample_values = Box::new([one.id, two.id]);
    scope.observations.variants = [one.clone(), two]
        .map(|value| AnalyzedCaptureVariant {
            value,
            weight: AnalyzedOrderWeight::Counted(ObservationWeight::Exact(1)),
        })
        .into();
    let database: UserAgentDatabase = [captured].into_iter().collect();
    let mut query = request(context.clone());
    query.pins.request = Some(one.id);
    let seed = ProfileSeed([71; 32]);
    let selected = database.select(&query, seed, DrawKey([72; 32])).unwrap();
    let connection = selected
        .connection(&context, seed, DrawKey([73; 32]))
        .unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(COOKIE, HeaderValue::from_static("a=1; b=2; c=3"));
    let request = selected
        .request(
            &connection,
            &flow(context, Version::HTTP_3),
            &headers,
            seed,
            DrawKey([74; 32]),
        )
        .unwrap();
    assert_eq!(request.variant, one.id);
    assert_eq!(request.effective.cookie_layout, CookieLayoutEvidence::Split);
    let replayed = request.replay_request(&headers).unwrap();
    assert!(replayed.report.is_exact());
    let headers = replayed.headers.unwrap();
    assert_eq!(
        headers
            .get_all(COOKIE)
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect::<Vec<_>>(),
        ["a=1", "b=2", "c=3"]
    );
}
