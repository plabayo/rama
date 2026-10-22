#[path = "support/representative.rs"]
mod representative;

#[tokio::test]
async fn representative_pac_routes_are_stable_across_repeated_calls() {
    let resolver = resolver_support::builder()
        .build_static(representative::SCRIPT)
        .unwrap();
    for _ in 0..3 {
        for (url, expected) in representative::CASES {
            let actual = resolver.find_proxy(&url.parse().unwrap()).await.unwrap();
            assert_eq!(actual.to_string(), expected, "{url}");
        }
    }
}

#[path = "support/resolver.rs"]
mod resolver_support;

#[path = "support/runtime.rs"]
mod runtime_support;
