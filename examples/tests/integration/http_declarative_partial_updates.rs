use super::utils;
use rama::{
    futures::StreamExt,
    http::{
        BodyExtractExt, StatusCode,
        headers::{ContentType, HeaderMapExt},
        mime,
    },
};
use std::time::{Duration, Instant};

/// String that only ever appears in the polyfill `<script src>` tag, so
/// its presence is an exact signal for `?polyfill=…` gating.
const POLYFILL_NEEDLE: &str = "template-for-polyfill";

#[tokio::test]
#[ignore]
async fn test_http_declarative_partial_updates() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("http_declarative_partial_updates", None);

    // -- ?polyfill toggle --------------------------------------------------
    //
    // Fast pre-checks that exercise the Query extractor; done first so the
    // 4s streaming run doesn't tie up the server.
    for (url, want, why) in [
        (
            "http://127.0.0.1:64805/?polyfill=false",
            false,
            "explicit false must omit the polyfill",
        ),
        (
            "http://127.0.0.1:64805/?polyfill=true",
            true,
            "explicit true must include the polyfill",
        ),
        (
            "http://127.0.0.1:64805/?other=1",
            true,
            "unrelated query params must still default to on",
        ),
        (
            "http://127.0.0.1:64805",
            true,
            "no query string must default to on",
        ),
    ] {
        let body = runner
            .get(url)
            .send()
            .await
            .unwrap()
            .try_into_string()
            .await
            .unwrap();
        assert_eq!(body.contains(POLYFILL_NEEDLE), want, "{why}");
    }

    // -- streaming behaviour ----------------------------------------------

    let response = runner.get("http://127.0.0.1:64805").send().await.unwrap();
    assert_eq!(StatusCode::OK, response.status());
    assert!(
        response
            .headers()
            .typed_get::<ContentType>()
            .map(|ct| ct.mime().eq(&mime::TEXT_HTML_UTF_8))
            .unwrap_or_default()
    );

    let mut body = response.into_body().into_data_stream();
    let first = body.next().await.unwrap().unwrap();
    let t0 = Instant::now();
    let first_str = std::str::from_utf8(&first).unwrap();
    for m in ["recs", "herd", "ping"] {
        assert!(
            first_str.contains(&format!(r#"<?start name="{m}">"#)),
            "shell missing start marker {m}"
        );
    }
    for m in ["recs", "herd", "ping"] {
        assert!(
            !first_str.contains(&format!(r#"<template for="{m}">"#)),
            "shell must not yet contain the {m} fragment template"
        );
    }

    let mut fragments: Vec<(Duration, String)> = Vec::new();
    while let Some(chunk) = body.next().await {
        let bytes = chunk.unwrap();
        fragments.push((
            t0.elapsed(),
            String::from_utf8(bytes.to_vec()).expect("utf8"),
        ));
    }

    // Fragment chunks must arrive in completion order — fastest first —
    // each within a generous window around its server-side delay. Wide
    // tolerances (-300ms / +1500ms) survive CI scheduler jitter and the
    // streaming compressor's per-chunk overhead, while still failing if
    // chunks get pre-buffered, batched, or arrive in declaration order.
    assert_eq!(
        fragments.len(),
        3,
        "expected exactly 3 fragment chunks after the shell, got {}",
        fragments.len()
    );
    let expected = [
        ("ping", Duration::from_millis(500)),
        ("herd", Duration::from_millis(2000)),
        ("recs", Duration::from_millis(4000)),
    ];
    for ((arrival, body), (name, want)) in fragments.iter().zip(expected.iter()) {
        let lower = want.saturating_sub(Duration::from_millis(300));
        let upper = *want + Duration::from_millis(1500);
        assert!(
            *arrival >= lower && *arrival <= upper,
            "fragment {name} arrived at {arrival:?}, want within [{lower:?}, {upper:?}]"
        );
        assert!(
            body.contains(&format!(r#"<template for="{name}">"#)),
            "chunk at {arrival:?} should be the {name} fragment, got: {body:?}"
        );
    }
}
