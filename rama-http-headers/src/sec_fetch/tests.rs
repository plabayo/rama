use rama_http_types::{HeaderMap, HeaderValue, header};

use super::*;

fn headers(fields: &[(&'static str, &'static str)]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in fields {
        headers.append(*name, HeaderValue::from_static(value));
    }
    headers
}

fn navigation() -> FetchMetadata {
    FetchMetadata::default()
        .with_site(SecFetchSite::None)
        .with_mode(SecFetchMode::Navigate)
        .with_dest(SecFetchDest::Document)
        .with_user(true)
}

#[test]
fn no_headers_is_none() {
    assert_eq!(FetchMetadata::from_headers(&HeaderMap::new()), None);
    assert_eq!(
        FetchMetadata::from_headers(&headers(&[("accept", "*/*")])),
        None
    );
}

#[test]
fn full_set() {
    let metadata = FetchMetadata::from_headers(&headers(&[
        ("sec-fetch-site", "none"),
        ("sec-fetch-mode", "navigate"),
        ("sec-fetch-dest", "document"),
        ("sec-fetch-user", "?1"),
    ]));
    assert_eq!(metadata, Some(navigation()));
}

#[test]
fn partial_set_keeps_present_fields() {
    let metadata =
        FetchMetadata::from_headers(&headers(&[("sec-fetch-site", "cross-site")])).unwrap();
    assert_eq!(
        metadata,
        FetchMetadata::default().with_site(SecFetchSite::CrossSite)
    );

    let metadata = FetchMetadata::from_headers(&headers(&[
        ("sec-fetch-mode", "no-cors"),
        ("sec-fetch-dest", "audio"),
    ]))
    .unwrap();
    assert_eq!(metadata.site, None);
    assert_eq!(metadata.mode, Some(SecFetchMode::NoCors));
    assert_eq!(metadata.dest, Some(SecFetchDest::Audio));
    assert!(!metadata.user);
}

#[test]
fn invalid_headers_leave_fields_empty() {
    let metadata = FetchMetadata::from_headers(&headers(&[
        ("sec-fetch-site", "same-origin"),
        ("sec-fetch-site", "cross-site"),
        ("sec-fetch-mode", ""),
        ("sec-fetch-dest", "image"),
        ("sec-fetch-user", "?0"),
    ]))
    .unwrap();
    assert_eq!(
        metadata,
        FetchMetadata::default().with_dest(SecFetchDest::Image)
    );

    // Only invalid values: the same answer as no metadata at all.
    assert_eq!(
        FetchMetadata::from_headers(&headers(&[
            ("sec-fetch-user", "?0"),
            ("sec-fetch-mode", "")
        ])),
        None
    );
}

#[test]
fn unknown_values_are_kept() {
    let metadata = FetchMetadata::from_headers(&headers(&[
        ("sec-fetch-mode", "webtransport"),
        ("sec-fetch-dest", "speculationrules"),
    ]))
    .unwrap();
    assert_eq!(
        metadata.mode,
        Some(SecFetchMode::Unknown("webtransport".into()))
    );
    assert_eq!(
        metadata.dest,
        Some(SecFetchDest::Unknown("speculationrules".into()))
    );
}

#[test]
fn insert_into_round_trips() {
    for metadata in [
        navigation(),
        FetchMetadata::default().with_site(SecFetchSite::SameSite),
        FetchMetadata::default()
            .with_mode(SecFetchMode::Cors)
            .with_dest(SecFetchDest::Empty),
        FetchMetadata::default().with_dest(SecFetchDest::Unknown("speculationrules".into())),
    ] {
        let mut headers = HeaderMap::new();
        metadata.insert_into(&mut headers);
        assert_eq!(FetchMetadata::from_headers(&headers), Some(metadata));
    }
}

#[test]
fn insert_into_writes_wire_values() {
    let mut headers = HeaderMap::new();
    navigation().insert_into(&mut headers);
    assert_eq!(headers.len(), 4);
    assert_eq!(headers[header::SEC_FETCH_SITE], "none");
    assert_eq!(headers[header::SEC_FETCH_MODE], "navigate");
    assert_eq!(headers[header::SEC_FETCH_DEST], "document");
    assert_eq!(headers[header::SEC_FETCH_USER], "?1");
}

#[test]
fn insert_into_replaces_and_removes() {
    let mut headers = headers(&[
        ("sec-fetch-site", "cross-site"),
        ("sec-fetch-mode", "navigate"),
        ("sec-fetch-dest", "document"),
        ("sec-fetch-user", "?1"),
        ("accept", "*/*"),
    ]);
    let subresource = FetchMetadata::default()
        .with_site(SecFetchSite::SameOrigin)
        .with_mode(SecFetchMode::NoCors);
    subresource.insert_into(&mut headers);

    assert_eq!(headers[header::SEC_FETCH_SITE], "same-origin");
    assert_eq!(headers[header::SEC_FETCH_MODE], "no-cors");
    assert!(!headers.contains_key(header::SEC_FETCH_DEST));
    assert!(!headers.contains_key(header::SEC_FETCH_USER));
    assert_eq!(headers[header::ACCEPT], "*/*");

    FetchMetadata::default().insert_into(&mut headers);
    assert_eq!(FetchMetadata::from_headers(&headers), None);
    assert_eq!(headers.len(), 1);
}

#[test]
fn builder_set_and_unset() {
    let mut metadata = navigation();
    metadata.unset_dest().set_user(false);
    assert_eq!(metadata.dest, None);
    assert!(!metadata.user);

    let metadata = metadata.without_site().without_mode().maybe_with_dest(None);
    assert!(metadata.is_empty());
}
