//! Fetch Metadata headers.

use rama_http_types::HeaderMap;

use crate::{
    FetchMetadata, SecFetchDest, SecFetchMode, SecFetchSite, SecFetchUser,
    fuzz::{
        ValuesExercise,
        support::{sink, token},
    },
};

/// Drive a single decoded field through [`FetchMetadata`] and back.
fn metadata(metadata: &FetchMetadata) {
    let mut headers = HeaderMap::new();
    metadata.insert_into(&mut headers);
    let again = FetchMetadata::from_headers(&headers);
    assert_eq!(again.as_ref(), Some(metadata), "{headers:?}");
}

pub(super) const HEADERS: &[ValuesExercise] = &[
    decode!(SecFetchDest, |h| {
        token(&h);
        sink(h.as_str());
        metadata(&FetchMetadata::default().with_dest(h));
    }),
    decode!(SecFetchMode, |h| {
        token(&h);
        sink(h.as_str());
        metadata(&FetchMetadata::default().with_mode(h));
    }),
    decode!(SecFetchSite, |h| {
        token(&h);
        sink(h.as_str());
        metadata(&FetchMetadata::default().with_site(h));
    }),
    decode!(SecFetchUser, |_h| {
        metadata(&FetchMetadata::default().with_user(true));
    }),
];
