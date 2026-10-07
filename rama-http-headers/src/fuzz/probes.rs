//! Fixed and input-derived arguments that query methods are probed with.

use std::{
    sync::LazyLock,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rama_http_types::HeaderValue;

use crate::{
    ETag, HeaderDecode, IfMatch, IfNoneMatch, IfRange, LastModified,
    fuzz::support::{roundtrip, sink},
};

// Content lengths every range query is probed with.
pub(super) const CONTENT_LENGTHS: [u64; 4] = [0, 1, 100, u64::MAX];

pub(super) static FIXED_ETAGS: LazyLock<Vec<ETag>> = LazyLock::new(|| {
    [
        "\"xyzzy\"",
        "W/\"xyzzy\"",
        "\"\"",
        "W/\"\"",
        "\"a\"",
        "W/\"a\"",
    ]
    .into_iter()
    .filter_map(|s| s.parse().ok())
    .collect()
});

pub(super) static FIXED_LAST_MODIFIED: LazyLock<Vec<LastModified>> = LazyLock::new(|| {
    [0, 1, 1_700_000_000, 253_402_300_799]
        .into_iter()
        .filter_map(|secs| UNIX_EPOCH.checked_add(Duration::from_secs(secs)))
        .map(LastModified::from)
        .collect()
});

pub(super) fn probe_etags(values: &[HeaderValue]) -> Vec<ETag> {
    let mut tags = FIXED_ETAGS.clone();
    tags.extend(ETag::decode(&mut values.iter()).ok());
    tags.extend(
        values
            .iter()
            .filter_map(|value| ETag::decode(&mut std::iter::once(value)).ok()),
    );
    tags
}

pub(super) fn probe_last_modified(values: &[HeaderValue]) -> Vec<LastModified> {
    let mut dates = FIXED_LAST_MODIFIED.clone();
    dates.extend(LastModified::decode(&mut values.iter()).ok());
    dates
}

// Modification times queries are probed with, including ones outside the HTTP-date range.
pub(super) fn probe_times() -> impl Iterator<Item = SystemTime> {
    [
        UNIX_EPOCH.checked_sub(Duration::from_secs(1)),
        Some(UNIX_EPOCH),
        UNIX_EPOCH.checked_add(Duration::from_secs(1_700_000_000)),
        UNIX_EPOCH.checked_add(Duration::from_secs(253_402_300_799)),
        UNIX_EPOCH.checked_add(Duration::from_secs(253_402_300_800)),
        UNIX_EPOCH.checked_add(Duration::from_secs(4_294_967_295_000)),
    ]
    .into_iter()
    .flatten()
}

pub(super) fn etag_preconditions(tag: &ETag) {
    let mut probes = FIXED_ETAGS.clone();
    probes.push(tag.clone());
    let if_match = IfMatch::from(tag.clone());
    let if_none_match = IfNoneMatch::from(tag.clone());
    let if_range = IfRange::etag(tag.clone());
    roundtrip(&if_match);
    roundtrip(&if_none_match);
    roundtrip(&if_range);
    for probe in &probes {
        sink(if_match.precondition_passes(probe));
        sink(if_none_match.precondition_passes(probe));
        sink(if_range.is_modified(Some(probe), None));
        sink(IfMatch::from(probe.clone()).precondition_passes(tag));
        sink(IfNoneMatch::from(probe.clone()).precondition_passes(tag));
        sink(IfRange::etag(probe.clone()).is_modified(Some(tag), None));
    }
}
