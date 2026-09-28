//! Every fallible numeric constructor of this crate.

use std::{
    ops::Bound,
    time::{Duration, UNIX_EPOCH},
};

use rama_http_types::mime::Mime;
use rama_net::tls::ApplicationProtocol;

use crate::{
    AccessControlMaxAge, Age, AltSvc, AlternativeService, CacheControl, ContentLength,
    ContentRange, ContentType, Date, Downlink, Expires, IfModifiedSince, IfRange,
    IfUnmodifiedSince, LastModified, Priority, Range, RetryAfter, Rtt, SaveData,
    StrictTransportSecurity, Te, TeDirective,
    fuzz::{
        NumbersExercise,
        parts::{directive_date_time, quality_value, seconds_value},
        support::{low_u8, low_u16, low_u32, roundtrip, sink},
    },
    specifier::{Quality, QualityValue},
    util::Seconds,
    x_robots_tag::DirectiveDateTime,
};

pub(super) const NUMBERS: &[NumbersExercise] = &[
    ("ContentRange::bytes", |a, b| {
        let candidates = [
            ContentRange::bytes(a..=b, Some(b)),
            ContentRange::bytes(a..=b, None::<u64>),
            ContentRange::bytes(a..b, Some(b)),
            ContentRange::bytes(a.., Some(b)),
            ContentRange::bytes(..b, Some(a)),
            ContentRange::bytes(..=b, None::<u64>),
            ContentRange::bytes(.., Some(a)),
            ContentRange::bytes((Bound::Excluded(a), Bound::Excluded(b)), Some(b)),
            Ok(ContentRange::unsatisfied_bytes(a)),
        ];
        for range in candidates.into_iter().flatten() {
            roundtrip(&range);
            sink((range.bytes_range(), range.bytes_len()));
        }
    }),
    ("Range::bytes", |a, b| {
        let candidates = [
            Range::bytes(a..=b),
            Range::bytes(a..b),
            Range::bytes(a..),
            Range::bytes((Bound::Excluded(a), Bound::Excluded(b))),
            Ok(Range::suffix(a)),
        ];
        for range in candidates.into_iter().flatten() {
            roundtrip(&range);
            sink(range.first_satisfiable_range(b));
            sink(range.satisfiable_ranges(b).count());
        }
    }),
    ("Priority::new", |a, b| {
        if let Some(priority) = Priority::new(low_u8(a), b & 1 == 1) {
            roundtrip(&priority);
            sink(priority.field_value());
        }
    }),
    ("DirectiveDateTime::try_new_ymd_and_hms", |a, b| {
        let year = i32::from_le_bytes(low_u32(a).to_le_bytes());
        let [month, day, hour, min, sec, ..] = b.to_le_bytes();
        let [month, day, hour, min, sec] = [month, day, hour, min, sec].map(u32::from);
        if let Ok(date_time) =
            DirectiveDateTime::try_new_ymd_and_hms(year, month, day, hour, min, sec)
        {
            directive_date_time(&date_time);
        }
        if let Ok(date_time) = DirectiveDateTime::try_new_ymd(year, month, day) {
            directive_date_time(&date_time);
        }
    }),
    ("Seconds", |a, b| {
        let duration = Duration::new(a, low_u32(b).min(999_999_999));
        seconds_value(Seconds::new(a));
        seconds_value(Seconds::from_duration_rounded(duration));
        if let Some(seconds) = Seconds::try_from_duration(duration) {
            seconds_value(seconds);
        }
        roundtrip(&Age::from_seconds(a));
        roundtrip(&Age::from_duration_rounded(duration));
        roundtrip(&AccessControlMaxAge::from_seconds(a));
        roundtrip(&AccessControlMaxAge::from_duration_rounded(duration));
        roundtrip(&RetryAfter::delay(Seconds::new(a)));
        if let Ok(service) = AlternativeService::new(ApplicationProtocol::HTTP_3, low_u16(b)) {
            roundtrip(&AltSvc::new(service.with_max_age_seconds(a)));
        }
    }),
    ("CacheControl", |a, b| {
        let duration = Duration::new(a, low_u32(b).min(999_999_999));
        roundtrip(
            &CacheControl::new()
                .with_max_age_seconds(a)
                .with_max_stale_seconds(b)
                .with_min_fresh_seconds(a)
                .with_s_max_age_seconds(b),
        );
        roundtrip(
            &CacheControl::new()
                .with_max_age_duration_rounded(duration)
                .with_max_stale_duration_rounded(duration)
                .with_min_fresh_duration_rounded(duration)
                .with_s_max_age_duration_rounded(duration),
        );
        if let Ok(cache_control) = CacheControl::new().try_with_max_age_duration(duration) {
            roundtrip(&cache_control);
        }
        roundtrip(&CacheControl::short_shared_revalidate(low_u32(a)));
    }),
    ("StrictTransportSecurity", |a, b| {
        let duration = Duration::new(a, low_u32(b).min(999_999_999));
        roundtrip(
            &StrictTransportSecurity::including_subdomains_for_max_seconds(a).with_preload(true),
        );
        roundtrip(
            &StrictTransportSecurity::excluding_subdomains_for_max_duration_rounded(duration),
        );
        if let Some(sts) = StrictTransportSecurity::including_subdomains_for_max_duration(duration)
        {
            roundtrip(&sts);
        }
    }),
    ("SystemTime", |a, b| {
        let times = [
            UNIX_EPOCH.checked_add(Duration::from_secs(a)),
            UNIX_EPOCH.checked_add(Duration::from_secs(a.min(253_402_300_799))),
            UNIX_EPOCH.checked_sub(Duration::from_secs(b)),
        ];
        for time in times.into_iter().flatten() {
            roundtrip(&Date::from(time));
            roundtrip(&Expires::from(time));
            roundtrip(&LastModified::from(time));
            roundtrip(&IfModifiedSince::from(time));
            roundtrip(&IfUnmodifiedSince::from(time));
            roundtrip(&IfRange::date(time));
            roundtrip(&RetryAfter::date(time));
        }
    }),
    ("client_hints", |a, b| {
        let rtt = Rtt::from_millis(a);
        roundtrip(&rtt);
        sink(rtt.as_duration());
        roundtrip(&Downlink::new(f64::from_bits(b)));
        roundtrip(&SaveData::new(a & 1 == 1));
        roundtrip(&ContentLength(b));
    }),
    ("Quality::new_clamped", |a, _| {
        let quality = Quality::new_clamped(low_u16(a));
        quality_value(&QualityValue::new(Mime::from(ContentType::json()), quality));
        roundtrip(&Te::new(QualityValue::new(TeDirective::Trailers, quality)));
    }),
];
