//! Bounded synchronous fuzz entry points driving every typed header through its public API.

use std::{
    fmt,
    hint::black_box,
    net::IpAddr,
    ops::Bound,
    sync::LazyLock,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rama_core::extensions::Extensions;
use rama_http_types::{
    HeaderMap, HeaderName, HeaderValue, Method, header,
    mime::{self, Mime},
};
use rama_net::{
    address::{Domain, Host as NetHost, HostWithOptPort},
    forwarded::{ForwardedAuthority, ForwardedElement, NodeId},
    tls::ApplicationProtocol,
    user::{Basic, Bearer, RawToken},
};
use rama_utils::{
    collections::{NonEmptySmallVec, NonEmptyVec},
    str::NonEmptyStr,
};

use crate::{
    Accept, AcceptCh, AcceptRanges, AccessControlAllowCredentials, AccessControlAllowHeaders,
    AccessControlAllowMethods, AccessControlAllowOrigin, AccessControlAllowPrivateNetwork,
    AccessControlExposeHeaders, AccessControlMaxAge, AccessControlRequestHeaders,
    AccessControlRequestMethod, AccessControlRequestPrivateNetwork, After, Age, Allow,
    AllowlistSource, AltSvc, AltUsed, AlternativeService, Authorization, CacheControl, ClientHint,
    Connection, ContentDisposition, ContentEncoding, ContentEncodingDirective, ContentLength,
    ContentLocation, ContentRange, ContentSecurityPolicy, ContentType, Cookie, CriticalCh,
    CrossOriginEmbedderPolicy, CrossOriginEmbedderPolicyReportOnly, CrossOriginEmbedderPolicyValue,
    CrossOriginOpenerPolicy, CrossOriginOpenerPolicyReportOnly, CrossOriginOpenerPolicyValue,
    CrossOriginResourcePolicy, DatastarRequest, Date, DirectiveName, Downlink, ETag, Ect, Expect,
    Expires, HashAlgorithm, HeaderDecode, HeaderEncode, HeaderMapExt, Host, HostSource, IfMatch,
    IfModifiedSince, IfNoneMatch, IfRange, IfUnmodifiedSince, LastEventId, LastModified, Location,
    Origin, PermissionsPolicy, PermissionsPolicyDirective, PermissionsPolicyDirectiveName, Pragma,
    Priority, ProxyAuthorization, Range, Referer, ReferrerPolicy, RetryAfter, Rtt, SaveData,
    SecFetchSite, SecWebSocketAccept, SecWebSocketExtensions, SecWebSocketKey,
    SecWebSocketProtocol, SecWebSocketVersion, Server, SetCookie, SourceExpression, SourceList,
    StrictTransportSecurity, Te, TeDirective, TransferEncoding, TransferEncodingDirective, Upgrade,
    UserAgent, Vary, XContentTypeOptions, XFrameOptions, XRobotsTag,
    authorization::AuthoritySync,
    encoding::{
        AcceptEncoding, Encoding, SupportedEncodings, maybe_preferred_encoding_with_wildcard,
        parse_accept_encoding_headers, parse_accept_encoding_wildcard_quality,
    },
    exotic::XClacksOverhead,
    forwarded::{
        CFConnectingIp, ClientIp, ForwardHeader, Forwarded, TrueClientIp, Via, XClientIp,
        XForwardedFor, XForwardedHost, XForwardedProto, XRealIp,
    },
    privacy::{Dnt, SecGpc},
    sec_websocket_extensions::{Extension, PerMessageDeflateConfig, PerMessageDeflateIdentifier},
    specifier::{Quality, QualityValue, sort_quality_values_non_empty_vec},
    util::{HeaderValueString, HttpDate, Seconds, ValuesOrAny, csv},
    x_robots_tag::{DirectiveDateTime, MaxImagePreviewSetting, RobotsTag, robots_tag_parse_iter},
};

/// A named exercise over the values of one header field.
pub type ValuesExercise = (&'static str, fn(&[HeaderValue]));

/// A named exercise over a single untrusted string.
pub type StrExercise = (&'static str, fn(&str));

/// A named exercise of fallible constructors over two input-derived numbers.
pub type NumbersExercise = (&'static str, fn(u64, u64));

/// Upper bound on the header values `exercise_bytes` splits its input into.
pub const MAX_VALUES: usize = 16;

// Content lengths every range query is probed with.
const CONTENT_LENGTHS: [u64; 4] = [0, 1, 100, u64::MAX];

/// Decode every typed header from `values` and drive each success through its public API.
pub fn exercise_header_values(values: &[HeaderValue]) {
    for (_, exercise) in VALUES_EXERCISES {
        exercise(values);
    }
}

/// Run every public string parser of this crate on `s` and drive each success through its API.
pub fn exercise_str(s: &str) {
    for (_, exercise) in STR_EXERCISES {
        exercise(s);
    }
}

/// Run every fallible numeric constructor of this crate on `a` and `b`.
pub fn exercise_numbers(a: u64, b: u64) {
    for (_, exercise) in NUMBERS_EXERCISES {
        exercise(a, b);
    }
}

/// Fuzz entry point: `data` is split on `\n` into header values and strings.
pub fn exercise_bytes(data: &[u8]) {
    let chunks: Vec<&[u8]> = data.split(|byte| *byte == b'\n').take(MAX_VALUES).collect();
    let values: Vec<HeaderValue> = chunks
        .iter()
        .filter_map(|chunk| HeaderValue::from_bytes(chunk).ok())
        .collect();
    exercise_header_values(&values);
    if values.len() > 1 {
        for value in &values {
            exercise_header_values(std::slice::from_ref(value));
        }
    }
    if let Ok(s) = std::str::from_utf8(data) {
        exercise_str(s);
    }
    if chunks.len() > 1 {
        for s in chunks
            .iter()
            .filter_map(|chunk| std::str::from_utf8(chunk).ok())
        {
            exercise_str(s);
        }
    }
    let mut numbers = data.chunks(8).map(|chunk| {
        let mut buf = [0u8; 8];
        for (dst, src) in buf.iter_mut().zip(chunk) {
            *dst = *src;
        }
        u64::from_le_bytes(buf)
    });
    let a = numbers.next().unwrap_or_default();
    let b = numbers.next().unwrap_or_default();
    exercise_numbers(a, b);
}

macro_rules! decode {
    ($ty:ty) => {
        (stringify!($ty), |values: &[HeaderValue]| {
            sink(decoded::<$ty>(values));
        })
    };
    ($ty:ty, |$h:ident| $body:block) => {
        (stringify!($ty), |values: &[HeaderValue]| {
            if let Some($h) = decoded::<$ty>(values) $body
        })
    };
    ($ty:ty, |$h:ident, $values:ident| $body:block) => {
        (stringify!($ty), |$values: &[HeaderValue]| {
            if let Some($h) = decoded::<$ty>($values) $body
        })
    };
}

macro_rules! parse_str {
    ($ty:ty) => {
        (concat!(stringify!($ty), "::from_str"), |s: &str| {
            if let Ok(parsed) = s.parse::<$ty>() {
                roundtrip(&parsed);
                display(&parsed);
            }
        })
    };
}

macro_rules! enum_str {
    ($ty:ty $(, |$v:ident| $header:expr)?) => {
        (concat!(stringify!($ty), "::from"), |s: &str| {
            let parsed = <$ty>::from(s);
            token(&parsed);
            sink(parsed.as_str());
            sink(parsed.as_static_str());
            sink(<$ty>::strict_parse(s));
            sink(s.parse::<$ty>());
            $(
                let $v = parsed;
                roundtrip(&$header);
            )?
        })
    };
}

/// Every typed header decoded from a list of values, plus value-level parsers.
pub const VALUES_EXERCISES: &[ValuesExercise] = &[
    decode!(Accept, |h| {
        eq(&h);
        for qv in h.0.iter() {
            quality_value(qv);
            mime_type(&qv.value);
            sink(qv.partial_cmp(h.0.first()));
        }
        if let Some(mut values) = NonEmptyVec::collect(h.0.iter().cloned()) {
            sort_quality_values_non_empty_vec(&mut values);
            sink(values);
        }
        let mut sorted = h;
        sorted.sort_quality_values();
        roundtrip(&sorted);
    }),
    decode!(AcceptRanges, |h| {
        eq(&h);
        sink((h.is_bytes(), h.is_none()));
    }),
    decode!(AccessControlAllowCredentials, |h| {
        eq(&h);
    }),
    decode!(AccessControlAllowHeaders, |h| {
        eq(&h);
        sink(h.is_any());
        values_or_any(&h.0);
        sink(h.as_values().map(|names| names.len()));
        sink(h.into_values());
    }),
    decode!(AccessControlAllowMethods, |h| {
        eq(&h);
        sink(h.is_any());
        values_or_any(&h.0);
        sink(h.as_values().map(|methods| methods.len()));
        sink(h.into_values());
    }),
    decode!(AccessControlAllowOrigin, |h| {
        eq(&h);
        if let Some(value) = h.origin() {
            origin(value);
        }
    }),
    decode!(AccessControlAllowPrivateNetwork, |h| {
        eq(&h);
    }),
    decode!(AccessControlExposeHeaders, |h| {
        sink(h.is_any());
        values_or_any(&h.0);
        sink(h.as_values().map(|names| names.len()));
        sink(h.into_values());
    }),
    decode!(AccessControlMaxAge, |h| {
        eq(&h);
        sink((h.as_secs(), Duration::from(h)));
    }),
    decode!(AccessControlRequestHeaders, |h| {
        for name in h.0.iter() {
            sink(name.as_str());
        }
    }),
    decode!(AccessControlRequestMethod, |h| {
        eq(&h);
        sink(h.0.as_str());
        sink(Method::from(h));
    }),
    decode!(AccessControlRequestPrivateNetwork, |h| {
        eq(&h);
    }),
    decode!(Age, |h| {
        eq(&h);
        sink((h.as_secs(), Duration::from(h)));
    }),
    decode!(Allow, |h| {
        eq(&h);
        for method in h.0.iter() {
            sink(method.as_str());
        }
    }),
    decode!(AltSvc, |h| {
        eq(&h);
        sink(h.is_clear());
        if let Some(services) = h.alternatives() {
            for service in services {
                alternative_service(service);
            }
        }
    }),
    decode!(AltUsed, |h| {
        eq(&h);
        display(&h);
        host_with_opt_port(&h.0);
    }),
    decode!(Authorization<Basic>, |h| {
        eq(&h);
        basic(h.credentials());
        roundtrip(&ProxyAuthorization(h.into_inner()));
    }),
    decode!(Authorization<Bearer>, |h| {
        eq(&h);
        sink(h.token());
        display(h.credentials());
        roundtrip(&ProxyAuthorization(h.into_inner()));
    }),
    decode!(Authorization<RawToken>, |h| {
        eq(&h);
        sink(h.token());
        display(h.credentials());
        roundtrip(&ProxyAuthorization(h.into_inner()));
    }),
    decode!(ProxyAuthorization<Basic>, |h| {
        eq(&h);
        basic(&h.0);
        roundtrip(&Authorization::new(h.0));
    }),
    decode!(ProxyAuthorization<Bearer>, |h| {
        eq(&h);
        sink(h.0.token());
        display(&h.0);
        roundtrip(&Authorization::new(h.0));
    }),
    decode!(ProxyAuthorization<RawToken>, |h| {
        eq(&h);
        sink(h.0.token());
        display(&h.0);
        roundtrip(&Authorization::new(h.0));
    }),
    decode!(CacheControl, |h| {
        eq(&h);
        sink((
            h.clone().has_no_cache(),
            h.clone().has_no_store(),
            h.clone().has_no_transform(),
            h.clone().has_only_if_cached(),
            h.clone().has_public(),
            h.clone().has_private(),
            h.clone().has_immutable(),
            h.clone().has_must_understand(),
            h.has_must_revalidate(),
        ));
        sink((h.max_age(), h.max_stale(), h.min_fresh(), h.s_max_age()));
    }),
    decode!(Connection, |h| {
        sink((h.is_close(), h.contains_upgrade(), h.contains_keep_alive()));
        sink(h.contains_header(&header::CONNECTION));
        for name in h.iter_headers() {
            sink((name.as_str(), h.contains_header(name)));
        }
    }),
    decode!(ContentDisposition, |h| {
        sink((h.is_inline(), h.is_attachment(), h.is_form_data()));
    }),
    decode!(ContentEncoding, |h| {
        sink(h.contains_directive("gzip"));
        for directive in h.0.iter() {
            token(directive);
            sink(h.contains_directive(directive.clone()));
            sink(h.contains_directive(directive.as_str()));
            sink(Encoding::maybe_from_content_encoding_directive(
                directive, true,
            ));
            sink(Encoding::maybe_from_content_encoding_directive(
                directive,
                AcceptEncoding::default(),
            ));
        }
    }),
    decode!(ContentLength, |h| {
        eq(&h);
        sink(h.0);
    }),
    decode!(ContentLocation, |h| {
        eq(&h);
    }),
    decode!(ContentRange, |h| {
        eq(&h);
        sink(h.bytes_len());
        if let Some((first, last)) = h.bytes_range()
            && let Ok(again) = ContentRange::bytes(first..=last, h.bytes_len())
        {
            roundtrip(&again);
        }
    }),
    decode!(ContentSecurityPolicy, |h| {
        eq(&h);
        display(&h);
        for directive in h.directives() {
            display(directive);
            token(&directive.name);
            sink(directive.name.as_str());
            display(&directive.sources);
            sink(directive.sources.as_slice().len());
            for expression in directive.sources.iter() {
                source_expression(expression);
            }
        }
    }),
    decode!(ContentType, |h| {
        eq(&h);
        display(&h);
        sink((h == ContentType::grpc(), ContentType::markdown_utf8() == h));
        mime_type(h.mime());
        sink(h.into_mime());
    }),
    decode!(Cookie, |h| {
        eq(&h);
        for (name, value) in h.iter().take(4) {
            sink((h.get(name), h.get(value)));
        }
        for name in ["", "=", " ", "a"] {
            sink(h.get(name));
        }
    }),
    decode!(CrossOriginEmbedderPolicy, |h| {
        eq(&h);
        display(&h);
        token(&h.value);
        sink((h.value.as_str(), h.report_to.as_deref()));
        roundtrip(&CrossOriginEmbedderPolicyReportOnly::from_enforcing(h));
    }),
    decode!(CrossOriginEmbedderPolicyReportOnly, |h| {
        eq(&h);
        display(&h);
        token(&h.value);
        sink((h.value.as_str(), h.report_to.as_deref()));
        roundtrip(&CrossOriginEmbedderPolicy {
            value: h.value,
            report_to: h.report_to,
        });
    }),
    decode!(CrossOriginOpenerPolicy, |h| {
        eq(&h);
        display(&h);
        token(&h.value);
        sink((h.value.as_str(), h.report_to.as_deref()));
        roundtrip(&CrossOriginOpenerPolicyReportOnly::from_enforcing(h));
    }),
    decode!(CrossOriginOpenerPolicyReportOnly, |h| {
        eq(&h);
        display(&h);
        token(&h.value);
        sink((h.value.as_str(), h.report_to.as_deref()));
        roundtrip(&CrossOriginOpenerPolicy {
            value: h.value,
            report_to: h.report_to,
        });
    }),
    decode!(CrossOriginResourcePolicy, |h| {
        token(&h);
        sink(h.as_str());
    }),
    decode!(Date, |h| {
        eq(&h);
        sink(SystemTime::from(h));
    }),
    decode!(ETag, |h| {
        eq(&h);
        sink(h.is_weak());
        etag_preconditions(&h);
    }),
    decode!(Expect, |h| {
        eq(&h);
    }),
    decode!(Expires, |h| {
        eq(&h);
        sink(SystemTime::from(h));
    }),
    decode!(Host, |h| {
        eq(&h);
        display(&h);
        host_with_opt_port(&h.0);
        sink(HostWithOptPort::from(h.clone()));
        sink(NetHost::from(h));
    }),
    decode!(IfMatch, |h, values| {
        eq(&h);
        sink(h.is_any());
        for tag in probe_etags(values) {
            sink(h.precondition_passes(&tag));
        }
    }),
    decode!(IfModifiedSince, |h| {
        eq(&h);
        sink(SystemTime::from(h));
        for time in probe_times() {
            sink(h.is_modified(time));
        }
    }),
    decode!(IfNoneMatch, |h, values| {
        eq(&h);
        for tag in probe_etags(values) {
            sink(h.precondition_passes(&tag));
        }
    }),
    decode!(IfRange, |h, values| {
        eq(&h);
        let tags = probe_etags(values);
        let dates = probe_last_modified(values);
        sink(h.is_modified(None, None));
        for tag in &tags {
            sink(h.is_modified(Some(tag), None));
            for date in &dates {
                sink(h.is_modified(Some(tag), Some(date)));
            }
        }
        for date in &dates {
            sink(h.is_modified(None, Some(date)));
        }
    }),
    decode!(IfUnmodifiedSince, |h| {
        eq(&h);
        sink(SystemTime::from(h));
        for time in probe_times() {
            sink(h.precondition_passes(time));
        }
    }),
    decode!(LastEventId, |h| {
        eq(&h);
        display(&h);
        let as_ref: &str = h.as_ref();
        sink((h.as_str(), as_ref));
    }),
    decode!(LastModified, |h| {
        eq(&h);
        sink(SystemTime::from(h));
    }),
    decode!(Location, |h| {
        eq(&h);
        sink(h.to_str());
    }),
    decode!(Origin, |h| {
        eq(&h);
        origin(&h);
    }),
    decode!(PermissionsPolicy, |h| {
        eq(&h);
        display(&h);
        for directive in h.directives() {
            display(directive);
            token(&directive.name);
            sink(directive.name.as_str());
            for source in &directive.allow_list {
                token(source);
                sink(source.as_str());
            }
            roundtrip(&PermissionsPolicy::empty().with_directive(directive.clone()));
        }
    }),
    decode!(Pragma, |h| {
        eq(&h);
        sink(h.is_no_cache());
    }),
    decode!(Priority, |h| {
        eq(&h);
        sink((h.urgency(), h.incremental(), h.field_value()));
    }),
    decode!(Range, |h| {
        eq(&h);
        for spec in h.iter() {
            debug(&spec);
            display(&spec);
            for len in CONTENT_LENGTHS {
                sink(spec.to_satisfiable_range(len));
            }
        }
        for len in CONTENT_LENGTHS {
            sink(h.first_satisfiable_range(len));
            for (first, last) in h.satisfiable_ranges(len) {
                if let Ok(range) = ContentRange::bytes(first..=last, len) {
                    roundtrip(&range);
                }
            }
        }
    }),
    decode!(Referer, |h| {
        eq(&h);
        display(&h);
    }),
    decode!(ReferrerPolicy, |h| {
        eq(&h);
        roundtrip(&h.clone().with_fallback(h));
    }),
    decode!(RetryAfter, |h| {
        eq(&h);
        after(h.after());
    }),
    decode!(SecFetchSite, |h| {
        token(&h);
        sink(h.as_str());
    }),
    decode!(SecWebSocketAccept, |h| {
        eq(&h);
    }),
    decode!(SecWebSocketExtensions, |h| {
        eq(&h);
        for extension in h.0.iter() {
            ws_extension(extension);
        }
    }),
    decode!(SecWebSocketKey, |h| {
        eq(&h);
        if let Ok(accept) = SecWebSocketAccept::try_from(h) {
            roundtrip(&accept);
        }
    }),
    decode!(SecWebSocketProtocol, |h| {
        eq(&h);
        for protocol in h.iter() {
            sink(h.contains(protocol));
        }
        sink((h.contains(""), h.contains_any(["chat", " "])));
        let accepted = h.accept_first_protocol();
        debug(&accepted);
        roundtrip(&accepted.into_header());
    }),
    decode!(SecWebSocketVersion, |h| {
        eq(&h);
    }),
    decode!(Server, |h| {
        eq(&h);
        display(&h);
        sink(h.as_str());
    }),
    decode!(SetCookie, |h| {
        for value in h.iter_header_values() {
            sink(value.to_str());
        }
    }),
    decode!(StrictTransportSecurity, |h| {
        eq(&h);
        sink((h.include_subdomains(), h.preload(), h.max_age()));
    }),
    decode!(Te, |h| {
        eq(&h);
        for qv in h.0.iter() {
            quality_value(qv);
            token(&qv.value);
        }
    }),
    decode!(TransferEncoding, |h| {
        sink(h.is_chunked());
        for directive in h.0.iter() {
            token(directive);
        }
    }),
    decode!(Upgrade, |h| {
        eq(&h);
        sink((h.as_bytes(), h.is_websocket(), h.contains_websocket()));
    }),
    decode!(UserAgent, |h| {
        eq(&h);
        display(&h);
        sink(h.as_str());
    }),
    decode!(Vary, |h| {
        sink(h.is_any());
        if let Some(names) = h.iter_strs() {
            for name in names {
                sink(name.as_str());
            }
        }
    }),
    decode!(XContentTypeOptions, |h| {
        eq(&h);
    }),
    decode!(XFrameOptions, |h| {
        eq(&h);
    }),
    decode!(AcceptCh, |h| {
        eq(&h);
        client_hints(&h.0);
    }),
    decode!(CriticalCh, |h| {
        eq(&h);
        client_hints(&h.0);
    }),
    decode!(SaveData, |h| {
        eq(&h);
        sink((h.is_on(), bool::from(h)));
    }),
    decode!(Ect, |h| {
        eq(&h);
        display(&h);
        sink(h.as_str());
    }),
    decode!(Rtt, |h| {
        eq(&h);
        sink((h.as_millis(), h.as_duration(), Duration::from(h)));
    }),
    decode!(Downlink, |h| {
        eq(&h);
        sink((h.as_mbps(), f64::from(h)));
    }),
    decode!(DatastarRequest, |h| {
        eq(&h);
    }),
    decode!(XClacksOverhead, |h| {
        eq(&h);
        display(&h);
        sink(h.as_str());
    }),
    decode!(Dnt),
    decode!(SecGpc),
    decode!(Forwarded, |h| {
        eq(&h);
        display(&*h);
        sink((h.client_port(), h.client_ip(), h.client_proto()));
        sink((h.client_version(), h.client_socket_addr()));
        if let Some(authority) = h.client_host() {
            forwarded_authority(authority);
        }
        for element in h.iter() {
            forwarded_element(element);
        }
        forward_header(&h);
    }),
    decode!(Via, |h| {
        eq(&h);
        forward_header(&h);
    }),
    decode!(XForwardedFor, |h| {
        eq(&h);
        for ip in h.iter() {
            display(ip);
        }
        forward_header(&h);
    }),
    decode!(XForwardedHost, |h| {
        eq(&h);
        net_host(h.host());
        sink(h.port());
        forwarded_authority(h.inner());
        forward_header(&h);
    }),
    decode!(XForwardedProto, |h| {
        eq(&h);
        let protocol = h.protocol();
        display(protocol);
        sink((protocol.as_str(), protocol.is_http(), protocol.is_secure()));
        sink(protocol.as_scheme());
        forward_header(&h);
    }),
    decode!(CFConnectingIp, |h| {
        eq(&h);
        forward_header(&h);
    }),
    decode!(TrueClientIp, |h| {
        eq(&h);
        forward_header(&h);
    }),
    decode!(XRealIp, |h| {
        eq(&h);
        forward_header(&h);
    }),
    decode!(ClientIp, |h| {
        eq(&h);
        forward_header(&h);
    }),
    decode!(XClientIp, |h| {
        eq(&h);
        forward_header(&h);
    }),
    decode!(XRobotsTag, |h| {
        for tag in h.0.iter() {
            robots_tag(tag);
        }
        robots_tag(h.first_tag());
        roundtrip(&XRobotsTag::new(h.into_first_tag()));
    }),
    ("encoding", |values: &[HeaderValue]| {
        let mut map = HeaderMap::new();
        for value in values {
            map.append(header::ACCEPT_ENCODING, value.clone());
            map.append(header::CONTENT_ENCODING, value.clone());
        }
        encodings(&map, true);
        encodings(&map, false);
        encodings(&map, AcceptEncoding::default());
        encodings(&map, AcceptEncoding::new_gzip());
    }),
    ("csv::from_comma_delimited", |values: &[HeaderValue]| {
        sink(csv::from_comma_delimited::<_, IpAddr, Vec<_>>(
            &mut values.iter(),
        ));
        sink(csv::from_comma_delimited::<_, u64, Vec<_>>(
            &mut values.iter(),
        ));
        sink(csv::from_comma_delimited::<_, String, Vec<_>>(
            &mut values.iter(),
        ));
        if let Ok(tags) = csv::from_comma_delimited::<_, ETag, Vec<_>>(&mut values.iter()) {
            for tag in &tags {
                etag_preconditions(tag);
            }
        }
    }),
    ("Seconds::try_from_val", |values: &[HeaderValue]| {
        for value in values {
            if let Some(seconds) = Seconds::try_from_val(value) {
                seconds_value(seconds);
            }
        }
    }),
    ("HeaderValueString::from_val", |values: &[HeaderValue]| {
        for value in values {
            if let Ok(s) = HeaderValueString::from_val(value) {
                header_value_string(&s);
            }
        }
    }),
    (
        "Origin::try_from_header_value",
        |values: &[HeaderValue]| {
            for value in values {
                if let Some(value) = Origin::try_from_header_value(value) {
                    origin(&value);
                    roundtrip(&value);
                }
                if let Some(allow) = AccessControlAllowOrigin::try_from_origin_header_value(value) {
                    roundtrip(&allow);
                }
            }
        },
    ),
    ("Priority::parse", |values: &[HeaderValue]| {
        for value in values {
            if let Ok(priority) = Priority::parse(value.as_bytes()) {
                roundtrip(&priority);
            }
        }
    }),
    ("robots_tag_parse_iter", |values: &[HeaderValue]| {
        for value in values {
            for tag in robots_tag_parse_iter(value.as_bytes()).take(64).flatten() {
                robots_tag(&tag);
            }
        }
    }),
    (
        "ClientHint::match_header_name",
        |values: &[HeaderValue]| {
            for value in values {
                if let Ok(name) = HeaderName::from_bytes(value.as_bytes())
                    && let Some(hint) = ClientHint::match_header_name(&name)
                {
                    client_hint(hint);
                }
            }
        },
    ),
];

/// Every public string parser of this crate.
pub const STR_EXERCISES: &[StrExercise] = &[
    ("ETag::from_str", |s: &str| {
        if let Ok(tag) = s.parse::<ETag>() {
            roundtrip(&tag);
            sink(tag.is_weak());
            etag_preconditions(&tag);
        }
    }),
    ("HeaderValueString::from_str", |s: &str| {
        if let Ok(value) = s.parse::<HeaderValueString>() {
            header_value_string(&value);
        }
        if let Some(value) = HeaderValueString::from_string(s.to_owned()) {
            header_value_string(&value);
        }
    }),
    ("Quality::from_str", |s: &str| {
        if let Ok(quality) = s.parse::<Quality>() {
            debug(&quality);
            sink(quality.as_u16());
        }
    }),
    ("QualityValue<Mime>::from_str", |s: &str| {
        if let Ok(qv) = s.parse::<QualityValue<Mime>>() {
            quality_value(&qv);
            mime_type(&qv.value);
            roundtrip(&Accept::new(qv));
        }
    }),
    ("QualityValue<TeDirective>::from_str", |s: &str| {
        if let Ok(qv) = s.parse::<QualityValue<TeDirective>>() {
            quality_value(&qv);
            roundtrip(&Te::new(qv));
        }
    }),
    ("QualityValue<String>::from_str", |s: &str| {
        if let Ok(qv) = s.parse::<QualityValue<String>>() {
            quality_value(&qv);
        }
    }),
    ("ContentType::from_str", |s: &str| {
        if let Ok(content_type) = s.parse::<ContentType>() {
            roundtrip(&content_type);
            display(&content_type);
            mime_type(content_type.mime());
        }
    }),
    ("DirectiveDateTime::from_str", |s: &str| {
        if let Ok(date_time) = s.parse::<DirectiveDateTime>() {
            directive_date_time(&date_time);
            roundtrip(&XRobotsTag::new(RobotsTag::new_unavailable_after(
                date_time,
            )));
        }
    }),
    ("HttpDate::from_str", |s: &str| {
        if let Ok(date) = s.parse::<HttpDate>() {
            after(After::DateTime(date));
            roundtrip(&LastModified::from(SystemTime::from(date)));
        }
    }),
    ("HostSource::from_str", |s: &str| {
        if let Ok(source) = s.parse::<HostSource>() {
            host_source(&source);
            let expression = SourceExpression::host(source);
            roundtrip(
                &ContentSecurityPolicy::empty()
                    .with(DirectiveName::DefaultSrc, SourceList::from(expression)),
            );
        }
    }),
    ("SourceExpression::from_str", |s: &str| {
        if let Ok(expression) = s.parse::<SourceExpression>() {
            source_expression(&expression);
            roundtrip(
                &ContentSecurityPolicy::empty()
                    .with(DirectiveName::ScriptSrc, SourceList::from(expression)),
            );
        }
    }),
    ("ClientHint::from_str", |s: &str| {
        if let Ok(hint) = s.parse::<ClientHint>() {
            client_hint(hint);
            roundtrip(&AcceptCh::new(hint));
            roundtrip(&CriticalCh::new(hint));
        }
        sink(ClientHint::try_from(s.to_owned()));
    }),
    parse_str!(LastEventId),
    parse_str!(Referer),
    parse_str!(Server),
    parse_str!(UserAgent),
    parse_str!(XClacksOverhead),
    ("Extension::from_str", |s: &str| {
        if let Ok(extension) = s.parse::<Extension>() {
            ws_extension(&extension);
            roundtrip(&extension.into_header());
        }
    }),
    ("AccessControlAllowOrigin::try_from", |s: &str| {
        if let Ok(allow) = AccessControlAllowOrigin::try_from(s) {
            roundtrip(&allow);
            if let Some(value) = allow.origin() {
                origin(value);
            }
        }
    }),
    ("Origin::try_from_parts", |s: &str| {
        let mut candidates = vec![
            Origin::try_from_parts("https", s, None),
            Origin::try_from_parts("https", s, Some(443)),
            Origin::try_from_parts(s, "example.com", None),
        ];
        if let Some((scheme, host)) = s.split_once("://") {
            candidates.push(Origin::try_from_parts(scheme, host, None));
        }
        for value in candidates.into_iter().flatten() {
            origin(&value);
            roundtrip(&value);
        }
    }),
    ("ContentDisposition::try_attachment", |s: &str| {
        if let Ok(disposition) = ContentDisposition::try_attachment(s) {
            roundtrip(&disposition);
            sink(disposition.is_attachment());
        }
        let disposition = ContentDisposition::attachment(s);
        roundtrip(&disposition);
        sink(disposition.is_attachment());
    }),
    ("SecWebSocketProtocol::try_new", |s: &str| {
        if let Ok(value) = NonEmptyStr::try_from(s) {
            if let Ok(protocol) = SecWebSocketProtocol::try_new(value.clone()) {
                roundtrip(&protocol);
            }
            roundtrip(&SecWebSocketProtocol::new(value));
        }
    }),
    ("AllowlistSource::origin", |s: &str| {
        let directive = PermissionsPolicyDirective::allow_from(
            PermissionsPolicyDirectiveName::Camera,
            [AllowlistSource::origin(s), AllowlistSource::from(s)],
        );
        roundtrip(&PermissionsPolicy::empty().with_directive(directive));
    }),
    ("AlternativeService::try_with_host", |s: &str| {
        let mut services = vec![AlternativeService::new(
            ApplicationProtocol::from(s.as_bytes()),
            443,
        )];
        if let (Ok(host), Ok(service)) = (
            NetHost::try_from(s),
            AlternativeService::new(ApplicationProtocol::HTTP_3, 443),
        ) {
            services.push(service.try_with_host(host));
        }
        for service in services.into_iter().flatten() {
            alternative_service(&service);
        }
    }),
    ("report_to builders", |s: &str| {
        let endpoint = s.to_owned();
        roundtrip(&CrossOriginEmbedderPolicy::require_corp().with_report_to(endpoint.clone()));
        roundtrip(&CrossOriginOpenerPolicy::same_origin().with_report_to(endpoint));
    }),
    ("SourceList builders", |s: &str| {
        let sources = SourceList::empty()
            .with_nonce(s.to_owned())
            .with_hash(HashAlgorithm::Sha256, s.to_owned());
        roundtrip(&ContentSecurityPolicy::empty().with_script_src(sources));
        if let Ok(domain) = Domain::try_from(s) {
            let source = HostSource::new(domain)
                .with_path(s.to_owned())
                .with_any_port();
            host_source(&source);
            roundtrip(
                &ContentSecurityPolicy::empty().with_img_src(SourceList::empty().with_host(source)),
            );
        }
    }),
    enum_str!(ContentEncodingDirective, |d| ContentEncoding::new(d)),
    enum_str!(TransferEncodingDirective, |d| TransferEncoding::new(d)),
    enum_str!(TeDirective, |d| Te::new(QualityValue::new_value(d))),
    enum_str!(DirectiveName, |name| ContentSecurityPolicy::empty()
        .with(name, SourceList::self_origin())),
    enum_str!(CrossOriginEmbedderPolicyValue, |value| {
        CrossOriginEmbedderPolicy {
            value,
            report_to: None,
        }
    }),
    enum_str!(CrossOriginOpenerPolicyValue, |value| {
        CrossOriginOpenerPolicy {
            value,
            report_to: None,
        }
    }),
    enum_str!(CrossOriginResourcePolicy, |policy| policy),
    enum_str!(SecFetchSite, |site| site),
    enum_str!(PermissionsPolicyDirectiveName, |name| {
        PermissionsPolicy::empty().with_directive(PermissionsPolicyDirective::deny(name))
    }),
    enum_str!(AllowlistSource),
    enum_str!(MaxImagePreviewSetting, |setting| XRobotsTag::new(
        RobotsTag::new_max_image_preview(setting)
    )),
    enum_str!(PerMessageDeflateIdentifier, |identifier| {
        SecWebSocketExtensions::per_message_deflate_with_config(PerMessageDeflateConfig::from(
            identifier,
        ))
    }),
];

/// Every fallible numeric constructor of this crate.
pub const NUMBERS_EXERCISES: &[NumbersExercise] = &[
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

fn sink<T>(value: T) {
    drop(black_box(value));
}

fn debug<T: fmt::Debug>(value: &T) {
    sink(format!("{value:?}"));
}

fn display<T: fmt::Display + ?Sized>(value: &T) {
    sink(value.to_string());
}

fn eq<T: PartialEq + Clone>(value: &T) {
    sink(*value == value.clone());
}

fn token<T: fmt::Display + fmt::Debug + PartialEq + Clone>(value: &T) {
    debug(value);
    display(value);
    eq(value);
}

fn decoded<H>(values: &[HeaderValue]) -> Option<H>
where
    H: HeaderDecode + HeaderEncode + Clone + fmt::Debug,
{
    let header = H::decode(&mut values.iter()).ok()?;
    roundtrip(&header);
    Some(header)
}

fn roundtrip<H>(header: &H)
where
    H: HeaderDecode + HeaderEncode + Clone + fmt::Debug,
{
    debug(header);
    sink(header.encode_to_value());
    let mut encoded = Vec::new();
    header.encode(&mut encoded);
    if let Ok(again) = H::decode(&mut encoded.iter()) {
        debug(&again);
        sink(again.encode_to_value());
    }
    let mut map = HeaderMap::new();
    map.typed_insert(header.clone());
    sink(map.typed_try_get::<H>());
}

fn low_u8(n: u64) -> u8 {
    let [a, ..] = n.to_le_bytes();
    a
}

fn low_u16(n: u64) -> u16 {
    let [a, b, ..] = n.to_le_bytes();
    u16::from_le_bytes([a, b])
}

fn low_u32(n: u64) -> u32 {
    let [a, b, c, d, ..] = n.to_le_bytes();
    u32::from_le_bytes([a, b, c, d])
}

static FIXED_ETAGS: LazyLock<Vec<ETag>> = LazyLock::new(|| {
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

static FIXED_LAST_MODIFIED: LazyLock<Vec<LastModified>> = LazyLock::new(|| {
    [0, 1, 1_700_000_000, 253_402_300_799]
        .into_iter()
        .filter_map(|secs| UNIX_EPOCH.checked_add(Duration::from_secs(secs)))
        .map(LastModified::from)
        .collect()
});

fn probe_etags(values: &[HeaderValue]) -> Vec<ETag> {
    let mut tags = FIXED_ETAGS.clone();
    tags.extend(ETag::decode(&mut values.iter()).ok());
    tags.extend(
        values
            .iter()
            .filter_map(|value| ETag::decode(&mut std::iter::once(value)).ok()),
    );
    tags
}

fn probe_last_modified(values: &[HeaderValue]) -> Vec<LastModified> {
    let mut dates = FIXED_LAST_MODIFIED.clone();
    dates.extend(LastModified::decode(&mut values.iter()).ok());
    dates
}

// Modification times queries are probed with, including ones outside the HTTP-date range.
fn probe_times() -> impl Iterator<Item = SystemTime> {
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

fn etag_preconditions(tag: &ETag) {
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

fn quality_value<T: fmt::Display + fmt::Debug>(qv: &QualityValue<T>) {
    debug(qv);
    display(qv);
    sink(qv.quality.as_u16());
}

fn values_or_any<T: fmt::Debug>(value: &ValuesOrAny<T>) {
    if let ValuesOrAny::Values(values) = value {
        for value in values.iter() {
            debug(value);
        }
    }
}

fn mime_type(mime: &Mime) {
    display(mime);
    sink((mime.type_().as_str(), mime.subtype().as_str()));
    sink((mime.suffix().map(|name| name.as_str()), mime.essence_str()));
    sink(mime.get_param(mime::CHARSET));
    for (name, value) in mime.params() {
        sink((name.as_str(), value.as_str()));
    }
}

fn header_value_string(value: &HeaderValueString) {
    debug(value);
    display(value);
    sink(value.as_str());
    sink(HeaderValue::from(value));
}

fn seconds_value(seconds: Seconds) {
    debug(&seconds);
    display(&seconds);
    sink((
        seconds.as_u64(),
        seconds.as_duration(),
        HeaderValue::from(&seconds),
    ));
}

fn after(value: After) {
    debug(&value);
    sink(HeaderValue::try_from(&value));
    match value {
        After::DateTime(date) => {
            debug(&date);
            display(&date);
            sink(SystemTime::from(date));
            sink(HeaderValue::try_from(&date));
        }
        After::Delay(seconds) => seconds_value(seconds),
    }
}

fn net_host(host: &NetHost) {
    debug(host);
    display(host);
    sink((host.to_str(), host.is_loopback(), host.is_empty()));
    sink((host.try_as_domain(), host.try_as_ip()));
    sink(host.clone().canonicalize());
}

fn host_with_opt_port(value: &HostWithOptPort) {
    debug(value);
    display(value);
    net_host(&value.host);
}

fn origin(value: &Origin) {
    display(value);
    sink((value.is_null(), value.scheme(), value.port()));
    let hostname = value.hostname();
    if !value.is_null() {
        sink(Origin::try_from_parts(
            value.scheme(),
            &hostname,
            value.port(),
        ));
    }
}

fn basic(credentials: &Basic) {
    debug(credentials);
    display(credentials);
    sink((credentials.username(), credentials.password()));
    if let Ok(fixed) = "user:pass".parse::<Basic>() {
        let ext = Extensions::new();
        sink(<Basic as AuthoritySync<Basic, ()>>::authorized(
            &fixed,
            &ext,
            credentials,
        ));
        sink(<Basic as AuthoritySync<Basic, ()>>::authorized(
            credentials,
            &ext,
            &fixed,
        ));
        sink(<Basic as AuthoritySync<Basic, ()>>::authorized(
            credentials,
            &ext,
            credentials,
        ));
    }
}

fn alternative_service(service: &AlternativeService) {
    debug(service);
    sink(service.protocol().as_bytes());
    if let Some(host) = service.host() {
        net_host(host);
    }
    sink((service.port(), service.max_age(), service.persist()));
    roundtrip(&AltSvc::new(service.clone()));
}

fn host_source(source: &HostSource) {
    debug(source);
    display(source);
    sink((source.scheme().map(|scheme| scheme.as_str()), source.path()));
    display(source.host());
    if let Some(port) = source.port() {
        display(&port);
    }
    sink(HostSource::try_parse(&source.to_string()));
}

fn source_expression(expression: &SourceExpression) {
    debug(expression);
    display(expression);
    match expression {
        SourceExpression::Host(source) => host_source(source),
        SourceExpression::Scheme(scheme) => display(scheme.as_str()),
        SourceExpression::Hash { algorithm, value } => {
            display(algorithm);
            sink((algorithm.as_str(), value.len()));
        }
        SourceExpression::Nonce(nonce) => display(nonce),
        _ => {}
    }
    sink(expression.to_string().parse::<SourceExpression>());
}

fn ws_extension(extension: &Extension) {
    debug(extension);
    display(extension);
    match extension {
        Extension::PerMessageDeflate(config) => {
            debug(config);
            token(&config.identifier);
            sink(config.identifier.as_str());
        }
        Extension::Unknown(value) => display(value.as_str()),
        Extension::Empty => {}
    }
    if let Ok(again) = extension.to_string().parse::<Extension>() {
        roundtrip(&again.into_header());
    }
}

fn client_hint(hint: ClientHint) {
    token(&hint);
    sink((
        hint.as_str(),
        hint.is_low_entropy(),
        hint.header_name_strs(),
    ));
    sink(hint.iter_header_names().count());
}

fn client_hints(hints: &NonEmptySmallVec<16, ClientHint>) {
    for hint in hints.iter() {
        client_hint(*hint);
    }
    if let Some(vary) = Vary::from_client_hints(hints.iter()) {
        roundtrip(&vary);
    }
}

fn directive_date_time(date_time: &DirectiveDateTime) {
    debug(date_time);
    display(date_time);
    sink(date_time.date_time());
    display(&date_time.clone().with_format_rfc3339());
    display(&date_time.clone().with_format_rfc2822());
    display(&date_time.clone().with_format_rfc855());
    display(&date_time.clone().with_format_default());
}

fn robots_tag(tag: &RobotsTag) {
    debug(tag);
    display(tag);
    if let Some(name) = tag.bot_name() {
        header_value_string(name);
    }
    for rule in tag.custom_rules() {
        let (key, value) = rule.as_tuple();
        header_value_string(key);
        if let Some(value) = value {
            header_value_string(value);
        }
    }
    sink((tag.all(), tag.no_index(), tag.no_follow(), tag.none()));
    sink((
        tag.no_snippet(),
        tag.index_if_embedded(),
        tag.no_translate(),
    ));
    sink((
        tag.no_image_index(),
        tag.no_ai(),
        tag.no_image_ai(),
        tag.spc(),
    ));
    sink((tag.max_snippet(), tag.max_video_preview()));
    if let Some(setting) = tag.max_image_preview() {
        token(setting);
    }
    if let Some(date_time) = tag.unavailable_after() {
        directive_date_time(date_time);
    }
}

fn node_id(node: &NodeId) {
    debug(node);
    display(node);
    sink((
        node.ip(),
        node.port(),
        node.has_any_port(),
        node.authority(),
    ));
}

fn forwarded_authority(authority: &ForwardedAuthority) {
    debug(authority);
    display(authority);
    host_with_opt_port(&authority.0);
}

fn forwarded_element(element: &ForwardedElement) {
    debug(element);
    display(element);
    if let Some(node) = element.forwarded_for() {
        node_id(node);
    }
    if let Some(node) = element.forwarded_by() {
        node_id(node);
    }
    if let Some(authority) = element.forwarded_host() {
        forwarded_authority(authority);
    }
    if let Some(protocol) = element.forwarded_proto() {
        display(&protocol);
    }
    if let Some(version) = element.forwarded_version() {
        display(&version);
    }
    sink(element.authority());
}

fn forward_header<H>(header: &H)
where
    H: ForwardHeader + Clone + fmt::Debug,
{
    let elements: Vec<ForwardedElement> = header.clone().into_iter().collect();
    for element in &elements {
        forwarded_element(element);
    }
    converted::<Forwarded>(&elements);
    converted::<Via>(&elements);
    converted::<XForwardedFor>(&elements);
    converted::<XForwardedHost>(&elements);
    converted::<XForwardedProto>(&elements);
    converted::<CFConnectingIp>(&elements);
    converted::<TrueClientIp>(&elements);
    converted::<XRealIp>(&elements);
    converted::<ClientIp>(&elements);
    converted::<XClientIp>(&elements);
}

fn converted<H>(elements: &[ForwardedElement])
where
    H: ForwardHeader + Clone + fmt::Debug,
{
    if let Some(header) = H::try_from_forwarded(elements) {
        roundtrip(&header);
    }
}

fn encodings<S: SupportedEncodings>(map: &HeaderMap, supported: S) {
    sink(Encoding::maybe_from_content_encoding_header(map, supported));
    sink(Encoding::from_content_encoding_header(map, supported));
    sink(Encoding::maybe_from_accept_encoding_headers(map, supported));
    sink(Encoding::from_accept_encoding_headers(map, supported));
    let accepted: Vec<_> = parse_accept_encoding_headers(map, supported).collect();
    for qv in &accepted {
        quality_value(qv);
        sink((qv.value.to_file_extension(), HeaderValue::from(qv.value)));
    }
    let wildcard = parse_accept_encoding_wildcard_quality(map);
    sink(maybe_preferred_encoding_with_wildcard(
        &accepted, wildcard, supported,
    ));
    sink(Encoding::maybe_preferred_encoding(accepted.into_iter()));
    sink(AcceptEncoding::default().maybe_to_header_value());
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::{
        cell::{Cell, RefCell},
        collections::BTreeMap,
        panic::{self, AssertUnwindSafe},
        sync::Once,
    };

    const ADVERSARIAL: &[&[u8]] = &[
        b"",
        b" ",
        b"\t",
        b"W",
        b"W/",
        b"W/\"",
        b"W/\"a",
        b"w/\"a\"",
        b"W/ \"a\"",
        b"\"",
        b"\"\"",
        b"\"\"\"",
        b"\"a",
        b"a\"",
        b"\"a b\"",
        b"\" \"",
        b"\"\t\"",
        b"x",
        b"xyzzy",
        b"\"xyzzy\"",
        b"W/\"xyzzy\"",
        b" \"a\" ",
        b"\"a\", W/",
        b"\"a\",,W/\"b\"",
        b"*",
        b"*, \"a\"",
        b",",
        b",,",
        b", ,",
        b"=",
        b";",
        b";;q=",
        b"q=",
        b"q=2",
        b"q=-0",
        b"q=1.001",
        b"q=0.0000",
        b"a;q=",
        b"a;q=0.5",
        b"a;q=1.",
        b";q=1",
        b"*/*",
        b"*/*;q=",
        b"*/*;q=0.1, text/html",
        b"/",
        b"a/",
        b"/b",
        b"a/b;c",
        b"a/b; charset=\"",
        b"text/plain; charset=utf-8",
        b"bytes=",
        b"bytes=-",
        b"bytes=0-",
        b"bytes=-0",
        b"bytes=0-0",
        b"bytes=5-1",
        b"bytes=1-5",
        b"bytes=,",
        b"bytes=0-1,2-3,-4,5-",
        b"bytes=0-18446744073709551615",
        b"bytes=18446744073709551615-18446744073709551616",
        b"bytes=18446744073709551615-",
        b"bytes=-18446744073709551615",
        b"bytes=\xc3\xa9",
        b"bytes */0",
        b"bytes */*",
        b"bytes 0-0/0",
        b"bytes 5-1/10",
        b"bytes 0-18446744073709551615/18446744073709551615",
        b"bytes 18446744073709551615-18446744073709551615/*",
        b"bytes -1-2/3",
        b"0",
        b"-0",
        b"-1",
        b"+1",
        b"0x10",
        b"1e9",
        b"1.5",
        b"NaN",
        b"inf",
        b"-inf",
        b"4294967296",
        b"2147483648",
        b"18446744073709551615",
        b"18446744073709551616",
        b"99999999999999999999999999999999",
        b"00000000000000000000000000001",
        b"Sun, 06 Nov 1994 08:49:37 GMT",
        b"Sunday, 06-Nov-94 08:49:37 GMT",
        b"Sun Nov  6 08:49:37 1994",
        b"Thu, 01 Jan 1970 00:00:00 GMT",
        b"Wed, 31 Dec 1969 23:59:59 GMT",
        b"Mon, 01 Jan 0000 00:00:00 GMT",
        b"Fri, 31 Dec 9999 23:59:59 GMT",
        b"Sat, 01 Jan 10000 00:00:00 GMT",
        b"Mon, 01 Jan 99999 00:00:00 GMT",
        b"Mon, 32 Jan 2024 00:00:00 GMT",
        b"Wed, 29 Feb 2023 00:00:00 GMT",
        b"Mon, 01 Jan 2024 25:61:61 GMT",
        b"2024-01-01T00:00:00Z",
        b"2024-01-01T00:00:00+99:99",
        b"2024-01-01T00:00:00-00:00",
        b"0000-01-01",
        b"9999-12-31T23:59:59Z",
        b"+009999-12-31",
        b"-000001-01-01",
        b"-009999-01-01T00:00:00Z",
        b"25 Jun 2010 15:00:00 PST",
        b"Friday, 01-Jan-99 00:00:00 XYZ",
        b"unavailable_after: 2024-13-45",
        b"unavailable_after: -000001-01-01",
        b"unavailable_after: -009999-01-01T00:00:00Z",
        b"unavailable_after: 0000-01-01",
        b"\xc3\xa9",
        b"\xe6\x97\xa5\xe6\x9c\xac",
        b"\xf0\x9f\x98\x80",
        b"\x80",
        b"\xff",
        b"\xc3",
        b"\xe6\x97",
        b"a\x80b",
        b"\"\x80\"",
        b"W/\"\xff\"",
        b"\"\xc3\xa9\"",
        b"W/\"\xc3\xa9\"",
        b"Basic",
        b"Basic ",
        b"Basic  ",
        b"Basic !!!",
        b"Basic dXNlcg==",
        b"Basic dXNlcjo=",
        b"Basic OnBhc3M=",
        b"Basic Og==",
        b"Basic gA==",
        b"basic dXNlcjpwYXNz",
        b"Basic\tdXNlcjpwYXNz",
        b"Basic dXNlcjpwYXNz",
        b"Bearer",
        b"Bearer ",
        b"Bearer  ",
        b"Bearer \x80",
        b"bearer x",
        b"Digest x",
        b"[::1",
        b"[::1]",
        b"[::1]:",
        b"[::1]:99999",
        b"::ffff:1.2.3.4",
        b"1.2.3.4:",
        b"1.2.3.4:65536",
        b"[",
        b"]",
        b"[]",
        b":",
        b"::",
        b":80",
        b"host:",
        b"a..b",
        b".",
        b"-a.com",
        b"xn--",
        b"xn--\xc3\xa9",
        b"http://",
        b"https://a",
        b"https://a/",
        b"https://a/b",
        b"https://a?b",
        b"https://a#b",
        b"https://u@a",
        b"null",
        b"http://[::1]:0",
        b"https://\xc3\xa9.com",
        b"a://b:99999",
        b"default-src 'self'",
        b"script-src 'nonce-",
        b"script-src 'sha256-'",
        b"img-src *:*",
        b"a https://:*/",
        b"a ://",
        b"'",
        b"''",
        b"h3=\":443\"",
        b"h3=\":\"",
        b"h3=\"\"",
        b"h3=\"[::1]:443\"; ma=18446744073709551616; persist=1",
        b"h3=\"a:1\"; ma=1; ma=2",
        b"h3=\"a:1\";",
        b"%",
        b"%%",
        b"%zz=\":1\"",
        b"h%33=\":1\"",
        b"clear",
        b"u=",
        b"u=8",
        b"u=-1, i",
        b"i=?2",
        b"u=99999999999999999",
        b"camera=()",
        b"camera=(\"\")",
        b"camera=(self \"https://a\")",
        b"camera",
        b"=()",
        b"max-age=",
        b"max-age=-1",
        b"max-age=18446744073709551616",
        b"max-age=\"1\"; includeSubDomains; preload",
        b"no-cache, max-age=1, max-age=2",
        b"s-maxage=18446744073709551615",
        b"permessage-deflate; server_max_window_bits=99999",
        b"permessage-deflate; client_max_window_bits",
        b"permessage-deflate;;",
        b"attachment; filename*=UTF-8''%",
        b"attachment; filename*=UTF-8''%e9",
        b"form-data",
        b"websocket, h2c",
        b"dGhlIHNhbXBsZSBub25jZQ==",
        b"13",
        b"100-continue",
        b"on",
        b"off",
        b"slow-2g",
        b"sec-ch-ua, ect",
        b"noindex, googlebot: nofollow",
        b"max-snippet: -1",
        b"max-video-preview: 99999999999",
        b"max-image-preview: \xc3\xa9",
        b"googlebot:",
        b"a: b: c",
        b"for=1.2.3.4;proto=https;by=_x;host=\"a:1\"",
        b"for=\"[::1]:80\"",
        b"for=",
        b";;;",
        b"1.1 proxy",
        b"HTTP/1.1 a, 2 b",
        b"/1.1 x",
        b"http/ x",
        b"same-origin; report-to=\"",
        b"require-corp; report-to=",
        b"no-referrer, ,unsafe-url",
    ];

    fn long_inputs() -> Vec<Vec<u8>> {
        vec![
            vec![b'a'; 64 * 1024],
            vec![0xff; 64 * 1024],
            vec![b','; 10_000],
            vec![b'"'; 10_000],
            vec![b'['; 10_000],
            vec![b'('; 10_000],
            vec![b';'; 10_000],
            vec![b'1'; 10_000],
            b"W/\"".repeat(5_000),
            b"\"a\", ".repeat(5_000),
            b"0-1,".repeat(5_000),
            [b"bytes=".as_slice(), &b"0-1,".repeat(5_000)].concat(),
            [b"bytes=".as_slice(), &b"-1,".repeat(5_000)].concat(),
            [b"q=0.".as_slice(), &[b'0'; 10_000]].concat(),
            b"a=b; ".repeat(5_000),
            b"%41".repeat(5_000),
            b"noindex, ".repeat(5_000),
            b"a: ".repeat(5_000),
            b"h3=\":1\", ".repeat(2_000),
        ]
    }

    const TOKENS: &[&[u8]] = &[
        b"W/",
        b"\"",
        b"*",
        b",",
        b", ",
        b";",
        b"=",
        b" ",
        b"\t",
        b"q=",
        b"q=0.5",
        b"q=1",
        b"q=2",
        b"0",
        b"1",
        b"9",
        b"-",
        b"/",
        b":",
        b".",
        b"[",
        b"]",
        b"(",
        b")",
        b"%",
        b"%41",
        b"'",
        b"?1",
        b"a",
        b"Z",
        b"xyzzy",
        b"\xc3\xa9",
        b"\x80",
        b"\xff",
        b"bytes=",
        b"bytes ",
        b"*/*",
        b"text/html",
        b"gzip",
        b"br",
        b"identity",
        b"chunked",
        b"Basic ",
        b"Bearer ",
        b"dXNlcjpwYXNz",
        b"max-age=",
        b"no-cache",
        b"ma=",
        b"persist=1",
        b"h3=",
        b"\":443\"",
        b"u=",
        b"i",
        b"filename*=UTF-8''",
        b"'self'",
        b"'nonce-",
        b"'sha256-",
        b"https://",
        b"example.com",
        b"::1",
        b"1.2.3.4",
        b"for=",
        b"proto=",
        b"by=",
        b"host=",
        b"HTTP/1.1",
        b"null",
        b"close",
        b"keep-alive",
        b"websocket",
        b"noindex",
        b"googlebot:",
        b"unavailable_after: ",
        b"2024-01-01",
        b"Sun, 06 Nov 1994 08:49:37 GMT",
        b"GMT",
        b"18446744073709551615",
        b"18446744073709551616",
        b"99999",
        b"-1",
        b"NaN",
        b"1e9",
        b"report-to=",
        b"permessage-deflate",
        b"server_max_window_bits=",
        b"camera=",
    ];

    const STR_ONLY: &[&str] = &[
        "\n",
        "\r\n",
        "\0",
        "\x7f",
        "a\nb",
        "\"\n\"",
        "W/\"\n\"",
        "https://a\n",
        "attachment\u{7f}",
        "\u{2028}",
        "\u{feff}",
        "\u{10ffff}",
        "é://é",
        "a://",
        "://",
        "'nonce-\n'",
        "*:\n",
    ];

    struct XorShift(u64);

    impl XorShift {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x.wrapping_shl(13);
            x ^= x.wrapping_shr(7);
            x ^= x.wrapping_shl(17);
            self.0 = x;
            x
        }

        fn below(&mut self, n: usize) -> usize {
            usize::try_from(self.next())
                .unwrap_or_default()
                .checked_rem(n)
                .unwrap_or_default()
        }

        fn bytes(&mut self) -> Vec<u8> {
            let count = self.below(10).saturating_add(1);
            (0..count)
                .flat_map(|_| TOKENS[self.below(TOKENS.len())].iter().copied())
                .collect()
        }
    }

    fn value(bytes: &[u8]) -> Option<HeaderValue> {
        HeaderValue::from_bytes(bytes).ok()
    }

    fn value_corpus() -> Vec<Vec<HeaderValue>> {
        let mut singles: Vec<Vec<u8>> = ADVERSARIAL.iter().map(|b| b.to_vec()).collect();
        singles.extend(
            (0x20..=0x7e)
                .chain([0x09, 0x80, 0xc3, 0xff])
                .map(|b| vec![b]),
        );
        singles.extend(long_inputs());
        let mut corpus: Vec<Vec<HeaderValue>> = singles
            .iter()
            .filter_map(|b| value(b))
            .map(|v| vec![v])
            .collect();
        let pairable: Vec<HeaderValue> = ADVERSARIAL
            .iter()
            .step_by(4)
            .filter_map(|b| value(b))
            .collect();
        for a in &pairable {
            for b in &pairable {
                corpus.push(vec![a.clone(), b.clone()]);
            }
        }
        corpus.push(pairable);
        let mut rng = XorShift(0x9e37_79b9_7f4a_7c15);
        for _ in 0..3_000 {
            let count = rng.below(3).saturating_add(1);
            let values: Vec<HeaderValue> = (0..count).filter_map(|_| value(&rng.bytes())).collect();
            if !values.is_empty() {
                corpus.push(values);
            }
        }
        corpus
    }

    fn str_corpus() -> Vec<String> {
        let mut corpus: Vec<String> = ADVERSARIAL
            .iter()
            .filter_map(|b| std::str::from_utf8(b).ok())
            .chain(STR_ONLY.iter().copied())
            .map(str::to_owned)
            .collect();
        corpus.extend((0u8..=0x7f).map(|b| char::from(b).to_string()));
        corpus.extend(
            long_inputs()
                .into_iter()
                .filter_map(|b| String::from_utf8(b).ok()),
        );
        let mut rng = XorShift(0x2545_f491_4f6c_dd1d);
        for _ in 0..3_000 {
            let mut bytes = rng.bytes();
            if rng.below(4) == 0 {
                bytes.push(b"\n\r\0\x7f"[rng.below(4)]);
            }
            if let Ok(s) = String::from_utf8(bytes) {
                corpus.push(s);
            }
        }
        corpus
    }

    const EDGE_NUMBERS: &[u64] = &[
        0,
        1,
        2,
        12,
        13,
        31,
        32,
        99,
        100,
        101,
        1_000,
        4_294_967_295,
        253_402_300_799,
        253_402_300_800,
        i64::MAX.unsigned_abs(),
        u64::MAX - 1,
        u64::MAX,
    ];

    thread_local! {
        static CAPTURING: Cell<bool> = const { Cell::new(false) };
        static CAPTURED: RefCell<Option<(String, String)>> = const { RefCell::new(None) };
    }

    fn install_panic_capture() {
        static HOOK: Once = Once::new();
        HOOK.call_once(|| {
            let previous = panic::take_hook();
            panic::set_hook(Box::new(move |info| {
                if CAPTURING.get() {
                    let location = info
                        .location()
                        .map(|l| format!("{}:{}", l.file(), l.line()))
                        .unwrap_or_default();
                    let message = info.payload_as_str().unwrap_or_default().to_owned();
                    CAPTURED.set(Some((location, message)));
                } else {
                    previous(info);
                }
            }));
        });
    }

    #[derive(Default)]
    struct Failures {
        sites: BTreeMap<(String, String), (String, String, usize)>,
    }

    impl Failures {
        fn check(&mut self, exercise: &str, input: impl FnOnce() -> String, f: impl FnOnce()) {
            CAPTURING.set(true);
            let result = panic::catch_unwind(AssertUnwindSafe(f));
            CAPTURING.set(false);
            if result.is_ok() {
                return;
            }
            let (location, message) = CAPTURED.take().unwrap_or_default();
            let input = input();
            let entry = self
                .sites
                .entry((exercise.to_owned(), location))
                .or_insert_with(|| (message.clone(), input.clone(), 0));
            entry.2 = entry.2.saturating_add(1);
            if input.len() < entry.1.len() {
                entry.0 = message;
                entry.1 = input;
            }
        }

        fn assert_empty(self, kind: &str) {
            let report: Vec<String> = self
                .sites
                .into_iter()
                .map(|((exercise, location), (message, input, count))| {
                    let mut input = input;
                    if input.len() > 160 {
                        let cut = (0..=160).rev().find(|i| input.is_char_boundary(*i)).unwrap_or(0);
                        input.truncate(cut);
                        input.push_str("...");
                    }
                    format!("{exercise} @ {location} ({count} inputs): {message}\n    minimal input: {input}")
                })
                .collect();
            assert!(
                report.is_empty(),
                "{} distinct {kind} panic sites:\n{}",
                report.len(),
                report.join("\n")
            );
        }
    }

    #[test]
    fn typed_headers_never_panic_on_adversarial_values() {
        install_panic_capture();
        let mut failures = Failures::default();
        for values in value_corpus() {
            for (name, exercise) in VALUES_EXERCISES {
                failures.check(name, || format!("{values:?}"), || exercise(&values));
            }
        }
        failures.assert_empty("header value");
    }

    #[test]
    fn string_parsers_never_panic_on_adversarial_input() {
        install_panic_capture();
        let mut failures = Failures::default();
        for s in str_corpus() {
            for (name, exercise) in STR_EXERCISES {
                failures.check(name, || format!("{s:?}"), || exercise(&s));
            }
        }
        failures.assert_empty("string");
    }

    #[test]
    fn numeric_constructors_never_panic_on_edge_values() {
        install_panic_capture();
        let mut failures = Failures::default();
        for &a in EDGE_NUMBERS {
            for &b in EDGE_NUMBERS {
                for (name, exercise) in NUMBERS_EXERCISES {
                    failures.check(name, || format!("({a}, {b})"), || exercise(a, b));
                }
            }
        }
        failures.assert_empty("numeric constructor");
    }

    #[test]
    fn exercise_bytes_accepts_arbitrary_data() {
        install_panic_capture();
        let mut failures = Failures::default();
        let mut rng = XorShift(0xdead_beef_cafe_f00d);
        for _ in 0..200 {
            let data: Vec<u8> = (0..rng.below(4).saturating_add(1))
                .flat_map(|_| {
                    let mut chunk = rng.bytes();
                    chunk.push(b'\n');
                    chunk
                })
                .collect();
            failures.check(
                "exercise_bytes",
                || format!("{data:?}"),
                || exercise_bytes(&data),
            );
        }
        failures.assert_empty("exercise_bytes");
    }
}
