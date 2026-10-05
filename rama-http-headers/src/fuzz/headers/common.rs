//! Headers of the crate's `common` module.

use std::time::{Duration, SystemTime};

use rama_http_types::{Method, header};
use rama_net::{
    address::{Host as NetHost, HostWithOptPort},
    user::{Basic, Bearer, RawToken},
};
use rama_utils::collections::NonEmptyVec;

use crate::{
    Accept, AcceptRanges, AccessControlAllowCredentials, AccessControlAllowHeaders,
    AccessControlAllowMethods, AccessControlAllowOrigin, AccessControlAllowPrivateNetwork,
    AccessControlExposeHeaders, AccessControlMaxAge, AccessControlRequestHeaders,
    AccessControlRequestMethod, AccessControlRequestPrivateNetwork, Age, Allow, AltSvc, AltUsed,
    Authorization, CacheControl, CapsuleProtocol, Connection, ContentDisposition, ContentEncoding,
    ContentLength, ContentLocation, ContentRange, ContentSecurityPolicy, ContentType, Cookie,
    CrossOriginEmbedderPolicy, CrossOriginEmbedderPolicyReportOnly, CrossOriginOpenerPolicy,
    CrossOriginOpenerPolicyReportOnly, CrossOriginResourcePolicy, Date, ETag, Expect, Expires,
    Host, IfMatch, IfModifiedSince, IfNoneMatch, IfRange, IfUnmodifiedSince, LastEventId,
    LastModified, Location, Origin, PermissionsPolicy, Pragma, Priority, ProxyAuthorization, Range,
    Referer, ReferrerPolicy, RetryAfter, SecFetchSite, SecWebSocketAccept, SecWebSocketExtensions,
    SecWebSocketKey, SecWebSocketProtocol, SecWebSocketVersion, Server, SetCookie,
    StrictTransportSecurity, Te, TransferEncoding, Upgrade, UserAgent, Vary, XContentTypeOptions,
    XFrameOptions,
    encoding::{AcceptEncoding, Encoding},
    fuzz::{
        ValuesExercise,
        parts::{
            after, alternative_service, basic, host_with_opt_port, mime_type, origin,
            quality_value, source_expression, values_or_any, ws_extension,
        },
        probes::{
            CONTENT_LENGTHS, etag_preconditions, probe_etags, probe_last_modified, probe_times,
        },
        support::{debug, display, eq, roundtrip, sink, token},
    },
    specifier::sort_quality_values_non_empty_vec,
};

pub(super) const HEADERS: &[ValuesExercise] = &[
    decode!(Accept, |h| {
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
        sink((h.is_bytes(), h.is_none()));
    }),
    decode!(AccessControlAllowCredentials),
    decode!(AccessControlAllowHeaders, |h| {
        sink(h.is_any());
        values_or_any(&h.0);
        sink(h.as_values().map(|names| names.len()));
        sink(h.into_values());
    }),
    decode!(AccessControlAllowMethods, |h| {
        sink(h.is_any());
        values_or_any(&h.0);
        sink(h.as_values().map(|methods| methods.len()));
        sink(h.into_values());
    }),
    decode!(AccessControlAllowOrigin, |h| {
        if let Some(value) = h.origin() {
            origin(value);
        }
    }),
    decode!(AccessControlAllowPrivateNetwork),
    decode!(AccessControlExposeHeaders, |h| {
        sink(h.is_any());
        values_or_any(&h.0);
        sink(h.as_values().map(|names| names.len()));
        sink(h.into_values());
    }),
    decode!(AccessControlMaxAge, |h| {
        sink((h.as_secs(), Duration::from(h)));
    }),
    decode!(AccessControlRequestHeaders, |h| {
        for name in h.0.iter() {
            sink(name.as_str());
        }
    }),
    decode!(AccessControlRequestMethod, |h| {
        sink(h.0.as_str());
        sink(Method::from(h));
    }),
    decode!(AccessControlRequestPrivateNetwork),
    decode!(Age, |h| {
        sink((h.as_secs(), Duration::from(h)));
    }),
    decode!(Allow, |h| {
        for method in h.0.iter() {
            sink(method.as_str());
        }
    }),
    decode!(AltSvc, |h| {
        sink(h.is_clear());
        if let Some(services) = h.alternatives() {
            for service in services {
                alternative_service(service);
            }
        }
    }),
    decode!(AltUsed, |h| {
        display(&h);
        host_with_opt_port(&h.0);
    }),
    decode!(Authorization<Basic>, |h| {
        basic(h.credentials());
        roundtrip(&ProxyAuthorization(h.into_inner()));
    }),
    decode!(Authorization<Bearer>, |h| {
        sink(h.token());
        display(h.credentials());
        roundtrip(&ProxyAuthorization(h.into_inner()));
    }),
    decode!(Authorization<RawToken>, |h| {
        sink(h.token());
        display(h.credentials());
        roundtrip(&ProxyAuthorization(h.into_inner()));
    }),
    decode!(ProxyAuthorization<Basic>, |h| {
        basic(&h.0);
        roundtrip(&Authorization::new(h.0));
    }),
    decode!(ProxyAuthorization<Bearer>, |h| {
        sink(h.0.token());
        display(&h.0);
        roundtrip(&Authorization::new(h.0));
    }),
    decode!(ProxyAuthorization<RawToken>, |h| {
        sink(h.0.token());
        display(&h.0);
        roundtrip(&Authorization::new(h.0));
    }),
    decode!(CapsuleProtocol, |h| {
        sink(h.is_enabled());
    }),
    decode!(CacheControl, |h| {
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
        sink(h.0);
    }),
    decode!(ContentLocation),
    decode!(ContentRange, |h| {
        sink(h.bytes_len());
        if let Some((first, last)) = h.bytes_range()
            && let Ok(again) = ContentRange::bytes(first..=last, h.bytes_len())
        {
            roundtrip(&again);
        }
    }),
    decode!(ContentSecurityPolicy, |h| {
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
        display(&h);
        token(&h.value);
        sink((h.value.as_str(), h.report_to.as_deref()));
        roundtrip(&CrossOriginEmbedderPolicyReportOnly::from_enforcing(h));
    }),
    decode!(CrossOriginEmbedderPolicyReportOnly, |h| {
        display(&h);
        token(&h.value);
        sink((h.value.as_str(), h.report_to.as_deref()));
        roundtrip(&CrossOriginEmbedderPolicy {
            value: h.value,
            report_to: h.report_to,
        });
    }),
    decode!(CrossOriginOpenerPolicy, |h| {
        display(&h);
        token(&h.value);
        sink((h.value.as_str(), h.report_to.as_deref()));
        roundtrip(&CrossOriginOpenerPolicyReportOnly::from_enforcing(h));
    }),
    decode!(CrossOriginOpenerPolicyReportOnly, |h| {
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
        sink(SystemTime::from(h));
    }),
    decode!(ETag, |h| {
        sink(h.is_weak());
        etag_preconditions(&h);
    }),
    decode!(Expect),
    decode!(Expires, |h| {
        sink(SystemTime::from(h));
    }),
    decode!(Host, |h| {
        display(&h);
        host_with_opt_port(&h.0);
        sink(HostWithOptPort::from(h.clone()));
        sink(NetHost::from(h));
    }),
    decode!(IfMatch, |h, values| {
        sink(h.is_any());
        for tag in probe_etags(values) {
            sink(h.precondition_passes(&tag));
        }
    }),
    decode!(IfModifiedSince, |h| {
        sink(SystemTime::from(h));
        for time in probe_times() {
            sink(h.is_modified(time));
        }
    }),
    decode!(IfNoneMatch, |h, values| {
        for tag in probe_etags(values) {
            sink(h.precondition_passes(&tag));
        }
    }),
    decode!(IfRange, |h, values| {
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
        sink(SystemTime::from(h));
        for time in probe_times() {
            sink(h.precondition_passes(time));
        }
    }),
    decode!(LastEventId, |h| {
        display(&h);
        let as_ref: &str = h.as_ref();
        sink((h.as_str(), as_ref));
    }),
    decode!(LastModified, |h| {
        sink(SystemTime::from(h));
    }),
    decode!(Location, |h| {
        sink(h.to_str());
    }),
    decode!(Origin, |h| {
        origin(&h);
    }),
    decode!(PermissionsPolicy, |h| {
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
        sink(h.is_no_cache());
    }),
    decode!(Priority, |h| {
        sink((h.urgency(), h.incremental(), h.field_value()));
    }),
    decode!(Range, |h| {
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
        display(&h);
    }),
    decode!(ReferrerPolicy, |h| {
        roundtrip(&h.clone().with_fallback(h));
    }),
    decode!(RetryAfter, |h| {
        after(h.after());
    }),
    decode!(SecFetchSite, |h| {
        token(&h);
        sink(h.as_str());
    }),
    decode!(SecWebSocketAccept),
    decode!(SecWebSocketExtensions, |h| {
        for extension in h.0.iter() {
            ws_extension(extension);
        }
    }),
    decode!(SecWebSocketKey, |h| {
        if let Ok(accept) = SecWebSocketAccept::try_from(h) {
            roundtrip(&accept);
        }
    }),
    decode!(SecWebSocketProtocol, |h| {
        for protocol in h.iter() {
            sink(h.contains(protocol));
        }
        sink((h.contains(""), h.contains_any(["chat", " "])));
        let accepted = h.accept_first_protocol();
        debug(&accepted);
        roundtrip(&accepted.into_header());
    }),
    decode!(SecWebSocketVersion),
    decode!(Server, |h| {
        display(&h);
        sink(h.as_str());
    }),
    decode!(SetCookie, |h| {
        for value in h.iter_header_values() {
            sink(value.to_str());
        }
    }),
    decode!(StrictTransportSecurity, |h| {
        sink((h.include_subdomains(), h.preload(), h.max_age()));
    }),
    decode!(Te, |h| {
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
        sink((h.as_bytes(), h.is_websocket(), h.contains_websocket()));
    }),
    decode!(UserAgent, |h| {
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
    decode!(XContentTypeOptions),
    decode!(XFrameOptions),
];
