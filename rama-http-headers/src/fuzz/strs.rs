//! Every public string parser of this crate.

use std::time::SystemTime;

use rama_http_types::mime::Mime;
use rama_net::{
    address::{Domain, Host as NetHost},
    tls::ApplicationProtocol,
};
use rama_utils::str::NonEmptyStr;

use crate::{
    Accept, AcceptCh, AccessControlAllowOrigin, After, AllowlistSource, AlternativeService,
    ClientHint, ContentDisposition, ContentEncoding, ContentEncodingDirective,
    ContentSecurityPolicy, ContentType, CriticalCh, CrossOriginEmbedderPolicy,
    CrossOriginEmbedderPolicyValue, CrossOriginOpenerPolicy, CrossOriginOpenerPolicyValue,
    CrossOriginResourcePolicy, DirectiveName, ETag, HashAlgorithm, HostSource, LastEventId,
    LastModified, Origin, PermissionsPolicy, PermissionsPolicyDirective,
    PermissionsPolicyDirectiveName, Referer, SecFetchSite, SecWebSocketExtensions,
    SecWebSocketProtocol, Server, SourceExpression, SourceList, Te, TeDirective, TransferEncoding,
    TransferEncodingDirective, UserAgent, XRobotsTag,
    exotic::XClacksOverhead,
    fuzz::{
        StrExercise,
        parts::{
            after, alternative_service, client_hint, directive_date_time, header_value_string,
            host_source, mime_type, origin, quality_value, source_expression, ws_extension,
        },
        probes::etag_preconditions,
        support::{debug, display, roundtrip, sink},
    },
    sec_websocket_extensions::{Extension, PerMessageDeflateConfig, PerMessageDeflateIdentifier},
    specifier::{Quality, QualityValue},
    util::{HeaderValueString, HttpDate},
    x_robots_tag::{DirectiveDateTime, MaxImagePreviewSetting, RobotsTag},
};

pub(super) const STRS: &[StrExercise] = &[
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
