//! Exercises for the values nested inside decoded headers.

use std::{fmt, time::SystemTime};

use rama_core::extensions::Extensions;
use rama_http_types::{
    HeaderMap, HeaderValue,
    mime::{self, Mime},
};
use rama_net::{
    address::{Host as NetHost, HostWithOptPort},
    forwarded::{ForwardedAuthority, ForwardedElement, NodeId},
    user::Basic,
};
use rama_utils::collections::NonEmptySmallVec;

use crate::{
    After, AltSvc, AlternativeService, ClientHint, HostSource, Origin, SourceExpression, Vary,
    authorization::AuthoritySync,
    encoding::{
        AcceptEncoding, Encoding, SupportedEncodings, maybe_preferred_encoding_with_wildcard,
        parse_accept_encoding_headers, parse_accept_encoding_wildcard_quality,
    },
    forwarded::{
        CFConnectingIp, ClientIp, ForwardHeader, Forwarded, TrueClientIp, Via, XClientIp,
        XForwardedFor, XForwardedHost, XForwardedProto, XRealIp,
    },
    fuzz::support::{debug, display, roundtrip, sink, token},
    sec_websocket_extensions::Extension,
    specifier::QualityValue,
    util::{HeaderValueString, Seconds, ValuesOrAny},
    x_robots_tag::{DirectiveDateTime, RobotsTag},
};

pub(super) fn quality_value<T: fmt::Display + fmt::Debug>(qv: &QualityValue<T>) {
    debug(qv);
    display(qv);
    sink(qv.quality.as_u16());
}

pub(super) fn values_or_any<T: fmt::Debug>(value: &ValuesOrAny<T>) {
    if let ValuesOrAny::Values(values) = value {
        for value in values.iter() {
            debug(value);
        }
    }
}

pub(super) fn mime_type(mime: &Mime) {
    display(mime);
    sink((mime.type_().as_str(), mime.subtype().as_str()));
    sink((mime.suffix().map(|name| name.as_str()), mime.essence_str()));
    sink(mime.get_param(mime::CHARSET));
    for (name, value) in mime.params() {
        sink((name.as_str(), value.as_str()));
    }
}

pub(super) fn header_value_string(value: &HeaderValueString) {
    debug(value);
    display(value);
    sink(value.as_str());
    sink(HeaderValue::from(value));
}

pub(super) fn seconds_value(seconds: Seconds) {
    debug(&seconds);
    display(&seconds);
    sink((
        seconds.as_u64(),
        seconds.as_duration(),
        HeaderValue::from(&seconds),
    ));
}

pub(super) fn after(value: After) {
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

pub(super) fn net_host(host: &NetHost) {
    debug(host);
    display(host);
    sink((host.to_str(), host.is_loopback(), host.is_empty()));
    sink((host.try_as_domain(), host.try_as_ip()));
    sink(host.clone().canonicalize());
}

pub(super) fn host_with_opt_port(value: &HostWithOptPort) {
    debug(value);
    display(value);
    net_host(&value.host);
}

pub(super) fn origin(value: &Origin) {
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

pub(super) fn basic(credentials: &Basic) {
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

pub(super) fn alternative_service(service: &AlternativeService) {
    debug(service);
    sink(service.protocol().as_bytes());
    if let Some(host) = service.host() {
        net_host(host);
    }
    sink((service.port(), service.max_age(), service.persist()));
    roundtrip(&AltSvc::new(service.clone()));
}

pub(super) fn host_source(source: &HostSource) {
    debug(source);
    display(source);
    sink((source.scheme().map(|scheme| scheme.as_str()), source.path()));
    display(source.host());
    if let Some(port) = source.port() {
        display(&port);
    }
    sink(HostSource::try_parse(&source.to_string()));
}

pub(super) fn source_expression(expression: &SourceExpression) {
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

pub(super) fn ws_extension(extension: &Extension) {
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

pub(super) fn client_hint(hint: ClientHint) {
    token(&hint);
    sink((
        hint.as_str(),
        hint.is_low_entropy(),
        hint.header_name_strs(),
    ));
    sink(hint.iter_header_names().count());
}

pub(super) fn client_hints(hints: &NonEmptySmallVec<16, ClientHint>) {
    for hint in hints.iter() {
        client_hint(*hint);
    }
    if let Some(vary) = Vary::from_client_hints(hints.iter()) {
        roundtrip(&vary);
    }
}

pub(super) fn directive_date_time(date_time: &DirectiveDateTime) {
    debug(date_time);
    display(date_time);
    sink(date_time.date_time());
    display(&date_time.clone().with_format_rfc3339());
    display(&date_time.clone().with_format_rfc2822());
    display(&date_time.clone().with_format_rfc855());
    display(&date_time.clone().with_format_default());
}

pub(super) fn robots_tag(tag: &RobotsTag) {
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

pub(super) fn node_id(node: &NodeId) {
    debug(node);
    display(node);
    sink((
        node.ip(),
        node.port(),
        node.has_any_port(),
        node.authority(),
    ));
}

pub(super) fn forwarded_authority(authority: &ForwardedAuthority) {
    debug(authority);
    display(authority);
    host_with_opt_port(&authority.0);
}

pub(super) fn forwarded_element(element: &ForwardedElement) {
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

pub(super) fn forward_header<H>(header: &H)
where
    H: ForwardHeader + Clone + fmt::Debug,
{
    let elements: Vec<ForwardedElement> = header.clone().into_iter().collect();
    for element in &elements {
        forwarded_element(element);
    }
    for (_, convert) in FORWARD_HEADERS {
        convert(&elements);
    }
}

/// Every [`ForwardHeader`], rebuilt from forwarded elements.
pub(super) const FORWARD_HEADERS: &[(&str, fn(&[ForwardedElement]))] = &[
    forward_conversion!(Forwarded),
    forward_conversion!(Via),
    forward_conversion!(XForwardedFor),
    forward_conversion!(XForwardedHost),
    forward_conversion!(XForwardedProto),
    forward_conversion!(CFConnectingIp),
    forward_conversion!(TrueClientIp),
    forward_conversion!(XRealIp),
    forward_conversion!(ClientIp),
    forward_conversion!(XClientIp),
];

pub(super) fn converted<H>(elements: &[ForwardedElement])
where
    H: ForwardHeader + Clone + fmt::Debug,
{
    if let Some(header) = H::try_from_forwarded(elements) {
        roundtrip(&header);
    }
}

pub(super) fn encodings<S: SupportedEncodings>(map: &HeaderMap, supported: S) {
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
