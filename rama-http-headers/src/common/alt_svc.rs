use std::io::Write as _;
use std::time::Duration;

use rama_core::error::{BoxError, BoxErrorExt as _, ErrorContext as _};
use rama_core::telemetry::tracing;
use rama_http_types::{HeaderName, HeaderValue};
use rama_net::{
    address::{AuthorityRef, Host, HostRef, HostWithPort, OptPort},
    tls::ApplicationProtocol,
};
use rama_utils::collections::NonEmptyVec;

use crate::util::{
    ListMembers, QuotedString, Seconds, is_http_token_byte, scan_quoted_string, skip_ows, trim_ows,
};
use crate::{Error, HeaderDecode, HeaderEncode, TypedHeader};

const DEFAULT_MAX_AGE_SECONDS: u64 = 24 * 60 * 60;
const DELTA_SECONDS_OVERFLOW: u64 = 2_147_483_648;
const MAX_ALPN_PROTOCOL_LEN: usize = u8::MAX as usize;
const FIRST_INVALID_ALPN_PROTOCOL_LEN: usize = MAX_ALPN_PROTOCOL_LEN.saturating_add(1);
const MAX_ENCODED_PROTOCOL_LEN: usize = MAX_ALPN_PROTOCOL_LEN * 3;

/// The `Alt-Svc` response header defined by RFC 7838 section 3.
///
/// Alternative services are ordered by server preference. [`Self::Clear`]
/// asks a client to invalidate every cached alternative for the origin.
/// Unknown parameters are ignored during decoding and are not re-encoded.
///
/// # Security
///
/// This header is an untrusted routing hint, not authorization. Consumers must
/// retain the origin URI authority and HTTP `Host` header; use the origin host
/// for SNI, certificate, and pin validation; reject weaker protocols; and
/// preserve proxy policy. See RFC 7838 sections 2.1 through 2.4 and 9.
///
/// # Example
///
/// ```
/// use rama_http_headers::{AltSvc, AlternativeService, HeaderMapExt};
/// use rama_http_types::HeaderMap;
/// use rama_net::tls::ApplicationProtocol;
///
/// let service = AlternativeService::new(ApplicationProtocol::HTTP_3, 443)
///     .unwrap()
///     .with_max_age_seconds(3_600)
///     .with_persist(true);
/// let mut headers = HeaderMap::new();
/// headers.typed_insert(AltSvc::new(service));
///
/// assert_eq!(
///     headers["alt-svc"],
///     r#"h3=":443"; ma=3600; persist=1"#,
/// );
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AltSvc {
    /// Invalidate every cached alternative service for the origin.
    Clear,
    /// Ordered alternative services, most preferred first.
    Alternatives(NonEmptyVec<AlternativeService>),
}

impl From<AlternativeService> for AltSvc {
    fn from(service: AlternativeService) -> Self {
        Self::new(service)
    }
}

impl AltSvc {
    /// Create a header advertising one alternative service.
    #[must_use]
    pub fn new(service: AlternativeService) -> Self {
        Self::Alternatives(NonEmptyVec::new(service))
    }

    /// Return whether this header clears cached alternatives.
    #[must_use]
    pub const fn is_clear(&self) -> bool {
        matches!(self, Self::Clear)
    }

    /// Return the advertised services, or `None` for [`Self::Clear`].
    #[must_use]
    pub fn alternatives(&self) -> Option<impl ExactSizeIterator<Item = &AlternativeService>> {
        match self {
            Self::Clear => None,
            Self::Alternatives(services) => Some(services.iter()),
        }
    }
}

/// One RFC 7838 alternative service.
///
/// The optional host is absent when the alternative uses the origin host.
/// `max_age` defaults to 24 hours and `persist` defaults to `false`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AlternativeService {
    protocol: ApplicationProtocol,
    host: Option<Host>,
    port: u16,
    max_age: Seconds,
    persist: bool,
}

impl AlternativeService {
    /// Create an alternative on the origin host.
    ///
    /// # Errors
    ///
    /// Returns an error when the ALPN protocol identifier is empty or exceeds
    /// the one-octet ALPN length limit.
    pub fn new(protocol: ApplicationProtocol, port: u16) -> Result<Self, BoxError> {
        validate_protocol(&protocol)?;
        Ok(Self {
            protocol,
            host: None,
            port,
            max_age: Seconds::new(DEFAULT_MAX_AGE_SECONDS),
            persist: false,
        })
    }

    /// Try to use a different host than the origin.
    ///
    /// An empty host is normalized to the origin host.
    ///
    /// # Errors
    ///
    /// Returns an error when `host` has no strict RFC 3986 presentation.
    pub fn try_with_host(mut self, host: impl Into<Host>) -> Result<Self, BoxError> {
        let host = host.into();
        if host.is_empty() {
            self.host = None;
        } else {
            validate_alternative_host(&host)?;
            self.host = Some(host);
        }
        Ok(self)
    }

    /// Set the alternative-service freshness lifetime in whole seconds.
    #[must_use]
    pub fn with_max_age_seconds(mut self, max_age: u64) -> Self {
        self.max_age = Seconds::new(max_age);
        self
    }

    /// Set whether this service may survive network changes.
    #[must_use]
    pub fn with_persist(mut self, persist: bool) -> Self {
        self.persist = persist;
        self
    }

    /// Return the ALPN protocol identifier.
    #[must_use]
    pub fn protocol(&self) -> &ApplicationProtocol {
        &self.protocol
    }

    /// Return the alternative host, or `None` when using the origin host.
    #[must_use]
    pub fn host(&self) -> Option<&Host> {
        self.host.as_ref()
    }

    /// Return the alternative port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Return the advertised max-age before response-age adjustment.
    #[must_use]
    pub fn max_age(&self) -> Duration {
        self.max_age.as_duration()
    }

    /// Return whether the service may survive network changes.
    #[must_use]
    pub const fn persist(&self) -> bool {
        self.persist
    }
}

impl TypedHeader for AltSvc {
    fn name() -> &'static HeaderName {
        &::rama_http_types::header::ALT_SVC
    }
}

impl HeaderDecode for AltSvc {
    fn decode<'i, I>(values: &mut I) -> Result<Self, Error>
    where
        I: Iterator<Item = &'i HeaderValue>,
    {
        decode(values).map_err(|err| {
            tracing::debug!("failed to decode Alt-Svc header: {err}");
            Error::invalid()
        })
    }
}

impl HeaderEncode for AltSvc {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        let services = match self {
            Self::Clear => {
                values.extend(std::iter::once(HeaderValue::from_static("clear")));
                return;
            }
            Self::Alternatives(services) => services,
        };
        let mut encoded = Vec::new();
        encode_service(&mut encoded, &services.head);
        for service in &services.tail {
            encoded.extend_from_slice(b", ");
            encode_service(&mut encoded, service);
        }

        match HeaderValue::try_from(encoded) {
            Ok(value) => values.extend(std::iter::once(value)),
            Err(err) => tracing::debug!("failed to encode Alt-Svc header: {err}"),
        }
    }
}

fn validate_protocol(protocol: &ApplicationProtocol) -> Result<(), BoxError> {
    if protocol.as_bytes().is_empty() {
        return Err(BoxError::from_static_str(
            "Alt-Svc ALPN protocol identifier is empty",
        ));
    }
    if protocol.as_bytes().len() > MAX_ALPN_PROTOCOL_LEN {
        return Err(BoxError::from_static_str(
            "Alt-Svc ALPN protocol identifier exceeds 255 octets",
        ));
    }
    Ok(())
}

fn decode<'i, I>(values: &mut I) -> Result<AltSvc, BoxError>
where
    I: Iterator<Item = &'i HeaderValue>,
{
    let mut alternatives = None;
    let mut first_error = None;
    let mut saw_value = false;

    for value in values {
        saw_value = true;
        match decode_value(value.as_bytes(), &mut alternatives) {
            Ok(true) => return Ok(AltSvc::Clear),
            Err(err) if first_error.is_none() => first_error = Some(err),
            Ok(false) | Err(_) => {}
        }
    }

    if let Some(err) = first_error {
        return Err(err);
    }
    if !saw_value {
        return Err(BoxError::from_static_str("Alt-Svc header has no values"));
    }

    alternatives
        .map(AltSvc::Alternatives)
        .ok_or_else(|| BoxError::from_static_str("Alt-Svc header has no alternatives"))
}

/// Decode one physical header value. `true` means the `clear` member occurred.
fn decode_value(
    input: &[u8],
    alternatives: &mut Option<NonEmptyVec<AlternativeService>>,
) -> Result<bool, BoxError> {
    for member in ListMembers::new(input) {
        if trim_ows(member?) == b"clear" {
            return Ok(true);
        }
    }

    for member in ListMembers::new(input) {
        decode_member(member?, alternatives)?;
    }
    Ok(false)
}

fn decode_member(
    input: &[u8],
    alternatives: &mut Option<NonEmptyVec<AlternativeService>>,
) -> Result<(), BoxError> {
    let input = trim_ows(input);
    if input.is_empty() {
        return Ok(());
    }

    let service = parse_service(input)?;
    match alternatives {
        Some(alternatives) => alternatives.push(service),
        None => *alternatives = Some(NonEmptyVec::new(service)),
    }
    Ok(())
}

fn parse_service(input: &[u8]) -> Result<AlternativeService, BoxError> {
    let mut cursor = 0;
    let protocol_start = cursor;
    while input
        .get(cursor)
        .is_some_and(|byte| is_http_token_byte(*byte))
    {
        cursor = cursor.saturating_add(1);
    }
    let protocol = parse_protocol_id(&input[protocol_start..cursor])?;
    require_byte(input, &mut cursor, b'=')?;
    let authority = scan_quoted_string(input, &mut cursor)?.decode();
    let (host, port) = parse_authority(&authority)?;

    let mut max_age = Seconds::new(DEFAULT_MAX_AGE_SECONDS);
    let mut saw_max_age = false;
    let mut persist = false;

    loop {
        skip_ows(input, &mut cursor);
        if cursor == input.len() {
            break;
        }
        require_byte(input, &mut cursor, b';')?;
        skip_ows(input, &mut cursor);

        let name_start = cursor;
        while input
            .get(cursor)
            .is_some_and(|byte| is_http_token_byte(*byte))
        {
            cursor = cursor.saturating_add(1);
        }
        if cursor == name_start {
            return Err(BoxError::from_static_str("Alt-Svc parameter name is empty"));
        }
        let name = &input[name_start..cursor];
        require_byte(input, &mut cursor, b'=')?;
        let value = parse_parameter_value(input, &mut cursor)?;

        if name.eq_ignore_ascii_case(b"ma") {
            if saw_max_age {
                return Err(BoxError::from_static_str(
                    "Alt-Svc contains duplicate ma parameters",
                ));
            }
            max_age = Seconds::new(parse_delta_seconds(value)?);
            saw_max_age = true;
        } else if name.eq_ignore_ascii_case(b"persist") && value.eq_decoded(b"1") {
            persist = true;
        }
    }

    Ok(AlternativeService {
        protocol,
        host,
        port,
        max_age,
        persist,
    })
}

fn parse_protocol_id(input: &[u8]) -> Result<ApplicationProtocol, BoxError> {
    if input.is_empty() {
        return Err(BoxError::from_static_str(
            "Alt-Svc protocol identifier is empty",
        ));
    }
    if input.len() > MAX_ENCODED_PROTOCOL_LEN {
        return Err(BoxError::from_static_str(
            "Alt-Svc encoded protocol identifier exceeds 765 octets",
        ));
    }

    if !input.contains(&b'%') {
        if input.len() > MAX_ALPN_PROTOCOL_LEN {
            return Err(BoxError::from_static_str(
                "Alt-Svc ALPN protocol identifier exceeds 255 octets",
            ));
        }
        let protocol = ApplicationProtocol::from(input);
        return Ok(protocol);
    }

    let mut decoded = Vec::with_capacity(input.len().min(MAX_ALPN_PROTOCOL_LEN));
    let mut cursor = 0;
    while cursor < input.len() {
        let byte = input[cursor];
        if byte != b'%' {
            if !is_http_token_byte(byte) {
                return Err(BoxError::from_static_str(
                    "Alt-Svc protocol identifier contains a non-token octet",
                ));
            }
            decoded.push(byte);
            if decoded.len() == FIRST_INVALID_ALPN_PROTOCOL_LEN {
                return Err(BoxError::from_static_str(
                    "Alt-Svc ALPN protocol identifier exceeds 255 octets",
                ));
            }
            cursor = cursor.saturating_add(1);
            continue;
        }

        let high = *input.get(cursor + 1).ok_or_else(|| {
            BoxError::from_static_str("Alt-Svc protocol identifier has a truncated escape")
        })?;
        let low = *input.get(cursor + 2).ok_or_else(|| {
            BoxError::from_static_str("Alt-Svc protocol identifier has a truncated escape")
        })?;
        let byte = rama_utils::hex::decode_upper_pair(high, low).ok_or_else(|| {
            BoxError::from_static_str(
                "Alt-Svc protocol identifier escape is not uppercase hexadecimal",
            )
        })?;
        if byte != b'%' && is_http_token_byte(byte) {
            return Err(BoxError::from_static_str(
                "Alt-Svc protocol identifier unnecessarily escapes a token octet",
            ));
        }
        decoded.push(byte);
        if decoded.len() == FIRST_INVALID_ALPN_PROTOCOL_LEN {
            return Err(BoxError::from_static_str(
                "Alt-Svc ALPN protocol identifier exceeds 255 octets",
            ));
        }
        cursor = cursor.saturating_add(3);
    }

    Ok(ApplicationProtocol::from(decoded))
}

fn parse_authority(input: &[u8]) -> Result<(Option<Host>, u16), BoxError> {
    if let Some(port) = input.strip_prefix(b":") {
        let port = parse_u16(port)?;
        return Ok((None, port));
    }

    let authority =
        AuthorityRef::parse_strict(input).context("parse Alt-Svc alternative authority")?;
    if authority.userinfo().is_some() {
        return Err(BoxError::from_static_str(
            "Alt-Svc alternative authority contains userinfo",
        ));
    }
    let OptPort::Set(port) = authority.port() else {
        return Err(BoxError::from_static_str(
            "Alt-Svc alternative authority requires an explicit port",
        ));
    };
    Ok((Some(authority.host().into_owned()), port))
}

fn parse_delta_seconds(input: ParameterValue<'_>) -> Result<u64, BoxError> {
    let mut value = 0_u64;
    let mut saw_digit = false;
    let mut overflowed = false;
    for byte in input.decoded_bytes() {
        if !byte.is_ascii_digit() {
            return Err(BoxError::from_static_str(
                "Alt-Svc ma parameter is not delta-seconds",
            ));
        }
        saw_digit = true;
        if !overflowed {
            match value
                .checked_mul(10)
                .and_then(|value| value.checked_add(u64::from(byte - b'0')))
            {
                Some(next) => value = next,
                None => overflowed = true,
            }
        }
    }
    if !saw_digit {
        return Err(BoxError::from_static_str("Alt-Svc ma parameter is empty"));
    }
    Ok(if overflowed {
        DELTA_SECONDS_OVERFLOW
    } else {
        value
    })
}

fn parse_u16(input: &[u8]) -> Result<u16, BoxError> {
    if input.is_empty() {
        return Err(BoxError::from_static_str(
            "Alt-Svc authority port is not decimal",
        ));
    }
    let mut value = 0_u16;
    for &byte in input {
        if !byte.is_ascii_digit() {
            return Err(BoxError::from_static_str(
                "Alt-Svc authority port is not decimal",
            ));
        }
        value = value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u16::from(byte - b'0')))
            .ok_or_else(|| BoxError::from_static_str("Alt-Svc authority port exceeds u16"))?;
    }
    Ok(value)
}

#[derive(Clone, Copy)]
enum ParameterValue<'a> {
    Token(&'a [u8]),
    Quoted(QuotedString<'a>),
}

impl<'a> ParameterValue<'a> {
    fn decoded_bytes(self) -> ParameterValueBytes<'a> {
        match self {
            Self::Token(bytes) => ParameterValueBytes {
                bytes,
                cursor: 0,
                quoted: false,
            },
            Self::Quoted(value) => ParameterValueBytes {
                bytes: value.raw(),
                cursor: 0,
                quoted: true,
            },
        }
    }

    fn eq_decoded(self, expected: &[u8]) -> bool {
        self.decoded_bytes().eq(expected.iter().copied())
    }
}

struct ParameterValueBytes<'a> {
    bytes: &'a [u8],
    cursor: usize,
    quoted: bool,
}

impl Iterator for ParameterValueBytes<'_> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        let mut byte = *self.bytes.get(self.cursor)?;
        self.cursor = self.cursor.saturating_add(1);
        if self.quoted && byte == b'\\' {
            byte = *self.bytes.get(self.cursor)?;
            self.cursor = self.cursor.saturating_add(1);
        }
        Some(byte)
    }
}

fn parse_parameter_value<'a>(
    input: &'a [u8],
    cursor: &mut usize,
) -> Result<ParameterValue<'a>, BoxError> {
    if input.get(*cursor) == Some(&b'"') {
        return scan_quoted_string(input, cursor).map(ParameterValue::Quoted);
    }

    let value_start = *cursor;
    while input
        .get(*cursor)
        .is_some_and(|byte| is_http_token_byte(*byte))
    {
        *cursor = cursor.saturating_add(1);
    }
    if *cursor == value_start {
        return Err(BoxError::from_static_str(
            "Alt-Svc parameter value is empty",
        ));
    }
    Ok(ParameterValue::Token(&input[value_start..*cursor]))
}

fn require_byte(input: &[u8], cursor: &mut usize, expected: u8) -> Result<(), BoxError> {
    if input.get(*cursor) != Some(&expected) {
        return Err(BoxError::from_static_str(
            "Alt-Svc value does not match the required syntax",
        ));
    }
    *cursor = cursor.saturating_add(1);
    Ok(())
}

fn encode_service(output: &mut Vec<u8>, service: &AlternativeService) {
    output.reserve(
        service
            .protocol
            .as_bytes()
            .len()
            .saturating_mul(3)
            .saturating_add(32),
    );
    for &byte in service.protocol.as_bytes() {
        if byte != b'%' && is_http_token_byte(byte) {
            output.push(byte);
        } else {
            output.push(b'%');
            output.extend_from_slice(&rama_utils::hex::encode_byte_upper(byte));
        }
    }
    output.extend_from_slice(b"=\"");
    if let Some(host) = &service.host {
        _ = write!(output, "{}", HostWithPort::new(host.clone(), service.port));
        output.push(b'"');
    } else {
        _ = write!(output, ":{}\"", service.port);
    }
    if service.max_age.as_u64() != DEFAULT_MAX_AGE_SECONDS {
        _ = write!(output, "; ma={}", service.max_age);
    }
    if service.persist {
        output.extend_from_slice(b"; persist=1");
    }
}

fn validate_alternative_host(host: &Host) -> Result<(), BoxError> {
    match host.view() {
        HostRef::Address(_) => Ok(()),
        HostRef::Name(domain) => validate_strict_host_bytes(domain.as_bytes()),
        HostRef::Uninterpreted(host) if host.is_bracketed() => Ok(()),
        HostRef::Uninterpreted(host) => validate_strict_host_bytes(host.as_bytes()),
        _ => Err(BoxError::from_static_str(
            "Alt-Svc alternative host has an unsupported representation",
        )),
    }
}

fn validate_strict_host_bytes(input: &[u8]) -> Result<(), BoxError> {
    let authority =
        AuthorityRef::parse_strict(input).context("validate Alt-Svc alternative host")?;
    if authority.userinfo().is_some() || !authority.port().is_unset() {
        return Err(BoxError::from_static_str(
            "Alt-Svc alternative host is not a standalone RFC 3986 host",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HeaderDecode, HeaderEncode};

    fn decode(values: &[&str]) -> Option<AltSvc> {
        let values: Vec<_> = values
            .iter()
            .map(|value| HeaderValue::from_bytes(value.as_bytes()).unwrap())
            .collect();
        AltSvc::decode(&mut values.iter()).ok()
    }

    fn encode(value: &AltSvc) -> HeaderValue {
        value.encode_to_value().unwrap()
    }

    #[test]
    fn decodes_rfc_examples() {
        let value = decode(&[r#"h2="new.example.org:80""#]).unwrap();
        let services: Vec<_> = value.alternatives().unwrap().collect();
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].protocol(), &ApplicationProtocol::HTTP_2);
        assert_eq!(services[0].host().unwrap().to_string(), "new.example.org");
        assert_eq!(services[0].port(), 80);
        assert_eq!(services[0].max_age(), Duration::from_secs(86_400));
        assert!(!services[0].persist());

        let value = decode(&[r#"h2=":443"; ma=2592000; persist=1"#]).unwrap();
        let service = value.alternatives().unwrap().next().unwrap();
        assert_eq!(service.host(), None);
        assert_eq!(service.port(), 443);
        assert_eq!(service.max_age(), Duration::from_secs(2_592_000));
        assert!(service.persist());
    }

    #[test]
    fn preserves_preference_across_field_lines() {
        let value = decode(&[r#"h3=":443""#, r#"h2="other.example:8443""#]).unwrap();
        let protocols: Vec<_> = value
            .alternatives()
            .unwrap()
            .map(|service| service.protocol().clone())
            .collect();
        assert_eq!(
            protocols,
            [ApplicationProtocol::HTTP_3, ApplicationProtocol::HTTP_2]
        );
    }

    #[test]
    fn clear_is_case_sensitive_and_wins_over_alternatives() {
        assert!(decode(&["clear"]).unwrap().is_clear());
        assert!(decode(&[r#"h3=":443", clear"#]).unwrap().is_clear());
        assert!(decode(&[r#"invalid, clear"#]).unwrap().is_clear());
        assert!(
            decode(&["invalid", r#"h3=":443""#, "clear"])
                .unwrap()
                .is_clear()
        );
        assert!(!decode(&[r#"h3=":443""#]).unwrap().is_clear());
        assert!(decode(&["CLEAR"]).is_none());
    }

    #[test]
    fn ignores_unknown_and_unsupported_persist_parameters() {
        let value =
            decode(&[r#"h3=":443"; x-note="a,b;c"; escaped="a\"b"; empty=""; persist=0"#]).unwrap();
        assert!(!value.alternatives().unwrap().next().unwrap().persist());
    }

    #[test]
    fn ignores_rfc_list_empty_elements() {
        let value = decode(&[",", r#", h3=":443",,"#, ""]).unwrap();
        let services: Vec<_> = value.alternatives().unwrap().collect();
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].protocol(), &ApplicationProtocol::HTTP_3);

        assert!(decode(&[]).is_none());
        assert!(decode(&["", ",", " , , "]).is_none());
    }

    #[test]
    fn decodes_canonical_protocol_escapes() {
        let value = decode(&[r#"w%3Dx%3Ay#z=":443""#]).unwrap();
        let service = value.alternatives().unwrap().next().unwrap();
        assert_eq!(service.protocol().as_bytes(), b"w=x:y#z");

        let value = decode(&[r#"x%25y=":443""#]).unwrap();
        let service = value.alternatives().unwrap().next().unwrap();
        assert_eq!(service.protocol().as_bytes(), b"x%y");
    }

    #[test]
    fn protocol_identifier_round_trips_every_octet_class() {
        let bytes: Vec<_> = (0..=254).collect();
        let value = AltSvc::new(
            AlternativeService::new(ApplicationProtocol::from(bytes.clone()), 443).unwrap(),
        );
        let encoded = encode(&value);
        let decoded = decode(&[encoded.to_str().unwrap()]).unwrap();
        assert_eq!(decoded, value);
        assert_eq!(
            decoded
                .alternatives()
                .unwrap()
                .next()
                .unwrap()
                .protocol()
                .as_bytes(),
            bytes
        );
    }

    #[test]
    fn rejects_noncanonical_protocol_escapes() {
        for value in [
            r#"h%32=":443""#,
            r#"x%3ay=":443""#,
            r#"x%=":443""#,
            r#"x%3=":443""#,
        ] {
            assert!(decode(&[value]).is_none(), "accepted {value}");
        }
    }

    #[test]
    fn rejects_invalid_syntax_and_values() {
        for value in [
            "",
            ",",
            r#"h3=:443"#,
            r#"h3="443""#,
            r#"h3=":65536""#,
            r#"h3=":443"; ma=nope"#,
            r#"h3=":443"; ma=1; ma=2"#,
            r#"h3=":443"; ma"#,
            r#"h3=":443"; ma =1"#,
            r#"h3=":443"; note="unterminated"#,
            r#"h3=":443"; note="#,
            r#"h3=":443"; note="bad\"#,
            r#"h3=":443"; note=="#,
        ] {
            assert!(decode(&[value]).is_none(), "accepted {value}");
        }
    }

    #[test]
    fn decodes_port_boundaries() {
        for (value, expected_port) in [
            (r#"h3=":0""#, Some(0)),
            (r#"h3=":65535""#, Some(u16::MAX)),
            (r#"h3=":""#, None),
            (r#"h3=":65536""#, None),
        ] {
            let actual_port = decode(&[value])
                .and_then(|value| value.alternatives()?.next().map(AlternativeService::port));
            assert_eq!(actual_port, expected_port, "decoded {value}");
        }
    }

    #[test]
    fn decodes_delta_seconds_and_case_insensitive_parameters() {
        for (value, expected) in [
            (r#"h3=":443"; ma=0"#, 0),
            (
                r#"h3=":443"; MA="18446744073709551615"; PERSIST="1""#,
                u64::MAX,
            ),
            (r#"h3=":443"; ma=18446744073709551616"#, 2_147_483_648),
            (
                r#"h3=":443"; ma=99999999999999999999999999999999999999999999999999"#,
                2_147_483_648,
            ),
            (r#"h3=":443"; mA="3\6\0\0""#, 3600),
        ] {
            let decoded = decode(&[value]).unwrap();
            let service = decoded.alternatives().unwrap().next().unwrap();
            assert_eq!(service.max_age(), Duration::from_secs(expected));
            if value.contains("PERSIST") {
                assert!(service.persist());
            }
        }

        assert!(decode(&[r#"h3=":443"; ma=18446744073709551616x"#]).is_none());
        assert!(decode(&[r#"h3=":443"; ma="""#]).is_none());
    }

    #[test]
    fn retains_the_first_error_when_no_later_clear_occurs() {
        let values = [
            HeaderValue::from_static(r#"h3=":65536""#),
            HeaderValue::from_static(r#"h3=":443"; ma=nope"#),
        ];
        let error = super::decode(&mut values.iter()).unwrap_err();
        assert!(
            error.to_string().contains("port exceeds u16"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn supports_ipv4_and_bracketed_ipv6_hosts() {
        let value = decode(&[r#"h3="127.0.0.1:443", h3="[2001:db8::1]:8443""#]).unwrap();
        let hosts: Vec<_> = value
            .alternatives()
            .unwrap()
            .map(|service| service.host().unwrap().to_string())
            .collect();
        assert_eq!(hosts, ["127.0.0.1", "2001:db8::1"]);
    }

    #[test]
    fn strict_authorities_support_percent_encoding_quoted_pairs_and_ipvfuture() {
        for value in [
            r#"h3="exa%6Dple.com:443""#,
            r#"h3="example.com\:443""#,
            r#"h3="[v1.fe80::a]:443""#,
        ] {
            let decoded = decode(&[value]).unwrap();
            let encoded = encode(&decoded);
            assert_eq!(decode(&[encoded.to_str().unwrap()]), Some(decoded));
        }

        assert!(decode(&[r#"h3="münchen.de:443""#]).is_none());
        assert!(decode(&[r#"h3="user@example.com:443""#]).is_none());
        assert!(decode(&[r#"h3="example.com""#]).is_none());
    }

    #[test]
    fn constructor_authorities_round_trip_ipv4_and_ipv6() {
        for (host, expected) in [
            (
                Host::Address("192.0.2.1".parse().unwrap()),
                r#"h3="192.0.2.1:443""#,
            ),
            (
                Host::Address("2001:db8::1".parse().unwrap()),
                r#"h3="[2001:db8::1]:443""#,
            ),
        ] {
            let service = AlternativeService::new(ApplicationProtocol::HTTP_3, 443)
                .unwrap()
                .try_with_host(host)
                .unwrap();
            let value = AltSvc::new(service);
            assert_eq!(encode(&value), expected);
            assert_eq!(decode(&[expected]), Some(value));
        }
    }

    #[test]
    fn constructor_validates_uninterpreted_host_shapes() {
        for (host, expected) in [
            (
                Host::try_from("exa%6Dple.com").unwrap(),
                r#"h3="exa%6Dple.com:443""#,
            ),
            (
                Host::try_from("[v1.fe80::a]").unwrap(),
                r#"h3="[v1.fe80::a]:443""#,
            ),
        ] {
            assert!(matches!(host.view(), HostRef::Uninterpreted(_)));
            let value = AltSvc::new(
                AlternativeService::new(ApplicationProtocol::HTTP_3, 443)
                    .unwrap()
                    .try_with_host(host)
                    .unwrap(),
            );
            assert_eq!(encode(&value), expected);
            assert_eq!(decode(&[expected]), Some(value));
        }

        let non_ascii_reg_name = Host::try_from("münchen!").unwrap();
        assert!(
            matches!(non_ascii_reg_name.view(), HostRef::Uninterpreted(host) if !host.is_bracketed())
        );
        AlternativeService::new(ApplicationProtocol::HTTP_3, 443)
            .unwrap()
            .try_with_host(non_ascii_reg_name)
            .unwrap_err();

        validate_strict_host_bytes(b"user@example.com").unwrap_err();
        validate_strict_host_bytes(b"example.com:443").unwrap_err();
        validate_strict_host_bytes("münchen.de".as_bytes()).unwrap_err();
    }

    #[test]
    fn encodes_canonical_header_values() {
        let first = AlternativeService::new(ApplicationProtocol::HTTP_3, 443)
            .unwrap()
            .with_max_age_seconds(3600)
            .with_persist(true);
        let second = AlternativeService::new(ApplicationProtocol::from(b"w=x:y#z"), 8443)
            .unwrap()
            .try_with_host(Host::from_static("alt.example"))
            .unwrap();
        let value = AltSvc::Alternatives(NonEmptyVec {
            head: first,
            tail: vec![second],
        });
        assert_eq!(
            encode(&value),
            HeaderValue::from_static(
                r#"h3=":443"; ma=3600; persist=1, w%3Dx%3Ay#z="alt.example:8443""#
            )
        );
        assert_eq!(decode(&[encode(&value).to_str().unwrap()]), Some(value));
    }

    #[test]
    fn encodes_binary_protocol_identifier() {
        let service = AlternativeService::new(ApplicationProtocol::from(&[0, 0xff]), 443).unwrap();
        assert_eq!(encode(&AltSvc::new(service)), "%00%FF=\":443\"");
    }

    #[test]
    fn constructors_enforce_alpn_length() {
        AlternativeService::new(ApplicationProtocol::from(b""), 443).unwrap_err();
        AlternativeService::new(ApplicationProtocol::from(vec![b'x'; 255]), 443).unwrap();
        AlternativeService::new(ApplicationProtocol::from(vec![b'x'; 256]), 443).unwrap_err();
    }

    #[test]
    fn decoder_enforces_alpn_length_before_unbounded_allocation() {
        let raw_boundary = format!("{}=\":443\"", "x".repeat(255));
        assert_eq!(
            decode(&[&raw_boundary])
                .unwrap()
                .alternatives()
                .unwrap()
                .next()
                .unwrap()
                .protocol()
                .as_bytes()
                .len(),
            255
        );

        let escaped_boundary = format!("{}=\":443\"", "%00".repeat(255));
        assert_eq!(
            decode(&[&escaped_boundary])
                .unwrap()
                .alternatives()
                .unwrap()
                .next()
                .unwrap()
                .protocol()
                .as_bytes(),
            &[0; 255]
        );

        let mixed_boundary = format!("%00{}=\":443\"", "x".repeat(254));
        let mixed_protocol = decode(&[&mixed_boundary])
            .unwrap()
            .alternatives()
            .unwrap()
            .next()
            .unwrap()
            .protocol()
            .clone();
        assert_eq!(mixed_protocol.as_bytes().len(), 255);
        assert_eq!(mixed_protocol.as_bytes()[0], 0);
        assert!(
            mixed_protocol.as_bytes()[1..]
                .iter()
                .all(|&byte| byte == b'x')
        );

        let raw = format!("{}=\":443\"", "x".repeat(256));
        assert!(decode(&[&raw]).is_none());

        let escaped = format!("{}=\":443\"", "%00".repeat(256));
        assert!(decode(&[&escaped]).is_none());

        let mixed = format!("{}%00=\":443\"", "x".repeat(255));
        assert!(decode(&[&mixed]).is_none());
    }

    #[test]
    fn clear_encodes_without_allocation_specific_state() {
        assert_eq!(encode(&AltSvc::Clear), HeaderValue::from_static("clear"));
    }
}
