//! Capture-safe header values and protocol-owned request bindings.

pub(in crate::profile) mod structure;

use ahash::HashMap;

use rama_http::{
    HeaderMap, HeaderName, HeaderValue, Version,
    header::{CONTENT_LENGTH, HOST, TE, TRANSFER_ENCODING},
    headers::{Connection, ContentLength, HeaderDecode as _, HeaderMapExt as _},
    proto::h3::{
        observation::{FieldRepresentation, ObservedFieldRepresentation},
        qpack::{encoding::FieldPreferences, static_table},
    },
};
use rama_utils::octets::kib;
use serde::Serialize;

use crate::profile::{
    capture::completeness::ProfileCaptureCompleteness,
    format::canonical::{
        CanonicalDomain, CanonicalReader, CanonicalValue, CanonicalWriter, HEADER_DOMAIN,
        ProfileDataError,
    },
};

/// Values produced by the actual request or protocol adapter, never replayed from a capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum RequestBinding {
    Authority,
    Framing,
    BodyMetadata,
    Cookie,
    Authorization,
    WebSocketKey,
    Origin,
    Referer,
    Cors,
    Conditional,
    Range,
    Connection,
    Sensitive,
    Custom,
    Forwarding,
    PerRequestId,
    Proof,
    WebSocketProtocol,
    /// Network quality hints that change on every request; only in structural keys.
    NetworkHint,
    /// Device and user preference hints that differ per device; only in structural keys.
    DeviceHint,
    /// User language preferences that differ per device; only in structural keys.
    Locale,
}

impl RequestBinding {
    pub(in crate::profile) fn tag(self) -> u8 {
        match self {
            Self::Authority => 0,
            Self::Framing => 1,
            Self::BodyMetadata => 2,
            Self::Cookie => 3,
            Self::Authorization => 4,
            Self::WebSocketKey => 5,
            Self::Origin => 6,
            Self::Referer => 7,
            Self::Cors => 8,
            Self::Conditional => 9,
            Self::Range => 10,
            Self::Connection => 11,
            Self::Sensitive => 12,
            Self::Custom => 13,
            Self::Forwarding => 14,
            Self::PerRequestId => 15,
            Self::Proof => 16,
            Self::WebSocketProtocol => 17,
            Self::NetworkHint => 18,
            Self::DeviceHint => 19,
            Self::Locale => 20,
        }
    }

    pub(in crate::profile) fn from_tag(tag: u8) -> Result<Self, ProfileDataError> {
        Ok(match tag {
            0 => Self::Authority,
            1 => Self::Framing,
            2 => Self::BodyMetadata,
            3 => Self::Cookie,
            4 => Self::Authorization,
            5 => Self::WebSocketKey,
            6 => Self::Origin,
            7 => Self::Referer,
            8 => Self::Cors,
            9 => Self::Conditional,
            10 => Self::Range,
            11 => Self::Connection,
            12 => Self::Sensitive,
            13 => Self::Custom,
            14 => Self::Forwarding,
            15 => Self::PerRequestId,
            16 => Self::Proof,
            17 => Self::WebSocketProtocol,
            18 => Self::NetworkHint,
            19 => Self::DeviceHint,
            20 => Self::Locale,
            _ => return Err(ProfileDataError::Invalid("request binding")),
        })
    }
}

/// Request-bound fields take precedence over importer overrides.
#[must_use]
pub fn header_request_binding(name: &HeaderName) -> Option<RequestBinding> {
    Some(match name.as_lower_str().as_ref() {
        "host" | "alt-used" => RequestBinding::Authority,
        "forwarded" | "x-real-ip" | "via" | "cdn-loop" | "max-forwards" => {
            RequestBinding::Forwarding
        }
        name if name.starts_with("x-forwarded-") => RequestBinding::Forwarding,
        "traceparent" | "tracestate" | "baggage" | "x-request-id" | "request-id"
        | "x-correlation-id" | "correlation-id" | "idempotency-key" | "last-event-id" => {
            RequestBinding::PerRequestId
        }
        "dpop" | "signature" | "signature-input" => RequestBinding::Proof,
        "sec-websocket-protocol" => RequestBinding::WebSocketProtocol,
        "content-length" | "transfer-encoding" => RequestBinding::Framing,
        // Multipart boundaries belong to the body; their format is not emulated.
        "content-type" | "content-encoding" | "content-range" | "content-digest"
        | "repr-digest" | "digest" | "content-md5" | "expect" => RequestBinding::BodyMetadata,
        name if name.starts_with("content-") => RequestBinding::BodyMetadata,
        "cookie" | "set-cookie" => RequestBinding::Cookie,
        "authorization" | "proxy-authorization" => RequestBinding::Authorization,
        "sec-websocket-key" | "sec-websocket-accept" => RequestBinding::WebSocketKey,
        "origin" => RequestBinding::Origin,
        "referer" | "ping-from" | "ping-to" => RequestBinding::Referer,
        "access-control-request-method"
        | "access-control-request-headers"
        | "access-control-request-private-network" => RequestBinding::Cors,
        "if-match" | "if-none-match" | "if-modified-since" | "if-unmodified-since" => {
            RequestBinding::Conditional
        }
        "range" | "if-range" => RequestBinding::Range,
        "connection" | "keep-alive" | "proxy-connection" | "te" | "trailer" | "upgrade"
        | "early-data" | "http2-settings" => RequestBinding::Connection,
        _ => return None,
    })
}

/// Header sent by the fingerprint page on every script request with a unique value.
const FINGERPRINT_MARKER_HEADER: &str = "x-rama-custom-header-marker";

/// Fields whose captured value is request-owned unless an importer overrides it.
/// Unlike [`header_default_request_binding`], stored literals of these stay valid.
fn header_capture_binding(name: &HeaderName) -> Option<RequestBinding> {
    (name.as_lower_str().as_ref() == FINGERPRINT_MARKER_HEADER).then_some(RequestBinding::Custom)
}

/// Values sampled per device or per request: kept in captures, never in structural keys.
pub(in crate::profile) fn header_value_class(name: &HeaderName) -> Option<RequestBinding> {
    Some(match name.as_lower_str().as_ref() {
        "downlink" | "rtt" | "ect" | "sec-ch-downlink" | "sec-ch-rtt" | "sec-ch-ect" => {
            RequestBinding::NetworkHint
        }
        "device-memory"
        | "sec-ch-device-memory"
        | "dpr"
        | "sec-ch-dpr"
        | "width"
        | "sec-ch-width"
        | "viewport-width"
        | "sec-ch-viewport-width"
        | "sec-ch-viewport-height"
        | "sec-ch-ua-platform-version"
        | "sec-ch-ua-model"
        | "sec-ch-ua-full-version"
        | "sec-ch-ua-full-version-list"
        | "sec-ch-prefers-color-scheme"
        | "sec-ch-prefers-reduced-motion"
        | "sec-ch-prefers-reduced-transparency"
        | "save-data" => RequestBinding::DeviceHint,
        "accept-language" => RequestBinding::Locale,
        _ => return None,
    })
}

/// Conservative defaults for application credentials and SDK/proxy metadata.
/// An explicit capture-safe importer choice can override these custom names.
/// Broad credential patterns also bind fixed metadata such as
/// Sec-Private-State-Token-Crypto-Version until an importer marks it capture-safe.
fn header_default_request_binding(name: &HeaderName) -> Option<RequestBinding> {
    let name = name.as_lower_str();
    Some(match name.as_ref() {
        "sentry-trace"
        | "b3"
        | "x-amzn-trace-id"
        | "x-cloud-trace-context"
        | "uber-trace-id"
        | "newrelic" => RequestBinding::PerRequestId,
        name if name.starts_with("x-b3-") || name.starts_with("x-datadog-") => {
            RequestBinding::PerRequestId
        }
        "true-client-ip"
        | "x-client-ip"
        | "client-ip"
        | "x-cluster-client-ip"
        | "cf-connecting-ip"
        | "fastly-client-ip" => RequestBinding::Forwarding,
        name if [
            "token",
            "secret",
            "api-key",
            "apikey",
            "auth",
            "password",
            "credential",
            "bearer",
            "jwt",
            "csrf",
            "xsrf",
            "session",
            "signature",
        ]
        .iter()
        .any(|part| name.contains(part)) =>
        {
            RequestBinding::Sensitive
        }
        _ => return None,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum HeaderOwnership {
    Profile,
    Request,
}

/// Custom capture-safe fields can explicitly opt into or out of profile ownership.
#[derive(Debug, Clone, Serialize)]
pub struct HeaderOwnershipOverride {
    pub name: HeaderName,
    pub ownership: HeaderOwnership,
}

#[derive(Debug, Clone)]
pub struct HeaderCapturePolicy {
    pub fields: usize,
    pub bytes: usize,
    pub overrides: Box<[HeaderOwnershipOverride]>,
}

impl Default for HeaderCapturePolicy {
    fn default() -> Self {
        Self {
            fields: 256,
            bytes: kib(64),
            overrides: Box::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub enum HeaderValueSource {
    Profile(Box<[u8]>),
    /// Explicit importer assertion that a custom field is capture-safe. This does
    /// not override protocol bindings, never-index, or the sensitivity flag.
    CaptureSafeProfile(Box<[u8]>),
    Request(RequestBinding),
}

/// An occurrence retains its spelling and compression metadata independently of value ownership.
#[derive(Debug, Clone, Serialize)]
pub struct HeaderOccurrence {
    pub name: HeaderName,
    pub occurrence: u32,
    pub sensitive: bool,
    pub representation: Option<ObservedFieldRepresentation>,
    pub value: HeaderValueSource,
}

#[derive(Debug, Clone, Serialize)]
pub struct HeaderCapture {
    pub completeness: ProfileCaptureCompleteness,
    pub version: Version,
    pub fields: Box<[HeaderOccurrence]>,
}

impl HeaderCapturePolicy {
    fn validate(&self) -> Result<(), ProfileDataError> {
        if self.overrides.len() > self.fields {
            return Err(ProfileDataError::LimitExceeded(
                "header ownership overrides",
            ));
        }
        for (index, field) in self.overrides.iter().enumerate() {
            if self.overrides[..index]
                .iter()
                .any(|other| other.name == field.name)
            {
                return Err(ProfileDataError::Invalid(
                    "duplicate header ownership override",
                ));
            }
            if field.ownership == HeaderOwnership::Profile
                && header_request_binding(&field.name).is_some()
            {
                return Err(ProfileDataError::Invalid(
                    "protocol binding cannot be profile-owned",
                ));
            }
        }
        Ok(())
    }

    /// `representations` contains regular fields only, in the same order as `headers`.
    /// Pseudo fields are captured separately from their request-owned values.
    pub fn capture(
        &self,
        completeness: ProfileCaptureCompleteness,
        version: Version,
        headers: &HeaderMap,
        representations: Option<&[ObservedFieldRepresentation]>,
    ) -> Result<HeaderCapture, ProfileDataError> {
        completeness.require_complete("header observation")?;
        self.validate()?;
        if headers.len() > self.fields {
            return Err(ProfileDataError::LimitExceeded("header fields"));
        }
        let mut remaining = self.bytes;
        for (name, value) in headers.ordered_iter() {
            remaining = remaining
                .checked_sub(name.as_str().len())
                .and_then(|n| n.checked_sub(value.len()))
                .ok_or(ProfileDataError::LimitExceeded("header input bytes"))?;
        }
        if representations.is_some_and(|values| values.len() != headers.len()) {
            return Err(ProfileDataError::Incomplete("header representations"));
        }
        if let Some(values) = representations {
            for ((name, field), metadata) in headers.ordered_iter().zip(values) {
                validate_representation(version, *metadata)?;
                validate_static_binding(
                    name.as_lower_str().as_bytes(),
                    Some(field.as_bytes()),
                    *metadata,
                )?;
            }
        }
        validate_framing(version, headers)?;
        let connection = headers
            .typed_try_get::<Connection>()
            .map_err(|_error| ProfileDataError::Invalid("connection header"))?;
        let mut occurrences = HashMap::<HeaderName, u32>::default();
        let mut fields = Vec::with_capacity(headers.len());
        for (index, (name, value)) in headers.ordered_iter().enumerate() {
            let occurrence = occurrences.entry(name.clone()).or_default();
            let ownership = self.overrides.iter().find(|field| field.name == *name);
            let representation = representations
                .and_then(|values| values.get(index))
                .copied();
            let sensitive =
                value.is_sensitive() || representation.is_some_and(|value| value.never_index);
            let mut binding = header_request_binding(name);
            if connection
                .as_ref()
                .is_some_and(|value| value.iter_headers().any(|h| h == name))
            {
                binding = binding.or(Some(RequestBinding::Connection));
            }
            if sensitive {
                binding = binding.or(Some(RequestBinding::Sensitive));
            }
            if let Some(ownership) = ownership {
                match ownership.ownership {
                    HeaderOwnership::Request => binding = binding.or(Some(RequestBinding::Custom)),
                    HeaderOwnership::Profile if binding.is_some() => {
                        return Err(ProfileDataError::Invalid(
                            "sensitive or connection-owned override",
                        ));
                    }
                    HeaderOwnership::Profile => {}
                }
            }
            if ownership.is_none() {
                binding = binding.or_else(|| header_capture_binding(name));
            }
            let capture_safe = ownership
                .is_some_and(|field| field.ownership == HeaderOwnership::Profile)
                && header_default_request_binding(name).is_some();
            if !capture_safe {
                binding = binding.or_else(|| header_default_request_binding(name));
            }
            fields.push(HeaderOccurrence {
                name: name.clone(),
                occurrence: *occurrence,
                sensitive,
                representation,
                value: match binding {
                    Some(binding) => HeaderValueSource::Request(binding),
                    None if capture_safe => {
                        HeaderValueSource::CaptureSafeProfile(value.as_bytes().into())
                    }
                    None => HeaderValueSource::Profile(value.as_bytes().into()),
                },
            });
            *occurrence = occurrence
                .checked_add(1)
                .ok_or(ProfileDataError::CounterOverflow)?;
        }
        Ok(HeaderCapture {
            completeness,
            version,
            fields: fields.into_boxed_slice(),
        })
    }
}

fn validate_framing(version: Version, headers: &HeaderMap) -> Result<(), ProfileDataError> {
    if headers.get_all(HOST).iter().count() > 1 {
        return Err(ProfileDataError::Invalid("duplicate authority"));
    }
    if headers.contains_key(CONTENT_LENGTH) {
        if headers.contains_key(TRANSFER_ENCODING) {
            return Err(ProfileDataError::Invalid("conflicting message framing"));
        }
        let values = headers
            .get_all(CONTENT_LENGTH)
            .iter()
            .flat_map(|value| value.as_bytes().split(|byte| *byte == b','))
            .map(|value| {
                HeaderValue::from_bytes(value.trim_ascii())
                    .map_err(|_error| ProfileDataError::Invalid("content length"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        ContentLength::decode(&mut values.iter())
            .map_err(|_error| ProfileDataError::Invalid("conflicting content lengths"))?;
    }
    if matches!(version, Version::HTTP_2 | Version::HTTP_3) {
        for name in headers.keys() {
            if forbidden_multiplexed_field(name) {
                return Err(ProfileDataError::Invalid(
                    "connection field in multiplexed HTTP",
                ));
            }
        }
        for value in headers.get_all(TE) {
            if !value.as_bytes().eq_ignore_ascii_case(b"trailers") {
                return Err(ProfileDataError::Invalid("invalid multiplexed HTTP TE"));
            }
        }
    }
    Ok(())
}

fn forbidden_multiplexed_field(name: &HeaderName) -> bool {
    matches!(
        name.as_lower_str().as_ref(),
        "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding" | "upgrade"
    )
}

pub(in crate::profile) fn validate_representation(
    version: Version,
    value: ObservedFieldRepresentation,
) -> Result<(), ProfileDataError> {
    if version != Version::HTTP_3 {
        return Err(ProfileDataError::Invalid("QPACK metadata outside HTTP/3"));
    }
    if FieldPreferences::from_observed(&value).is_none() {
        return Err(ProfileDataError::Invalid("inconsistent QPACK metadata"));
    }
    Ok(())
}

pub(in crate::profile) fn version_tag(version: Version) -> u8 {
    match version {
        Version::HTTP_09 => 0,
        Version::HTTP_10 => 1,
        Version::HTTP_11 => 2,
        Version::HTTP_2 => 3,
        Version::HTTP_3 => 4,
    }
}

pub(in crate::profile) fn version_from_tag(tag: u8) -> Result<Version, ProfileDataError> {
    Ok(match tag {
        0 => Version::HTTP_09,
        1 => Version::HTTP_10,
        2 => Version::HTTP_11,
        3 => Version::HTTP_2,
        4 => Version::HTTP_3,
        _ => return Err(ProfileDataError::Unsupported("HTTP version")),
    })
}

pub(in crate::profile) fn representation_tag(value: FieldRepresentation) -> u8 {
    match value {
        FieldRepresentation::StaticIndex => 0,
        FieldRepresentation::DynamicIndex => 1,
        FieldRepresentation::DynamicPostBaseIndex => 2,
        FieldRepresentation::LiteralStaticName => 3,
        FieldRepresentation::LiteralDynamicName => 4,
        FieldRepresentation::LiteralPostBaseName => 5,
        FieldRepresentation::LiteralName => 6,
    }
}

pub(in crate::profile) fn representation_from_tag(
    tag: u8,
) -> Result<FieldRepresentation, ProfileDataError> {
    Ok(match tag {
        0 => FieldRepresentation::StaticIndex,
        1 => FieldRepresentation::DynamicIndex,
        2 => FieldRepresentation::DynamicPostBaseIndex,
        3 => FieldRepresentation::LiteralStaticName,
        4 => FieldRepresentation::LiteralDynamicName,
        5 => FieldRepresentation::LiteralPostBaseName,
        6 => FieldRepresentation::LiteralName,
        _ => return Err(ProfileDataError::Invalid("header representation")),
    })
}

impl HeaderCapture {
    /// Canonical storage contains no request-bound values, including multipart boundaries.
    pub fn canonical(
        &self,
        policy: &HeaderCapturePolicy,
    ) -> Result<CanonicalValue, ProfileDataError> {
        self.canonical_with_domain(HEADER_DOMAIN, version_tag(self.version), policy)
    }

    pub(in crate::profile) fn canonical_with_domain(
        &self,
        domain: CanonicalDomain,
        tag: u8,
        policy: &HeaderCapturePolicy,
    ) -> Result<CanonicalValue, ProfileDataError> {
        self.completeness.require_complete("header observation")?;
        policy.validate()?;
        if self.fields.len() > policy.fields {
            return Err(ProfileDataError::LimitExceeded("header fields"));
        }
        let mut remaining = policy.bytes;
        let mut host_seen = false;
        let mut content_length = false;
        let mut transfer_encoding = false;
        for field in &self.fields {
            remaining = remaining
                .checked_sub(field.name.as_str().len())
                .and_then(|n| match &field.value {
                    HeaderValueSource::Profile(value)
                    | HeaderValueSource::CaptureSafeProfile(value) => n.checked_sub(value.len()),
                    HeaderValueSource::Request(_) => Some(n),
                })
                .ok_or(ProfileDataError::LimitExceeded("header input bytes"))?;
            if matches!(self.version, Version::HTTP_2 | Version::HTTP_3)
                && forbidden_multiplexed_field(&field.name)
            {
                return Err(ProfileDataError::Invalid(
                    "connection field in multiplexed HTTP",
                ));
            }
            if field.name == HOST {
                if host_seen {
                    return Err(ProfileDataError::Invalid("duplicate authority"));
                }
                host_seen = true;
            }
            content_length |= field.name == CONTENT_LENGTH;
            transfer_encoding |= field.name == TRANSFER_ENCODING;
            if let Some(value) = field.representation {
                validate_representation(self.version, value)?;
                let literal = match &field.value {
                    HeaderValueSource::Profile(bytes)
                    | HeaderValueSource::CaptureSafeProfile(bytes) => Some(bytes.as_ref()),
                    HeaderValueSource::Request(_) => None,
                };
                validate_static_binding(field.name.as_lower_str().as_bytes(), literal, value)?;
                if value.never_index && !field.sensitive {
                    return Err(ProfileDataError::Invalid(
                        "never-index field without sensitivity",
                    ));
                }
            }
        }
        if content_length && transfer_encoding {
            return Err(ProfileDataError::Invalid("conflicting message framing"));
        }
        let mut writer = CanonicalWriter::new(domain, policy.bytes)?;
        writer.u8(tag)?;
        writer.u8(self.completeness.tag())?;
        writer.u64(self.fields.len() as u64)?;
        let mut occurrences = HashMap::<HeaderName, u32>::default();
        for field in &self.fields {
            let occurrence = occurrences.entry(field.name.clone()).or_default();
            if field.occurrence != *occurrence {
                return Err(ProfileDataError::Invalid("header occurrence ordinal"));
            }
            *occurrence = occurrence
                .checked_add(1)
                .ok_or(ProfileDataError::CounterOverflow)?;
            let name = if matches!(self.version, Version::HTTP_2 | Version::HTTP_3) {
                field.name.as_lower_str()
            } else {
                field.name.as_original_str()
            };
            writer.bytes(name.as_bytes())?;
            writer.u32(field.occurrence)?;
            writer.u8(u8::from(field.sensitive))?;
            encode_representation(&mut writer, field.representation)?;
            match &field.value {
                HeaderValueSource::Profile(value)
                | HeaderValueSource::CaptureSafeProfile(value) => {
                    let capture_safe =
                        matches!(field.value, HeaderValueSource::CaptureSafeProfile(_));
                    if field.sensitive
                        || (!capture_safe && header_default_request_binding(&field.name).is_some())
                        || header_request_binding(&field.name).is_some()
                        || policy.overrides.iter().any(|override_| {
                            override_.name == field.name
                                && override_.ownership == HeaderOwnership::Request
                        })
                    {
                        return Err(ProfileDataError::Invalid("captured request-bound value"));
                    }
                    HeaderValue::from_bytes(value)
                        .map_err(|_error| ProfileDataError::Invalid("profile header value"))?;
                    writer.u8(if capture_safe { 2 } else { 0 })?;
                    writer.bytes(value)?;
                }
                HeaderValueSource::Request(binding) => {
                    let valid = match header_request_binding(&field.name) {
                        Some(expected) => expected == *binding,
                        None => {
                            matches!(
                                binding,
                                RequestBinding::Custom
                                    | RequestBinding::Sensitive
                                    | RequestBinding::Connection
                            ) || header_default_request_binding(&field.name) == Some(*binding)
                                || header_value_class(&field.name) == Some(*binding)
                        }
                    };
                    if !valid {
                        return Err(ProfileDataError::Invalid("incorrect request binding"));
                    }
                    writer.u8(1)?;
                    writer.u8(binding.tag())?;
                }
            }
        }
        Ok(writer.finish())
    }

    /// Decode the owned format with limits before allocating field collections.
    pub fn from_canonical(
        value: &CanonicalValue,
        policy: &HeaderCapturePolicy,
    ) -> Result<Self, ProfileDataError> {
        value.verify(HEADER_DOMAIN, policy.bytes)?;
        let mut reader = CanonicalReader::new(&value.bytes, HEADER_DOMAIN)?;
        let version = version_from_tag(reader.u8()?)?;
        let completeness = ProfileCaptureCompleteness::from_tag(reader.u8()?)?;
        completeness.require_complete("header observation")?;
        let fields = decode_fields(&mut reader, policy)?;
        reader.finish()?;
        let capture = Self {
            completeness,
            version,
            fields,
        };
        if capture.canonical(policy)?.bytes != value.bytes {
            return Err(ProfileDataError::Invalid("noncanonical header encoding"));
        }
        Ok(capture)
    }
}

fn read_bool(reader: &mut CanonicalReader<'_>) -> Result<bool, ProfileDataError> {
    match reader.u8()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(ProfileDataError::Invalid("canonical boolean")),
    }
}

pub(in crate::profile) fn encode_representation(
    writer: &mut CanonicalWriter,
    representation: Option<ObservedFieldRepresentation>,
) -> Result<(), ProfileDataError> {
    match representation {
        Some(value) => {
            writer.u8(1)?;
            writer.u8(representation_tag(value.representation))?;
            match value.index {
                Some(index) => {
                    writer.u8(1)?;
                    writer.u64(index)?;
                }
                None => writer.u8(0)?,
            }
            writer.u8(u8::from(value.name_huffman))?;
            writer.u8(u8::from(value.value_huffman))?;
            writer.u8(u8::from(value.never_index))?;
        }
        None => writer.u8(0)?,
    }
    Ok(())
}

pub(in crate::profile) fn decode_representation(
    reader: &mut CanonicalReader<'_>,
) -> Result<Option<ObservedFieldRepresentation>, ProfileDataError> {
    let representation = if read_bool(reader)? {
        let representation = representation_from_tag(reader.u8()?)?;
        let index = if read_bool(reader)? {
            Some(reader.u64()?)
        } else {
            None
        };
        Some(ObservedFieldRepresentation {
            representation,
            index,
            name_huffman: read_bool(reader)?,
            value_huffman: read_bool(reader)?,
            never_index: read_bool(reader)?,
        })
    } else {
        None
    };
    Ok(representation)
}

/// Static entries constrain the decoded name and, for an indexed field, its value.
/// Dynamic references remain tied to their observed connection's table context.
pub(in crate::profile) fn validate_static_binding(
    name: &[u8],
    value: Option<&[u8]>,
    metadata: ObservedFieldRepresentation,
) -> Result<(), ProfileDataError> {
    if matches!(
        metadata.representation,
        FieldRepresentation::StaticIndex | FieldRepresentation::LiteralStaticName
    ) {
        let index = metadata
            .index
            .ok_or(ProfileDataError::Invalid("QPACK static table index"))?;
        let index = usize::try_from(index)
            .map_err(|_error| ProfileDataError::Invalid("QPACK static table index"))?;
        let (expected_name, expected_value) = static_table::get(index)
            .ok_or(ProfileDataError::Invalid("QPACK static table index"))?;
        if name != expected_name {
            return Err(ProfileDataError::Invalid("QPACK static name binding"));
        }
        if metadata.representation == FieldRepresentation::StaticIndex
            && value.is_some_and(|value| value != expected_value)
        {
            return Err(ProfileDataError::Invalid("QPACK static value binding"));
        }
    }
    Ok(())
}

pub(in crate::profile) fn decode_fields(
    reader: &mut CanonicalReader<'_>,
    policy: &HeaderCapturePolicy,
) -> Result<Box<[HeaderOccurrence]>, ProfileDataError> {
    let count = reader.count(policy.fields)?;
    let mut fields = Vec::new();
    for _ in 0..count {
        let name = HeaderName::from_bytes(reader.bytes(policy.bytes)?)
            .map_err(|_error| ProfileDataError::Invalid("header name"))?;
        let occurrence = reader.u32()?;
        let sensitive = read_bool(reader)?;
        let representation = decode_representation(reader)?;
        let source = match reader.u8()? {
            0 => HeaderValueSource::Profile(reader.bytes(policy.bytes)?.into()),
            1 => HeaderValueSource::Request(RequestBinding::from_tag(reader.u8()?)?),
            2 => HeaderValueSource::CaptureSafeProfile(reader.bytes(policy.bytes)?.into()),
            _ => return Err(ProfileDataError::Invalid("header value source")),
        };
        fields.push(HeaderOccurrence {
            name,
            occurrence,
            sensitive,
            representation,
            value: source,
        });
    }
    Ok(fields.into_boxed_slice())
}

#[cfg(test)]
mod tests;
