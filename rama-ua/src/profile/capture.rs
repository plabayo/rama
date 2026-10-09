//! Capture-safe header values and protocol-owned request bindings.

use ahash::HashMap;

use rama_http::{
    HeaderMap, HeaderName, HeaderValue, Version,
    header::{CONTENT_LENGTH, HOST, TE, TRANSFER_ENCODING},
    headers::{Connection, ContentLength, HeaderDecode as _, HeaderMapExt as _},
    proto::h3::observation::{FieldRepresentation, ObservedFieldRepresentation},
};
use rama_utils::octets::kib;
use serde::Serialize;

use super::{
    CanonicalValue, ProfileDataError,
    canonical::{CanonicalReader, CanonicalWriter, HEADER_DOMAIN},
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
}

impl RequestBinding {
    fn tag(self) -> u8 {
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
        }
    }

    fn from_tag(tag: u8) -> Result<Self, ProfileDataError> {
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
            _ => return Err(ProfileDataError::Invalid("request binding")),
        })
    }
}

/// The protocol-defined binding takes precedence over importer overrides.
#[must_use]
pub fn header_request_binding(name: &HeaderName) -> Option<RequestBinding> {
    Some(match name.as_lower_str().as_ref() {
        "host" => RequestBinding::Authority,
        "content-length" | "transfer-encoding" => RequestBinding::Framing,
        // Multipart boundaries belong to the body; their format is not emulated.
        "content-type" | "content-encoding" | "content-range" | "content-digest"
        | "repr-digest" | "digest" | "content-md5" => RequestBinding::BodyMetadata,
        "cookie" | "set-cookie" => RequestBinding::Cookie,
        "authorization" | "proxy-authorization" => RequestBinding::Authorization,
        "sec-websocket-key" | "sec-websocket-accept" => RequestBinding::WebSocketKey,
        "origin" => RequestBinding::Origin,
        "referer" => RequestBinding::Referer,
        "access-control-request-method"
        | "access-control-request-headers"
        | "access-control-request-private-network" => RequestBinding::Cors,
        "if-match" | "if-none-match" | "if-modified-since" | "if-unmodified-since" => {
            RequestBinding::Conditional
        }
        "range" | "if-range" => RequestBinding::Range,
        "connection" | "keep-alive" | "proxy-connection" | "te" | "trailer" | "upgrade" => {
            RequestBinding::Connection
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
    pub version: Version,
    pub fields: Box<[HeaderOccurrence]>,
}

impl HeaderCapturePolicy {
    /// `representations` contains regular fields only, in the same order as `headers`.
    /// Pseudo fields are captured separately from their request-owned values.
    pub fn capture(
        &self,
        version: Version,
        headers: &HeaderMap,
        representations: Option<&[ObservedFieldRepresentation]>,
    ) -> Result<HeaderCapture, ProfileDataError> {
        if headers.len() > self.fields || self.overrides.len() > self.fields {
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
            for value in values {
                validate_representation(version, *value)?;
            }
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
        validate_framing(version, headers)?;
        let connection = headers
            .typed_try_get::<Connection>()
            .map_err(|_error| ProfileDataError::Invalid("connection header"))?;
        let mut occurrences = HashMap::<HeaderName, u32>::default();
        let mut fields = Vec::with_capacity(headers.len());
        for (index, (name, value)) in headers.ordered_iter().enumerate() {
            let occurrence = occurrences.entry(name.clone()).or_default();
            let ownership = self.overrides.iter().find(|field| field.name == *name);
            let representation = representations.map(|values| values[index]);
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
            fields.push(HeaderOccurrence {
                name: name.clone(),
                occurrence: *occurrence,
                sensitive,
                representation,
                value: match binding {
                    Some(binding) => HeaderValueSource::Request(binding),
                    None => HeaderValueSource::Profile(value.as_bytes().into()),
                },
            });
            *occurrence = occurrence
                .checked_add(1)
                .ok_or(ProfileDataError::CounterOverflow)?;
        }
        Ok(HeaderCapture {
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

fn validate_representation(
    version: Version,
    value: ObservedFieldRepresentation,
) -> Result<(), ProfileDataError> {
    if version != Version::HTTP_3 {
        return Err(ProfileDataError::Invalid("QPACK metadata outside HTTP/3"));
    }
    let valid = match value.representation {
        FieldRepresentation::StaticIndex
        | FieldRepresentation::DynamicIndex
        | FieldRepresentation::DynamicPostBaseIndex => {
            value.index.is_some()
                && !value.name_huffman
                && !value.value_huffman
                && !value.never_index
        }
        FieldRepresentation::LiteralStaticName
        | FieldRepresentation::LiteralDynamicName
        | FieldRepresentation::LiteralPostBaseName => value.index.is_some() && !value.name_huffman,
        FieldRepresentation::LiteralName => value.index.is_none(),
    };
    if !valid {
        return Err(ProfileDataError::Invalid("inconsistent QPACK metadata"));
    }
    Ok(())
}

fn version_tag(version: Version) -> u8 {
    match version {
        Version::HTTP_09 => 0,
        Version::HTTP_10 => 1,
        Version::HTTP_11 => 2,
        Version::HTTP_2 => 3,
        Version::HTTP_3 => 4,
    }
}

fn representation_tag(value: FieldRepresentation) -> u8 {
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

impl HeaderCapture {
    /// Canonical storage contains no request-bound values, including multipart boundaries.
    pub fn canonical(
        &self,
        policy: &HeaderCapturePolicy,
    ) -> Result<CanonicalValue, ProfileDataError> {
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
                    HeaderValueSource::Profile(value) => n.checked_sub(value.len()),
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
        let mut writer = CanonicalWriter::new(HEADER_DOMAIN, policy.bytes)?;
        writer.u8(version_tag(self.version))?;
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
            match field.representation {
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
            match &field.value {
                HeaderValueSource::Profile(value) => {
                    if field.sensitive || header_request_binding(&field.name).is_some() {
                        return Err(ProfileDataError::Invalid("captured request-bound value"));
                    }
                    HeaderValue::from_bytes(value)
                        .map_err(|_error| ProfileDataError::Invalid("profile header value"))?;
                    writer.u8(0)?;
                    writer.bytes(value)?;
                }
                HeaderValueSource::Request(binding) => {
                    let valid = match header_request_binding(&field.name) {
                        Some(expected) => expected == *binding,
                        None => matches!(
                            binding,
                            RequestBinding::Custom
                                | RequestBinding::Sensitive
                                | RequestBinding::Connection
                        ),
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
        let version = match reader.u8()? {
            0 => Version::HTTP_09,
            1 => Version::HTTP_10,
            2 => Version::HTTP_11,
            3 => Version::HTTP_2,
            4 => Version::HTTP_3,
            _ => return Err(ProfileDataError::Unsupported("HTTP version")),
        };
        let count = reader.count(policy.fields)?;
        let mut fields = Vec::new();
        for _ in 0..count {
            let name = HeaderName::from_bytes(reader.bytes(policy.bytes)?)
                .map_err(|_error| ProfileDataError::Invalid("header name"))?;
            let occurrence = reader.u32()?;
            let sensitive = read_bool(&mut reader)?;
            let representation = if read_bool(&mut reader)? {
                let representation = match reader.u8()? {
                    0 => FieldRepresentation::StaticIndex,
                    1 => FieldRepresentation::DynamicIndex,
                    2 => FieldRepresentation::DynamicPostBaseIndex,
                    3 => FieldRepresentation::LiteralStaticName,
                    4 => FieldRepresentation::LiteralDynamicName,
                    5 => FieldRepresentation::LiteralPostBaseName,
                    6 => FieldRepresentation::LiteralName,
                    _ => return Err(ProfileDataError::Invalid("header representation")),
                };
                let index = if read_bool(&mut reader)? {
                    Some(reader.u64()?)
                } else {
                    None
                };
                Some(ObservedFieldRepresentation {
                    representation,
                    index,
                    name_huffman: read_bool(&mut reader)?,
                    value_huffman: read_bool(&mut reader)?,
                    never_index: read_bool(&mut reader)?,
                })
            } else {
                None
            };
            let source = match reader.u8()? {
                0 => HeaderValueSource::Profile(reader.bytes(policy.bytes)?.into()),
                1 => HeaderValueSource::Request(RequestBinding::from_tag(reader.u8()?)?),
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
        reader.finish()?;
        let capture = Self {
            version,
            fields: fields.into_boxed_slice(),
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

#[cfg(test)]
mod tests;
