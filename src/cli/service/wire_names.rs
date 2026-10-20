//! Display names for QUIC and HTTP/3 codepoints.
//!
//! Shared by the echo and fingerprint services, so both name a codepoint identically.

use std::{borrow::Cow, fmt};

use serde::{Serialize, Serializer};

use crate::{
    http::proto::h3::{Code, FrameType as H3FrameType, SettingId, StreamType},
    quic::proto::{
        Version, frame::FrameType as QuicFrameType, transport_parameters::TransportParameterId,
    },
};

/// The display name of one protocol codepoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodepointName {
    /// A registered name.
    Known(Cow<'static, str>),
    /// A value reserved for greasing.
    Grease,
    /// A value reserved by the registry without a meaning.
    Reserved,
    /// A value this implementation does not recognise.
    Unknown,
}

impl CodepointName {
    /// The name, or `grease`, `reserved` or `unknown`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Known(name) => name,
            Self::Grease => "grease",
            Self::Reserved => "reserved",
            Self::Unknown => "unknown",
        }
    }

    /// A label for human display: the known name, or the class with the hex value.
    #[must_use]
    pub fn label(&self, raw: u64) -> String {
        match self {
            Self::Known(name) => name.clone().into_owned(),
            other => format!("{} {raw:#x}", other.as_str()),
        }
    }

    fn from_parts(name: Option<&'static str>, grease: bool, reserved: bool) -> Self {
        match name {
            Some(name) => Self::Known(Cow::Borrowed(name)),
            None if grease => Self::Grease,
            None if reserved => Self::Reserved,
            None => Self::Unknown,
        }
    }
}

impl fmt::Display for CodepointName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for CodepointName {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// A raw codepoint together with its display name.
#[derive(Debug, Clone, Serialize)]
pub struct Named<R> {
    pub raw: R,
    pub name: CodepointName,
}

/// A QUIC version: `v1`, `v2`, `grease` for `0x?a?a?a?a` (RFC 9000 §15) or `unknown`.
#[must_use]
pub fn quic_version_name(version: Version) -> CodepointName {
    match version {
        Version::V1 => CodepointName::Known(Cow::Borrowed("v1")),
        Version::V2 => CodepointName::Known(Cow::Borrowed("v2")),
        other if other.is_reserved() => CodepointName::Grease,
        _ => CodepointName::Unknown,
    }
}

/// A QUIC version with its 32-bit wire value as hex text.
#[must_use]
pub fn named_quic_version(version: Version) -> Named<String> {
    Named {
        raw: format!("{:#010x}", version.as_u32()),
        name: quic_version_name(version),
    }
}

/// A transport parameter by its registry name, such as `initial_max_streams_bidi`.
#[must_use]
pub fn transport_parameter_name(id: TransportParameterId) -> CodepointName {
    match id {
        TransportParameterId::Unknown(_) if id.is_reserved() => CodepointName::Grease,
        TransportParameterId::Unknown(_) => CodepointName::Unknown,
        known => CodepointName::Known(Cow::Owned(snake_case(&known.variant_name()))),
    }
}

/// A transport parameter identifier with its name.
#[must_use]
pub fn named_transport_parameter(id: TransportParameterId) -> Named<u64> {
    Named {
        raw: u64::from(id),
        name: transport_parameter_name(id),
    }
}

/// A QUIC frame type (RFC 9000 §19).
#[must_use]
pub fn quic_frame_name(frame_type: u64) -> CodepointName {
    CodepointName::from_parts(QuicFrameType::from_u64(frame_type).name(), false, false)
}

/// An HTTP/3 setting identifier (RFC 9114 §7.2.4).
#[must_use]
pub fn h3_setting_name(id: u64) -> CodepointName {
    let id = SettingId::new(id);
    CodepointName::from_parts(id.name(), id.is_reserved(), id.is_h2_forbidden())
}

/// An HTTP/3 unidirectional stream type (RFC 9114 §6.2).
#[must_use]
pub fn h3_stream_type_name(stream_type: u64) -> CodepointName {
    let ty = StreamType::new(stream_type);
    CodepointName::from_parts(ty.name(), ty.is_reserved(), false)
}

/// An HTTP/3 frame type (RFC 9114 §7.2).
#[must_use]
pub fn h3_frame_type_name(frame_type: u64) -> CodepointName {
    let ty = H3FrameType::new(frame_type);
    CodepointName::from_parts(ty.name(), ty.is_reserved(), ty.is_h2_reserved())
}

/// An HTTP/3 error code (RFC 9114 §8.1).
#[must_use]
pub fn h3_error_name(code: u64) -> CodepointName {
    let code = Code::new(code);
    CodepointName::from_parts(code.name(), code.is_reserved(), false)
}

/// Pair a raw value with the name `name_of` gives it.
#[must_use]
pub fn named(raw: u64, name_of: fn(u64) -> CodepointName) -> Named<u64> {
    Named {
        raw,
        name: name_of(raw),
    }
}

fn snake_case(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 8);
    for (index, c) in name.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if index > 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, to_value};

    #[test]
    fn names_cover_known_grease_reserved_and_unknown_codepoints() {
        assert_eq!(quic_version_name(Version::V1).as_str(), "v1");
        assert_eq!(quic_version_name(Version::V2).as_str(), "v2");
        assert_eq!(
            quic_version_name(Version::from_u32(0x0a1a_2a3a)).as_str(),
            "grease"
        );
        assert_eq!(
            quic_version_name(Version::from_u32(0xff00_001d)).as_str(),
            "unknown"
        );
        assert_eq!(named_quic_version(Version::V2).raw, "0x6b3343cf");

        for (id, name) in [
            (0x08, "initial_max_streams_bidi"),
            (0x11, "version_information"),
            (0x2ab2, "grease_quic_bit"),
            (0xff04_de1b, "min_ack_delay_draft07"),
            (31 * 5 + 27, "grease"),
            (0x4243, "unknown"),
        ] {
            assert_eq!(
                transport_parameter_name(TransportParameterId::from(id)).as_str(),
                name
            );
        }

        assert_eq!(quic_frame_name(0x06).as_str(), "CRYPTO");
        assert_eq!(quic_frame_name(0x0a).as_str(), "STREAM");
        assert_eq!(quic_frame_name(0x4243).as_str(), "unknown");

        assert_eq!(h3_setting_name(0x06).as_str(), "MAX_FIELD_SECTION_SIZE");
        assert_eq!(h3_setting_name(0x21).as_str(), "grease");
        assert_eq!(h3_setting_name(0x02).as_str(), "reserved");
        assert_eq!(h3_setting_name(0x4d45).as_str(), "unknown");
        assert_eq!(h3_stream_type_name(0x02).as_str(), "QPACK_ENCODER");
        assert_eq!(h3_frame_type_name(0x04).as_str(), "SETTINGS");
        assert_eq!(h3_frame_type_name(0x06).as_str(), "reserved");
        assert_eq!(h3_error_name(0x0101).as_str(), "H3_GENERAL_PROTOCOL_ERROR");

        assert_eq!(h3_setting_name(0x21).label(0x21), "grease 0x21");
        assert_eq!(
            h3_setting_name(0x01).label(0x01),
            "QPACK_MAX_TABLE_CAPACITY"
        );
    }

    #[test]
    fn named_serializes_raw_and_name() {
        assert_eq!(
            to_value(named(8, h3_setting_name)).unwrap(),
            json!({"raw": 8, "name": "ENABLE_CONNECT_PROTOCOL"})
        );
        assert_eq!(
            to_value(named_quic_version(Version::V1)).unwrap(),
            json!({"raw": "0x00000001", "name": "v1"})
        );
    }
}
