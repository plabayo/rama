//! HTTP/3 SETTINGS (RFC 9114 §7.2.4) and the QPACK settings (RFC 9204 §5).

use std::fmt;

use rama_core::bytes::{Buf, BufMut};
use rama_quic_proto::{VarInt, coding::Codec};

/// The identifier of an HTTP/3 setting (RFC 9114 §7.2.4, §11.2.2).
///
/// Unknown identifiers are preserved (an endpoint "MUST ignore ... unknown or unsupported values",
/// RFC 9114 §7.2.4.1) while still being subject to duplicate detection. The setting identifiers
/// HTTP/2 defined without an HTTP/3 counterpart are reserved and their receipt is a connection
/// error of type `H3_SETTINGS_ERROR`; [`SettingId::is_h2_forbidden`] recognizes them.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SettingId(u64);

impl SettingId {
    /// `SETTINGS_QPACK_MAX_TABLE_CAPACITY` (RFC 9204 §5).
    pub const QPACK_MAX_TABLE_CAPACITY: Self = Self(0x01);
    /// `SETTINGS_MAX_FIELD_SECTION_SIZE` (RFC 9114 §7.2.4.1).
    pub const MAX_FIELD_SECTION_SIZE: Self = Self(0x06);
    /// `SETTINGS_QPACK_BLOCKED_STREAMS` (RFC 9204 §5).
    pub const QPACK_BLOCKED_STREAMS: Self = Self(0x07);

    /// Construct a setting identifier from its raw value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// The raw identifier value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }

    /// Whether this is a reserved identifier of the form `0x1f * N + 0x21` (RFC 9114 §11.2.2) used
    /// for greasing. Reserved identifiers are legal on the wire and ignored on receipt.
    #[must_use]
    pub const fn is_reserved(self) -> bool {
        self.0 >= 0x21 && (self.0 - 0x21).is_multiple_of(0x1f)
    }

    /// Whether this identifier was reserved because HTTP/2 defined it and HTTP/3 does not reuse it
    /// (`0x00`, `0x02`, `0x03`, `0x04`, `0x05`; RFC 9114 §7.2.4.1, §11.2.2). Its receipt is a
    /// connection error of type `H3_SETTINGS_ERROR`.
    #[must_use]
    pub const fn is_h2_forbidden(self) -> bool {
        matches!(self.0, 0x00 | 0x02 | 0x03 | 0x04 | 0x05)
    }

    /// A human-readable name for a known setting identifier, if any.
    #[must_use]
    pub const fn name(self) -> Option<&'static str> {
        Some(match self {
            Self::QPACK_MAX_TABLE_CAPACITY => "QPACK_MAX_TABLE_CAPACITY",
            Self::MAX_FIELD_SECTION_SIZE => "MAX_FIELD_SECTION_SIZE",
            Self::QPACK_BLOCKED_STREAMS => "QPACK_BLOCKED_STREAMS",
            _ => return None,
        })
    }
}

impl From<u64> for SettingId {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl fmt::Debug for SettingId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => write!(f, "SettingId::{name}"),
            None if self.is_reserved() => write!(f, "SettingId(0x{:x}, reserved)", self.0),
            None => write!(f, "SettingId(0x{:x})", self.0),
        }
    }
}

/// One HTTP/3 setting: an identifier and its value.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Setting {
    /// The setting identifier.
    pub id: SettingId,
    /// The setting value.
    pub value: u64,
}

impl Setting {
    /// Construct a setting.
    #[must_use]
    pub const fn new(id: SettingId, value: u64) -> Self {
        Self { id, value }
    }
}

/// The default cap on the number of entries [`Settings::decode`] will accept, bounding memory when
/// parsing a peer's SETTINGS frame. Well-behaved peers send only a handful.
pub const DEFAULT_MAX_SETTINGS_ENTRIES: usize = 32;

/// An ordered collection of HTTP/3 settings (RFC 9114 §7.2.4).
///
/// Order is preserved so that a caller reproducing a specific wire image (a fingerprint profile,
/// for example) can control it. Duplicate identifiers — known, unknown or reserved — are rejected,
/// and the HTTP/2-forbidden identifiers are rejected, both as required by RFC 9114 §7.2.4.1.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Settings {
    entries: Vec<Setting>,
}

impl Settings {
    /// An empty settings set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The settings in wire order.
    #[must_use]
    pub fn entries(&self) -> &[Setting] {
        &self.entries
    }

    /// The number of settings.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there are no settings.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The value of a setting, if present.
    #[must_use]
    pub fn get(&self, id: SettingId) -> Option<u64> {
        self.entries.iter().find(|s| s.id == id).map(|s| s.value)
    }

    /// `SETTINGS_QPACK_MAX_TABLE_CAPACITY`, defaulting to 0 (RFC 9204 §5).
    #[must_use]
    pub fn qpack_max_table_capacity(&self) -> u64 {
        self.get(SettingId::QPACK_MAX_TABLE_CAPACITY).unwrap_or(0)
    }

    /// `SETTINGS_QPACK_BLOCKED_STREAMS`, defaulting to 0 (RFC 9204 §5).
    #[must_use]
    pub fn qpack_blocked_streams(&self) -> u64 {
        self.get(SettingId::QPACK_BLOCKED_STREAMS).unwrap_or(0)
    }

    /// `SETTINGS_MAX_FIELD_SECTION_SIZE`, defaulting to unlimited (`None`; RFC 9114 §7.2.4.1).
    #[must_use]
    pub fn max_field_section_size(&self) -> Option<u64> {
        self.get(SettingId::MAX_FIELD_SECTION_SIZE)
    }

    /// Append a setting, rejecting duplicates and HTTP/2-forbidden identifiers.
    pub fn insert(&mut self, setting: Setting) -> Result<(), SettingsError> {
        if setting.id.is_h2_forbidden() {
            return Err(SettingsError::Forbidden(setting.id));
        }
        if self.entries.iter().any(|s| s.id == setting.id) {
            return Err(SettingsError::Duplicate(setting.id));
        }
        self.entries.push(setting);
        Ok(())
    }

    /// Append a setting by identifier and value; see [`Settings::insert`].
    pub fn set(&mut self, id: SettingId, value: u64) -> Result<(), SettingsError> {
        self.insert(Setting::new(id, value))
    }

    /// Encode the settings payload (the entries, without the frame header) into `dst`.
    ///
    /// Returns `None` without writing if any identifier or value exceeds the variable-length
    /// integer range.
    pub fn encode_payload<B: BufMut>(&self, dst: &mut B) -> Option<()> {
        for s in &self.entries {
            let id = VarInt::from_u64(s.id.0).ok()?;
            let value = VarInt::from_u64(s.value).ok()?;
            id.encode(dst);
            value.encode(dst);
        }
        Some(())
    }

    /// The encoded byte length of the settings payload, or `None` if a value is out of range.
    #[must_use]
    pub fn payload_len(&self) -> Option<usize> {
        let mut total = 0;
        for s in &self.entries {
            total += VarInt::from_u64(s.id.0).ok()?.size();
            total += VarInt::from_u64(s.value).ok()?.size();
        }
        Some(total)
    }

    /// Decode a complete SETTINGS payload from `src`, using [`DEFAULT_MAX_SETTINGS_ENTRIES`].
    ///
    /// `src` must contain exactly the frame payload; the caller (which owns framing) is responsible
    /// for having buffered `len` bytes and for bounding `len` before doing so.
    pub fn decode(src: &[u8]) -> Result<Self, SettingsError> {
        Self::decode_with_limit(src, DEFAULT_MAX_SETTINGS_ENTRIES)
    }

    /// Decode a complete SETTINGS payload, accepting at most `max_entries` entries.
    pub fn decode_with_limit(mut src: &[u8], max_entries: usize) -> Result<Self, SettingsError> {
        let mut settings = Self::new();
        while src.has_remaining() {
            let id = VarInt::decode(&mut src)?;
            if !src.has_remaining() {
                // an identifier without a value
                return Err(SettingsError::Malformed);
            }
            let value = VarInt::decode(&mut src)?;
            if settings.entries.len() >= max_entries {
                return Err(SettingsError::TooMany);
            }
            settings.insert(Setting::new(
                SettingId::from(id.into_inner()),
                value.into_inner(),
            ))?;
        }
        Ok(settings)
    }
}

impl fmt::Debug for Settings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.entries.iter()).finish()
    }
}

/// An error encountered while validating or decoding HTTP/3 settings (RFC 9114 §7.2.4.1).
///
/// Every variant maps to a connection error of type `H3_SETTINGS_ERROR`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SettingsError {
    /// The same identifier appeared twice (including unknown identifiers).
    Duplicate(SettingId),
    /// An HTTP/2-forbidden identifier (`0x00`, `0x02`–`0x05`) was present.
    Forbidden(SettingId),
    /// More entries than the configured budget.
    TooMany,
    /// The payload was truncated or otherwise not a valid identifier/value sequence.
    Malformed,
}

impl fmt::Display for SettingsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Duplicate(id) => write!(f, "duplicate HTTP/3 setting {id:?}"),
            Self::Forbidden(id) => write!(f, "forbidden HTTP/2 setting identifier {id:?}"),
            Self::TooMany => f.write_str("too many HTTP/3 settings"),
            Self::Malformed => f.write_str("malformed HTTP/3 SETTINGS payload"),
        }
    }
}

impl std::error::Error for SettingsError {}

impl From<rama_quic_proto::coding::UnexpectedEnd> for SettingsError {
    fn from(_: rama_quic_proto::coding::UnexpectedEnd) -> Self {
        Self::Malformed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::bytes::BytesMut;

    #[test]
    fn insert_and_get() {
        let mut s = Settings::new();
        s.set(SettingId::QPACK_MAX_TABLE_CAPACITY, 4096).unwrap();
        s.set(SettingId::QPACK_BLOCKED_STREAMS, 16).unwrap();
        assert_eq!(s.qpack_max_table_capacity(), 4096);
        assert_eq!(s.qpack_blocked_streams(), 16);
        assert_eq!(s.max_field_section_size(), None);
    }

    #[test]
    fn rejects_duplicate() {
        let mut s = Settings::new();
        s.set(SettingId::MAX_FIELD_SECTION_SIZE, 1).unwrap();
        assert_eq!(
            s.set(SettingId::MAX_FIELD_SECTION_SIZE, 2),
            Err(SettingsError::Duplicate(SettingId::MAX_FIELD_SECTION_SIZE))
        );
    }

    #[test]
    fn rejects_duplicate_unknown() {
        let mut s = Settings::new();
        s.set(SettingId::new(0x9999), 1).unwrap();
        assert_eq!(
            s.set(SettingId::new(0x9999), 2),
            Err(SettingsError::Duplicate(SettingId::new(0x9999)))
        );
    }

    #[test]
    fn rejects_forbidden_h2_ids() {
        for raw in [0x00u64, 0x02, 0x03, 0x04, 0x05] {
            let mut s = Settings::new();
            assert_eq!(
                s.set(SettingId::new(raw), 1),
                Err(SettingsError::Forbidden(SettingId::new(raw)))
            );
        }
    }

    #[test]
    fn preserves_unknown_settings() {
        let mut s = Settings::new();
        s.set(SettingId::new(0x21), 7).unwrap(); // reserved/grease
        s.set(SettingId::new(0x4d4d), 9).unwrap(); // unknown
        assert_eq!(s.get(SettingId::new(0x21)), Some(7));
        assert_eq!(s.get(SettingId::new(0x4d4d)), Some(9));
    }

    #[test]
    fn round_trip_payload() {
        let mut s = Settings::new();
        s.set(SettingId::QPACK_MAX_TABLE_CAPACITY, 4096).unwrap();
        s.set(SettingId::MAX_FIELD_SECTION_SIZE, 65536).unwrap();
        let mut buf = BytesMut::new();
        s.encode_payload(&mut buf).unwrap();
        assert_eq!(buf.len(), s.payload_len().unwrap());
        let decoded = Settings::decode(&buf).unwrap();
        assert_eq!(decoded, s);
    }

    #[test]
    fn decode_rejects_forbidden() {
        // id 0x02 (forbidden), value 0
        let payload = [0x02u8, 0x00];
        assert_eq!(
            Settings::decode(&payload),
            Err(SettingsError::Forbidden(SettingId::new(0x02)))
        );
    }

    #[test]
    fn decode_rejects_duplicate() {
        // id 0x06 value 1, id 0x06 value 2
        let payload = [0x06u8, 0x01, 0x06, 0x02];
        assert_eq!(
            Settings::decode(&payload),
            Err(SettingsError::Duplicate(SettingId::MAX_FIELD_SECTION_SIZE))
        );
    }

    #[test]
    fn decode_rejects_missing_value() {
        // id 0x06 with no value byte
        let payload = [0x06u8];
        assert_eq!(Settings::decode(&payload), Err(SettingsError::Malformed));
    }

    #[test]
    fn decode_rejects_too_many() {
        // build a payload with more than the limit of distinct unknown ids
        let mut buf = BytesMut::new();
        for id in 0x100u64..0x100 + (DEFAULT_MAX_SETTINGS_ENTRIES as u64) + 1 {
            VarInt::from_u64(id).unwrap().encode(&mut buf);
            VarInt::from_u64(0).unwrap().encode(&mut buf);
        }
        assert_eq!(Settings::decode(&buf), Err(SettingsError::TooMany));
    }
}
