//! Typed, invariant-preserving QUIC wire profiles.
//!
//! A [`QuicProfile`] describes the parts of a connection's wire image that an implementation
//! is free to choose: which versions it offers, how it lays out its transport parameters,
//! how long its connection IDs are, how large and how many its Initial datagrams are, and how
//! frames are arranged inside them. Every knob is checked when it is set, so a profile can
//! reproduce another implementation's first flight but never an invalid one; there is no raw
//! byte hook.
//!
//! [`QuicProfile::standard()`] is what this crate does on its own. The browser profiles were
//! taken from captures of the named browser versions and are verified against those captures
//! in this crate's tests; [`crate::capture`] is the parser that reads a first flight back.

use core::{fmt, time::Duration};

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::{MAX_CID_SIZE, VarInt, version::ClientVersionPolicy};

/// The identifier of a transport parameter (RFC 9000 §18.2 and the QUIC transport parameter
/// registry), including ones this crate does not otherwise know.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ParameterId(pub u64);

impl ParameterId {
    pub const ORIGINAL_DESTINATION_CONNECTION_ID: Self = Self(0x00);
    pub const MAX_IDLE_TIMEOUT: Self = Self(0x01);
    pub const STATELESS_RESET_TOKEN: Self = Self(0x02);
    pub const MAX_UDP_PAYLOAD_SIZE: Self = Self(0x03);
    pub const INITIAL_MAX_DATA: Self = Self(0x04);
    pub const INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: Self = Self(0x05);
    pub const INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: Self = Self(0x06);
    pub const INITIAL_MAX_STREAM_DATA_UNI: Self = Self(0x07);
    pub const INITIAL_MAX_STREAMS_BIDI: Self = Self(0x08);
    pub const INITIAL_MAX_STREAMS_UNI: Self = Self(0x09);
    pub const ACK_DELAY_EXPONENT: Self = Self(0x0a);
    pub const MAX_ACK_DELAY: Self = Self(0x0b);
    pub const DISABLE_ACTIVE_MIGRATION: Self = Self(0x0c);
    pub const PREFERRED_ADDRESS: Self = Self(0x0d);
    pub const ACTIVE_CONNECTION_ID_LIMIT: Self = Self(0x0e);
    pub const INITIAL_SOURCE_CONNECTION_ID: Self = Self(0x0f);
    pub const RETRY_SOURCE_CONNECTION_ID: Self = Self(0x10);
    /// RFC 9368.
    pub const VERSION_INFORMATION: Self = Self(0x11);
    /// RFC 9221.
    pub const MAX_DATAGRAM_FRAME_SIZE: Self = Self(0x20);
    /// RFC 9287.
    pub const GREASE_QUIC_BIT: Self = Self(0x2ab2);
    /// draft-ietf-quic-ack-frequency-07.
    pub const MIN_ACK_DELAY: Self = Self(0xff04_de1b);
    /// Not a parameter: where the greased parameter goes in a fixed order.
    pub const GREASE: Self = Self(u64::MAX);

    /// Whether this identifier is one reserved for greasing (RFC 9000 §18.1): `31 * N + 27`.
    #[must_use]
    pub const fn is_reserved(self) -> bool {
        self.0 % 31 == 27
    }

    /// Whether this crate writes this parameter itself: the RFC 9000 §18.2 registry entries plus
    /// the extensions rama supports. Mirrors the engine's transport-parameter table.
    #[must_use]
    pub fn is_known(self) -> bool {
        matches!(self.0, 0x00..=0x11 | 0x1b | 0x20 | 0x2ab2 | 0xff04_de1b)
    }
}

impl fmt::Display for ParameterId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if *self == Self::GREASE {
            f.write_str("grease")
        } else {
            write!(f, "{:#x}", self.0)
        }
    }
}

/// The order transport parameters are written in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ParameterOrder {
    /// A fresh random order per connection.
    Shuffled,
    /// This order; parameters not listed follow in this crate's canonical order.
    /// [`ParameterId::GREASE`] names the greased parameter's place.
    Fixed(Vec<ParameterId>),
}

/// The reserved parameter written to exercise the peer's tolerance (RFC 9000 §18.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum GreaseParameter {
    /// None.
    None,
    /// A random reserved identifier with a random value of at most 16 bytes, or of exactly
    /// `value_len` bytes when given.
    Random { value_len: Option<usize> },
    /// This identifier and value on every connection.
    Fixed { id: ParameterId, value: Vec<u8> },
}

/// A transport parameter this crate does not interpret, written as given.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpaqueParameter {
    pub id: ParameterId,
    pub value: Vec<u8>,
}

/// How the transport parameters are laid out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "TransportParameterProfileRepr")]
pub struct TransportParameterProfile {
    order: ParameterOrder,
    grease: GreaseParameter,
    extra: Vec<OpaqueParameter>,
    min_ack_delay: bool,
    max_datagram_frame_size: Option<u64>,
}

/// The wire form of a [`TransportParameterProfile`]; deserialization goes through it and the
/// builder checks, so a parsed value is as valid as a built one.
#[derive(Deserialize)]
struct TransportParameterProfileRepr {
    order: ParameterOrder,
    grease: GreaseParameter,
    extra: Vec<OpaqueParameter>,
    min_ack_delay: bool,
    max_datagram_frame_size: Option<u64>,
}

impl TryFrom<TransportParameterProfileRepr> for TransportParameterProfile {
    type Error = ProfileError;
    fn try_from(repr: TransportParameterProfileRepr) -> Result<Self, Self::Error> {
        Self::default()
            .try_with_order(repr.order)?
            .try_with_grease(repr.grease)?
            .try_with_extra(repr.extra)?
            .try_with_max_datagram_frame_size(repr.max_datagram_frame_size)
            .map(|profile| profile.with_min_ack_delay(repr.min_ack_delay))
    }
}

/// A value this profile cannot hold.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProfileError {
    /// A parameter identifier appears twice.
    DuplicateParameter(ParameterId),
    /// An extra parameter uses an identifier this crate writes itself.
    KnownParameter(ParameterId),
    /// A greased parameter's identifier is not of the reserved form.
    NotReserved(ParameterId),
    /// A value is longer than a parameter may carry here.
    ValueTooLong(ParameterId),
    /// A connection ID length outside what QUIC allows.
    ConnectionIdLength(u8),
    /// An Initial datagram below QUIC's minimum or above what UDP carries.
    InitialDatagramSize(u16),
    /// A packet number length outside 1 to 4 bytes.
    PacketNumberLength(u8),
    /// A limit outside what its transport parameter can express.
    Limit(&'static str),
    /// The version policy is unusable.
    Version(crate::version::VersionPolicyError),
}

impl From<crate::version::VersionPolicyError> for ProfileError {
    fn from(error: crate::version::VersionPolicyError) -> Self {
        Self::Version(error)
    }
}

impl fmt::Display for ProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateParameter(id) => write!(f, "transport parameter {id} is listed twice"),
            Self::KnownParameter(id) => {
                write!(
                    f,
                    "transport parameter {id} is written by rama, not as an extra"
                )
            }
            Self::NotReserved(id) => {
                write!(
                    f,
                    "transport parameter {id} is not a reserved (31n+27) identifier"
                )
            }
            Self::ValueTooLong(id) => write!(f, "transport parameter {id} has a value too long"),
            Self::ConnectionIdLength(len) => {
                write!(f, "connection ID length {len} is outside 0..=20")
            }
            Self::InitialDatagramSize(size) => {
                write!(f, "Initial datagram size {size} is outside 1200..=65527")
            }
            Self::PacketNumberLength(len) => {
                write!(f, "packet number length {len} is outside 1..=4")
            }
            Self::Limit(what) => write!(f, "{what} is outside what its parameter can express"),
            Self::Version(error) => write!(f, "{error}"),
        }
    }
}

impl core::error::Error for ProfileError {}

/// Extra parameters carry at most this much.
const MAX_EXTRA_VALUE: usize = 1024;

impl Default for TransportParameterProfile {
    fn default() -> Self {
        Self {
            order: ParameterOrder::Shuffled,
            grease: GreaseParameter::Random { value_len: None },
            extra: Vec::new(),
            min_ack_delay: true,
            max_datagram_frame_size: None,
        }
    }
}

impl TransportParameterProfile {
    /// This crate's own layout: shuffled, one random greased parameter, the ACK frequency
    /// extension advertised.
    #[must_use]
    pub fn standard() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn order(&self) -> &ParameterOrder {
        &self.order
    }

    #[must_use]
    pub fn grease(&self) -> &GreaseParameter {
        &self.grease
    }

    #[must_use]
    pub fn extra(&self) -> &[OpaqueParameter] {
        &self.extra
    }

    /// Whether the `min_ack_delay` parameter of the ACK frequency extension is sent.
    #[must_use]
    pub fn sends_min_ack_delay(&self) -> bool {
        self.min_ack_delay
    }

    /// The `max_datagram_frame_size` value advertised in place of the receive buffer size.
    #[must_use]
    pub fn max_datagram_frame_size(&self) -> Option<u64> {
        self.max_datagram_frame_size
    }

    /// The order parameters are written in; a fixed order may list each identifier once.
    pub fn try_with_order(mut self, order: ParameterOrder) -> Result<Self, ProfileError> {
        if let ParameterOrder::Fixed(ids) = &order {
            for (index, id) in ids.iter().enumerate() {
                if ids[..index].contains(id) {
                    return Err(ProfileError::DuplicateParameter(*id));
                }
            }
        }
        self.order = order;
        Ok(self)
    }

    /// The greased parameter; a fixed one must use a reserved identifier.
    pub fn try_with_grease(mut self, grease: GreaseParameter) -> Result<Self, ProfileError> {
        match &grease {
            GreaseParameter::Fixed { id, value } => {
                if !id.is_reserved() {
                    return Err(ProfileError::NotReserved(*id));
                }
                if value.len() > MAX_EXTRA_VALUE {
                    return Err(ProfileError::ValueTooLong(*id));
                }
            }
            GreaseParameter::Random {
                value_len: Some(len),
            } if *len > MAX_EXTRA_VALUE => {
                return Err(ProfileError::ValueTooLong(ParameterId::GREASE));
            }
            GreaseParameter::None | GreaseParameter::Random { .. } => {}
        }
        self.grease = grease;
        Ok(self)
    }

    /// Parameters written as given; none may be one this crate writes itself, and each
    /// identifier appears once.
    pub fn try_with_extra(mut self, extra: Vec<OpaqueParameter>) -> Result<Self, ProfileError> {
        for (index, parameter) in extra.iter().enumerate() {
            if parameter.id.is_known() || parameter.id == ParameterId::GREASE {
                return Err(ProfileError::KnownParameter(parameter.id));
            }
            if extra[..index].iter().any(|other| other.id == parameter.id) {
                return Err(ProfileError::DuplicateParameter(parameter.id));
            }
            if parameter.value.len() > MAX_EXTRA_VALUE {
                return Err(ProfileError::ValueTooLong(parameter.id));
            }
        }
        self.extra = extra;
        Ok(self)
    }

    rama_utils::macros::generate_set_and_with! {
        /// Whether to advertise `min_ack_delay` (draft-ietf-quic-ack-frequency). On by default.
        pub fn min_ack_delay(mut self, send: bool) -> Self {
            self.min_ack_delay = send;
            self
        }
    }

    /// Advertise this `max_datagram_frame_size` instead of the receive buffer size; the buffer
    /// still bounds what is accepted. Must fit a variable-length integer.
    pub fn try_with_max_datagram_frame_size(
        mut self,
        size: Option<u64>,
    ) -> Result<Self, ProfileError> {
        if size.is_some_and(|size| VarInt::from_u64(size).is_err()) {
            return Err(ProfileError::Limit("max_datagram_frame_size"));
        }
        self.max_datagram_frame_size = size;
        Ok(self)
    }
}

/// How long packet numbers are encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum PacketNumberLength {
    /// The fewest bytes that disambiguate the number (RFC 9000 §17.1).
    Minimal,
    /// At least this many bytes, 1 to 4, and more when the number needs them.
    AtLeast(u8),
}

/// How the frames of a client's Initial packets are arranged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum InitialFlightLayout {
    /// CRYPTO frames in order, padding after them.
    Ordered,
    /// The CRYPTO data split into fragments of random size in random order, with PING and
    /// PADDING frames between them, as Chromium's chaos protection does.
    Chaos,
}

/// Where the bytes that bring an Initial datagram up to size go.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum PaddingPlacement {
    /// PADDING frames inside the last packet.
    Frames,
    /// Zero bytes after the last packet, which receivers ignore (RFC 9000 §12.2).
    DatagramTail,
}

/// How packets and datagrams are formed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "PacketizationProfileRepr")]
pub struct PacketizationProfile {
    initial_datagram_size: u16,
    packet_number_length: PacketNumberLength,
    first_packet_number: u64,
    layout: InitialFlightLayout,
    padding: PaddingPlacement,
    coalesce: bool,
}

/// The wire form of a [`PacketizationProfile`]; deserialization goes through it and the builder
/// checks, so a parsed value is as valid as a built one.
#[derive(Deserialize)]
struct PacketizationProfileRepr {
    initial_datagram_size: u16,
    packet_number_length: PacketNumberLength,
    first_packet_number: u64,
    layout: InitialFlightLayout,
    padding: PaddingPlacement,
    coalesce: bool,
}

impl TryFrom<PacketizationProfileRepr> for PacketizationProfile {
    type Error = ProfileError;
    fn try_from(repr: PacketizationProfileRepr) -> Result<Self, Self::Error> {
        Ok(Self::default()
            .try_with_initial_datagram_size(repr.initial_datagram_size)?
            .try_with_packet_number_length(repr.packet_number_length)?
            .try_with_first_packet_number(repr.first_packet_number)?
            .with_layout(repr.layout)
            .with_padding(repr.padding)
            .with_coalesce(repr.coalesce))
    }
}

impl Default for PacketizationProfile {
    fn default() -> Self {
        Self {
            initial_datagram_size: 1200,
            packet_number_length: PacketNumberLength::Minimal,
            first_packet_number: 0,
            layout: InitialFlightLayout::Ordered,
            padding: PaddingPlacement::Frames,
            coalesce: true,
        }
    }
}

impl PacketizationProfile {
    /// This crate's own packetization.
    #[must_use]
    pub fn standard() -> Self {
        Self::default()
    }

    /// The size Initial datagrams are padded to (RFC 9000 §14.1 requires at least 1200).
    #[must_use]
    pub fn initial_datagram_size(&self) -> u16 {
        self.initial_datagram_size
    }

    #[must_use]
    pub fn packet_number_length(&self) -> PacketNumberLength {
        self.packet_number_length
    }

    /// The packet number of the first packet in every space.
    #[must_use]
    pub fn first_packet_number(&self) -> u64 {
        self.first_packet_number
    }

    #[must_use]
    pub fn layout(&self) -> InitialFlightLayout {
        self.layout
    }

    #[must_use]
    pub fn padding(&self) -> PaddingPlacement {
        self.padding
    }

    /// Whether long-header packets of different spaces share a datagram.
    #[must_use]
    pub fn coalesces(&self) -> bool {
        self.coalesce
    }

    pub fn try_with_initial_datagram_size(mut self, size: u16) -> Result<Self, ProfileError> {
        if !(1200..=65527).contains(&size) {
            return Err(ProfileError::InitialDatagramSize(size));
        }
        self.initial_datagram_size = size;
        Ok(self)
    }

    pub fn try_with_packet_number_length(
        mut self,
        length: PacketNumberLength,
    ) -> Result<Self, ProfileError> {
        if let PacketNumberLength::AtLeast(len) = length
            && !(1..=4).contains(&len)
        {
            return Err(ProfileError::PacketNumberLength(len));
        }
        self.packet_number_length = length;
        Ok(self)
    }

    /// The first packet number. Since nothing is acknowledged yet, this packet's truncated number
    /// spans twice its value, and QUIC's largest truncation is four bytes (RFC 9000 §17.1), so it
    /// must stay below 2^31 to be encodable.
    pub fn try_with_first_packet_number(mut self, first: u64) -> Result<Self, ProfileError> {
        if first >= 1 << 31 {
            return Err(ProfileError::Limit("first packet number"));
        }
        self.first_packet_number = first;
        Ok(self)
    }

    rama_utils::macros::generate_set_and_with! {
        pub fn layout(mut self, layout: InitialFlightLayout) -> Self {
            self.layout = layout;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        pub fn padding(mut self, padding: PaddingPlacement) -> Self {
            self.padding = padding;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Whether long-header packets of different spaces share a datagram. On by default.
        pub fn coalesce(mut self, coalesce: bool) -> Self {
            self.coalesce = coalesce;
            self
        }
    }

    /// The minimum packet-number length this profile encodes with.
    #[must_use]
    pub fn min_packet_number_len(&self) -> u8 {
        match self.packet_number_length {
            PacketNumberLength::Minimal => 1,
            PacketNumberLength::AtLeast(len) => len,
        }
    }
}

/// Connection ID lengths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ConnectionIdProfileRepr")]
pub struct ConnectionIdProfile {
    initial_destination_len: u8,
    local_len: u8,
}

/// The wire form of a [`ConnectionIdProfile`]; deserialization goes through it and the builder
/// checks, so a parsed value is as valid as a built one.
#[derive(Deserialize)]
struct ConnectionIdProfileRepr {
    initial_destination_len: u8,
    local_len: u8,
}

impl TryFrom<ConnectionIdProfileRepr> for ConnectionIdProfile {
    type Error = ProfileError;
    fn try_from(repr: ConnectionIdProfileRepr) -> Result<Self, Self::Error> {
        Self::default()
            .try_with_initial_destination_len(repr.initial_destination_len)?
            .try_with_local_len(repr.local_len)
    }
}

impl Default for ConnectionIdProfile {
    fn default() -> Self {
        Self {
            initial_destination_len: MAX_CID_SIZE as u8,
            local_len: 8,
        }
    }
}

impl ConnectionIdProfile {
    /// This crate's own: a 20-byte first destination and 8-byte local identifiers.
    #[must_use]
    pub fn standard() -> Self {
        Self::default()
    }

    /// The length of the destination connection ID a client picks for its first Initial
    /// (RFC 9000 §7.2 requires at least 8).
    #[must_use]
    pub fn initial_destination_len(&self) -> u8 {
        self.initial_destination_len
    }

    /// The length of the connection IDs this endpoint issues.
    #[must_use]
    pub fn local_len(&self) -> u8 {
        self.local_len
    }

    pub fn try_with_initial_destination_len(mut self, len: u8) -> Result<Self, ProfileError> {
        if !(8..=MAX_CID_SIZE as u8).contains(&len) {
            return Err(ProfileError::ConnectionIdLength(len));
        }
        self.initial_destination_len = len;
        Ok(self)
    }

    pub fn try_with_local_len(mut self, len: u8) -> Result<Self, ProfileError> {
        if len > MAX_CID_SIZE as u8 {
            return Err(ProfileError::ConnectionIdLength(len));
        }
        self.local_len = len;
        Ok(self)
    }
}

/// The advertised flow-control and timing limits, as the transport parameters carry them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "TransportLimitsRepr")]
pub struct TransportLimits {
    pub max_idle_timeout: Duration,
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    pub max_ack_delay: Duration,
    /// Advertised as-is when set; the crate stores at most five, so more is refused.
    pub active_connection_id_limit: Option<u64>,
    pub max_udp_payload_size: u64,
    /// The datagram receive buffer, from which `max_datagram_frame_size` follows; `None`
    /// disables the extension.
    pub datagram_receive_buffer_size: Option<usize>,
}

/// The wire form of [`TransportLimits`]; deserialization goes through it and the same checks the
/// builder applies, so a parsed value cannot hold a limit its transport parameter cannot express.
#[derive(Deserialize)]
struct TransportLimitsRepr {
    max_idle_timeout: Duration,
    initial_max_data: u64,
    initial_max_stream_data_bidi_local: u64,
    initial_max_stream_data_bidi_remote: u64,
    initial_max_stream_data_uni: u64,
    initial_max_streams_bidi: u64,
    initial_max_streams_uni: u64,
    max_ack_delay: Duration,
    active_connection_id_limit: Option<u64>,
    max_udp_payload_size: u64,
    datagram_receive_buffer_size: Option<usize>,
}

impl TryFrom<TransportLimitsRepr> for TransportLimits {
    type Error = ProfileError;
    fn try_from(repr: TransportLimitsRepr) -> Result<Self, Self::Error> {
        let limits = Self {
            max_idle_timeout: repr.max_idle_timeout,
            initial_max_data: repr.initial_max_data,
            initial_max_stream_data_bidi_local: repr.initial_max_stream_data_bidi_local,
            initial_max_stream_data_bidi_remote: repr.initial_max_stream_data_bidi_remote,
            initial_max_stream_data_uni: repr.initial_max_stream_data_uni,
            initial_max_streams_bidi: repr.initial_max_streams_bidi,
            initial_max_streams_uni: repr.initial_max_streams_uni,
            max_ack_delay: repr.max_ack_delay,
            active_connection_id_limit: repr.active_connection_id_limit,
            max_udp_payload_size: repr.max_udp_payload_size,
            datagram_receive_buffer_size: repr.datagram_receive_buffer_size,
        };
        limits.check()?;
        Ok(limits)
    }
}

impl TransportLimits {
    /// This crate's own advertised limits, matching what its engine sends by default.
    #[must_use]
    pub fn standard() -> Self {
        // Bytes/s * ms / 1000: the bandwidth-delay product the engine sizes its windows to.
        const STREAM_RWND: u64 = 1_250_000;
        Self {
            max_idle_timeout: Duration::from_millis(30_000),
            initial_max_data: VarInt::MAX.into_inner(),
            initial_max_stream_data_bidi_local: STREAM_RWND,
            initial_max_stream_data_bidi_remote: STREAM_RWND,
            initial_max_stream_data_uni: STREAM_RWND,
            initial_max_streams_bidi: 100,
            initial_max_streams_uni: 100,
            max_ack_delay: Duration::from_millis(25),
            active_connection_id_limit: None,
            max_udp_payload_size: 1472,
            datagram_receive_buffer_size: Some(STREAM_RWND as usize),
        }
    }

    fn check(&self) -> Result<(), ProfileError> {
        let var = |value: u64, what: &'static str| {
            VarInt::from_u64(value).map_err(|_error| ProfileError::Limit(what))
        };
        var(self.initial_max_data, "initial_max_data")?;
        var(
            self.initial_max_stream_data_bidi_local,
            "initial_max_stream_data_bidi_local",
        )?;
        var(
            self.initial_max_stream_data_bidi_remote,
            "initial_max_stream_data_bidi_remote",
        )?;
        var(
            self.initial_max_stream_data_uni,
            "initial_max_stream_data_uni",
        )?;
        if self.initial_max_streams_bidi > crate::MAX_STREAM_COUNT
            || self.initial_max_streams_uni > crate::MAX_STREAM_COUNT
        {
            return Err(ProfileError::Limit("initial_max_streams"));
        }
        let idle = u64::try_from(self.max_idle_timeout.as_millis())
            .map_err(|_error| ProfileError::Limit("max_idle_timeout"))?;
        var(idle, "max_idle_timeout")?;
        if self.max_ack_delay.as_millis() >= 1 << 14 {
            return Err(ProfileError::Limit("max_ack_delay"));
        }
        // The RFC 9000 §18.2 floor; an engine clamps the ceiling to what it can store when it
        // applies the profile.
        if let Some(limit) = self.active_connection_id_limit
            && (limit < 2 || VarInt::from_u64(limit).is_err())
        {
            return Err(ProfileError::Limit("active_connection_id_limit"));
        }
        if !(1200..=65527).contains(&self.max_udp_payload_size) {
            return Err(ProfileError::Limit("max_udp_payload_size"));
        }
        Ok(())
    }
}

/// A complete wire profile; see the [module documentation](self).
///
/// Every field is a type that can only hold values its builder accepts and that validates its own
/// deserialization, so a `QuicProfile` is valid by construction: there is no separate check to
/// remember, and none to forget.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuicProfile {
    versions: ClientVersionPolicy,
    transport_parameters: TransportParameterProfile,
    connection_ids: ConnectionIdProfile,
    packetization: PacketizationProfile,
    limits: TransportLimits,
    grease_quic_bit: bool,
}

impl Default for QuicProfile {
    fn default() -> Self {
        Self::standard()
    }
}

impl QuicProfile {
    /// What this crate does on its own.
    #[must_use]
    pub fn standard() -> Self {
        Self {
            versions: ClientVersionPolicy::default(),
            transport_parameters: TransportParameterProfile::standard(),
            connection_ids: ConnectionIdProfile::standard(),
            packetization: PacketizationProfile::standard(),
            limits: TransportLimits::standard(),
            grease_quic_bit: true,
        }
    }

    #[must_use]
    pub fn versions(&self) -> &ClientVersionPolicy {
        &self.versions
    }

    #[must_use]
    pub fn transport_parameters(&self) -> &TransportParameterProfile {
        &self.transport_parameters
    }

    #[must_use]
    pub fn connection_ids(&self) -> &ConnectionIdProfile {
        &self.connection_ids
    }

    #[must_use]
    pub fn packetization(&self) -> &PacketizationProfile {
        &self.packetization
    }

    #[must_use]
    pub fn limits(&self) -> &TransportLimits {
        &self.limits
    }

    /// Whether the endpoint advertises and performs QUIC bit greasing (RFC 9287).
    #[must_use]
    pub fn greases_quic_bit(&self) -> bool {
        self.grease_quic_bit
    }

    rama_utils::macros::generate_set_and_with! {
        pub fn versions(mut self, versions: ClientVersionPolicy) -> Self {
            self.versions = versions;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        pub fn transport_parameters(mut self, parameters: TransportParameterProfile) -> Self {
            self.transport_parameters = parameters;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        pub fn connection_ids(mut self, ids: ConnectionIdProfile) -> Self {
            self.connection_ids = ids;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        pub fn packetization(mut self, packetization: PacketizationProfile) -> Self {
            self.packetization = packetization;
            self
        }
    }

    /// The advertised limits, checked against what their parameters can express.
    pub fn try_with_limits(mut self, limits: TransportLimits) -> Result<Self, ProfileError> {
        limits.check()?;
        self.limits = limits;
        Ok(self)
    }

    rama_utils::macros::generate_set_and_with! {
        pub fn grease_quic_bit(mut self, grease: bool) -> Self {
            self.grease_quic_bit = grease;
            self
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The first packet number stays below what the initial packet's truncated number can encode
    /// (twice its value, four bytes), so a profile can never make packet building panic.
    #[test]
    fn first_packet_number_is_bounded_to_what_the_encoder_can_hold() {
        assert_eq!(
            PacketizationProfile::standard()
                .try_with_first_packet_number((1 << 31) - 1)
                .unwrap()
                .first_packet_number(),
            (1 << 31) - 1
        );
        assert_eq!(
            PacketizationProfile::standard().try_with_first_packet_number(1 << 31),
            Err(ProfileError::Limit("first packet number"))
        );
    }

    /// A valid profile survives a serde round-trip unchanged.
    #[test]
    fn a_valid_profile_round_trips_through_serde() {
        let profile = QuicProfile::standard();
        let json = serde_json::to_string(&profile).unwrap();
        assert_eq!(serde_json::from_str::<QuicProfile>(&json).unwrap(), profile);
    }

    /// Every part validates its own deserialization, so a document holding one value the builder
    /// would reject fails to parse rather than yielding a profile that misbehaves downstream. A
    /// bad part is written out structurally, then the parse of that same bytes must fail.
    #[test]
    fn deserialization_rejects_an_invalid_value_in_every_part() {
        fn rejected<T: Serialize + serde::de::DeserializeOwned + fmt::Debug>(bad: &T) {
            let json = serde_json::to_string(bad).unwrap();
            serde_json::from_str::<T>(&json).unwrap_err();
        }

        // A version policy has private fields, so tamper with its serialized form instead: an empty
        // compatible list is one the builder rejects.
        let mut raw = serde_json::to_value(ClientVersionPolicy::default()).unwrap();
        raw["compatible"] = serde_json::json!([]);
        serde_json::from_value::<ClientVersionPolicy>(raw).unwrap_err();

        rejected(&TransportParameterProfile {
            // An extra parameter may not reuse an identifier this crate writes itself.
            extra: alloc::vec![OpaqueParameter {
                id: ParameterId::MAX_IDLE_TIMEOUT,
                value: Vec::new(),
            }],
            ..TransportParameterProfile::standard()
        });
        rejected(&ConnectionIdProfile {
            local_len: MAX_CID_SIZE as u8 + 1,
            initial_destination_len: 8,
        });
        rejected(&PacketizationProfile {
            first_packet_number: 1 << 40,
            ..PacketizationProfile::standard()
        });
        rejected(&TransportLimits {
            // 17 s is past the 2^14 ms the max_ack_delay transport parameter can carry.
            max_ack_delay: Duration::from_secs(17),
            ..TransportLimits::standard()
        });
        // Each remaining limit check has its own rejected input, so none can be quietly dropped.
        rejected(&TransportLimits {
            initial_max_streams_bidi: crate::MAX_STREAM_COUNT + 1,
            ..TransportLimits::standard()
        });
        rejected(&TransportLimits {
            initial_max_streams_uni: crate::MAX_STREAM_COUNT + 1,
            ..TransportLimits::standard()
        });
        rejected(&TransportLimits {
            // RFC 9000 §18.2 floors the active_connection_id_limit at 2.
            active_connection_id_limit: Some(1),
            ..TransportLimits::standard()
        });
        rejected(&TransportLimits {
            max_udp_payload_size: 1199,
            ..TransportLimits::standard()
        });
        rejected(&TransportLimits {
            max_udp_payload_size: 65528,
            ..TransportLimits::standard()
        });

        // The inclusive boundaries are accepted, which pins the comparisons that guard them: the
        // largest allowed stream counts and the smallest allowed active_connection_id_limit.
        let json = serde_json::to_string(&TransportLimits {
            initial_max_streams_bidi: crate::MAX_STREAM_COUNT,
            initial_max_streams_uni: crate::MAX_STREAM_COUNT,
            active_connection_id_limit: Some(2),
            ..TransportLimits::standard()
        })
        .unwrap();
        serde_json::from_str::<TransportLimits>(&json).unwrap();

        // And an invalid part sunk inside an otherwise-standard profile fails the whole parse.
        let bad = QuicProfile {
            limits: TransportLimits {
                max_ack_delay: Duration::from_secs(17),
                ..TransportLimits::standard()
            },
            ..QuicProfile::standard()
        };
        let json = serde_json::to_string(&bad).unwrap();
        serde_json::from_str::<QuicProfile>(&json).unwrap_err();
    }
}
