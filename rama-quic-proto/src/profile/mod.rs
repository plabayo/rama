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

pub mod initial;

#[cfg(feature = "std")]
use rama_core::extensions::Extension;

use core::{fmt, time::Duration};

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::{
    MAX_CID_SIZE, VarInt,
    coding::BufExt as _,
    transport_parameters::{RawParameter, TransportParameterId, TransportParameters},
    version::ClientVersionPolicy,
};

/// The order transport parameters are written in.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ParameterOrder {
    /// A fresh random order per connection.
    Shuffled,
    /// This order; parameters not listed follow in this crate's canonical order.
    /// [`ParameterOrderEntry::Grease`] names the greased parameter's place.
    Fixed(Vec<ParameterOrderEntry>),
    /// Fixed order that also emits listed integer parameters at their protocol defaults.
    ///
    /// This preserves explicit defaults in a capture. Unlisted parameters still follow
    /// in canonical order; absent optional parameters are not created. Connection-bound
    /// values continue to come from the current connection.
    FixedWithExplicitDefaults(Vec<ParameterOrderEntry>),
}

impl ParameterOrder {
    /// Order concrete wire identifiers; unlisted parameters follow canonically.
    pub fn fixed(ids: impl IntoIterator<Item = TransportParameterId>) -> Self {
        Self::Fixed(
            ids.into_iter()
                .map(ParameterOrderEntry::Parameter)
                .collect(),
        )
    }

    /// Also retain explicitly listed integer parameters at their default values.
    pub fn fixed_with_explicit_defaults(
        ids: impl IntoIterator<Item = TransportParameterId>,
    ) -> Self {
        Self::FixedWithExplicitDefaults(
            ids.into_iter()
                .map(ParameterOrderEntry::Parameter)
                .collect(),
        )
    }
}

/// One position in a fixed transport-parameter emission order.
/// The GREASE marker is profile policy, never a wire identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ParameterOrderEntry {
    Parameter(TransportParameterId),
    Grease,
}

impl From<TransportParameterId> for ParameterOrderEntry {
    fn from(id: TransportParameterId) -> Self {
        Self::Parameter(id)
    }
}

/// The reserved parameter written to exercise the peer's tolerance (RFC 9000 §18.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum GreaseParameter {
    /// None.
    None,
    /// A random reserved identifier with a random value of at most 16 bytes, or of exactly
    /// `value_len` bytes when given.
    Random { value_len: Option<usize> },
    /// This identifier and value on every connection.
    Fixed {
        id: TransportParameterId,
        value: Vec<u8>,
    },
}

/// A transport parameter this crate does not interpret, written as given.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OpaqueParameter {
    pub id: TransportParameterId,
    pub value: Vec<u8>,
}

/// How the transport parameters are laid out.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    InitialFlight(&'static str),
    /// A fixed order repeats the GREASE marker.
    DuplicateGrease,
    /// A generated reserved parameter value exceeds the profile budget.
    GreaseValueTooLong,
    /// A literal parameter identifier does not fit a QUIC variable-length integer.
    ParameterIdOutOfRange(TransportParameterId),
    /// A parameter identifier appears twice.
    DuplicateParameter(TransportParameterId),
    /// An extra parameter uses an identifier this crate writes itself.
    KnownParameter(TransportParameterId),
    /// A greased parameter's identifier is not of the reserved form.
    NotReserved(TransportParameterId),
    /// A value is longer than a parameter may carry here.
    ValueTooLong(TransportParameterId),
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
            Self::DuplicateGrease => f.write_str("duplicate GREASE ordering marker"),
            Self::GreaseValueTooLong => {
                f.write_str("GREASE parameter value exceeds profile budget")
            }
            Self::InitialFlight(reason) => write!(f, "invalid recorded Initial flight: {reason}"),
            Self::ParameterIdOutOfRange(id) => {
                write!(f, "transport parameter {id} exceeds the QUIC integer range")
            }
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

/// Profile builders validate numeric range even for explicitly constructed Unknown values.
fn check_parameter_id(id: TransportParameterId) -> Result<(), ProfileError> {
    if u64::from(id) > VarInt::MAX.into_inner() {
        return Err(ProfileError::ParameterIdOutOfRange(id));
    }
    Ok(())
}

impl TransportParameterProfile {
    /// This crate's own layout: shuffled, one random greased parameter, the ACK frequency
    /// extension advertised.
    #[must_use]
    pub fn standard() -> Self {
        Self::default()
    }

    /// The layout of the transport parameters a client sent, for a relay that repeats them:
    /// their order, and every parameter this crate does not interpret (a greased one
    /// included) with its value, as sent. Values this crate derives per connection
    /// (connection IDs, tokens) or takes from [`TransportLimits`] are not part of a layout.
    pub fn try_from_sent(parameters: &[RawParameter]) -> Result<Self, ProfileError> {
        let mut order = Vec::with_capacity(parameters.len());
        let mut extra = Vec::new();
        let mut min_ack_delay = false;
        let mut max_datagram_frame_size = None;
        for RawParameter { id, value } in parameters {
            let id = TransportParameterId::from(u64::from(*id));
            order.push(id);
            if id == TransportParameterId::MinAckDelayDraft07 {
                min_ack_delay = true;
            } else if id == TransportParameterId::MaxDatagramFrameSize {
                max_datagram_frame_size = Some(sent_integer(id, value)?);
            } else if !id.is_implemented() {
                extra.push(OpaqueParameter {
                    id,
                    value: value.clone(),
                });
            }
        }
        Self::standard()
            .try_with_order(ParameterOrder::fixed_with_explicit_defaults(order))?
            .try_with_grease(GreaseParameter::None)?
            .try_with_extra(extra)?
            .with_min_ack_delay(min_ack_delay)
            .try_with_max_datagram_frame_size(max_datagram_frame_size)
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
        if let ParameterOrder::Fixed(ids) | ParameterOrder::FixedWithExplicitDefaults(ids) = &order
        {
            let mut grease_seen = false;
            for (index, entry) in ids.iter().enumerate() {
                match entry {
                    ParameterOrderEntry::Grease => {
                        if grease_seen {
                            return Err(ProfileError::DuplicateGrease);
                        }
                        grease_seen = true;
                    }
                    ParameterOrderEntry::Parameter(id) => {
                        check_parameter_id(*id)?;
                        if ids[..index].iter().any(|other| match other {
                            ParameterOrderEntry::Parameter(other) => {
                                u64::from(*other) == u64::from(*id)
                            }
                            ParameterOrderEntry::Grease => false,
                        }) {
                            return Err(ProfileError::DuplicateParameter(*id));
                        }
                    }
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
                check_parameter_id(*id)?;
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
                return Err(ProfileError::GreaseValueTooLong);
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
            check_parameter_id(parameter.id)?;
            if parameter.id.is_implemented() {
                return Err(ProfileError::KnownParameter(parameter.id));
            }
            if extra[..index]
                .iter()
                .any(|other| u64::from(other.id) == u64::from(parameter.id))
            {
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
    /// still bounds local retention. Valid frames that do not fit are dropped without a
    /// protocol error. Must fit a variable-length integer.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum PacketNumberLength {
    /// The fewest bytes that disambiguate the number (RFC 9000 §17.1).
    Minimal,
    /// At least this many bytes, 1 to 4, and more when the number needs them.
    AtLeast(u8),
}

/// How the frames of a client's Initial packets are arranged.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum InitialFlightLayout {
    /// Reproduce validated original frame shapes with fresh handshake bytes.
    /// Later packets retain the ordinary packetization policy.
    Recorded(initial::RecordedInitialFlight),
    /// CRYPTO frames in order, padding after them.
    Ordered,
    /// The CRYPTO data split into fragments of random size in random order, with PING and
    /// PADDING frames between them, as Chromium's chaos protection does.
    Chaos,
}

/// Where the bytes that bring an Initial datagram up to size go.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum PaddingPlacement {
    /// PADDING frames inside the last packet.
    Frames,
    /// Zero bytes after the last packet, which receivers ignore (RFC 9000 §12.2).
    DatagramTail,
}

/// How packets and datagrams are formed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
        match &self.layout {
            InitialFlightLayout::Recorded(flight) => flight.packets()[0].datagram_size(),
            _ => self.initial_datagram_size,
        }
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
    pub fn layout(&self) -> &InitialFlightLayout {
        &self.layout
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    /// Advertised as-is when set. An engine clamps values above its CID storage
    /// limit to that limit when applying the profile, tracing the change.
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
    /// The limits a client's sent transport parameters advertised, over
    /// [`Self::protocol_defaults`] for those it omitted.
    pub fn try_from_sent(parameters: &[RawParameter]) -> Result<Self, ProfileError> {
        let mut limits = Self::protocol_defaults();
        for RawParameter { id, value } in parameters {
            let integer = || sent_integer(*id, value);
            match TransportParameterId::from(u64::from(*id)) {
                TransportParameterId::MaxIdleTimeout => {
                    limits.max_idle_timeout = Duration::from_millis(integer()?);
                }
                TransportParameterId::MaxUdpPayloadSize => limits.max_udp_payload_size = integer()?,
                TransportParameterId::InitialMaxData => limits.initial_max_data = integer()?,
                TransportParameterId::InitialMaxStreamDataBidiLocal => {
                    limits.initial_max_stream_data_bidi_local = integer()?;
                }
                TransportParameterId::InitialMaxStreamDataBidiRemote => {
                    limits.initial_max_stream_data_bidi_remote = integer()?;
                }
                TransportParameterId::InitialMaxStreamDataUni => {
                    limits.initial_max_stream_data_uni = integer()?;
                }
                TransportParameterId::InitialMaxStreamsBidi => {
                    limits.initial_max_streams_bidi = integer()?;
                }
                TransportParameterId::InitialMaxStreamsUni => {
                    limits.initial_max_streams_uni = integer()?
                }
                TransportParameterId::MaxAckDelay => {
                    limits.max_ack_delay = Duration::from_millis(integer()?);
                }
                TransportParameterId::ActiveConnectionIdLimit => {
                    limits.active_connection_id_limit = Some(integer()?);
                }
                TransportParameterId::MaxDatagramFrameSize => {
                    limits.datagram_receive_buffer_size = Some(
                        usize::try_from(integer()?)
                            .map_err(|_error| ProfileError::Limit("max_datagram_frame_size"))?,
                    );
                }
                _ => {}
            }
        }
        limits.check()?;
        Ok(limits)
    }

    /// Limits implied by omitted transport parameters (RFC 9000 section 18.2).
    ///
    /// Capture compilers start here and replace only observed values. In
    /// particular, omitted flow-control limits grant no credit, an omitted idle
    /// timeout is disabled, and omitting the DATAGRAM extension disables reception.
    /// [`Self::standard`] instead supplies Rama's ordinary endpoint configuration.
    #[must_use]
    pub fn protocol_defaults() -> Self {
        let defaults = TransportParameters::default();
        Self {
            max_idle_timeout: Duration::from_millis(defaults.max_idle_timeout.into_inner()),
            initial_max_data: defaults.initial_max_data.into_inner(),
            initial_max_stream_data_bidi_local: defaults
                .initial_max_stream_data_bidi_local
                .into_inner(),
            initial_max_stream_data_bidi_remote: defaults
                .initial_max_stream_data_bidi_remote
                .into_inner(),
            initial_max_stream_data_uni: defaults.initial_max_stream_data_uni.into_inner(),
            initial_max_streams_bidi: defaults.initial_max_streams_bidi.into_inner(),
            initial_max_streams_uni: defaults.initial_max_streams_uni.into_inner(),
            max_ack_delay: Duration::from_millis(defaults.max_ack_delay.into_inner()),
            active_connection_id_limit: Some(defaults.active_connection_id_limit.into_inner()),
            max_udp_payload_size: defaults.max_udp_payload_size.into_inner(),
            datagram_receive_buffer_size: None,
        }
    }

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
        // The RFC 9000 §18.2 floor. Each engine clamps profiles above its own
        // storage ceiling when applying this protocol-level descriptor.
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
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

#[cfg(feature = "std")]
impl Extension for QuicProfile {}

/// The integer value of a sent transport parameter, which must fill its value exactly.
fn sent_integer(id: TransportParameterId, value: &[u8]) -> Result<u64, ProfileError> {
    let mut reader = value;
    let integer = reader
        .get_var()
        .map_err(|_error| ProfileError::Limit("transport parameter integer"))?;
    if !reader.is_empty() {
        return Err(ProfileError::ValueTooLong(id));
    }
    Ok(integer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coding::Codec as _;

    #[test]
    fn sent_limit_aliases_preserve_values_and_integer_validation() {
        // Compare complete limits after encoding real TLV integer bodies, so a
        // missing dispatch arm cannot silently replace an advertised value.
        for (id, value) in [
            (TransportParameterId::MaxIdleTimeout, 42),
            (TransportParameterId::MaxUdpPayloadSize, 1300),
            (TransportParameterId::InitialMaxData, 42),
            (TransportParameterId::InitialMaxStreamDataBidiLocal, 42),
            (TransportParameterId::InitialMaxStreamDataBidiRemote, 42),
            (TransportParameterId::InitialMaxStreamDataUni, 42),
            (TransportParameterId::InitialMaxStreamsBidi, 42),
            (TransportParameterId::InitialMaxStreamsUni, 42),
            (TransportParameterId::MaxAckDelay, 42),
            (TransportParameterId::ActiveConnectionIdLimit, 42),
            (TransportParameterId::MaxDatagramFrameSize, 42),
        ] {
            let alias = TransportParameterId::Unknown(u64::from(id));
            let mut body = Vec::new();
            VarInt::from_u32(value).encode(&mut body);
            let sent = |id, value| RawParameter { id, value };
            let known = TransportLimits::try_from_sent(&[sent(id, body.clone())]).unwrap();
            assert_ne!(known, TransportLimits::protocol_defaults(), "{id}");
            assert_eq!(
                TransportLimits::try_from_sent(&[sent(alias, body.clone())]).unwrap(),
                known,
                "{id}",
            );

            for malformed in [Vec::new(), alloc::vec![0x40], alloc::vec![0, 0]] {
                TransportLimits::try_from_sent(&[sent(id, malformed.clone())]).unwrap_err();
                TransportLimits::try_from_sent(&[sent(alias, malformed)]).unwrap_err();
            }
        }
    }

    #[test]
    fn parameter_value_classification_is_protocol_owned() {
        for id in [
            TransportParameterId::OriginalDestinationConnectionId,
            TransportParameterId::StatelessResetToken,
            TransportParameterId::PreferredAddress,
            TransportParameterId::InitialSourceConnectionId,
            TransportParameterId::RetrySourceConnectionId,
            TransportParameterId::GoogleHandshakeMessage,
            TransportParameterId::GoogleLegacyCustomParameters,
            TransportParameterId::DebuggingSni,
        ] {
            assert!(id.has_connection_specific_value(), "{id}");
            assert!(!id.is_observation_only(), "{id}");
        }

        for id in [
            TransportParameterId::InitialRoundTripTime,
            TransportParameterId::Discard,
        ] {
            assert!(id.is_observation_only(), "{id}");
            assert!(!id.has_connection_specific_value(), "{id}");
        }

        assert!(!TransportParameterId::GoogleConnectionOptions.has_connection_specific_value());
        assert!(!TransportParameterId::GoogleConnectionOptions.is_observation_only());
    }

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
                id: TransportParameterId::MaxIdleTimeout,
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

    #[test]
    fn profile_parameter_ids_order_stays_within_wire_range() {
        let invalid = TransportParameterId::from(VarInt::MAX.into_inner() + 1);
        assert_eq!(
            TransportParameterProfile::standard()
                .try_with_order(ParameterOrder::fixed(vec![invalid]))
                .unwrap_err(),
            ProfileError::ParameterIdOutOfRange(invalid),
        );
        let invalid_profile = TransportParameterProfile {
            order: ParameterOrder::fixed(vec![invalid]),
            ..TransportParameterProfile::standard()
        };
        serde_json::from_str::<TransportParameterProfile>(
            &serde_json::to_string(&invalid_profile).unwrap(),
        )
        .unwrap_err();
        TransportParameterProfile::standard()
            .try_with_order(ParameterOrder::Fixed(vec![
                TransportParameterId::from(VarInt::MAX.into_inner()).into(),
                ParameterOrderEntry::Grease,
            ]))
            .unwrap();
    }

    #[test]
    fn order_and_extra_validation_use_wire_identity_for_unknown_aliases() {
        let id = TransportParameterId::MaxAckDelay;
        let alias = TransportParameterId::Unknown(u64::from(id));
        for order in [
            ParameterOrder::fixed([id, alias]),
            ParameterOrder::fixed_with_explicit_defaults([id, alias]),
        ] {
            assert!(matches!(
                TransportParameterProfile::standard().try_with_order(order),
                Err(ProfileError::DuplicateParameter(_))
            ));
        }
        let id = TransportParameterId::GoogleConnectionOptions;
        let alias = TransportParameterId::Unknown(u64::from(id));
        assert!(matches!(
            TransportParameterProfile::standard().try_with_extra(vec![
                OpaqueParameter { id, value: vec![] },
                OpaqueParameter {
                    id: alias,
                    value: vec![]
                }
            ]),
            Err(ProfileError::DuplicateParameter(_))
        ));
        // Known bindings cannot evade typed native ownership through Unknown.
        assert!(matches!(
            TransportParameterProfile::standard().try_with_extra(vec![OpaqueParameter {
                id: TransportParameterId::Unknown(u64::from(
                    TransportParameterId::InitialSourceConnectionId
                )),
                value: vec![1]
            }]),
            Err(ProfileError::KnownParameter(_))
        ));
    }

    #[test]
    fn explicit_default_order_rejects_invalid_and_duplicate_identifiers() {
        for ids in [
            vec![TransportParameterId::from(VarInt::MAX.into_inner() + 1).into()],
            vec![
                TransportParameterId::MaxAckDelay.into(),
                TransportParameterId::MaxAckDelay.into(),
            ],
            vec![ParameterOrderEntry::Grease, ParameterOrderEntry::Grease],
        ] {
            TransportParameterProfile::standard()
                .try_with_order(ParameterOrder::FixedWithExplicitDefaults(ids.clone()))
                .unwrap_err();
            let invalid = TransportParameterProfile {
                order: ParameterOrder::FixedWithExplicitDefaults(ids),
                ..TransportParameterProfile::standard()
            };
            serde_json::from_str::<TransportParameterProfile>(
                &serde_json::to_string(&invalid).unwrap(),
            )
            .unwrap_err();
        }
        let profile = TransportParameterProfile::standard()
            .try_with_order(ParameterOrder::FixedWithExplicitDefaults(vec![
                TransportParameterId::MaxAckDelay.into(),
                ParameterOrderEntry::Grease,
            ]))
            .unwrap();
        let roundtrip: TransportParameterProfile =
            serde_json::from_str(&serde_json::to_string(&profile).unwrap()).unwrap();
        assert_eq!(profile, roundtrip);
    }

    #[test]
    fn profile_parameter_ids_extra_stays_within_wire_range() {
        for id in [
            TransportParameterId::from(VarInt::MAX.into_inner() + 1),
            TransportParameterId::from(u64::MAX),
        ] {
            let extra = vec![OpaqueParameter {
                id,
                value: Vec::new(),
            }];
            assert_eq!(
                TransportParameterProfile::standard()
                    .try_with_extra(extra.clone())
                    .unwrap_err(),
                ProfileError::ParameterIdOutOfRange(id),
            );
            let invalid_profile = TransportParameterProfile {
                extra,
                ..TransportParameterProfile::standard()
            };
            serde_json::from_str::<TransportParameterProfile>(
                &serde_json::to_string(&invalid_profile).unwrap(),
            )
            .unwrap_err();
        }
        TransportParameterProfile::standard()
            .try_with_extra(vec![OpaqueParameter {
                id: TransportParameterId::from(VarInt::MAX.into_inner()),
                value: Vec::new(),
            }])
            .unwrap();
    }

    #[test]
    fn profile_parameter_ids_grease_stays_within_wire_range() {
        // The first reserved (31*N+27) identifier above the wire limit.
        let last_reserved =
            TransportParameterId::from((VarInt::MAX.into_inner() - 27) / 31 * 31 + 27);
        let id = TransportParameterId::from(u64::from(last_reserved) + 31);
        assert!(id.is_reserved());
        let grease = GreaseParameter::Fixed {
            id,
            value: Vec::new(),
        };
        assert_eq!(
            TransportParameterProfile::standard()
                .try_with_grease(grease.clone())
                .unwrap_err(),
            ProfileError::ParameterIdOutOfRange(id),
        );
        let invalid_profile = TransportParameterProfile {
            grease,
            ..TransportParameterProfile::standard()
        };
        serde_json::from_str::<TransportParameterProfile>(
            &serde_json::to_string(&invalid_profile).unwrap(),
        )
        .unwrap_err();
        assert!(u64::from(last_reserved) <= VarInt::MAX.into_inner());
        TransportParameterProfile::standard()
            .try_with_grease(GreaseParameter::Fixed {
                id: last_reserved,
                value: Vec::new(),
            })
            .unwrap();
    }
}
