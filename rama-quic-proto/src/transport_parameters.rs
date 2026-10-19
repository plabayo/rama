//! QUIC connection transport parameters
//!
//! The `TransportParameters` type is used to represent the transport parameters
//! negotiated by peers while establishing a QUIC connection. This process
//! happens as part of the establishment of the TLS session. As such, the types
//! contained in this modules should generally only be referred to by custom
//! implementations of the `crypto::Session` trait.

use alloc::{vec, vec::Vec};
use core::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

#[cfg(feature = "fuzz-utils")]
use arbitrary::Arbitrary;
use rama_core::bytes::{Buf, BufMut};
use rand::{Rng, RngExt, seq::SliceRandom as _};
use serde::{Deserialize, Serialize};

use crate::{
    MAX_CID_SIZE, MAX_STREAM_COUNT, RESET_TOKEN_SIZE, ResetToken, Side, TransportError, VarInt,
    VarIntBoundsExceeded,
    coding::{BufExt, BufMutExt, UnexpectedEnd, bounded_len},
    profile::{ParameterOrder, ParameterOrderEntry},
    shared::ConnectionId,
    version::VersionInformation,
};

// Apply a given macro to a list of all the transport parameters having integer types, along with
// their codes and default values. Using this helps us avoid error-prone duplication of the
// contained information across decoding, encoding, and the `Default` impl. Whenever we want to do
// something with transport parameters, we'll handle the bulk of cases by writing a macro that
// takes a list of arguments in this form, then passing it to this macro.
macro_rules! apply_params {
    ($macro:ident) => {
        $macro! {
            // #[doc] name (id) = default,
            /// Milliseconds, disabled if zero
            max_idle_timeout(MaxIdleTimeout) = 0,
            /// Limits the size of UDP payloads that the endpoint is willing to receive
            max_udp_payload_size(MaxUdpPayloadSize) = 65527,

            /// Initial value for the maximum amount of data that can be sent on the connection
            initial_max_data(InitialMaxData) = 0,
            /// Initial flow control limit for locally-initiated bidirectional streams
            initial_max_stream_data_bidi_local(InitialMaxStreamDataBidiLocal) = 0,
            /// Initial flow control limit for peer-initiated bidirectional streams
            initial_max_stream_data_bidi_remote(InitialMaxStreamDataBidiRemote) = 0,
            /// Initial flow control limit for unidirectional streams
            initial_max_stream_data_uni(InitialMaxStreamDataUni) = 0,

            /// Initial maximum number of bidirectional streams the peer may initiate
            initial_max_streams_bidi(InitialMaxStreamsBidi) = 0,
            /// Initial maximum number of unidirectional streams the peer may initiate
            initial_max_streams_uni(InitialMaxStreamsUni) = 0,

            /// Exponent used to decode the ACK Delay field in the ACK frame
            ack_delay_exponent(AckDelayExponent) = 3,
            /// Maximum amount of time in milliseconds by which the endpoint will delay sending
            /// acknowledgments
            max_ack_delay(MaxAckDelay) = 25,
            /// Maximum number of connection IDs from the peer that an endpoint is willing to store
            active_connection_id_limit(ActiveConnectionIdLimit) = 2,
        }
    };
}

macro_rules! make_struct {
    {$($(#[$doc:meta])* $name:ident ($id:ident) = $default:expr,)*} => {
        /// Transport parameters used to negotiate connection-level preferences between peers
        #[derive(Debug, Clone, Eq, PartialEq)]
        pub struct TransportParameters {
            $($(#[$doc])* pub $name : VarInt,)*

            /// Does the endpoint support active connection migration
            pub disable_active_migration: bool,
            /// Maximum size for datagram frames
            pub max_datagram_frame_size: Option<VarInt>,
            /// The value that the endpoint included in the Source Connection ID field of the first
            /// Initial packet it sends for the connection
            pub initial_src_cid: Option<ConnectionId>,
            /// The endpoint is willing to receive QUIC packets containing any value for the fixed
            /// bit
            pub grease_quic_bit: bool,

            /// Minimum amount of time in microseconds by which the endpoint is able to delay
            /// sending acknowledgments
            ///
            /// If a value is provided, it implies that the endpoint supports QUIC Acknowledgement
            /// Frequency
            pub min_ack_delay: Option<VarInt>,
            /// The version the endpoint chose and the versions it can work with (RFC 9368 §3)
            pub version_information: Option<VersionInformation>,

            // Server-only
            /// The value of the Destination Connection ID field from the first Initial packet sent
            /// by the client
            pub original_dst_cid: Option<ConnectionId>,
            /// The value that the server included in the Source Connection ID field of a Retry
            /// packet
            pub retry_src_cid: Option<ConnectionId>,
            /// Token used by the client to verify a stateless reset from the server
            pub stateless_reset_token: Option<ResetToken>,
            /// The server's preferred address for communication after handshake completion
            pub preferred_address: Option<PreferredAddress>,
            /// The randomly generated reserved transport parameter to sustain future extensibility
            /// of transport parameter extensions.
            /// When present, it is included during serialization but ignored during deserialization.
            pub grease_transport_parameter: Option<ReservedTransportParameter>,

            /// Parameters this crate does not interpret, written as given (a profile's extras).
            pub extra: Vec<(u64, Vec<u8>)>,

            /// The order in which transport parameters are serialized, one slot per parameter.
            ///
            /// Set only for outgoing `TransportParameters`; `None` for received ones.
            pub write_plan: Option<Vec<WriteSlot>>,
        }

        // We deliberately don't implement the `Default` trait, since that would be public, and
        // downstream crates should never construct `TransportParameters` except by decoding those
        // supplied by a peer.
        impl TransportParameters {
            /// Standard defaults, used if the peer does not supply a given parameter.
            #[expect(
                clippy::should_implement_trait,
                reason = "not a public `Default`: peers construct these only by decoding a peer's"
            )]
            pub fn default() -> Self {
                Self {
                    $($name: VarInt::from_u32($default),)*

                    disable_active_migration: false,
                    max_datagram_frame_size: None,
                    initial_src_cid: None,
                    grease_quic_bit: false,
                    min_ack_delay: None,
                    version_information: None,

                    original_dst_cid: None,
                    retry_src_cid: None,
                    stateless_reset_token: None,
                    preferred_address: None,
                    grease_transport_parameter: None,
                    extra: Vec::new(),
                    write_plan: None,
                }
            }
        }
    }
}

apply_params!(make_struct);

impl TransportParameters {
    /// The order to write in: the profile's, with what it does not name after it.
    pub fn plan(&self, order: &ParameterOrder, rng: &mut impl Rng) -> Vec<WriteSlot> {
        let mut slots: Vec<WriteSlot> = CANONICAL_WRITE_ORDER.to_vec();
        slots.extend((0..self.extra.len()).map(WriteSlot::Extra));
        let (ids, explicit_defaults) = match order {
            ParameterOrder::Fixed(ids) => (ids, false),
            ParameterOrder::FixedWithExplicitDefaults(ids) => (ids, true),
            // `Shuffled`, and any future ordering, use a fresh shuffle.
            _ => {
                slots.shuffle(rng);
                return slots;
            }
        };
        let mut planned: Vec<WriteSlot> = Vec::with_capacity(slots.len());
        for entry in ids {
            let slot = match entry {
                ParameterOrderEntry::Grease => Some(WriteSlot::Grease),
                ParameterOrderEntry::Parameter(id) => {
                    let id = TransportParameterId::from(u64::from(*id));
                    if id.is_implemented() {
                        Some(if explicit_defaults {
                            WriteSlot::KnownExplicit(id)
                        } else {
                            WriteSlot::Known(id)
                        })
                    } else {
                        self.extra
                            .iter()
                            .position(|(extra, _)| *extra == u64::from(id))
                            .map(WriteSlot::Extra)
                    }
                }
            };
            if let Some(slot) = slot
                && !planned.contains(&slot)
            {
                planned.push(slot);
            }
        }
        let rest: Vec<WriteSlot> = slots
            .into_iter()
            // Explicit and ordinary slots refer to the same parameter. Do not
            // append a second copy merely because its emission mode differs.
            .filter(|slot| !planned.iter().any(|planned| planned.same_parameter(*slot)))
            .collect();
        planned.extend(rest);
        planned
    }

    /// Check that these parameters are legal when resuming from
    /// certain cached parameters
    pub fn validate_resumption_from(&self, cached: &Self) -> Result<(), TransportError> {
        if cached.active_connection_id_limit > self.active_connection_id_limit
            || cached.initial_max_data > self.initial_max_data
            || cached.initial_max_stream_data_bidi_local > self.initial_max_stream_data_bidi_local
            || cached.initial_max_stream_data_bidi_remote > self.initial_max_stream_data_bidi_remote
            || cached.initial_max_stream_data_uni > self.initial_max_stream_data_uni
            || cached.initial_max_streams_bidi > self.initial_max_streams_bidi
            || cached.initial_max_streams_uni > self.initial_max_streams_uni
            || cached.max_datagram_frame_size > self.max_datagram_frame_size
            || cached.grease_quic_bit && !self.grease_quic_bit
        {
            return Err(TransportError::PROTOCOL_VIOLATION(
                "0-RTT accepted with incompatible transport parameters",
            ));
        }
        Ok(())
    }
}

#[cfg(feature = "fuzz-utils")]
impl<'arbitrary> Arbitrary<'arbitrary> for TransportParameters {
    fn arbitrary(u: &mut arbitrary::Unstructured<'arbitrary>) -> arbitrary::Result<Self> {
        Ok(Self {
            initial_max_streams_bidi: u.arbitrary()?,
            initial_max_streams_uni: u.arbitrary()?,
            ack_delay_exponent: u.arbitrary()?,
            max_udp_payload_size: u.arbitrary()?,
            ..Self::default()
        })
    }
}

/// A server's preferred address
///
/// This is communicated as a transport parameter during TLS session establishment.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct PreferredAddress {
    pub address_v4: Option<SocketAddrV4>,
    pub address_v6: Option<SocketAddrV6>,
    pub connection_id: ConnectionId,
    pub stateless_reset_token: ResetToken,
}

impl PreferredAddress {
    fn wire_size(&self) -> u16 {
        4 + 2 + 16 + 2 + 1 + self.connection_id.len() as u16 + 16
    }

    fn write<W: BufMut>(&self, w: &mut W) {
        w.write(self.address_v4.map_or(Ipv4Addr::UNSPECIFIED, |x| *x.ip()));
        w.write::<u16>(self.address_v4.map_or(0, |x| x.port()));
        w.write(self.address_v6.map_or(Ipv6Addr::UNSPECIFIED, |x| *x.ip()));
        w.write::<u16>(self.address_v6.map_or(0, |x| x.port()));
        w.write::<u8>(self.connection_id.len() as u8);
        w.put_slice(&self.connection_id);
        w.put_slice(&self.stateless_reset_token);
    }

    fn read<R: Buf>(r: &mut R) -> Result<Self, Error> {
        let ip_v4 = r.get::<Ipv4Addr>()?;
        let port_v4 = r.get::<u16>()?;
        let ip_v6 = r.get::<Ipv6Addr>()?;
        let port_v6 = r.get::<u16>()?;
        let cid_len = r.get::<u8>()?;
        if r.remaining() < cid_len as usize || cid_len > MAX_CID_SIZE as u8 {
            return Err(Error::Malformed);
        }
        let mut stage = [0; MAX_CID_SIZE];
        r.copy_to_slice(&mut stage[0..cid_len as usize]);
        let cid = ConnectionId::new(&stage[0..cid_len as usize]);
        if r.remaining() < 16 {
            return Err(Error::Malformed);
        }
        let mut token = [0; RESET_TOKEN_SIZE];
        r.copy_to_slice(&mut token);
        let address_v4 = if ip_v4.is_unspecified() && port_v4 == 0 {
            None
        } else {
            Some(SocketAddrV4::new(ip_v4, port_v4))
        };
        let address_v6 = if ip_v6.is_unspecified() && port_v6 == 0 {
            None
        } else {
            Some(SocketAddrV6::new(ip_v6, port_v6, 0, 0))
        };
        if address_v4.is_none() && address_v6.is_none() {
            return Err(Error::IllegalValue);
        }
        Ok(Self {
            address_v4,
            address_v6,
            connection_id: cid,
            stateless_reset_token: token.into(),
        })
    }
}

/// Errors encountered while decoding `TransportParameters`
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error {
    /// Parameters that are semantically invalid
    IllegalValue,
    /// Catch-all error for problems while decoding transport parameters
    Malformed,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::IllegalValue => f.write_str("parameter had illegal value"),
            Self::Malformed => f.write_str("parameters were malformed"),
        }
    }
}

impl core::error::Error for Error {}

impl From<Error> for TransportError {
    fn from(e: Error) -> Self {
        match e {
            Error::IllegalValue => Self::TRANSPORT_PARAMETER_ERROR("illegal value"),
            Error::Malformed => Self::TRANSPORT_PARAMETER_ERROR("malformed"),
        }
    }
}

impl From<UnexpectedEnd> for Error {
    fn from(_: UnexpectedEnd) -> Self {
        Self::Malformed
    }
}

impl TransportParameters {
    /// Encode `TransportParameters` into buffer
    pub fn write<W: BufMut>(&self, w: &mut W) {
        let canonical: Vec<WriteSlot> = CANONICAL_WRITE_ORDER
            .iter()
            .copied()
            .chain((0..self.extra.len()).map(WriteSlot::Extra))
            .collect();
        for slot in self.write_plan.as_ref().unwrap_or(&canonical) {
            let (id, explicit) = match slot {
                WriteSlot::Grease => {
                    if let Some(param) = &self.grease_transport_parameter {
                        param.write(w);
                    }
                    continue;
                }
                WriteSlot::Extra(index) => {
                    if let Some((id, value)) = self.extra.get(*index) {
                        w.write_var(*id);
                        w.write_var(value.len() as u64);
                        w.put_slice(value);
                    }
                    continue;
                }
                WriteSlot::Known(id) => (TransportParameterId::from(u64::from(*id)), false),
                WriteSlot::KnownExplicit(id) => (TransportParameterId::from(u64::from(*id)), true),
            };
            match id {
                TransportParameterId::StatelessResetToken => {
                    if let Some(ref x) = self.stateless_reset_token {
                        w.write_var(u64::from(id));
                        w.write_var(16);
                        w.put_slice(x);
                    }
                }
                TransportParameterId::DisableActiveMigration => {
                    if self.disable_active_migration {
                        w.write_var(u64::from(id));
                        w.write_var(0);
                    }
                }
                TransportParameterId::MaxDatagramFrameSize => {
                    if let Some(x) = self.max_datagram_frame_size {
                        w.write_var(u64::from(id));
                        w.write_var(x.size() as u64);
                        w.write(x);
                    }
                }
                TransportParameterId::PreferredAddress => {
                    if let Some(ref x) = self.preferred_address {
                        w.write_var(u64::from(id));
                        w.write_var(x.wire_size() as u64);
                        x.write(w);
                    }
                }
                TransportParameterId::OriginalDestinationConnectionId => {
                    if let Some(ref cid) = self.original_dst_cid {
                        w.write_var(u64::from(id));
                        w.write_var(cid.len() as u64);
                        w.put_slice(cid);
                    }
                }
                TransportParameterId::InitialSourceConnectionId => {
                    if let Some(ref cid) = self.initial_src_cid {
                        w.write_var(u64::from(id));
                        w.write_var(cid.len() as u64);
                        w.put_slice(cid);
                    }
                }
                TransportParameterId::RetrySourceConnectionId => {
                    if let Some(ref cid) = self.retry_src_cid {
                        w.write_var(u64::from(id));
                        w.write_var(cid.len() as u64);
                        w.put_slice(cid);
                    }
                }
                TransportParameterId::GreaseQuicBit => {
                    if self.grease_quic_bit {
                        w.write_var(u64::from(id));
                        w.write_var(0);
                    }
                }
                TransportParameterId::MinAckDelayDraft07 => {
                    if let Some(x) = self.min_ack_delay {
                        w.write_var(u64::from(id));
                        w.write_var(x.size() as u64);
                        w.write(x);
                    }
                }
                TransportParameterId::VersionInformation => {
                    if let Some(ref info) = self.version_information {
                        w.write_var(u64::from(id));
                        w.write_var(info.wire_size() as u64);
                        info.write(w);
                    }
                }
                id => {
                    macro_rules! write_params {
                        {$($(#[$doc:meta])* $name:ident ($id:ident) = $default:expr,)*} => {
                            match id {
                                $(TransportParameterId::$id if explicit || self.$name != $default => {
                                    w.write_var(u64::from(id));
                                    w.write(VarInt::try_from(self.$name.size()).unwrap());
                                    w.write(self.$name);
                                })*,
                                _ => {
                                    // Elided defaults and IDs without a native field emit nothing.
                                    // Opaque values use Extra slots instead.
                                }
                            }
                        }
                    }
                    apply_params!(write_params);
                }
            }
        }
    }

    /// Decode the peer's transport parameters. `side` is the local endpoint's role.
    pub fn read<R: Buf>(side: Side, r: &mut R) -> Result<Self, Error> {
        // Initialize to protocol-specified defaults
        let mut params = Self::default();

        // State to check for duplicate transport parameters.
        macro_rules! param_state {
            {$($(#[$doc:meta])* $name:ident ($id:ident) = $default:expr,)*} => {{
                struct ParamState {
                    $($name: bool,)*
                }

                ParamState {
                    $($name: false,)*
                }
            }}
        }
        let mut got = apply_params!(param_state);

        while r.has_remaining() {
            let id = r.get_var()?;
            let len =
                bounded_len(r.get_var()?, r.remaining()).map_err(|_error| Error::Malformed)?;
            let id = TransportParameterId::from(id);

            match id {
                TransportParameterId::OriginalDestinationConnectionId => {
                    decode_cid(len, &mut params.original_dst_cid, r)?
                }
                TransportParameterId::StatelessResetToken => {
                    if len != 16 || params.stateless_reset_token.is_some() {
                        return Err(Error::Malformed);
                    }
                    let mut tok = [0; RESET_TOKEN_SIZE];
                    r.copy_to_slice(&mut tok);
                    params.stateless_reset_token = Some(tok.into());
                }
                TransportParameterId::DisableActiveMigration => {
                    if len != 0 || params.disable_active_migration {
                        return Err(Error::Malformed);
                    }
                    params.disable_active_migration = true;
                }
                TransportParameterId::PreferredAddress => {
                    if params.preferred_address.is_some() {
                        return Err(Error::Malformed);
                    }
                    let mut value = r.take(len);
                    params.preferred_address = Some(PreferredAddress::read(&mut value)?);
                    if value.has_remaining() {
                        return Err(Error::Malformed);
                    }
                }
                TransportParameterId::InitialSourceConnectionId => {
                    decode_cid(len, &mut params.initial_src_cid, r)?
                }
                TransportParameterId::RetrySourceConnectionId => {
                    decode_cid(len, &mut params.retry_src_cid, r)?
                }
                TransportParameterId::MaxDatagramFrameSize => {
                    if len > 8 || params.max_datagram_frame_size.is_some() {
                        return Err(Error::Malformed);
                    }
                    params.max_datagram_frame_size = Some(read_integer_parameter(len, r)?);
                }
                TransportParameterId::GreaseQuicBit => match len {
                    0 if !params.grease_quic_bit => params.grease_quic_bit = true,
                    _ => return Err(Error::Malformed),
                },
                TransportParameterId::MinAckDelayDraft07 => {
                    if params.min_ack_delay.is_some() {
                        return Err(Error::Malformed);
                    }
                    params.min_ack_delay = Some(read_integer_parameter(len, r)?);
                }
                TransportParameterId::VersionInformation => {
                    if params.version_information.is_some() {
                        return Err(Error::Malformed);
                    }
                    params.version_information = Some(
                        VersionInformation::read(side.is_server(), len, r)
                            .map_err(|_error| Error::Malformed)?,
                    );
                }
                _ => {
                    macro_rules! parse {
                        {$($(#[$doc:meta])* $name:ident ($id:ident) = $default:expr,)*} => {
                            match id {
                                $(TransportParameterId::$id => {
                                    let value = read_integer_parameter(len, r)?;
                                    if got.$name { return Err(Error::Malformed); }
                                    params.$name = value.into();
                                    got.$name = true;
                                })*
                                _ => r.advance(len),
                            }
                        }
                    }
                    apply_params!(parse);
                }
            }
        }

        // Semantic validation

        // https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2-4.26.1
        if params.ack_delay_exponent > 20
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2-4.28.1
            || params.max_ack_delay >= 1 << 14
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2-6.2.1
            || params.active_connection_id_limit < 2
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2-4.10.1
            || params.max_udp_payload_size < 1200
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-4.6-2
            || params.initial_max_streams_bidi > MAX_STREAM_COUNT
            || params.initial_max_streams_uni > MAX_STREAM_COUNT
            // https://www.ietf.org/archive/id/draft-ietf-quic-ack-frequency-08.html#section-3-4
            || params.min_ack_delay.is_some_and(|min_ack_delay| {
                // min_ack_delay uses microseconds, whereas max_ack_delay uses milliseconds
                min_ack_delay > params.max_ack_delay.into_inner().saturating_mul(1_000)
            })
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2-8
            || (side.is_server()
                && (params.original_dst_cid.is_some()
                    || params.preferred_address.is_some()
                    || params.retry_src_cid.is_some()
                    || params.stateless_reset_token.is_some()))
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2-4.38.1
            || params
                .preferred_address.is_some_and(|x| x.connection_id.is_empty())
            || (params.preferred_address.is_some()
                && params.initial_src_cid.is_some_and(|cid| cid.is_empty()))
        {
            return Err(Error::IllegalValue);
        }

        Ok(params)
    }
}

/// A reserved transport parameter.
///
/// It has an identifier of the form 31 * N + 27 for the integer value of N.
/// Such identifiers are reserved to exercise the requirement that unknown transport parameters be ignored.
/// The reserved transport parameter has no semantics and can carry arbitrary values.
/// It may be included in transport parameters sent to the peer, and should be ignored when received.
///
/// See spec: <https://www.rfc-editor.org/rfc/rfc9000.html#section-18.1>
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ReservedTransportParameter {
    /// The reserved identifier of the transport parameter
    id: VarInt,

    /// The parameter payload
    payload: Vec<u8>,
}

/// One entry of the order transport parameters are written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteSlot {
    /// A known parameter with ordinary default elision.
    Known(TransportParameterId),
    /// A known parameter whose integer value is emitted even at its protocol default.
    KnownExplicit(TransportParameterId),
    Grease,
    /// An index into `TransportParameters::extra`.
    Extra(usize),
}

impl WriteSlot {
    fn same_parameter(self, other: Self) -> bool {
        match (self, other) {
            (
                Self::Known(left) | Self::KnownExplicit(left),
                Self::Known(right) | Self::KnownExplicit(right),
            ) => left == right,
            _ => self == other,
        }
    }
}

impl ReservedTransportParameter {
    /// Generates a transport parameter with a random payload and a reserved ID. The payload is
    /// `value_len` bytes when given, else a random length up to a small fixed maximum.
    pub fn random(rng: &mut impl Rng, value_len: Option<usize>) -> Self {
        let id = Self::generate_reserved_id(rng);
        let payload_len = value_len.unwrap_or_else(|| rng.random_range(0..Self::MAX_PAYLOAD_LEN));
        let mut payload = vec![0u8; payload_len];
        rng.fill_bytes(&mut payload);
        Self { id, payload }
    }

    /// A reserved parameter with this identifier and value on every connection.
    pub fn fixed(id: u64, value: &[u8]) -> Result<Self, VarIntBoundsExceeded> {
        Ok(Self {
            id: VarInt::from_u64(id)?,
            payload: value.to_vec(),
        })
    }

    fn write(&self, w: &mut impl BufMut) {
        w.write_var(self.id.into_inner());
        w.write_var(self.payload.len() as u64);
        w.put_slice(&self.payload);
    }

    /// Generates a random reserved identifier of the form `31 * N + 27`, as required by RFC 9000.
    /// Reserved transport parameter identifiers are used to test compliance with the requirement
    /// that unknown transport parameters must be ignored by peers.
    /// See: <https://www.rfc-editor.org/rfc/rfc9000.html#section-18.1> and <https://www.rfc-editor.org/rfc/rfc9000.html#section-22.3>
    #[expect(
        clippy::expect_used,
        reason = "`id = 31 * n + 27` with `n` drawn below 2^57 stays below 2^62"
    )]
    fn generate_reserved_id(rng: &mut impl Rng) -> VarInt {
        let id = {
            let rand = rng.random_range(0u64..(1 << 62) - 27);
            let n = rand / 31;
            31 * n + 27
        };
        debug_assert!(
            id % 31 == 27,
            "generated id does not have the form of 31 * N + 27"
        );
        VarInt::from_u64(id).expect(
            "generated id does fit into range of allowed transport parameter IDs: [0; 2^62)",
        )
    }

    /// The maximum length of the payload to include as the parameter payload.
    /// This value is not a specification-imposed limit but is chosen to match
    /// the limit commonly used by QUIC implementations.
    const MAX_PAYLOAD_LEN: usize = 16;
}

rama_utils::macros::enums::enum_builder! {
    /// A QUIC transport parameter identifier. Unknown values are retained;
    /// encoding a wire identifier also requires the QUIC variable-integer range.
    @U64
    pub enum TransportParameterId {
        /// `original_destination_connection_id` (RFC 9000 section 18.2).
        OriginalDestinationConnectionId => 0x00,
        /// `max_idle_timeout` (RFC 9000 section 18.2).
        MaxIdleTimeout => 0x01,
        /// `stateless_reset_token` (RFC 9000 section 18.2).
        StatelessResetToken => 0x02,
        /// `max_udp_payload_size` (RFC 9000 section 18.2).
        MaxUdpPayloadSize => 0x03,
        /// `initial_max_data` (RFC 9000 section 18.2).
        InitialMaxData => 0x04,
        /// `initial_max_stream_data_bidi_local` (RFC 9000 section 18.2).
        InitialMaxStreamDataBidiLocal => 0x05,
        /// `initial_max_stream_data_bidi_remote` (RFC 9000 section 18.2).
        InitialMaxStreamDataBidiRemote => 0x06,
        /// `initial_max_stream_data_uni` (RFC 9000 section 18.2).
        InitialMaxStreamDataUni => 0x07,
        /// `initial_max_streams_bidi` (RFC 9000 section 18.2).
        InitialMaxStreamsBidi => 0x08,
        /// `initial_max_streams_uni` (RFC 9000 section 18.2).
        InitialMaxStreamsUni => 0x09,
        /// `ack_delay_exponent` (RFC 9000 section 18.2).
        AckDelayExponent => 0x0a,
        /// `max_ack_delay` (RFC 9000 section 18.2).
        MaxAckDelay => 0x0b,
        /// `disable_active_migration` (RFC 9000 section 18.2).
        DisableActiveMigration => 0x0c,
        /// `preferred_address` (RFC 9000 section 18.2).
        PreferredAddress => 0x0d,
        /// `active_connection_id_limit` (RFC 9000 section 18.2).
        ActiveConnectionIdLimit => 0x0e,
        /// `initial_source_connection_id` (RFC 9000 section 18.2).
        InitialSourceConnectionId => 0x0f,
        /// `retry_source_connection_id` (RFC 9000 section 18.2).
        RetrySourceConnectionId => 0x10,
        /// RFC 9368.
        VersionInformation => 0x11,
        /// RFC 9221.
        MaxDatagramFrameSize => 0x20,
        /// QUICHE's discard parameter for quantum-readiness tests.
        Discard => 0x173e,
        /// SCONE protocol support.
        SconeSupported => 0x219e,
        /// QUICHE's opaque handshake message.
        GoogleHandshakeMessage => 0x26ab,
        /// QUICHE's cached initial round-trip-time measurement.
        InitialRoundTripTime => 0x3127,
        /// QUICHE's connection-option tags.
        GoogleConnectionOptions => 0x3128,
        /// QUICHE's debugging server name.
        DebuggingSni => 0x219b_bcd0,
        /// Legacy QUICHE custom parameters encoded as a Google QUIC_CRYPTO CHLO.
        GoogleLegacyCustomParameters => 0x4751,
        /// RFC 9287.
        GreaseQuicBit => 0x2ab2,
        /// draft-ietf-quic-ack-frequency-07.
        MinAckDelayDraft07 => 0xff04_de1b,
    }
}

impl TransportParameterId {
    /// Whether this identifier is one reserved for greasing (RFC 9000 §18.1): `31 * N + 27`.
    #[must_use]
    pub fn is_reserved(self) -> bool {
        u64::from(self) % 31 == 27
    }

    /// Whether the value identifies this connection or contains connection-specific material.
    /// Capture may retain its length, but it must not copy the value into a reusable profile.
    #[must_use]
    pub fn has_connection_specific_value(self) -> bool {
        matches!(
            Self::from(u64::from(self)),
            Self::OriginalDestinationConnectionId
                | Self::StatelessResetToken
                | Self::PreferredAddress
                | Self::InitialSourceConnectionId
                | Self::RetrySourceConnectionId
                | Self::GoogleHandshakeMessage
                | Self::GoogleLegacyCustomParameters
                | Self::DebuggingSni
        )
    }

    /// Whether the value describes a measured path or padding rather than reusable configuration.
    #[must_use]
    pub fn is_observation_only(self) -> bool {
        matches!(
            Self::from(u64::from(self)),
            Self::InitialRoundTripTime | Self::Discard
        )
    }

    /// Whether the native reader and writer encode this parameter body as one QUIC integer.
    /// Registry recognition alone does not classify an opaque extension's body.
    #[must_use]
    pub fn has_native_integer_value(self) -> bool {
        macro_rules! integer_parameters {
            {$($(#[$doc:meta])* $name:ident ($id:ident) = $default:expr,)*} => {
                matches!(
                    Self::from(u64::from(self)),
                    $(Self::$id |)* Self::MaxDatagramFrameSize | Self::MinAckDelayDraft07
                )
            }
        }
        apply_params!(integer_parameters)
    }

    /// Whether the native transport parameter reader/writer implements this value.
    /// Registry recognition alone does not grant a typed engine implementation.
    #[must_use]
    pub fn is_implemented(self) -> bool {
        u64::from(self) <= u64::from(Self::VersionInformation)
            || matches!(
                Self::from(u64::from(self)),
                Self::MaxDatagramFrameSize | Self::GreaseQuicBit | Self::MinAckDelayDraft07
            )
    }
}

/// A transport parameter as it was sent: identifier and raw value, in wire order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawParameter {
    pub id: TransportParameterId,
    pub value: Vec<u8>,
}

// Native emission order is engine policy, not a second protocol registry.
const CANONICAL_WRITE_ORDER: [WriteSlot; 22] = [
    WriteSlot::Known(TransportParameterId::MaxIdleTimeout),
    WriteSlot::Known(TransportParameterId::MaxUdpPayloadSize),
    WriteSlot::Known(TransportParameterId::InitialMaxData),
    WriteSlot::Known(TransportParameterId::InitialMaxStreamDataBidiLocal),
    WriteSlot::Known(TransportParameterId::InitialMaxStreamDataBidiRemote),
    WriteSlot::Known(TransportParameterId::InitialMaxStreamDataUni),
    WriteSlot::Known(TransportParameterId::InitialMaxStreamsBidi),
    WriteSlot::Known(TransportParameterId::InitialMaxStreamsUni),
    WriteSlot::Known(TransportParameterId::AckDelayExponent),
    WriteSlot::Known(TransportParameterId::MaxAckDelay),
    WriteSlot::Known(TransportParameterId::ActiveConnectionIdLimit),
    WriteSlot::Grease,
    WriteSlot::Known(TransportParameterId::StatelessResetToken),
    WriteSlot::Known(TransportParameterId::DisableActiveMigration),
    WriteSlot::Known(TransportParameterId::MaxDatagramFrameSize),
    WriteSlot::Known(TransportParameterId::PreferredAddress),
    WriteSlot::Known(TransportParameterId::OriginalDestinationConnectionId),
    WriteSlot::Known(TransportParameterId::InitialSourceConnectionId),
    WriteSlot::Known(TransportParameterId::RetrySourceConnectionId),
    WriteSlot::Known(TransportParameterId::GreaseQuicBit),
    WriteSlot::Known(TransportParameterId::MinAckDelayDraft07),
    WriteSlot::Known(TransportParameterId::VersionInformation),
];

fn read_integer_parameter<R: Buf>(len: usize, input: &mut R) -> Result<VarInt, Error> {
    let mut value = input.take(len);
    let result = value.get()?;
    if value.has_remaining() {
        return Err(Error::Malformed);
    }
    Ok(result)
}

fn decode_cid(len: usize, value: &mut Option<ConnectionId>, r: &mut impl Buf) -> Result<(), Error> {
    if len > MAX_CID_SIZE || value.is_some() || r.remaining() < len {
        return Err(Error::Malformed);
    }

    *value = Some(ConnectionId::from_buf(r, len).map_err(|_error| Error::Malformed)?);
    Ok(())
}

#[cfg(test)]
mod test {
    use core::convert::Infallible;

    use rand::{SeedableRng as _, TryRng, rngs::StdRng};

    use super::*;
    use crate::profile::TransportParameterProfile;

    #[test]
    fn registry_recognition_preserves_opaque_values_and_native_wire_order() {
        let raw = vec![
            RawParameter {
                id: TransportParameterId::MaxAckDelay,
                value: vec![17],
            },
            RawParameter {
                id: TransportParameterId::GoogleConnectionOptions,
                value: vec![1, 2, 3, 4],
            },
            RawParameter {
                id: TransportParameterId::from(27),
                value: vec![7, 8],
            },
            RawParameter {
                id: TransportParameterId::from(VarInt::MAX.into_inner()),
                value: vec![9],
            },
        ];
        let profile = TransportParameterProfile::try_from_sent(&raw).unwrap();
        let mut parameters = TransportParameters {
            max_ack_delay: VarInt::from_u32(17),
            extra: profile
                .extra()
                .iter()
                .map(|parameter| (u64::from(parameter.id), parameter.value.clone()))
                .collect(),
            ..TransportParameters::default()
        };
        parameters.write_plan =
            Some(parameters.plan(profile.order(), &mut StdRng::seed_from_u64(91)));
        let mut wire = Vec::new();
        parameters.write(&mut wire);
        let read = TransportParameters::read(Side::Server, &mut wire.as_slice()).unwrap();
        assert_eq!(read.max_ack_delay, parameters.max_ack_delay);
        let mut wire = wire.as_slice();
        for expected in raw {
            assert_eq!(wire.get_var().unwrap(), u64::from(expected.id));
            let len = wire.get_var().unwrap() as usize;
            assert_eq!(&wire[..len], expected.value);
            wire.advance(len);
        }
    }

    #[test]
    fn explicit_default_parameters_preserve_presence_order_and_uniqueness() {
        let ids = vec![
            TransportParameterId::MaxAckDelay,
            TransportParameterId::InitialMaxData,
            TransportParameterId::MaxIdleTimeout,
            TransportParameterId::AckDelayExponent,
        ];
        let mut parameters = TransportParameters {
            initial_max_data: VarInt::from_u32(12345),
            ..TransportParameters::default()
        };
        parameters.write_plan = Some(parameters.plan(
            &ParameterOrder::fixed_with_explicit_defaults(ids.clone()),
            &mut StdRng::seed_from_u64(73),
        ));
        let mut bytes = Vec::new();
        parameters.write(&mut bytes);
        let mut input = bytes.as_slice();
        let mut actual = Vec::new();
        while input.has_remaining() {
            let id = input.get_var().unwrap();
            let len = input.get_var().unwrap() as usize;
            let (mut value, rest) = input.split_at(len);
            actual.push((TransportParameterId::from(id), value.get_var().unwrap()));
            assert!(value.is_empty());
            input = rest;
        }
        assert_eq!(
            actual,
            ids.into_iter().zip([25, 12345, 0, 3]).collect::<Vec<_>>()
        );
        let decoded = TransportParameters::read(Side::Server, &mut bytes.as_slice()).unwrap();
        assert_eq!(decoded.initial_max_data, parameters.initial_max_data);
        assert_eq!(decoded.max_ack_delay, parameters.max_ack_delay);
        assert_eq!(decoded.max_idle_timeout, parameters.max_idle_timeout);
        assert_eq!(decoded.ack_delay_exponent, parameters.ack_delay_exponent);
    }

    #[test]
    fn ordinary_fixed_order_still_elides_integer_defaults() {
        let ids = vec![
            TransportParameterId::MaxAckDelay,
            TransportParameterId::InitialMaxData,
            TransportParameterId::MaxIdleTimeout,
            TransportParameterId::AckDelayExponent,
        ];
        let mut parameters = TransportParameters::default();
        parameters.write_plan =
            Some(parameters.plan(&ParameterOrder::fixed(ids), &mut StdRng::seed_from_u64(73)));
        let mut bytes = Vec::new();
        parameters.write(&mut bytes);
        assert!(bytes.is_empty());
    }

    #[test]
    fn parameter_lengths_past_the_buffer_are_refused() {
        for len in [9, 1u64 << 32, (1u64 << 32) + 1, VarInt::MAX.into_inner()] {
            let mut buf = Vec::new();
            buf.write_var(0x01);
            buf.write_var(len);
            buf.extend_from_slice(&[0; 8]);
            for side in [Side::Client, Side::Server] {
                assert!(
                    matches!(
                        TransportParameters::read(side, &mut buf.as_slice()),
                        Err(Error::Malformed)
                    ),
                    "length {len}"
                );
            }
        }
    }

    #[test]
    fn coding() {
        let mut buf = Vec::new();
        let params = TransportParameters {
            initial_src_cid: Some(ConnectionId::new(&[0x41])),
            original_dst_cid: Some(ConnectionId::new(&[])),
            initial_max_streams_bidi: 16u32.into(),
            initial_max_streams_uni: 16u32.into(),
            ack_delay_exponent: 2u32.into(),
            max_udp_payload_size: 1200u32.into(),
            preferred_address: Some(PreferredAddress {
                address_v4: Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 42)),
                address_v6: Some(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 24, 0, 0)),
                connection_id: ConnectionId::new(&[0x42]),
                stateless_reset_token: [0xab; RESET_TOKEN_SIZE].into(),
            }),
            grease_quic_bit: true,
            min_ack_delay: Some(2_000u32.into()),
            ..TransportParameters::default()
        };
        params.write(&mut buf);
        assert_eq!(
            TransportParameters::read(Side::Client, &mut buf.as_slice()).unwrap(),
            params
        );
    }

    #[test]
    fn native_integer_classification_matches_actual_writer_bodies() {
        macro_rules! integer_parameters {
            {$($(#[$doc:meta])* $name:ident ($id:ident) = $default:expr,)*} => {
                TransportParameters {
                    $($name: VarInt::from_u64($default + 1).unwrap(),)*
                    max_datagram_frame_size: Some(VarInt::from_u32(1200)),
                    min_ack_delay: Some(VarInt::from_u32(1000)),
                    ..TransportParameters::default()
                }
            }
        }
        let source = apply_params!(integer_parameters);
        let mut bytes = Vec::new();
        source.write(&mut bytes);
        assert!(!bytes.is_empty());
        let mut wire = bytes.as_slice();
        while wire.has_remaining() {
            let id = TransportParameterId::from(wire.get_var().unwrap());
            let len = wire.get_var().unwrap() as usize;
            let (mut value, rest) = wire.split_at(len);
            assert!(
                id.has_native_integer_value(),
                "native writer emitted {id:?}"
            );
            let integer = BufExt::get::<VarInt>(&mut value).unwrap();
            assert!(value.is_empty(), "{id:?} must contain exactly one integer");
            assert_eq!(integer.size(), len, "native integer {id:?} is minimal");
            wire = rest;
        }
        assert_eq!(
            TransportParameters::read(Side::Server, &mut bytes.as_slice()).unwrap(),
            source
        );

        // A CID may happen to look like an integer. Its native type still owns the body;
        // neither it nor flags/version lists participate in integer reconstruction policy.
        let source = TransportParameters {
            initial_src_cid: Some(ConnectionId::new(&[0x40, 1])),
            disable_active_migration: true,
            grease_quic_bit: true,
            version_information: Some(VersionInformation::new(
                crate::version::Version::V1,
                vec![crate::version::Version::V1],
            )),
            ..TransportParameters::default()
        };
        bytes.clear();
        source.write(&mut bytes);
        let mut wire = bytes.as_slice();
        while wire.has_remaining() {
            let id = TransportParameterId::from(wire.get_var().unwrap());
            let len = wire.get_var().unwrap() as usize;
            assert!(!id.has_native_integer_value(), "native noninteger {id:?}");
            wire.advance(len);
        }
        assert_eq!(
            TransportParameters::read(Side::Server, &mut bytes.as_slice()).unwrap(),
            source
        );
    }

    #[test]
    fn reserved_transport_parameter_generate_reserved_id() {
        let mut rngs = [
            StepRng(0),
            StepRng(1),
            StepRng(27),
            StepRng(31),
            StepRng(u32::MAX as u64),
            StepRng(u32::MAX as u64 - 1),
            StepRng(u32::MAX as u64 + 1),
            StepRng(u32::MAX as u64 - 27),
            StepRng(u32::MAX as u64 + 27),
            StepRng(u32::MAX as u64 - 31),
            StepRng(u32::MAX as u64 + 31),
            StepRng(u64::MAX),
            StepRng(u64::MAX - 1),
            StepRng(u64::MAX - 27),
            StepRng(u64::MAX - 31),
            StepRng(1 << 62),
            StepRng((1 << 62) - 1),
            StepRng((1 << 62) + 1),
            StepRng((1 << 62) - 27),
            StepRng((1 << 62) + 27),
            StepRng((1 << 62) - 31),
            StepRng((1 << 62) + 31),
        ];
        for rng in &mut rngs {
            let id = ReservedTransportParameter::generate_reserved_id(rng);
            assert!(id % 31 == 27)
        }
    }

    struct StepRng(u64);

    impl TryRng for StepRng {
        type Error = Infallible;

        #[inline]
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(self.next_u64() as u32)
        }

        #[inline]
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            let res = self.0;
            self.0 = self.0.wrapping_add(1);
            Ok(res)
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            let mut left = dst;
            while left.len() >= 8 {
                let (l, r) = left.split_at_mut(8);
                left = r;
                l.copy_from_slice(&self.next_u64().to_le_bytes());
            }
            let n = left.len();
            if n > 0 {
                left.copy_from_slice(&self.next_u32().to_le_bytes()[..n]);
            }

            Ok(())
        }
    }

    #[test]
    fn reserved_transport_parameter_ignored_when_read() {
        let mut buf = Vec::new();
        let reserved_parameter = ReservedTransportParameter::random(&mut rand::rng(), None);
        assert!(reserved_parameter.payload.len() < ReservedTransportParameter::MAX_PAYLOAD_LEN);
        assert!(reserved_parameter.id % 31 == 27);

        reserved_parameter.write(&mut buf);
        assert!(!buf.is_empty());
        let read_params = TransportParameters::read(Side::Server, &mut buf.as_slice()).unwrap();
        assert_eq!(read_params, TransportParameters::default());
    }

    #[test]
    fn integer_parameters_accept_wider_varints_with_exact_tlv_lengths() {
        // max_idle_timeout=1 with its permitted two-byte integer encoding.
        let encoded = [0x01, 0x02, 0x40, 0x01];
        let params = TransportParameters::read(Side::Server, &mut encoded.as_slice()).unwrap();
        assert_eq!(params.max_idle_timeout, VarInt::from_u32(1));
        // The same value must not consume bytes beyond its declared parameter length.
        let short_length = [0x01, 0x01, 0x40, 0x01];
        assert_eq!(
            TransportParameters::read(Side::Server, &mut short_length.as_slice()).unwrap_err(),
            Error::Malformed
        );
        let long_length = [0x01, 0x03, 0x40, 0x01, 0x00];
        assert_eq!(
            TransportParameters::read(Side::Server, &mut long_length.as_slice()).unwrap_err(),
            Error::Malformed
        );
    }

    #[test]
    fn extension_integer_parameters_enforce_exact_lengths() {
        for id in [
            TransportParameterId::MaxDatagramFrameSize,
            TransportParameterId::MinAckDelayDraft07,
        ] {
            for (len, payload) in [
                (1, &[0x40, 0x01][..]),
                (2, &[0x40, 0x01][..]),
                (3, &[0x40, 0x01, 0x00][..]),
            ] {
                let mut encoded = Vec::new();
                encoded.write_var(u64::from(id));
                encoded.write_var(len);
                encoded.extend_from_slice(payload);
                let result = TransportParameters::read(Side::Server, &mut encoded.as_slice());
                if len == 2 {
                    let params = result.unwrap();
                    let value = match id {
                        TransportParameterId::MaxDatagramFrameSize => {
                            params.max_datagram_frame_size
                        }
                        _ => params.min_ack_delay,
                    };
                    assert_eq!(value, Some(VarInt::from_u32(1)));
                } else {
                    assert_eq!(
                        result.unwrap_err(),
                        Error::Malformed,
                        "{id:?}, length {len}"
                    );
                }
            }
        }
    }

    #[test]
    fn duplicate_extension_parameters_are_malformed() {
        for (id, payload) in [
            (TransportParameterId::MaxDatagramFrameSize, &[1][..]),
            (TransportParameterId::MinAckDelayDraft07, &[1][..]),
            (TransportParameterId::GreaseQuicBit, &[][..]),
        ] {
            let mut encoded = Vec::new();
            for _ in 0..2 {
                encoded.write_var(u64::from(id));
                encoded.write_var(payload.len() as u64);
                encoded.extend_from_slice(payload);
            }
            assert_eq!(
                TransportParameters::read(Side::Server, &mut encoded.as_slice()).unwrap_err(),
                Error::Malformed,
                "{id:?}"
            );
        }
    }

    #[test]
    fn preferred_address_enforces_its_tlv_boundary() {
        let preferred = PreferredAddress {
            address_v4: Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 443)),
            address_v6: None,
            connection_id: ConnectionId::new(&[0x42]),
            stateless_reset_token: [0xab; RESET_TOKEN_SIZE].into(),
        };
        let mut value = Vec::new();
        preferred.write(&mut value);
        // These bytes would otherwise be decoded as a separate max_idle_timeout parameter.
        let trailing_parameter = [0x01, 0x01, 0x01];
        for declared_length in 0..=value.len() + trailing_parameter.len() {
            let mut encoded = Vec::new();
            encoded.write_var(u64::from(TransportParameterId::PreferredAddress));
            encoded.write_var(declared_length as u64);
            encoded.extend_from_slice(&value);
            encoded.extend_from_slice(&trailing_parameter);
            let result = TransportParameters::read(Side::Client, &mut encoded.as_slice());
            if declared_length == value.len() {
                let params = result.unwrap();
                assert_eq!(params.preferred_address, Some(preferred));
                assert_eq!(params.max_idle_timeout, VarInt::from_u32(1));
            } else {
                assert_eq!(result, Err(Error::Malformed), "length {declared_length}");
            }
        }
    }

    #[test]
    fn preferred_address_requires_nonempty_initial_and_preferred_connection_ids() {
        for initial_cid in [&[][..], &[0x41][..]] {
            for preferred_cid in [&[][..], &[0x42][..]] {
                let params = TransportParameters {
                    initial_src_cid: Some(ConnectionId::new(initial_cid)),
                    preferred_address: Some(PreferredAddress {
                        address_v4: Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 443)),
                        address_v6: None,
                        connection_id: ConnectionId::new(preferred_cid),
                        stateless_reset_token: [0xab; RESET_TOKEN_SIZE].into(),
                    }),
                    ..TransportParameters::default()
                };
                let mut encoded = Vec::new();
                params.write(&mut encoded);
                let result = TransportParameters::read(Side::Client, &mut encoded.as_slice());
                if initial_cid.is_empty() || preferred_cid.is_empty() {
                    assert_eq!(result, Err(Error::IllegalValue));
                } else {
                    assert_eq!(result, Ok(params));
                }
            }
        }
    }

    #[test]
    fn read_semantic_validation() {
        let illegal_params_builders: Vec<Box<dyn FnMut(&mut TransportParameters)>> = vec![
            Box::new(|t| {
                // This min_ack_delay is bigger than max_ack_delay!
                let min_ack_delay = t.max_ack_delay * 1_000 + 1;
                t.min_ack_delay = Some(VarInt::from_u64(min_ack_delay).unwrap())
            }),
            Box::new(|t| {
                // Preferred address can only be sent by senders (and we are reading the transport
                // params as a client)
                t.preferred_address = Some(PreferredAddress {
                    address_v4: Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 42)),
                    address_v6: None,
                    connection_id: ConnectionId::new(&[]),
                    stateless_reset_token: [0xab; RESET_TOKEN_SIZE].into(),
                })
            }),
        ];

        for mut builder in illegal_params_builders {
            let mut buf = Vec::new();
            let mut params = TransportParameters::default();
            builder(&mut params);
            params.write(&mut buf);

            assert_eq!(
                TransportParameters::read(Side::Server, &mut buf.as_slice()),
                Err(Error::IllegalValue)
            );
        }
    }

    #[test]
    fn resumption_params_validation() {
        let high_limit = TransportParameters {
            initial_max_streams_uni: 32u32.into(),
            ..TransportParameters::default()
        };
        let low_limit = TransportParameters {
            initial_max_streams_uni: 16u32.into(),
            ..TransportParameters::default()
        };
        high_limit.validate_resumption_from(&low_limit).unwrap();
        low_limit.validate_resumption_from(&high_limit).unwrap_err();
    }
}
