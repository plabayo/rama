//! Bounded inspection of one client Initial flight without producing packets.
//!
//! The caller retains original datagrams and their metadata for routing. This
//! inspector keeps only the ClientHello being assembled: each Initial is opened
//! once with keys derived once per attempt, and its CRYPTO data is copied straight
//! into place. Optional structural retention records frame geometry without keeping bodies.
//! It neither accepts a QUIC connection nor makes an interception decision. An
//! ECH ClientHello describes only the outer hello; offered ALPN is not negotiated
//! protocol evidence. Source/global admission and inspection rate limits belong
//! to the router and must run before calling [`InitialPeek::inspect`].

use std::{error::Error, fmt, time::Instant};

use rama_tls::client::{
    ClientHello, ClientHelloHandshakePrefix, parse_client_hello_message_prefix,
};

use crate::{
    MIN_INITIAL_DCID_SIZE, MIN_INITIAL_SIZE, Side, Version,
    capture::{
        CaptureError, CaptureLimits, ClientHelloAssembly, FirstFlight, InitialKeys, KeyProvider,
        ObservedFrame, PacketKind, initial_keys, observe_with_limits, open_initial, record_frame,
        transport_parameters_iter_from_hello,
    },
    crypto::{HeaderKey, PacketKey},
    frame::{self, Frame},
    packet::LONG_HEADER_FORM,
    profile::PaddingPlacement,
    transport_parameters::TransportParameterId,
    version::VersionInformation,
};

/// A terminal inspection outcome. The router decides what to do with retained
/// datagrams; malformed or expired input must not imply untouched forwarding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeekError {
    /// The association does not start with a QUIC client's flight: another protocol, or QUIC
    /// already past its handshake.
    NotClientFlight,
    /// The absolute inspection deadline has expired, even if bytes keep arriving.
    Deadline,
    /// Inspection already completed or failed; create a new inspector for a new attempt.
    Finished,
    /// Malformed, unsupported, undecryptable, or over-budget input.
    Capture(CaptureError),
}

impl fmt::Display for PeekError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotClientFlight => {
                f.write_str("QUIC inspection requires a client Initial or early-data packet")
            }
            Self::Deadline => f.write_str("QUIC inspection deadline expired"),
            Self::Finished => f.write_str("QUIC inspection already finished"),
            Self::Capture(error) => error.fmt(f),
        }
    }
}

impl Error for PeekError {}

impl From<CaptureError> for PeekError {
    fn from(error: CaptureError) -> Self {
        Self::Capture(error)
    }
}

/// Parsed Initial-flight metadata. This contains the outer ClientHello when
/// ECH is present and makes no claim about the eventual negotiated protocol.
pub struct PeekedClientHello {
    pub version: Version,
    pub client_hello: ClientHello,
    /// Protected 0-RTT was observed, but never decrypted by this inspector.
    /// Forwarding preserves its original datagrams; termination must drop it.
    pub early_data_observed: bool,
    /// Structural facts through the datagram that completed this ClientHello, when requested.
    /// This prefix does not claim to include optional datagrams sent after completion.
    pub first_flight: Option<FirstFlight>,
}

impl fmt::Debug for PeekedClientHello {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Do not accidentally log ClientHello contents through an error report.
        f.debug_struct("PeekedClientHello")
            .field("version", &self.version)
            .field("early_data_observed", &self.early_data_observed)
            .field("first_flight", &self.first_flight)
            .finish_non_exhaustive()
    }
}

/// Incremental, opt-in ClientHello inspection for one QUIC connection attempt.
///
/// Each datagram is decrypted once, with the attempt's Initial keys derived once.
/// Retransmissions, frames, fragments and input bytes consume cumulative budgets. The deadline is absolute and never renewed.
/// Both successful completion and errors release retained Initials and prevent
/// reuse. Callers must also expire a pending inspector when no datagrams arrive.
/// This type deliberately has no raw-data `Debug` or serialization implementation.
pub struct InitialPeek<H, P> {
    limits: CaptureLimits,
    remaining: CaptureLimits,
    deadline: Instant,
    identity: Option<(Version, Vec<u8>, Vec<u8>)>,
    /// The attempt's Initial keys, derived once from its version and destination identifier.
    keys: Option<InitialKeys<H, P>>,
    assembly: ClientHelloAssembly,
    finished: bool,
    early_data_observed: bool,
    first_flight: Option<RetainedFlight>,
}

/// Only structural facts retained by the opt-in inspector.
#[derive(Default)]
struct RetainedFlight {
    datagram_sizes: Vec<usize>,
    trailing_bytes: Vec<usize>,
    packet_numbers: Vec<u64>,
    packet_number_lengths: Vec<u8>,
    frames: Vec<Vec<ObservedFrame>>,
    token_len: usize,
    coalesced: bool,
}

impl<H: HeaderKey, P: PacketKey> InitialPeek<H, P> {
    #[must_use]
    pub fn new(limits: CaptureLimits, deadline: Instant) -> Self {
        Self {
            limits,
            remaining: limits,
            deadline,
            identity: None,
            keys: None,
            assembly: ClientHelloAssembly::new(&limits),
            finished: false,
            early_data_observed: false,
            first_flight: None,
        }
    }

    /// Inspect with bounded structural retention, without keeping another ClientHello copy.
    /// The result describes only the prefix through the datagram completing ClientHello.
    pub fn new_with_first_flight(limits: CaptureLimits, deadline: Instant) -> Self {
        Self {
            first_flight: Some(RetainedFlight::default()),
            ..Self::new(limits, deadline)
        }
    }

    /// Absolute deadline the caller uses for its receive timeout.
    #[must_use]
    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    /// Inspect one logical UDP datagram. `None` means more CRYPTO bytes are needed.
    /// Neither this call nor its key provider may emit QUIC responses.
    pub fn inspect<K: KeyProvider<Header = H, Packet = P>>(
        &mut self,
        now: Instant,
        datagram: &[u8],
        provider: &K,
    ) -> Result<Option<PeekedClientHello>, PeekError> {
        if self.finished {
            return Err(PeekError::Finished);
        }
        let result = self.inspect_pending(now, datagram, provider);
        if !matches!(&result, Ok(None)) {
            self.finished = true;
            // Release what was reassembled; an empty assembly holds no allocation.
            self.assembly = ClientHelloAssembly::new(&self.limits);
            self.identity = None;
            self.keys = None;
            self.first_flight = None;
        }
        result
    }

    fn inspect_pending<K: KeyProvider<Header = H, Packet = P>>(
        &mut self,
        now: Instant,
        datagram: &[u8],
        provider: &K,
    ) -> Result<Option<PeekedClientHello>, PeekError> {
        if now >= self.deadline {
            return Err(PeekError::Deadline);
        }
        if self.identity.is_none() {
            // Classified before any budget is charged: another protocol never counts as QUIC.
            admit_first(datagram)?;
        }
        charge(&mut self.remaining.datagrams, 1, "datagrams")?;
        // Admission precedes parsing, key derivation and peer-controlled copies.
        let byte_budget = self.remaining.bytes;
        charge(&mut self.remaining.bytes, datagram.len(), "bytes")?;
        let mut limits = self.remaining;
        limits.bytes = byte_budget;
        let observed = observe_with_limits(datagram, &limits)?;
        charge(
            &mut self.remaining.packets,
            observed.packets.len(),
            "packets",
        )?;

        if datagram.len() < MIN_INITIAL_SIZE
            && observed
                .packets
                .iter()
                .any(|packet| packet.kind == PacketKind::Initial)
        {
            return Err(CaptureError::Malformed("Initial datagram below 1200 bytes").into());
        }
        let lead = observed.packets.first().ok_or(PeekError::NotClientFlight)?;
        if self.identity.is_none() {
            // UDP reordering can deliver opaque 0-RTT before the Initial.
            // Bind its attempt identity and wait without attempting decryption.
            if !matches!(lead.kind, PacketKind::Initial | PacketKind::ZeroRtt) {
                return Err(PeekError::NotClientFlight);
            }
            let version = lead.version.ok_or(PeekError::NotClientFlight)?;
            let source = lead.scid.clone().ok_or(PeekError::NotClientFlight)?;
            if lead.dcid.len() < MIN_INITIAL_DCID_SIZE {
                return Err(
                    CaptureError::Malformed("Initial destination CID below 8 bytes").into(),
                );
            }
            self.identity = Some((version, lead.dcid.clone(), source));
        }
        let (version, destination, source) =
            self.identity.as_ref().ok_or(PeekError::NotClientFlight)?;
        // A second Initial must belong to this attempt. Do not combine CRYPTO
        // streams across versions or identifiers, even when an AEAD would open.
        for packet in &observed.packets {
            if matches!(packet.kind, PacketKind::Initial | PacketKind::ZeroRtt)
                && (packet.version != Some(*version)
                    || packet.dcid != *destination
                    || packet.scid.as_ref() != Some(source))
            {
                return Err(CaptureError::Malformed("mixed Initial attempts").into());
            }
        }
        self.early_data_observed |= observed
            .packets
            .iter()
            .any(|packet| packet.kind == PacketKind::ZeroRtt);
        if let Some(retained) = &mut self.first_flight {
            retained.datagram_sizes.push(observed.len);
            retained.trailing_bytes.push(observed.trailing);
            retained.coalesced |= observed
                .packets
                .iter()
                .any(|packet| packet.kind != PacketKind::Initial);
            retained.token_len = retained.token_len.max(
                observed
                    .packets
                    .iter()
                    .filter_map(|packet| packet.token.as_ref().map(Vec::len))
                    .max()
                    .unwrap_or(0),
            );
        }
        for packet in observed
            .packets
            .iter()
            .filter(|packet| packet.kind == PacketKind::Initial)
        {
            let keys = match &self.keys {
                Some(keys) => keys,
                None => {
                    self.keys
                        .insert(initial_keys(provider, *version, destination, Side::Server)?)
                }
            };
            let opened = open_initial(datagram, packet, *version, keys)?;
            let mut retained_frames = self.first_flight.as_ref().map(|_| Vec::new());
            if let Some(retained) = &mut self.first_flight {
                retained.packet_numbers.push(opened.packet_number);
                retained
                    .packet_number_lengths
                    .push(opened.packet_number_len);
            }
            let frames = frame::Iter::new(opened.payload)
                .map_err(|_error| CaptureError::Malformed("empty Initial payload"))?;
            // CRYPTO goes straight into the assembly; optional retention keeps only frame shape.
            let mut padding = false;
            for frame in frames {
                let frame = frame.map_err(|_error| CaptureError::Malformed("frame"))?;
                let is_padding = matches!(frame, Frame::Padding);
                // A run of PADDING counts as one frame against the budget.
                if !(is_padding && padding) {
                    charge(&mut self.remaining.frames, 1, "frames")?;
                }
                padding = is_padding;
                if let Some(retained) = &mut retained_frames {
                    record_frame(retained, &frame);
                }
                if let Frame::Crypto(crypto) = frame {
                    charge(&mut self.remaining.crypto_fragments, 1, "CRYPTO fragments")?;
                    self.assembly.take_in(crypto.offset, &crypto.data)?;
                }
            }
            if let (Some(retained), Some(frames)) = (&mut self.first_flight, retained_frames) {
                retained.frames.push(frames);
            }
        }
        let Some(message) = self.assembly.client_hello() else {
            return Ok(None);
        };
        match parse_client_hello_message_prefix(message) {
            ClientHelloHandshakePrefix::Complete(client_hello) => {
                let first_flight = self
                    .first_flight
                    .take()
                    .map(|retained| {
                        let mut parameters = Vec::new();
                        let mut info = None;
                        for parameter in
                            transport_parameters_iter_from_hello(&client_hello, &self.limits)?
                        {
                            let (id, value) = parameter?;
                            parameters.push(id);
                            if id == TransportParameterId::VersionInformation {
                                if info.is_some() {
                                    return Err(CaptureError::Malformed(
                                        "duplicate version_information",
                                    ));
                                }
                                info = Some(
                                    VersionInformation::read(true, value.len(), &mut &value[..])
                                        .map_err(|_error| {
                                            CaptureError::Malformed("version_information")
                                        })?,
                                );
                            }
                        }
                        Ok::<_, CaptureError>(FirstFlight {
                            version: *version,
                            dcid_len: destination.len(),
                            scid_len: source.len(),
                            token_len: retained.token_len,
                            first_packet_number: *retained
                                .packet_numbers
                                .first()
                                .ok_or(CaptureError::Malformed("no Initial packets"))?,
                            packet_number_len: *retained
                                .packet_number_lengths
                                .first()
                                .ok_or(CaptureError::Malformed("no Initial packets"))?,
                            padding: if retained.trailing_bytes.iter().any(|tail| *tail != 0) {
                                PaddingPlacement::DatagramTail
                            } else {
                                PaddingPlacement::Frames
                            },
                            datagram_sizes: retained.datagram_sizes,
                            trailing_bytes: retained.trailing_bytes,
                            packet_number_lengths: retained.packet_number_lengths,
                            frames: retained.frames,
                            coalesced: retained.coalesced,
                            parameters,
                            chosen_version: info.as_ref().map(VersionInformation::chosen),
                            available_versions: info
                                .map_or_else(Vec::new, |info| info.available().to_vec()),
                            packet_numbers: retained.packet_numbers,
                            complete: true,
                        })
                    })
                    .transpose()?;
                Ok(Some(PeekedClientHello {
                    version: *version,
                    client_hello,
                    early_data_observed: self.early_data_observed,
                    first_flight,
                }))
            }
            ClientHelloHandshakePrefix::Incomplete | ClientHelloHandshakePrefix::Invalid => {
                Err(CaptureError::Malformed("ClientHello").into())
            }
        }
    }
}

/// Whether a datagram can start a client's flight: a long header that is not Version
/// Negotiation, of an unknown version only at an Initial's size (RFC 8999 §5.1, RFC 9000 §14.1).
fn admit_first(datagram: &[u8]) -> Result<(), PeekError> {
    let Some(&[first, a, b, c, d]) = datagram.first_chunk::<5>() else {
        return Err(PeekError::NotClientFlight);
    };
    let version = Version::from_be_bytes([a, b, c, d]);
    let claims_quic = first & LONG_HEADER_FORM != 0
        && !version.is_negotiation()
        && (version.wire().is_some() || datagram.len() >= MIN_INITIAL_SIZE);
    if claims_quic {
        Ok(())
    } else {
        Err(PeekError::NotClientFlight)
    }
}

fn charge(remaining: &mut usize, amount: usize, name: &'static str) -> Result<(), CaptureError> {
    *remaining = remaining
        .checked_sub(amount)
        .ok_or(CaptureError::LimitExceeded(name))?;
    Ok(())
}
