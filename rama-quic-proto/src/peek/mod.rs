//! Bounded inspection of one client Initial flight without producing packets.
//!
//! The caller retains original datagrams and their metadata for routing. This
//! inspector retains only decoded Initials until ClientHello assembly completes.
//! It neither accepts a QUIC connection nor makes an interception decision. An
//! ECH ClientHello describes only the outer hello; offered ALPN is not negotiated
//! protocol evidence. Source/global admission and inspection rate limits belong
//! to the router and must run before calling [`InitialPeek::inspect`].

use std::{error::Error, fmt, time::Instant};

use rama_tls::client::{
    ClientHello, ClientHelloHandshakePrefix, parse_client_hello_message_prefix,
};

use crate::{
    Side, Version,
    capture::{
        CaptureError, CaptureLimits, InitialPacket, KeyProvider, PacketKind,
        client_hello_with_limits, observe_with_limits,
    },
};

/// A terminal inspection outcome. The router decides what to do with retained
/// datagrams; malformed or expired input must not imply untouched forwarding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeekError {
    /// The datagram cannot begin inspection of a client's Initial flight.
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
}

impl fmt::Debug for PeekedClientHello {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Do not accidentally log ClientHello contents through an error report.
        f.debug_struct("PeekedClientHello")
            .field("version", &self.version)
            .field("early_data_observed", &self.early_data_observed)
            .finish_non_exhaustive()
    }
}

/// Incremental, opt-in ClientHello inspection for one QUIC connection attempt.
///
/// Each datagram is decrypted once. Retransmissions, frames, fragments and input
/// bytes consume cumulative budgets. The deadline is absolute and never renewed.
/// Both successful completion and errors release retained Initials and prevent
/// reuse. Callers must also expire a pending inspector when no datagrams arrive.
/// This type deliberately has no raw-data `Debug` or serialization implementation.
pub struct InitialPeek {
    limits: CaptureLimits,
    remaining: CaptureLimits,
    deadline: Instant,
    identity: Option<(Version, Vec<u8>, Vec<u8>)>,
    initials: Vec<InitialPacket>,
    finished: bool,
    early_data_observed: bool,
}

impl InitialPeek {
    #[must_use]
    pub fn new(limits: CaptureLimits, deadline: Instant) -> Self {
        Self {
            limits,
            remaining: limits,
            deadline,
            identity: None,
            initials: Vec::new(),
            finished: false,
            early_data_observed: false,
        }
    }

    /// Absolute deadline the caller uses for its receive timeout.
    #[must_use]
    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    /// Inspect one logical UDP datagram. `None` means more CRYPTO bytes are needed.
    /// Neither this call nor its key provider may emit QUIC responses.
    pub fn inspect<P: KeyProvider>(
        &mut self,
        now: Instant,
        datagram: &[u8],
        provider: &P,
    ) -> Result<Option<PeekedClientHello>, PeekError> {
        if self.finished {
            return Err(PeekError::Finished);
        }
        let result = self.inspect_pending(now, datagram, provider);
        if !matches!(&result, Ok(None)) {
            self.finished = true;
            self.initials = Vec::new();
            self.identity = None;
        }
        result
    }

    fn inspect_pending<P: KeyProvider>(
        &mut self,
        now: Instant,
        datagram: &[u8],
        provider: &P,
    ) -> Result<Option<PeekedClientHello>, PeekError> {
        if now >= self.deadline {
            return Err(PeekError::Deadline);
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

        let lead = observed.packets.first().ok_or(PeekError::NotClientFlight)?;
        if self.identity.is_none() {
            // UDP reordering can deliver opaque 0-RTT before the Initial.
            // Bind its attempt identity and wait without attempting decryption.
            if !matches!(lead.kind, PacketKind::Initial | PacketKind::ZeroRtt) {
                return Err(PeekError::NotClientFlight);
            }
            let version = lead.version.ok_or(PeekError::NotClientFlight)?;
            let source = lead.scid.clone().ok_or(PeekError::NotClientFlight)?;
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
        // The capture decoder bounds temporary decoded copies separately from
        // cumulative wire admission. Reusing the remaining wire budget here
        // would reject the final admitted datagram merely for needing a copy.
        limits.bytes = self.limits.bytes;
        let packets = observed.unprotect_initials_with_limits(
            datagram,
            provider,
            Side::Server,
            Some(destination),
            &limits,
        )?;
        for packet in &packets {
            charge(&mut self.remaining.frames, packet.frames.len(), "frames")?;
            charge(
                &mut self.remaining.crypto_fragments,
                packet.crypto.len(),
                "CRYPTO fragments",
            )?;
        }
        self.initials.extend(packets);

        let Some(message) = client_hello_with_limits(&self.initials, &self.limits)? else {
            return Ok(None);
        };
        match parse_client_hello_message_prefix(&message) {
            ClientHelloHandshakePrefix::Complete(client_hello) => Ok(Some(PeekedClientHello {
                version: *version,
                client_hello,
                early_data_observed: self.early_data_observed,
            })),
            ClientHelloHandshakePrefix::Incomplete | ClientHelloHandshakePrefix::Invalid => {
                Err(CaptureError::Malformed("ClientHello").into())
            }
        }
    }
}

fn charge(remaining: &mut usize, amount: usize, name: &'static str) -> Result<(), CaptureError> {
    *remaining = remaining
        .checked_sub(amount)
        .ok_or(CaptureError::LimitExceeded(name))?;
    Ok(())
}
