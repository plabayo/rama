use std::{
    cmp,
    collections::VecDeque,
    convert::TryFrom,
    fmt, io, mem,
    net::{IpAddr, SocketAddr},
    ops::Range,
    sync::Arc,
};

use frame::StreamMetaVec;
use rama_core::bytes::{Bytes, BytesMut};

use rama_core::telemetry::tracing::{debug, error, trace, trace_span, warn};
use rand::{RngExt, SeedableRng, rngs::StdRng};

use crate::proto::{
    Dir, Duration, EndpointConfig, Frame, INITIAL_MTU, Instant, MAX_CID_SIZE, MAX_STREAM_COUNT,
    MIN_INITIAL_SIZE, SendPermit, Side, StreamId, TIMER_GRANULARITY, TokenStore, Transmit,
    TransportError, TransportErrorCode, VarInt,
    cid_generator::ConnectionIdGenerator,
    cid_queue::{CidQueue, OwnedRemotes, Retired, RouteDelta},
    coding::BufMutExt,
    config::{PreferredAddressPolicy, ServerConfig, TransportConfig},
    crypto::{self, KeyPair, Keys, PacketKey},
    frame::{self, Close, Datagram, FrameStruct, NewConnectionId, NewToken},
    packet::{
        FixedLengthConnectionIdParser, Header, InitialHeader, InitialPacket, LongType, Packet,
        PacketNumber, PartialDecode, SpaceId,
    },
    range_set::ArrayRangeSet,
    shared::{
        ConnectionEvent, ConnectionEventInner, ConnectionId, DatagramConnectionEvent, EcnCodepoint,
        EndpointEvent, EndpointEventInner,
    },
    token::{ResetToken, Token, TokenPayload},
    transport_parameters::{PreferredAddress, TransportParameters},
};

mod ack_frequency;
use ack_frequency::AckFrequencyState;

mod assembler;
pub use assembler::Chunk;

mod cid_state;
use cid_state::CidState;

mod datagrams;
use datagrams::DatagramState;
pub(crate) use datagrams::{Datagrams, SendDatagramError};

mod mtud;
mod pacing;

mod packet_builder;
use packet_builder::PacketBuilder;

mod packet_crypto;
use packet_crypto::{PrevCrypto, ZeroRttCrypto};

mod paths;
pub(crate) use paths::RttEstimator;
use paths::{PathData, PathResponses};

pub(crate) mod qlog;

mod send_buffer;

mod spaces;
#[cfg(fuzzing)]
pub use spaces::Retransmits;
#[cfg(not(fuzzing))]
use spaces::Retransmits;
use spaces::{PacketNumberFilter, PacketSpace, SendableFrames, SentPacket, ThinRetransmits};

mod stats;
pub use stats::{ConnectionStats, FrameStats, PathStats, UdpStats};

mod streams;
#[cfg(fuzzing)]
pub use streams::StreamsState;
#[cfg(not(fuzzing))]
use streams::StreamsState;
pub(crate) use streams::{
    Chunks, FinishError, ReadError, ReadableError, RecvStream, ShouldTransmit, StreamEvent,
    WriteError,
};
pub use streams::{ClosedStream, Written};
#[cfg(fuzzing)]
pub use streams::{SendStream, Streams};
#[cfg(not(fuzzing))]
pub(crate) use streams::{SendStream, Streams};

mod timer;
use crate::proto::congestion::Controller;
use timer::{Timer, TimerTable};

/// Protocol state and logic for a single QUIC connection
///
/// Objects of this type receive [`ConnectionEvent`]s and emit [`EndpointEvent`]s and application
/// [`Event`]s to make progress. To handle timeouts, a `Connection` returns timer updates and
/// expects timeouts through various methods. A number of simple getter methods are exposed
/// to allow callers to inspect some of the connection state.
///
/// `Connection` has roughly 4 types of methods:
///
/// - A. Simple getters, taking `&self`
/// - B. Handlers for incoming events from the network or system, named `handle_*`.
/// - C. State machine mutators, for incoming commands from the application. For convenience we
///   refer to this as "performing I/O" below, however as per the design of this library none of the
///   functions actually perform system-level I/O. For example, [`read`](RecvStream::read) and
///   [`write`](SendStream::write), but also things like [`reset`](SendStream::reset).
/// - D. Polling functions for outgoing events or actions for the caller to
///   take, named `poll_*`.
///
/// The simplest way to use this API correctly is to call (B) and (C) whenever
/// appropriate, then after each of those calls, as soon as feasible call all
/// polling methods (D) and deal with their outputs appropriately, e.g. by
/// passing it to the application or by making a system-level I/O call. You
/// should call the polling functions in this order:
///
/// 1. [`poll_transmit`](Self::poll_transmit)
/// 2. [`poll_timeout`](Self::poll_timeout)
/// 3. [`poll_endpoint_events`](Self::poll_endpoint_events)
/// 4. [`poll`](Self::poll)
///
/// Currently the only actual dependency is from (2) to (1), however additional
/// dependencies may be added in future, so the above order is recommended.
///
/// (A) may be called whenever desired.
///
/// Care should be made to ensure that the input events represent monotonically
/// increasing time. Specifically, calling [`handle_timeout`](Self::handle_timeout)
/// with events of the same [`Instant`] may be interleaved in any order with a
/// call to [`handle_event`](Self::handle_event) at that same instant; however
/// events or timeouts with different instants must not be interleaved.
/// The path the connection sent on before the current one, kept while the current one is being
/// validated so the connection can return to it.
struct PrevPath {
    path: PathData,
    /// Which destination connection ID that path is sent with.
    cid: PrevCid,
}

/// What becomes of the path a migration replaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreviousPath {
    /// Keep it as a fallback, challenged with the identifier bound to it.
    Keep(PrevCid),
    /// Leave it behind: we moved deliberately and will not send there again.
    Discard,
}

/// The destination connection ID bound to the previous path (RFC 9000 §9.5: never one that is
/// also sent to another address).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrevCid {
    /// The identifier used there, kept aside in the connection ID queue.
    Held,
    /// The current identifier: the peer moved without changing the ID it sends (NAT rebinding).
    Active,
    /// The peer retired the identifier meanwhile; returning needs a fresh one.
    Gone,
}

/// A peer move that waits for an unused destination connection ID.
#[derive(Debug, Clone, Copy)]
struct DeferredMigration {
    remote: SocketAddr,
    local: Option<SocketAddr>,
    /// The destination connection ID the peer used for the move.
    received_dcid: ConnectionId,
    /// Packet number of the newest non-probing packet asking for the move.
    number: u64,
    /// Path generation the move was recorded against; a path change makes it obsolete.
    generation: u64,
}

/// The sequence number a server binds to its preferred address (RFC 9000 §5.1.1).
const PREFERRED_ADDRESS_CID_SEQ: u64 = 1;

/// How many PATH_CHALLENGE probes are transmitted towards a preferred address before the attempt
/// is given up.
const MAX_PREFERRED_PROBES: usize = 3;

/// What became of the address a server advertised as preferred (RFC 9000 §9.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PreferredAddressState {
    /// None was advertised for the family in use, it is the address already in use, or the client
    /// declined it.
    Unused,
    /// Advertised; probing starts once the handshake is confirmed.
    Armed,
    /// A probe is outstanding.
    Probing,
    /// A probe was answered and the connection moved there.
    Validated,
    /// The attempt ended without a usable path; the connection stays where it was.
    Failed,
}

/// How many paths a connection will bind an identifier to at once. A path this connection does
/// not otherwise send on is one it answers a challenge on, nothing more, and every binding costs
/// an identifier the peer issued: a few is generous and keeps the reset token set small.
const PATH_CIDS: usize = 2;

/// A peer connection ID bound to one path, so that what this connection sends there carries an
/// identifier it sends from no other local address (RFC 9000 §9.5).
#[derive(Debug, Clone, Copy)]
struct PathCid {
    /// The address the identifier is sent to.
    remote: SocketAddr,
    /// The local address it is sent from, when known.
    local: Option<SocketAddr>,
    id: ConnectionId,
    seq: u64,
    reset_token: Option<ResetToken>,
}

/// A client's attempt at the server's preferred address (RFC 9000 §9.6.2): a path of its own,
/// probed with an identifier no other path is sent with.
struct PreferredCandidate {
    remote: SocketAddr,
    /// The identifier reserved for this path.
    cid: ConnectionId,
    /// Its sequence number and stateless reset token: once a probe has been transmitted, that
    /// token can reset this connection from this path (RFC 9000 §10.3.1).
    seq: u64,
    reset_token: Option<ResetToken>,
    /// Challenge data of the probes the network has taken, and how many that is.
    sent: [u64; MAX_PREFERRED_PROBES],
    transmitted: usize,
    /// Challenge data waiting for a datagram.
    pending: Option<u64>,
    /// Challenge data written into a datagram the sender has not taken yet. It counts, and its
    /// identifier becomes one we have used, only once the sender reports it gone.
    in_flight: Option<u64>,
}

impl PreferredCandidate {
    /// Whether this response's data belongs to one of our probes. A response validates the path
    /// its challenge went out on, whichever path it arrives on (RFC 9000 §8.2.3). A probe the
    /// sender has not reported counts here: an answer to it is proof enough that it went out.
    fn matches(&self, token: u64) -> bool {
        self.in_flight == Some(token)
            || self
                .sent
                .get(..self.transmitted)
                .is_some_and(|sent| sent.contains(&token))
    }

    /// Whether a probe is waiting for a datagram or for the sender to take one.
    fn outstanding(&self) -> bool {
        self.pending.is_some() || self.in_flight.is_some()
    }
}

pub(crate) struct Connection {
    endpoint_config: Arc<EndpointConfig>,
    config: Arc<TransportConfig>,
    rng: StdRng,
    crypto: Box<dyn crypto::Session>,
    /// The CID we initially chose, for use during the handshake
    handshake_cid: ConnectionId,
    /// The CID the peer initially chose, for use during the handshake
    rem_handshake_cid: ConnectionId,
    path: PathData,
    /// Incremented every time we see a new path
    ///
    /// Stored separately from `path.generation` to account for aborted migrations
    path_counter: u64,
    /// Whether MTU detection is supported in this environment
    allow_mtud: bool,
    /// The path sent on before the current one, kept while the current one is validated.
    prev_path: Option<PrevPath>,
    /// A peer move that could not be followed yet because no unused destination connection ID
    /// was available (RFC 9000 §9.5); completed when the peer issues one, unless newer traffic
    /// superseded it meanwhile.
    deferred_migration: Option<DeferredMigration>,
    /// The server's preferred address for the family in use, once advertised (client only).
    preferred_address: Option<SocketAddr>,
    /// How far this client got with that address.
    preferred_state: PreferredAddressState,
    /// The candidate path while it is being probed.
    candidate: Option<PreferredCandidate>,
    /// Identifiers bound to a path this connection does not otherwise send on, so an answer
    /// there carries one that is sent from no other local address (RFC 9000 §9.5).
    path_cids: [Option<PathCid>; PATH_CIDS],
    /// A protocol error raised where the caller cannot return one, such as a retirement queue
    /// reaching its bound during a timer. The connection closes with it at the next transmit.
    deferred_error: Option<TransportError>,
    /// Names each route installation, so a release or an acknowledgement in flight cannot be
    /// applied to a later one that reuses the same identifier and address.
    reset_generation: u64,
    /// Ack-eliciting packets sent and neither acknowledged, declared lost nor abandoned, across
    /// every packet number space and every path they were sent on, including paths since
    /// discarded. Loss recovery (RFC 9002 §6.2) is a connection-wide matter; the per-path
    /// `InFlight` counters serve congestion control and vanish with their path.
    in_flight_ack_eliciting: u64,
    state: State,
    side: ConnectionSide,
    /// Whether or not 0-RTT was enabled during the handshake. Does not imply acceptance.
    zero_rtt_enabled: bool,
    /// Set if 0-RTT is supported, then cleared when no longer needed.
    zero_rtt_crypto: Option<ZeroRttCrypto>,
    key_phase: bool,
    /// How many packets are in the current key phase. Used only for `Data` space.
    key_phase_size: u64,
    /// Transport parameters set by the peer
    peer_params: TransportParameters,
    /// Tests: keep HANDSHAKE_DONE from the peer (see [`hold_handshake_done`](Self::hold_handshake_done)).
    #[cfg(test)]
    hold_handshake_done: bool,
    /// Tests: HANDSHAKE_DONE that the seam above took out of the pending set.
    #[cfg(test)]
    withheld_handshake_done: bool,
    /// Source ConnectionId of the first packet received from the peer
    orig_rem_cid: ConnectionId,
    /// Destination ConnectionId sent by the client on the first Initial
    initial_dst_cid: ConnectionId,
    /// The value that the server included in the Source Connection ID field of a Retry packet, if
    /// one was received
    retry_src_cid: Option<ConnectionId>,
    events: VecDeque<Event>,
    endpoint_events: VecDeque<EndpointEventInner>,
    /// Whether the spin bit is in use for this connection
    spin_enabled: bool,
    /// Outgoing spin bit state
    spin: bool,
    /// Packet number spaces: initial, handshake, 1-RTT
    spaces: [PacketSpace; 3],
    /// Highest usable packet number space
    highest_space: SpaceId,
    /// 1-RTT keys used prior to a key update
    prev_crypto: Option<PrevCrypto>,
    /// 1-RTT keys to be used for the next key update
    ///
    /// These are generated in advance to prevent timing attacks and/or DoS by third-party attackers
    /// spoofing key updates.
    next_crypto: Option<KeyPair<Box<dyn PacketKey>>>,
    accepted_0rtt: bool,
    /// Whether the idle timer should be reset the next time an ack-eliciting packet is transmitted.
    permit_idle_reset: bool,
    /// Negotiated idle timeout
    idle_timeout: Option<Duration>,
    /// The time we send next bundled ACK
    ///
    /// The goal is to wait long enough for the peer to acknowledge our previous
    /// bundled ACK (see `next_bundled_ack_delay`).
    /// A packet-count threshold would over- or under-shoot this depending on how fast we happen
    /// to be sending, so a time threshold is used instead.
    next_bundled_ack_time: Option<Instant>,
    timers: TimerTable,
    /// Number of packets received which could not be authenticated
    authentication_failures: u64,
    /// Why the connection was lost, if it has been
    error: Option<ConnectionError>,
    /// Identifies Data-space packet numbers to skip. Not used in earlier spaces.
    packet_number_filter: PacketNumberFilter,

    //
    // Queued non-retransmittable 1-RTT data
    //
    /// Responses to PATH_CHALLENGE frames
    path_responses: PathResponses,
    close: bool,

    //
    // ACK frequency
    //
    ack_frequency: AckFrequencyState,

    //
    // Loss Detection
    //
    /// The number of times a PTO has been sent without receiving an ack.
    pto_count: u32,

    //
    // Congestion Control
    //
    /// Whether the most recently received packet had an ECN codepoint set
    receiving_ecn: bool,
    /// Number of packets authenticated
    total_authed_packets: u64,
    /// Whether the last `poll_transmit` call yielded no data because there was
    /// no outgoing application data.
    app_limited: bool,

    streams: StreamsState,
    /// Surplus remote CIDs for future use on new paths
    rem_cids: CidQueue,
    // Attributes of CIDs generated by local peer
    local_cid_state: CidState,
    /// State of the unreliable datagram extension
    datagrams: DatagramState,
    /// Connection level statistics
    stats: ConnectionStats,
    /// QUIC version used for the connection.
    version: u32,
}

impl Connection {
    pub(crate) fn new(
        endpoint_config: Arc<EndpointConfig>,
        config: Arc<TransportConfig>,
        init_cid: ConnectionId,
        loc_cid: ConnectionId,
        rem_cid: ConnectionId,
        remote: SocketAddr,
        local: Option<SocketAddr>,
        crypto: Box<dyn crypto::Session>,
        cid_gen: &dyn ConnectionIdGenerator,
        now: Instant,
        version: u32,
        allow_mtud: bool,
        rng_seed: [u8; 32],
        side_args: SideArgs,
    ) -> Self {
        let pref_addr_cid = side_args.pref_addr_cid();
        let path_validated = side_args.path_validated();
        let connection_side = ConnectionSide::from(side_args);
        let side = connection_side.side();
        let initial_space = PacketSpace {
            crypto: Some(crypto.initial_keys(&init_cid, side)),
            ..PacketSpace::new(now)
        };
        let state = State::Handshake(state::Handshake {
            rem_cid_set: side.is_server(),
            expected_token: Bytes::new(),
            client_hello: None,
        });
        let mut rng = StdRng::from_seed(rng_seed);
        let mut this = Self {
            endpoint_config,
            crypto,
            handshake_cid: loc_cid,
            rem_handshake_cid: rem_cid,
            local_cid_state: CidState::new(
                cid_gen.cid_len(),
                cid_gen.cid_lifetime(),
                now,
                if pref_addr_cid.is_some() { 2 } else { 1 },
            ),
            path: PathData::new(remote, local, allow_mtud, None, 0, now, &config),
            path_counter: 0,
            allow_mtud,
            prev_path: None,
            deferred_migration: None,
            preferred_address: None,
            preferred_state: PreferredAddressState::Unused,
            candidate: None,
            deferred_error: None,
            reset_generation: 0,
            // The handshake goes out with the identifier the peer chose for it.
            path_cids: [None; PATH_CIDS],
            in_flight_ack_eliciting: 0,
            state,
            side: connection_side,
            zero_rtt_enabled: false,
            zero_rtt_crypto: None,
            key_phase: false,
            // A small initial key phase size ensures peers that don't handle key updates correctly
            // fail sooner rather than later. It's okay for both peers to do this, as the first one
            // to perform an update will reset the other's key phase size in `update_keys`, and a
            // simultaneous key update by both is just like a regular key update with a really fast
            // response. Other implementations similarly perform the first key update early (for
            // example at the 100th short-header packet).
            key_phase_size: rng.random_range(10..1000),
            peer_params: TransportParameters::default(),
            #[cfg(test)]
            hold_handshake_done: false,
            #[cfg(test)]
            withheld_handshake_done: false,
            orig_rem_cid: rem_cid,
            initial_dst_cid: init_cid,
            retry_src_cid: None,
            events: VecDeque::new(),
            endpoint_events: VecDeque::new(),
            spin_enabled: config.allow_spin && rng.random_ratio(7, 8),
            spin: false,
            spaces: [initial_space, PacketSpace::new(now), PacketSpace::new(now)],
            highest_space: SpaceId::Initial,
            prev_crypto: None,
            next_crypto: None,
            accepted_0rtt: false,
            permit_idle_reset: true,
            idle_timeout: match config.max_idle_timeout {
                None | Some(VarInt(0)) => None,
                Some(dur) => Some(Duration::from_millis(dur.0)),
            },
            timers: TimerTable::default(),
            authentication_failures: 0,
            error: None,
            #[cfg(test)]
            packet_number_filter: match config.deterministic_packet_numbers {
                false => PacketNumberFilter::new(&mut rng),
                true => PacketNumberFilter::disabled(),
            },
            #[cfg(not(test))]
            packet_number_filter: PacketNumberFilter::new(&mut rng),

            path_responses: PathResponses::default(),
            close: false,

            ack_frequency: AckFrequencyState::new(get_max_ack_delay(
                &TransportParameters::default(),
            )),
            next_bundled_ack_time: None,

            pto_count: 0,

            app_limited: false,
            receiving_ecn: false,
            total_authed_packets: 0,

            streams: StreamsState::new(
                side,
                config.max_concurrent_uni_streams,
                config.max_concurrent_bidi_streams,
                config.send_window,
                config.receive_window,
                config.stream_receive_window,
            ),
            datagrams: DatagramState::default(),
            config,
            rem_cids: CidQueue::new(rem_cid),
            rng,
            stats: ConnectionStats::default(),
            version,
        };
        if let Some(deadline) = now.checked_add(this.endpoint_config.handshake_timeout) {
            this.timers.set(Timer::Handshake, deadline);
        } else {
            this.kill(
                TransportError::INTERNAL_ERROR("handshake timeout exceeds clock range").into(),
            );
            return this;
        }
        if path_validated {
            this.on_path_validated();
        }
        if side.is_client() {
            // Kick off the connection
            this.write_crypto();
            this.init_0rtt();
        }
        this
    }

    /// Returns the next time at which `handle_timeout` should be called
    ///
    /// The value returned may change after:
    /// - the application performed some I/O on the connection
    /// - a call was made to `handle_event`
    /// - a call to `poll_transmit` returned `Some`
    /// - a call was made to `handle_timeout`
    #[must_use]
    /// Expiry of the loss detection timer, if armed (test observation point)
    #[cfg(test)]
    pub(crate) fn loss_detection_timer(&self) -> Option<Instant> {
        self.timers.get(Timer::LossDetection)
    }

    /// The negotiated TLS key exchange group, if the session exposes it (test observation point)
    #[cfg(test)]
    pub(crate) fn negotiated_key_exchange_group(&self) -> Option<u16> {
        self.crypto.negotiated_key_exchange_group()
    }

    pub(crate) fn poll_timeout(&mut self) -> Option<Instant> {
        self.timers.next_timeout()
    }

    /// Returns application-facing events
    ///
    /// Connections should be polled for events after:
    /// - a call was made to `handle_event`
    /// - a call was made to `handle_timeout`
    #[must_use]
    pub(crate) fn poll(&mut self) -> Option<Event> {
        if let Some(x) = self.events.pop_front() {
            return Some(x);
        }

        if let Some(event) = self.streams.poll() {
            return Some(Event::Stream(event));
        }

        if let Some(err) = self.error.take() {
            return Some(Event::ConnectionLost { reason: err });
        }

        None
    }

    /// Return endpoint-facing events
    #[must_use]
    pub(crate) fn poll_endpoint_events(&mut self) -> Option<EndpointEvent> {
        self.endpoint_events.pop_front().map(EndpointEvent)
    }

    /// Provide control over streams
    #[must_use]
    pub(crate) fn streams(&mut self) -> Streams<'_> {
        Streams {
            state: &mut self.streams,
            conn_state: &self.state,
        }
    }

    /// Provide control over streams
    #[must_use]
    pub(crate) fn recv_stream(&mut self, id: StreamId) -> RecvStream<'_> {
        assert!(id.dir() == Dir::Bi || id.initiator() != self.side.side());
        RecvStream {
            id,
            state: &mut self.streams,
            pending: &mut self.spaces[SpaceId::Data].pending,
        }
    }

    /// Provide control over streams
    #[must_use]
    pub(crate) fn send_stream(&mut self, id: StreamId) -> SendStream<'_> {
        assert!(id.dir() == Dir::Bi || id.initiator() == self.side.side());
        SendStream {
            id,
            state: &mut self.streams,
            pending: &mut self.spaces[SpaceId::Data].pending,
            conn_state: &self.state,
        }
    }

    /// Returns packets to transmit
    ///
    /// Connections should be polled for transmit after:
    /// - the application performed some I/O on the connection
    /// - a call was made to `handle_event`
    /// - a call was made to `handle_timeout`
    ///
    /// `max_datagrams` specifies how many datagrams can be returned inside a
    /// single Transmit using GSO. This must be at least 1.
    #[must_use]
    pub(crate) fn poll_transmit(
        &mut self,
        now: Instant,
        max_datagrams: usize,
        buf: &mut Vec<u8>,
    ) -> Option<Transmit> {
        assert!(max_datagrams != 0);
        // A protocol error a timer could not report closes the connection here.
        if let Some(error) = self.deferred_error.take() {
            // The peer is told with the frame this error names, and the application is told the
            // cause: closing locally must not leave the connection to be reported later as an
            // engine that drained without a reason.
            let reason = ConnectionError::TransportError(error.clone());
            self.close_inner(now, Close::Connection(error.into()));
            if self.error.is_none() {
                self.error = Some(reason);
            }
        }
        let max_datagrams = match self.config.enable_segmentation_offload {
            false => 1,
            true => max_datagrams,
        };

        let mut num_datagrams = 0;
        // Position in `buf` of the first byte of the current UDP datagram. When coalescing QUIC
        // packets, this can be earlier than the start of the current QUIC packet.
        let mut datagram_start = 0;
        let mut segment_size = usize::from(self.path.current_mtu());

        if let Some(challenge) = self.send_path_challenge(now, buf) {
            return Some(challenge);
        }

        if let Some(probe) = self.send_preferred_probe(now, buf) {
            return Some(probe);
        }

        if let Some(response) = self.send_off_path_response(now, buf) {
            return Some(response);
        }

        // If we need to send a probe, make sure we have something to send.
        for space in SpaceId::iter() {
            let request_immediate_ack =
                space == SpaceId::Data && self.peer_supports_ack_frequency();
            self.spaces[space].maybe_queue_probe(request_immediate_ack, &self.streams);
        }

        // Check whether we need to send a close message
        let close = match self.state {
            State::Drained => {
                self.app_limited = true;
                return None;
            }
            State::Draining | State::Closed(_) => {
                // self.close is only reset once the associated packet had been
                // encoded successfully
                if !self.close {
                    self.app_limited = true;
                    return None;
                }
                true
            }
            _ => false,
        };

        // Check whether we need to send an ACK_FREQUENCY frame
        if let Some(config) = &self.config.ack_frequency_config {
            self.spaces[SpaceId::Data].pending.ack_frequency = self
                .ack_frequency
                .should_send_ack_frequency(self.path.rtt.get(), config, &self.peer_params)
                && self.highest_space == SpaceId::Data
                && self.peer_supports_ack_frequency();
        }

        // Reserving capacity can provide more capacity than we asked for. However, we are not
        // allowed to write more than `segment_size`. Therefore the maximum capacity is tracked
        // separately.
        let mut buf_capacity = 0;

        let mut coalesce = true;
        let mut builder_storage: Option<PacketBuilder> = None;
        let mut sent_frames = None;
        let mut pad_datagram = false;
        let mut pad_datagram_to_mtu = false;
        let mut congestion_blocked = false;

        // Iterate over all spaces and find data to send
        let mut space_idx = 0;
        let spaces = [SpaceId::Initial, SpaceId::Handshake, SpaceId::Data];
        // This loop will potentially spend multiple iterations in the same `SpaceId`,
        // so we cannot trivially rewrite it to take advantage of `SpaceId::iter()`.
        while space_idx < spaces.len() {
            let space_id = spaces[space_idx];
            // Number of bytes available for frames if this is a 1-RTT packet. We're guaranteed to
            // be able to send an individual frame at least this large in the next 1-RTT
            // packet. This could be generalized to support every space, but it's only needed to
            // handle large fixed-size frames, which only exist in 1-RTT (application datagrams). We
            // don't account for coalesced packets potentially occupying space because frames can
            // always spill into the next datagram.
            let pn = self.packet_number_filter.peek(&self.spaces[SpaceId::Data]);
            let frame_space_1rtt =
                segment_size.saturating_sub(self.predict_1rtt_overhead(Some(pn)));

            // Is there data or a close message to send in this space?
            let can_send = self.space_can_send(space_id, frame_space_1rtt);
            if can_send.is_empty() && (!close || self.spaces[space_id].crypto.is_none()) {
                space_idx += 1;
                continue;
            }

            let mut ack_eliciting = !self.spaces[space_id].pending.is_empty(&self.streams)
                || self.spaces[space_id].ping_pending
                || self.spaces[space_id].immediate_ack_pending;
            if space_id == SpaceId::Data {
                ack_eliciting |= self.can_send_1rtt(frame_space_1rtt);
            }

            pad_datagram_to_mtu |= space_id == SpaceId::Data && self.config.pad_to_mtu;

            // Can we append more data into the current buffer?
            // It is not safe to assume that `buf.len()` is the end of the data,
            // since the last packet might not have been finished.
            let buf_end = if let Some(builder) = &builder_storage {
                buf.len().max(builder.min_size) + builder.tag_len
            } else {
                buf.len()
            };

            #[expect(
                clippy::expect_used,
                clippy::unreachable,
                reason = "`space_can_send` selected this space because it has keys: Initial/Handshake keep `crypto` until discarded and the Data space has 1-RTT keys or, before the handshake completes, the 0-RTT keys"
            )]
            let tag_len = if let Some(ref crypto) = self.spaces[space_id].crypto {
                crypto.packet.local.tag_len()
            } else if space_id == SpaceId::Data {
                self.zero_rtt_crypto.as_ref().expect(
                    "sending packets in the application data space requires known 0-RTT or 1-RTT keys",
                ).packet.tag_len()
            } else {
                unreachable!("tried to send {:?} packet without keys", space_id)
            };
            if !coalesce || buf_capacity - buf_end < MIN_PACKET_SPACE + tag_len {
                // We need to send 1 more datagram and extend the buffer for that.

                // Is 1 more datagram allowed?
                if num_datagrams >= max_datagrams {
                    // No more datagrams allowed
                    break;
                }

                // Anti-amplification is only based on `total_sent`, which gets
                // updated at the end of this method. Therefore we pass the amount
                // of bytes for datagrams that are already created, as well as 1 byte
                // for starting another datagram. If there is any anti-amplification
                // budget left, we always allow a full MTU to be sent
                if self
                    .path
                    .anti_amplification_blocked(segment_size as u64 * (num_datagrams as u64) + 1)
                {
                    trace!("blocked by anti-amplification");
                    break;
                }

                // Congestion control and pacing checks
                // Tail loss probes must not be blocked by congestion, or a deadlock could arise.
                // Close packets contain only ACKs and CONNECTION_CLOSE, neither of which is
                // congestion controlled, and must not be blocked either: `ack_eliciting` reflects
                // pending frames that will never be sent once closing, and a closed connection no
                // longer processes ACKs, so the window could never drain
                if ack_eliciting && self.spaces[space_id].loss_probes == 0 && !close {
                    // Assume the current packet will get padded to fill the segment
                    let untracked_bytes = if let Some(builder) = &builder_storage {
                        buf_capacity - builder.partial_encode.start
                    } else {
                        0
                    } as u64;
                    debug_assert!(untracked_bytes <= segment_size as u64);

                    let bytes_to_send = segment_size as u64 + untracked_bytes;
                    if self.path.in_flight.bytes + bytes_to_send > self.path.congestion.window() {
                        space_idx += 1;
                        congestion_blocked = true;
                        // We continue instead of breaking here in order to avoid
                        // blocking loss probes queued for higher spaces.
                        trace!("blocked by congestion control");
                        continue;
                    }

                    // Check whether the next datagram is blocked by pacing
                    let smoothed_rtt = self.path.rtt.get();
                    if let Some(delay) = self.path.pacing.delay(
                        smoothed_rtt,
                        bytes_to_send,
                        self.path.current_mtu(),
                        self.path.congestion.window(),
                        now,
                    ) {
                        self.timers.set(Timer::Pacing, delay);
                        congestion_blocked = true;
                        // Loss probes should be subject to pacing, even though
                        // they are not congestion controlled.
                        trace!("blocked by pacing");
                        break;
                    }
                }

                // Finish current packet
                if let Some(mut builder) = builder_storage.take() {
                    if pad_datagram {
                        builder.pad_to(MIN_INITIAL_SIZE);
                    }

                    if num_datagrams > 1 || pad_datagram_to_mtu {
                        // If too many padding bytes would be required to continue the GSO batch
                        // after this packet, end the GSO batch here. Ensures that fixed-size frames
                        // with heterogeneous sizes (e.g. application datagrams) won't inadvertently
                        // waste large amounts of bandwidth. The exact threshold is a bit arbitrary
                        // and might benefit from further tuning, though there's no universally
                        // optimal value.
                        //
                        // Additionally, if this datagram is a loss probe and `segment_size` is
                        // larger than `INITIAL_MTU`, then padding it to `segment_size` to continue
                        // the GSO batch would risk failure to recover from a reduction in path
                        // MTU. Loss probes are the only packets for which we might grow
                        // `buf_capacity` by less than `segment_size`.
                        const MAX_PADDING: usize = 16;
                        let packet_len_unpadded = cmp::max(builder.min_size, buf.len())
                            - datagram_start
                            + builder.tag_len;
                        if (packet_len_unpadded + MAX_PADDING < segment_size
                            && !pad_datagram_to_mtu)
                            || datagram_start + segment_size > buf_capacity
                        {
                            trace!(
                                "GSO truncated by demand for {} padding bytes or loss probe",
                                segment_size - packet_len_unpadded
                            );
                            builder_storage = Some(builder);
                            break;
                        }

                        // Pad the current datagram to GSO segment size so it can be included in the
                        // GSO batch.
                        builder.pad_to(segment_size as u16);
                    }

                    builder.finish_and_track(now, self, sent_frames.take(), buf);

                    if num_datagrams == 1 {
                        // Set the segment size for this GSO batch to the size of the first UDP
                        // datagram in the batch. Larger data that cannot be fragmented
                        // (e.g. application datagrams) will be included in a future batch. When
                        // sending large enough volumes of data for GSO to be useful, we expect
                        // packet sizes to usually be consistent, e.g. populated by max-size STREAM
                        // frames or uniformly sized datagrams.
                        segment_size = buf.len();
                        // Clip the unused capacity out of the buffer so future packets don't
                        // overrun
                        buf_capacity = buf.len();

                        // Check whether the data we planned to send will fit in the reduced segment
                        // size. If not, bail out and leave it for the next GSO batch so we don't
                        // end up trying to send an empty packet. We can't easily compute the right
                        // segment size before the original call to `space_can_send`, because at
                        // that time we haven't determined whether we're going to coalesce with the
                        // first datagram or potentially pad it to `MIN_INITIAL_SIZE`.
                        if space_id == SpaceId::Data {
                            let frame_space_1rtt =
                                segment_size.saturating_sub(self.predict_1rtt_overhead(Some(pn)));
                            if self.space_can_send(space_id, frame_space_1rtt).is_empty() {
                                break;
                            }
                        }
                    }
                }

                // Allocate space for another datagram
                let next_datagram_size_limit = match self.spaces[space_id].loss_probes {
                    0 => segment_size,
                    _ => {
                        self.spaces[space_id].loss_probes -= 1;
                        // Clamp the datagram to at most the minimum MTU to ensure that loss probes
                        // can get through and enable recovery even if the path MTU has shrank
                        // unexpectedly.
                        std::cmp::min(segment_size, usize::from(INITIAL_MTU))
                    }
                };
                buf_capacity += next_datagram_size_limit;
                if buf.capacity() < buf_capacity {
                    // We reserve the maximum space for sending `max_datagrams` upfront
                    // to avoid any reallocations if more datagrams have to be appended later on.
                    // Benchmarks have shown shown a 5-10% throughput improvement
                    // compared to continuously resizing the datagram buffer.
                    // While this will lead to over-allocation for small transmits
                    // (e.g. purely containing ACKs), modern memory allocators
                    // (e.g. mimalloc and jemalloc) will pool certain allocation sizes
                    // and therefore this is still rather efficient.
                    buf.reserve(max_datagrams * segment_size);
                }
                num_datagrams += 1;
                coalesce = true;
                pad_datagram = false;
                datagram_start = buf.len();

                debug_assert_eq!(
                    datagram_start % segment_size,
                    0,
                    "datagrams in a GSO batch must be aligned to the segment size"
                );
            } else {
                // We can append/coalesce the next packet into the current
                // datagram.
                // Finish current packet without adding extra padding
                if let Some(builder) = builder_storage.take() {
                    builder.finish_and_track(now, self, sent_frames.take(), buf);
                }
            }

            debug_assert!(buf_capacity - buf.len() >= MIN_PACKET_SPACE);

            //
            // From here on, we've determined that a packet will definitely be sent.
            //

            if self.spaces[SpaceId::Initial].crypto.is_some()
                && space_id == SpaceId::Handshake
                && self.side.is_client()
            {
                // A client stops both sending and processing Initial packets when it
                // sends its first Handshake packet.
                self.discard_space(now, SpaceId::Initial);
            }
            if let Some(ref mut prev) = self.prev_crypto {
                prev.update_unacked = false;
            }

            debug_assert!(
                builder_storage.is_none() && sent_frames.is_none(),
                "Previous packet must have been finished"
            );

            let builder = builder_storage.insert(PacketBuilder::new(
                now,
                space_id,
                self.rem_cids.active(),
                buf,
                buf_capacity,
                datagram_start,
                ack_eliciting,
                self,
            )?);
            coalesce = coalesce && !builder.short_header;

            // https://tools.ietf.org/html/draft-ietf-quic-transport-34#section-14.1
            pad_datagram |=
                space_id == SpaceId::Initial && (self.side.is_client() || ack_eliciting);

            if close {
                trace!("sending CONNECTION_CLOSE");
                // Encode ACKs before the ConnectionClose message, to give the receiver
                // a better approximate on what data has been processed. This is
                // especially important with ack delay, since the peer might not
                // have gotten any other ACK for the data earlier on.
                if !self.spaces[space_id].pending_acks.ranges().is_empty() {
                    Self::try_populate_acks(
                        now,
                        self.receiving_ecn,
                        &mut SentFrames::default(),
                        &mut self.spaces[space_id],
                        buf,
                        &mut self.stats,
                        buf_capacity,
                    );
                }

                // Since there only 64 ACK frames there will always be enough space
                // to encode the ConnectionClose frame too. However we still have the
                // check here to prevent crashes if something changes.
                debug_assert!(
                    buf.len() + frame::ConnectionClose::SIZE_BOUND < builder.max_size,
                    "ACKs should leave space for ConnectionClose"
                );
                if buf.len() + frame::ConnectionClose::SIZE_BOUND < builder.max_size {
                    let max_frame_size = builder.max_size - buf.len();
                    match self.state {
                        State::Closed(state::Closed { ref reason }) => {
                            if space_id == SpaceId::Data || reason.is_transport_layer() {
                                reason.encode(buf, max_frame_size)
                            } else {
                                frame::ConnectionClose {
                                    error_code: TransportErrorCode::APPLICATION_ERROR,
                                    frame_type: None,
                                    reason: Bytes::new(),
                                }
                                .encode(buf, max_frame_size)
                            }
                        }
                        State::Draining => frame::ConnectionClose {
                            error_code: TransportErrorCode::NO_ERROR,
                            frame_type: None,
                            reason: Bytes::new(),
                        }
                        .encode(buf, max_frame_size),
                        #[expect(
                            clippy::unreachable,
                            reason = "this block only runs when `close` is true, which `poll_transmit` computes solely for `State::Draining | State::Closed`"
                        )]
                        _ => unreachable!(
                            "tried to make a close packet when the connection wasn't closed"
                        ),
                    }
                }
                if space_id == self.highest_space {
                    // Don't send another close packet
                    self.close = false;
                    // `CONNECTION_CLOSE` is the final packet
                    break;
                } else {
                    // Send a close frame in every possible space for robustness, per RFC9000
                    // "Immediate Close during the Handshake". Don't bother trying to send anything
                    // else.
                    space_idx += 1;
                    continue;
                }
            }

            let sent =
                self.populate_packet(now, space_id, buf, builder.max_size, builder.exact_number);

            // ACK-only packets should only be sent when explicitly allowed. If we write them due to
            // any other reason, there is a bug which leads to one component announcing write
            // readiness while not writing any data. This degrades performance. The condition is
            // only checked if the full MTU is available and when potentially large fixed-size
            // frames aren't queued, so that lack of space in the datagram isn't the reason for just
            // writing ACKs.
            debug_assert!(
                !(sent.is_ack_only(&self.streams)
                    && !can_send.acks
                    && can_send.other
                    && (buf_capacity - builder.datagram_start) == self.path.current_mtu() as usize
                    && self.datagrams.outgoing.is_empty()),
                "SendableFrames was {can_send:?}, but only ACKs have been written"
            );
            pad_datagram |= sent.requires_padding;

            if sent.largest_acked.is_some() {
                self.spaces[space_id].pending_acks.acks_sent();
                self.timers.stop(Timer::MaxAckDelay);
                self.next_bundled_ack_time = Some(now + self.next_bundled_ack_delay());
            }

            // Keep information about the packet around until it gets finalized
            sent_frames = Some(sent);

            // Don't increment space_idx.
            // We stay in the current space and check if there is more data to send.
        }

        // Finish the last packet
        if let Some(mut builder) = builder_storage {
            if pad_datagram {
                builder.pad_to(MIN_INITIAL_SIZE);
            }

            // If this datagram is a loss probe and `segment_size` is larger than `INITIAL_MTU`,
            // then padding it to `segment_size` would risk failure to recover from a reduction in
            // path MTU.
            // Loss probes are the only packets for which we might grow `buf_capacity`
            // by less than `segment_size`.
            if pad_datagram_to_mtu && buf_capacity >= datagram_start + segment_size {
                builder.pad_to(segment_size as u16);
            }

            let last_packet_number = builder.exact_number;
            builder.finish_and_track(now, self, sent_frames, buf);
            self.path
                .congestion
                .on_sent(now, buf.len() as u64, last_packet_number);

            self.config.qlog_sink.emit_recovery_metrics(
                self.pto_count,
                &mut self.path,
                now,
                self.orig_rem_cid,
            );
        }

        self.app_limited = buf.is_empty() && !congestion_blocked;

        // Send MTU probe if necessary
        if buf.is_empty() && self.state.is_established() {
            let space_id = SpaceId::Data;
            let probe_size = self
                .path
                .mtud
                .poll_transmit(now, self.packet_number_filter.peek(&self.spaces[space_id]))?;

            let buf_capacity = probe_size as usize;
            buf.reserve(buf_capacity);

            let mut builder = PacketBuilder::new(
                now,
                space_id,
                self.rem_cids.active(),
                buf,
                buf_capacity,
                0,
                true,
                self,
            )?;

            // We implement MTU probes as ping packets padded up to the probe size
            buf.write(frame::FrameType::PING);
            self.stats.frame_tx.ping += 1;

            // If supported by the peer, we want no delays to the probe's ACK
            if self.peer_supports_ack_frequency() {
                buf.write(frame::FrameType::IMMEDIATE_ACK);
                self.stats.frame_tx.immediate_ack += 1;
            }

            builder.pad_to(probe_size);
            let sent_frames = SentFrames {
                non_retransmits: true,
                ..Default::default()
            };
            builder.finish_and_track(now, self, Some(sent_frames), buf);

            self.stats.path.sent_plpmtud_probes += 1;
            num_datagrams = 1;

            trace!(?probe_size, "writing MTUD probe");
        }

        if buf.is_empty() {
            return None;
        }

        trace!("sending {} bytes in {} datagrams", buf.len(), num_datagrams);
        self.path.total_sent = self.path.total_sent.saturating_add(buf.len() as u64);

        self.stats.udp_tx.on_sent(num_datagrams as u64, buf.len());

        Some(Transmit {
            destination: self.path.remote,
            size: buf.len(),
            cid_used: Some(self.rem_cids.active_seq()),
            ecn: if self.path.sending_ecn {
                Some(EcnCodepoint::Ect0)
            } else {
                None
            },
            segment_size: match num_datagrams {
                1 => None,
                _ => Some(segment_size),
            },
            local: self.path.local,
        })
    }

    /// Send PATH_CHALLENGE for a previous path if necessary
    fn send_path_challenge(&mut self, now: Instant, buf: &mut Vec<u8>) -> Option<Transmit> {
        let held = self.rem_cids.held();
        let active = (self.rem_cids.active(), self.rem_cids.active_seq());
        let PrevPath {
            path: prev_path,
            cid,
        } = self.prev_path.as_mut()?;
        if !prev_path.challenge_pending {
            return None;
        }
        prev_path.challenge_pending = false;
        // The previous path is only ever sent with the connection ID bound to it, from the local
        // address that path uses (RFC 9000 §9.5).
        let (prev_cid, prev_seq) = match cid {
            PrevCid::Held => held.map(|held| (held.id, held.seq))?,
            PrevCid::Active => active,
            PrevCid::Gone => return None,
        };
        let local = prev_path.local;
        #[expect(
            clippy::expect_used,
            reason = "`challenge_pending` is set together with `challenge` in `migrate` and cleared before `challenge` is"
        )]
        let token = prev_path
            .challenge
            .expect("previous path challenge pending without token");
        let destination = prev_path.remote;
        debug_assert_eq!(
            self.highest_space,
            SpaceId::Data,
            "PATH_CHALLENGE queued without 1-RTT keys"
        );
        buf.reserve(MIN_INITIAL_SIZE as usize);

        let buf_capacity = buf.capacity();

        let mut builder = PacketBuilder::new(
            now,
            SpaceId::Data,
            prev_cid,
            buf,
            buf_capacity,
            0,
            false,
            self,
        )?;
        trace!("validating previous path with PATH_CHALLENGE {:08x}", token);
        buf.write(frame::FrameType::PATH_CHALLENGE);
        buf.write(token);
        self.stats.frame_tx.path_challenge += 1;

        // An endpoint MUST expand datagrams that contain a PATH_CHALLENGE frame
        // to at least the smallest allowed maximum datagram size of 1200 bytes,
        // unless the anti-amplification limit for the path does not permit
        // sending a datagram of this size
        builder.pad_to(MIN_INITIAL_SIZE);

        builder.finish(self, now, buf);
        self.stats.udp_tx.on_sent(1, buf.len());

        Some(Transmit {
            destination,
            size: buf.len(),
            ecn: None,
            segment_size: None,
            local,
            cid_used: Some(prev_seq),
        })
    }

    /// Answer a PATH_CHALLENGE that arrived on a path other than the current one. The answer
    /// leaves on that path (RFC 9000 §8.2.2) and carries the identifier bound to it (§9.5);
    /// without such an identifier the answer is dropped and counted, because answering with one
    /// this connection sends elsewhere is exactly the reuse §9.5 forbids.
    fn send_off_path_response(&mut self, now: Instant, buf: &mut Vec<u8>) -> Option<Transmit> {
        if self.highest_space != SpaceId::Data || self.state.is_closed() {
            return None;
        }
        let (token, remote, local) = self
            .path_responses
            .pop_off_path(self.path.remote, self.path.local)?;
        let Some((cid, seq)) = self.cid_for_path(remote, local) else {
            self.stats.path.unanswered_off_path_challenges += 1;
            debug!(%remote, ?local, "no connection ID bound to that path: its answer is dropped");
            return None;
        };
        buf.reserve(MIN_INITIAL_SIZE as usize);
        let buf_capacity = buf.capacity();
        let mut builder =
            PacketBuilder::new(now, SpaceId::Data, cid, buf, buf_capacity, 0, false, self)?;
        trace!(%remote, ?local, "PATH_RESPONSE {:08x} (off-path)", token);
        buf.write(frame::FrameType::PATH_RESPONSE);
        buf.write(token);
        self.stats.frame_tx.path_response += 1;
        builder.pad_to(MIN_INITIAL_SIZE);
        builder.finish(self, now, buf);
        self.stats.udp_tx.on_sent(1, buf.len());
        Some(Transmit {
            destination: remote,
            size: buf.len(),
            ecn: None,
            segment_size: None,
            local,
            cid_used: Some(seq),
        })
    }

    /// The peer's connection ID this connection may send on the path (`remote`, `local`), with its
    /// sequence number. A path this connection does not send on has none.
    fn cid_for_path(
        &mut self,
        remote: SocketAddr,
        local: Option<SocketAddr>,
    ) -> Option<(ConnectionId, u64)> {
        if remote == self.path.remote && self.same_local(local) {
            return Some((self.rem_cids.active(), self.rem_cids.active_seq()));
        }
        if let Some(bound) = self
            .path_cids
            .iter()
            .flatten()
            .find(|bound| bound.remote == remote && bound.local == local)
        {
            return Some((bound.id, bound.seq));
        }
        if let Some(prev) = self.prev_path.as_ref()
            && prev.path.remote == remote
            && match (prev.path.local, local) {
                (Some(theirs), Some(ours)) => theirs == ours,
                _ => true,
            }
        {
            match prev.cid {
                PrevCid::Held => {
                    if let Some(held) = self.rem_cids.held() {
                        return Some((held.id, held.seq));
                    }
                }
                // A rebinding kept the identifier: the previous address already saw it.
                PrevCid::Active => {
                    return Some((self.rem_cids.active(), self.rem_cids.active_seq()));
                }
                // The identifier that path had is retired: it may take a fresh one of its own.
                PrevCid::Gone => {}
            }
        }
        self.bind_path_cid(remote, local)
    }

    /// Bind an unused identifier to the path (`remote`, `local`) so that what goes out there
    /// carries one that is sent from no other local address (RFC 9000 §9.5). The binding lasts as
    /// long as the identifier does: it never returns to the unused pool, and the connection can
    /// answer on as many such paths as the peer left it identifiers for. `None` means exhaustion.
    fn bind_path_cid(
        &mut self,
        remote: SocketAddr,
        local: Option<SocketAddr>,
    ) -> Option<(ConnectionId, u64)> {
        let slot = self.path_cids.iter().position(Option::is_none)?;
        // One identifier stays unused whatever arrives: a path we do not send on cannot spend
        // what a move of our own needs.
        let cid = self.rem_cids.bind_unused(1)?;
        // The endpoint routes a reset carrying this identifier's token to us from now on, so no
        // reset can arrive before the route exists; whether we treat such a reset as ours waits
        // for a datagram with it to have gone out.
        self.install_reset_route(cid.seq, remote);
        self.path_cids[slot] = Some(PathCid {
            remote,
            local,
            id: cid.id,
            seq: cid.seq,
            reset_token: cid.reset_token,
        });
        trace!(%remote, ?local, seq = cid.seq, "bound a connection ID to that path");
        Some((cid.id, cid.seq))
    }

    /// Let go of the identifier numbered `seq` and of the path it was bound to.
    fn drop_path_cid(&mut self, seq: u64) {
        for slot in &mut self.path_cids {
            if slot.is_some_and(|bound| bound.seq == seq) {
                *slot = None;
            }
        }
    }

    /// Indicate what types of frames are ready to send for the given space
    fn space_can_send(&self, space_id: SpaceId, frame_space_1rtt: usize) -> SendableFrames {
        if self.spaces[space_id].crypto.is_none()
            && (space_id != SpaceId::Data
                || self.zero_rtt_crypto.is_none()
                || self.side.is_server())
        {
            // No keys available for this space
            return SendableFrames::empty();
        }
        let mut can_send = self.spaces[space_id].can_send(&self.streams);
        if space_id == SpaceId::Data {
            can_send.other |= self.can_send_1rtt(frame_space_1rtt);
        }
        can_send
    }

    /// The delay to wait after sending an ACK before bundling the next one.
    ///
    /// This delay prevents waste of peer's resources with processing bundled
    /// ACKs unnecessarily frequently.
    ///
    /// If we receive an ack-eliciting packet while this delay is still pending,
    /// `next_bundled_ack_time` is reset to `now`, which means this delay will be ignored.
    /// So this delay only matters when we keep sending but stop receiving ack-eliciting
    /// packets for a while.
    ///
    /// This should be at least `RTT + peer's max_ack_delay`: since a bundled ACK frame rides
    /// along with an ack-eliciting frame, the packet carrying it is itself ack-eliciting.
    /// We should give the peer enough time to acknowledge it.
    /// Otherwise, we risk bundling another ACK before the peer has even had a chance
    /// to acknowledge the previous one, which is a waste of remote peer's resources.
    fn next_bundled_ack_delay(&self) -> Duration {
        self.path.rtt.get() + self.ack_frequency.peer_max_ack_delay + TIMER_GRANULARITY
    }

    /// Process `ConnectionEvent`s generated by the associated `Endpoint`
    ///
    /// Will execute protocol logic upon receipt of a connection event, in turn preparing signals
    /// (including application `Event`s, `EndpointEvent`s and outgoing datagrams) that should be
    /// extracted through the relevant methods.
    pub(crate) fn handle_event(&mut self, event: ConnectionEvent) {
        use ConnectionEventInner::*;
        match event.0 {
            Datagram(DatagramConnectionEvent {
                now,
                remote,
                local,
                ecn,
                first_decode,
                remaining,
            }) => {
                // If this packet could initiate a migration and we're a client or a server that
                // forbids migration, drop the datagram. This could be relaxed to heuristically
                // permit NAT-rebinding-like migration.
                if remote != self.path.remote
                    && !self.side.remote_may_migrate()
                    && !self.probing_address(remote)
                {
                    trace!("discarding packet from unrecognized peer {}", remote);
                    return;
                }

                let was_anti_amplification_blocked = self.path.anti_amplification_blocked(1);

                self.stats.udp_rx.datagrams += 1;
                self.stats.udp_rx.bytes += first_decode.len() as u64;
                let data_len = first_decode.len();

                self.handle_decode(now, remote, local, ecn, first_decode);
                // The current `path` might have changed inside `handle_decode`,
                // since the packet could have triggered a migration. Make sure
                // the data received is accounted for the most recent path by accessing
                // `path` after `handle_decode`.
                self.path.total_recvd = self.path.total_recvd.saturating_add(data_len as u64);

                if let Some(data) = remaining {
                    self.stats.udp_rx.bytes += data.len() as u64;
                    self.handle_coalesced(now, remote, local, ecn, data);
                }

                self.config.qlog_sink.emit_recovery_metrics(
                    self.pto_count,
                    &mut self.path,
                    now,
                    self.orig_rem_cid,
                );

                if was_anti_amplification_blocked {
                    // A prior attempt to set the loss detection timer may have failed due to
                    // anti-amplification, so ensure it's set now. Prevents a handshake deadlock if
                    // the server's first flight is lost.
                    self.set_loss_detection_timer(now);
                }
            }
            NewIdentifiers(ids, now) => {
                self.local_cid_state.new_cids(&ids, now);
                ids.into_iter().rev().for_each(|frame| {
                    self.spaces[SpaceId::Data].pending.new_cids.push(frame);
                });
                // Update Timer::PushNewCid
                if self.timers.get(Timer::PushNewCid).is_none_or(|x| x <= now) {
                    self.reset_cid_retirement();
                }
            }
            ResetRouteInstalled(remote, seq, generation) => {
                // An acknowledgement naming an installation this identifier no longer has — a
                // retired one, or one a newer installation replaced — has nothing to open.
                self.rem_cids.route_installed(seq, remote, generation);
            }
            ResetRouteRefused(remote, seq, generation) => {
                // There is nowhere to route a reset for this identifier, so the datagram waiting
                // on it can never leave. That is a failure of ours, and it ends the connection
                // with its cause rather than leaving it silently stuck (or opening the gate).
                if self.rem_cids.route_refused(seq, remote, generation) {
                    self.defer_error(TransportError::INTERNAL_ERROR(
                        "no room to route a stateless reset for a connection ID",
                    ));
                }
            }
        }
    }

    /// Enforce the handshake lifetime before processing queued packets in the async driver.
    pub(crate) fn expire_handshake(&mut self, now: Instant) {
        if self.timers.is_expired(Timer::Handshake, now) {
            self.kill(ConnectionError::TimedOut);
        }
    }

    /// Process timer expirations
    ///
    /// Executes protocol logic, potentially preparing signals (including application `Event`s,
    /// `EndpointEvent`s and outgoing datagrams) that should be extracted through the relevant
    /// methods.
    ///
    /// It is most efficient to call this immediately after the system clock reaches the latest
    /// `Instant` that was output by `poll_timeout`; however spurious extra calls will simply
    /// no-op and therefore are safe.
    pub(crate) fn handle_timeout(&mut self, now: Instant) {
        for &timer in &Timer::VALUES {
            if !self.timers.is_expired(timer, now) {
                continue;
            }
            self.timers.stop(timer);
            trace!(timer = ?timer, "timeout");
            match timer {
                Timer::Close => {
                    self.state = State::Drained;
                    self.endpoint_events.push_back(EndpointEventInner::Drained);
                }
                Timer::Idle | Timer::Handshake => {
                    self.kill(ConnectionError::TimedOut);
                }
                Timer::KeepAlive => {
                    trace!("sending keep-alive");
                    self.ping();
                }
                Timer::LossDetection => {
                    self.on_loss_detection_timeout(now);

                    self.config.qlog_sink.emit_recovery_metrics(
                        self.pto_count,
                        &mut self.path,
                        now,
                        self.orig_rem_cid,
                    );
                }
                Timer::KeyDiscard => {
                    self.zero_rtt_crypto = None;
                    self.prev_crypto = None;
                }
                Timer::PathValidation => {
                    debug!("path validation failed");
                    self.abandon_current_path(now);
                }
                Timer::PathProbe => self.on_probe_timeout(now),
                Timer::Pacing => trace!("pacing timer expired"),
                Timer::PushNewCid => {
                    // Update `retire_prior_to` field in NEW_CONNECTION_ID frame
                    let num_new_cid = self.local_cid_state.on_cid_timeout().into();
                    if !self.state.is_closed() {
                        trace!(
                            "push a new cid to peer RETIRE_PRIOR_TO field {}",
                            self.local_cid_state.retire_prior_to()
                        );
                        self.endpoint_events
                            .push_back(EndpointEventInner::NeedIdentifiers(now, num_new_cid));
                    }
                }
                Timer::MaxAckDelay => {
                    trace!("max ack delay reached");
                    // This timer is only armed in the Data space
                    self.spaces[SpaceId::Data]
                        .pending_acks
                        .on_max_ack_delay_timeout()
                }
            }
        }
    }

    /// Close a connection immediately
    ///
    /// This does not ensure delivery of outstanding data. It is the application's responsibility to
    /// call this only when all important communications have been completed, e.g. by calling
    /// [`SendStream::finish`] on outstanding streams and waiting for the corresponding
    /// [`StreamEvent::Finished`] event.
    ///
    /// If [`Streams::send_streams`] returns 0, all outstanding stream data has been
    /// delivered. There may still be data from the peer that has not been received.
    ///
    /// [`StreamEvent::Finished`]: crate::proto::StreamEvent::Finished
    pub(crate) fn close(&mut self, now: Instant, error_code: VarInt, reason: Bytes) {
        self.close_inner(
            now,
            Close::Application(frame::ApplicationClose { error_code, reason }),
        )
    }

    fn close_inner(&mut self, now: Instant, reason: Close) {
        let was_closed = self.state.is_closed();
        if !was_closed {
            self.close_common();
            self.set_close_timer(now);
            self.close = true;
            self.state = State::Closed(state::Closed { reason });
        }
    }

    /// Control datagrams
    pub(crate) fn datagrams(&mut self) -> Datagrams<'_> {
        Datagrams { conn: self }
    }

    /// Returns connection statistics
    pub(crate) fn stats(&self) -> ConnectionStats {
        let mut stats = self.stats;
        stats.path.rtt = self.path.rtt.get();
        stats.path.min_rtt = self.path.rtt.min();
        stats.path.cwnd = self.path.congestion.window();
        stats.path.current_mtu = self.path.mtud.current_mtu();

        stats
    }

    /// Ping the remote endpoint
    ///
    /// Causes an ACK-eliciting packet to be transmitted.
    pub(crate) fn ping(&mut self) {
        self.spaces[self.highest_space].ping_pending = true;
    }

    /// Update traffic keys spontaneously
    ///
    /// This can be useful for testing key updates, as they otherwise only happen infrequently.
    pub(crate) fn force_key_update(&mut self) {
        if !self.state.is_established() {
            debug!("ignoring forced key update in illegal state");
            return;
        }
        if self.prev_crypto.is_some() {
            // We already just updated, or are currently updating, the keys. Concurrent key updates
            // are illegal.
            debug!("ignoring redundant forced key update");
            return;
        }
        self.update_keys(None, false);
    }

    /// Get a session reference
    pub(crate) fn crypto_session(&self) -> &dyn crypto::Session {
        &*self.crypto
    }

    /// Whether the connection is in the process of being established
    ///
    /// If this returns `false`, the connection may be either established or closed, signaled by the
    /// emission of a `Connected` or `ConnectionLost` message respectively.
    pub(crate) fn is_handshaking(&self) -> bool {
        self.state.is_handshake()
    }

    /// Whether the handshake is confirmed (RFC 9001 §4.1.2): the server confirms it on
    /// completion, the client once HANDSHAKE_DONE arrived and its Handshake keys are gone.
    /// Active migration is only allowed from then on (RFC 9000 §9).
    pub(crate) fn handshake_confirmed(&self) -> bool {
        !self.state.is_handshake()
            && (self.side.is_server() || self.spaces[SpaceId::Handshake].crypto.is_none())
    }

    /// Whether the peer's transport parameters allow this endpoint to migrate actively.
    /// Meaningful once the handshake is confirmed.
    pub(crate) fn peer_allows_active_migration(&self) -> bool {
        !self.peer_params.disable_active_migration
    }

    /// Whether the connection is closed
    ///
    /// Closed connections cannot transport any further data. A connection becomes closed when
    /// either peer application intentionally closes it, or when either transport layer detects an
    /// error such as a time-out or certificate validation failure.
    ///
    /// A `ConnectionLost` event is emitted with details when the connection becomes closed.
    pub(crate) fn is_closed(&self) -> bool {
        self.state.is_closed()
    }

    /// Whether there is no longer any need to keep the connection around
    ///
    /// Closed connections become drained after a brief timeout to absorb any remaining in-flight
    /// packets from the peer. All drained connections have been closed.
    pub(crate) fn is_drained(&self) -> bool {
        self.state.is_drained()
    }

    /// For clients, if the peer accepted the 0-RTT data packets
    ///
    /// The value is meaningless until after the handshake completes.
    pub(crate) fn accepted_0rtt(&self) -> bool {
        self.accepted_0rtt
    }

    /// Whether 0-RTT is/was possible during the handshake
    pub(crate) fn has_0rtt(&self) -> bool {
        self.zero_rtt_enabled
    }

    /// Whether there are any pending retransmits
    pub(crate) fn has_pending_retransmits(&self) -> bool {
        !self.spaces[SpaceId::Data].pending.is_empty(&self.streams)
    }

    /// Look up whether we're the client or server of this Connection
    pub(crate) fn side(&self) -> Side {
        self.side.side()
    }

    /// The latest socket address for this connection's peer
    pub(crate) fn remote_address(&self) -> SocketAddr {
        self.path.remote
    }

    /// The local IP address this connection's packets currently arrive on.
    ///
    /// This can be different from the address the endpoint is bound to, in case
    /// the endpoint is bound to a wildcard address like `0.0.0.0` or `::`.
    ///
    /// It is the local IP of the connection's current path, so it follows a migration between
    /// local sockets. `None` when no local address was passed to
    /// [`Endpoint::handle()`](crate::proto::Endpoint::handle) for this path's datagrams.
    pub(crate) fn local_ip(&self) -> Option<IpAddr> {
        self.path
            .local
            .map(|local| local.ip())
            .filter(|ip| !ip.is_unspecified())
    }

    /// Current best estimate of this connection's latency (round-trip-time)
    pub(crate) fn rtt(&self) -> Duration {
        self.path.rtt.get()
    }

    /// Minimum RTT seen on this path, ignoring ack delay
    pub(crate) fn min_rtt(&self) -> Duration {
        self.path.rtt.min()
    }

    /// Current state of this connection's congestion controller, for debugging purposes
    pub(crate) fn congestion_state(&self) -> &dyn Controller {
        self.path.congestion.as_ref()
    }

    /// Resets path-specific settings.
    ///
    /// This will force-reset several subsystems related to a specific network path.
    /// Currently this is the congestion controller, round-trip estimator, and the MTU
    /// discovery.
    ///
    /// This is useful when it is known the underlying network path has changed and the old
    /// state of these subsystems is no longer valid or optimal. In this case it might be
    /// faster or reduce loss to settle on optimal values by restarting from the initial
    /// configuration in the [`TransportConfig`].
    pub(crate) fn path_changed(&mut self, now: Instant) {
        self.path.reset(now, &self.config);
    }

    /// Modify the number of remotely initiated streams that may be concurrently open
    ///
    /// No streams may be opened by the peer unless fewer than `count` are already open. Large
    /// `count`s increase both minimum and worst-case memory consumption.
    pub(crate) fn set_max_concurrent_streams(&mut self, dir: Dir, count: VarInt) {
        self.streams.set_max_concurrent(dir, count);
        // If the limit was reduced, then a flow control update previously deemed insignificant may
        // now be significant.
        let pending = &mut self.spaces[SpaceId::Data].pending;
        self.streams.queue_max_stream_id(pending);
    }

    /// Current number of remotely initiated streams that may be concurrently open
    ///
    /// If the target for this limit is reduced using [`set_max_concurrent_streams`](Self::set_max_concurrent_streams),
    /// it will not change immediately, even if fewer streams are open. Instead, it will
    /// decrement by one for each time a remotely initiated stream of matching directionality is closed.
    pub(crate) fn max_concurrent_streams(&self, dir: Dir) -> u64 {
        self.streams.max_concurrent(dir)
    }

    /// See [`TransportConfig::send_window()`]
    pub(crate) fn set_send_window(&mut self, send_window: u64) {
        self.streams.set_send_window(send_window);
    }

    /// See [`TransportConfig::receive_window()`]
    pub(crate) fn set_receive_window(&mut self, receive_window: VarInt) {
        if self.streams.set_receive_window(receive_window) {
            self.spaces[SpaceId::Data].pending.max_data = true;
        }
    }

    fn on_ack_received(
        &mut self,
        now: Instant,
        space: SpaceId,
        ack: frame::Ack,
    ) -> Result<(), TransportError> {
        if ack.largest >= self.spaces[space].next_packet_number {
            return Err(TransportError::PROTOCOL_VIOLATION("unsent packet acked"));
        }
        let new_largest = {
            let space = &mut self.spaces[space];
            if space.largest_acked_packet.is_none_or(|pn| ack.largest > pn) {
                space.largest_acked_packet = Some(ack.largest);
                if let Some(info) = space.sent_packets.get(&ack.largest) {
                    // This should always succeed, but a misbehaving peer might ACK a packet we
                    // haven't sent. At worst, that will result in us spuriously reducing the
                    // congestion window.
                    space.largest_acked_packet_sent = info.time_sent;
                }
                true
            } else {
                false
            }
        };

        // Avoid DoS from unreasonably huge ack ranges by filtering out just the new acks.
        let mut newly_acked = ArrayRangeSet::new();
        for range in ack.iter() {
            self.packet_number_filter.check_ack(space, range.clone())?;
            for (&pn, _) in self.spaces[space].sent_packets.range(range) {
                newly_acked.insert_one(pn);
            }
        }

        if newly_acked.is_empty() {
            return Ok(());
        }

        let mut ack_eliciting_acked = false;
        for packet in newly_acked.elts() {
            if let Some(info) = self.spaces[space].take(packet) {
                if let Some(acked) = info.largest_acked {
                    // Assume ACKs for all packets below the largest acknowledged in `packet` have
                    // been received. This can cause the peer to spuriously retransmit if some of
                    // our earlier ACKs were lost, but allows for simpler state tracking. See
                    // discussion at
                    // https://www.rfc-editor.org/rfc/rfc9000.html#name-limiting-ranges-by-tracking
                    self.spaces[space].pending_acks.subtract_below(acked);
                }
                ack_eliciting_acked |= info.ack_eliciting;

                // Notify MTU discovery that a packet was acked, because it might be an MTU probe
                let mtu_updated = self.path.mtud.on_acked(space, packet, info.size);
                if mtu_updated {
                    self.path
                        .congestion
                        .on_mtu_update(self.path.mtud.current_mtu());
                }

                // Notify ack frequency that a packet was acked, because it might contain an ACK_FREQUENCY frame
                self.ack_frequency.on_acked(packet);

                self.on_packet_acked(now, info);
            }
        }

        self.path.congestion.on_end_acks(
            now,
            self.path.in_flight.bytes,
            self.app_limited,
            self.spaces[space].largest_acked_packet,
        );

        if new_largest && ack_eliciting_acked {
            let ack_delay = if space != SpaceId::Data {
                Duration::from_micros(0)
            } else {
                cmp::min(
                    self.ack_frequency.peer_max_ack_delay,
                    Duration::from_micros(ack.delay << self.peer_params.ack_delay_exponent.0),
                )
            };
            let rtt = now.saturating_duration_since(self.spaces[space].largest_acked_packet_sent);
            self.path.rtt.update(ack_delay, rtt);
            if self.path.first_packet_after_rtt_sample.is_none() {
                self.path.first_packet_after_rtt_sample =
                    Some((space, self.spaces[space].next_packet_number));
            }
        }

        // Must be called before crypto/pto_count are clobbered
        self.detect_lost_packets(now, space, true);

        if self.peer_completed_address_validation() {
            self.pto_count = 0;
        }

        // Explicit congestion notification
        if self.path.sending_ecn {
            if let Some(ecn) = ack.ecn {
                // We only examine ECN counters from ACKs that we are certain we received in transmit
                // order, allowing us to compute an increase in ECN counts to compare against the number
                // of newly acked packets that remains well-defined in the presence of arbitrary packet
                // reordering.
                if new_largest {
                    let sent = self.spaces[space].largest_acked_packet_sent;
                    self.process_ecn(now, space, newly_acked.len() as u64, ecn, sent);
                }
            } else {
                // We always start out sending ECN, so any ack that doesn't acknowledge it disables it.
                debug!("ECN not acknowledged by peer");
                self.path.sending_ecn = false;
            }
        }

        self.set_loss_detection_timer(now);
        Ok(())
    }

    /// Process a new ECN block from an in-order ACK
    fn process_ecn(
        &mut self,
        now: Instant,
        space: SpaceId,
        newly_acked: u64,
        ecn: frame::EcnCounts,
        largest_sent_time: Instant,
    ) {
        match self.spaces[space].detect_ecn(newly_acked, ecn) {
            Err(e) => {
                debug!("halting ECN due to verification failure: {}", e);
                self.path.sending_ecn = false;
                // Wipe out the existing value because it might be garbage and could interfere with
                // future attempts to use ECN on new paths.
                self.spaces[space].ecn_feedback = frame::EcnCounts::ZERO;
            }
            Ok(false) => {}
            Ok(true) => {
                self.stats.path.congestion_events += 1;
                self.path
                    .congestion
                    .on_congestion_event(now, largest_sent_time, false, 0);
            }
        }
    }

    // Not timing-aware, so it's safe to call this for inferred acks, such as arise from
    // high-latency handshakes
    fn on_packet_acked(&mut self, now: Instant, info: SentPacket) {
        self.remove_in_flight(&info);
        if info.ack_eliciting && self.path.challenge.is_none() {
            // Only pass ACKs to the congestion controller if we are not validating the current
            // path, so as to ignore any ACKs from older paths still coming in.
            self.path.congestion.on_ack(
                now,
                info.time_sent,
                info.size.into(),
                self.app_limited,
                &self.path.rtt,
            );
        }

        // Update state for confirmed delivery of frames
        if let Some(retransmits) = info.retransmits.get() {
            for (id, _) in retransmits.reset_stream.iter() {
                self.streams.reset_acked(*id);
            }
        }

        for frame in info.stream_frames {
            self.streams.received_ack_of(frame);
        }
    }

    fn set_key_discard_timer(&mut self, now: Instant, space: SpaceId) {
        #[expect(
            clippy::expect_used,
            reason = "without 0-RTT keys the discard timer is only armed after `upgrade_crypto`/`update_keys` moved the previous keys into `prev_crypto`"
        )]
        let start = if self.zero_rtt_crypto.is_some() {
            now
        } else {
            self.prev_crypto
                .as_ref()
                .expect("no previous keys")
                .end_packet
                .as_ref()
                .expect("update not acknowledged yet")
                .1
        };
        self.timers
            .set(Timer::KeyDiscard, start + self.pto(space) * 3);
    }

    fn on_loss_detection_timeout(&mut self, now: Instant) {
        if let Some((_, pn_space)) = self.loss_time_and_space() {
            // Time threshold loss Detection
            self.detect_lost_packets(now, pn_space, false);
            self.set_loss_detection_timer(now);
            return;
        }

        if self.in_flight_ack_eliciting() == 0 && self.peer_completed_address_validation() {
            // No ack-eliciting packet is outstanding in any packet number space: everything sent
            // was acknowledged, declared lost or abandoned after this timer was set, so there is
            // nothing to probe. Re-evaluating the timer stops it. (Replacing or dropping a path
            // does not remove its packets from the spaces and does not reach this branch.)
            self.set_loss_detection_timer(now);
            return;
        }
        let (_, space) = match self.pto_time_and_space(now) {
            Some(x) => x,
            None => {
                error!("PTO expired while unset");
                return;
            }
        };
        trace!(
            in_flight = self.path.in_flight.bytes,
            count = self.pto_count,
            ?space,
            "PTO fired"
        );

        let count = match self.in_flight_ack_eliciting() {
            // A PTO when we're not expecting any ACKs must be due to handshake anti-amplification
            // deadlock preventions
            0 => {
                debug_assert!(!self.peer_completed_address_validation());
                1
            }
            // Conventional loss probe
            _ => 2,
        };
        self.spaces[space].loss_probes = self.spaces[space].loss_probes.saturating_add(count);
        self.pto_count = self.pto_count.saturating_add(1);
        self.set_loss_detection_timer(now);
    }

    fn detect_lost_packets(&mut self, now: Instant, pn_space: SpaceId, due_to_ack: bool) {
        let mut lost_packets = Vec::<u64>::new();
        let mut lost_mtu_probe = None;
        let in_flight_mtu_probe = self.path.mtud.in_flight_mtu_probe();
        let rtt = self.path.rtt.conservative();
        let loss_delay = cmp::max(rtt.mul_f32(self.config.time_threshold), TIMER_GRANULARITY);

        #[expect(
            clippy::unwrap_used,
            reason = "`detect_lost_packets` runs from `on_ack_received` after setting `largest_acked_packet`, and the loss timer is only armed once a packet of the space was acknowledged"
        )]
        let largest_acked_packet = self.spaces[pn_space].largest_acked_packet.unwrap();
        let packet_threshold = self.config.packet_threshold as u64;
        let mut size_of_lost_packets = 0u64;

        // InPersistentCongestion: Determine if all packets in the time period before the newest
        // lost packet, including the edges, are marked lost. PTO computation must always
        // include max ACK delay, i.e. operate as if in Data space (see RFC9001 §7.6.1).
        let congestion_period = persistent_congestion_period(
            self.pto(SpaceId::Data),
            self.config.persistent_congestion_threshold,
        );
        let mut persistent_congestion_start: Option<Instant> = None;
        let mut prev_packet = None;
        let mut in_persistent_congestion = false;

        let space = &mut self.spaces[pn_space];
        space.loss_time = None;

        for (&packet, info) in space.sent_packets.range(0..largest_acked_packet) {
            if prev_packet != Some(packet.wrapping_sub(1)) {
                // An intervening packet was acknowledged
                persistent_congestion_start = None;
            }

            // Packets sent before now - loss_delay are deemed lost.
            // However, we avoid this subtraction as it can panic and there's no
            // saturating equivalent of this substraction operation with a Duration.
            let packet_too_old = now.saturating_duration_since(info.time_sent) >= loss_delay;
            if packet_too_old || largest_acked_packet >= packet + packet_threshold {
                if Some(packet) == in_flight_mtu_probe {
                    // Lost MTU probes are not included in `lost_packets`, because they should not
                    // trigger a congestion control response
                    lost_mtu_probe = in_flight_mtu_probe;
                } else {
                    lost_packets.push(packet);
                    size_of_lost_packets += info.size as u64;
                    if info.ack_eliciting && due_to_ack {
                        match persistent_congestion_start {
                            // Two ACK-eliciting packets lost more than congestion_period apart, with no
                            // ACKed packets in between
                            Some(start) if info.time_sent - start > congestion_period => {
                                in_persistent_congestion = true;
                            }
                            // Persistent congestion must start after the first RTT sample
                            None if self
                                .path
                                .first_packet_after_rtt_sample
                                .is_some_and(|x| x < (pn_space, packet)) =>
                            {
                                persistent_congestion_start = Some(info.time_sent);
                            }
                            _ => {}
                        }
                    }
                }
            } else {
                let next_loss_time = info.time_sent + loss_delay;
                space.loss_time = Some(
                    space
                        .loss_time
                        .map_or(next_loss_time, |x| cmp::min(x, next_loss_time)),
                );
                persistent_congestion_start = None;
            }

            prev_packet = Some(packet);
        }

        // OnPacketsLost
        if let Some(largest_lost) = lost_packets.last().cloned() {
            let old_bytes_in_flight = self.path.in_flight.bytes;
            let largest_lost_sent = self.spaces[pn_space].sent_packets[&largest_lost].time_sent;
            self.stats.path.lost_packets += lost_packets.len() as u64;
            self.stats.path.lost_bytes += size_of_lost_packets;
            trace!(
                "packets lost: {:?}, bytes lost: {}",
                lost_packets, size_of_lost_packets
            );

            for &packet in &lost_packets {
                #[expect(
                    clippy::unwrap_used,
                    reason = "`lost_packets` was collected from this space's `sent_packets` in the loop above and nothing removed entries since"
                )]
                let info = self.spaces[pn_space].take(packet).unwrap(); // safe: lost_packets is populated just above
                self.config.qlog_sink.emit_packet_lost(
                    packet,
                    &info,
                    loss_delay,
                    pn_space,
                    now,
                    self.orig_rem_cid,
                );
                self.remove_in_flight(&info);
                for frame in info.stream_frames {
                    self.streams.retransmit(frame);
                }
                self.spaces[pn_space].pending |= info.retransmits;
                self.path.mtud.on_non_probe_lost(packet, info.size);
            }

            if self.path.mtud.black_hole_detected(now) {
                self.stats.path.black_holes_detected += 1;
                self.path
                    .congestion
                    .on_mtu_update(self.path.mtud.current_mtu());
                if let Some(max_datagram_size) = self.datagrams().max_size() {
                    if self.datagrams.drop_oversized(max_datagram_size)
                        && self.datagrams.send_blocked
                    {
                        self.datagrams.send_blocked = false;
                        self.events.push_back(Event::DatagramsUnblocked);
                    }
                }
            }

            // Don't apply congestion penalty for lost ack-only packets
            let lost_ack_eliciting = old_bytes_in_flight != self.path.in_flight.bytes;

            if lost_ack_eliciting {
                self.stats.path.congestion_events += 1;
                self.path.congestion.on_congestion_event(
                    now,
                    largest_lost_sent,
                    in_persistent_congestion,
                    size_of_lost_packets,
                );
            }
        }

        // Handle a lost MTU probe
        if let Some(packet) = lost_mtu_probe {
            #[expect(
                clippy::unwrap_used,
                reason = "the lost MTU probe is excluded from `lost_packets`, so it is still in `sent_packets`"
            )]
            let info = self.spaces[SpaceId::Data].take(packet).unwrap(); // safe: lost_mtu_probe is omitted from lost_packets, and therefore must not have been removed yet
            self.remove_in_flight(&info);
            self.path.mtud.on_probe_lost();
            self.stats.path.lost_plpmtud_probes += 1;
        }
    }

    fn loss_time_and_space(&self) -> Option<(Instant, SpaceId)> {
        SpaceId::iter()
            .filter_map(|id| Some((self.spaces[id].loss_time?, id)))
            .min_by_key(|&(time, _)| time)
    }

    /// Ack-eliciting packets awaiting acknowledgement anywhere on the connection: packets sent on
    /// a path that a migration or a failed validation has since discarded still count, so the
    /// PTO keeps probing until they are acknowledged or declared lost (RFC 9002 §6.2.1: the PTO
    /// covers all packet number spaces, independent of the path).
    fn in_flight_ack_eliciting(&self) -> u64 {
        self.in_flight_ack_eliciting
    }

    fn pto_time_and_space(&self, now: Instant) -> Option<(Instant, SpaceId)> {
        let backoff = 2u32.pow(self.pto_count.min(MAX_BACKOFF_EXPONENT));
        let mut duration = self.path.rtt.pto_base() * backoff;

        if self.in_flight_ack_eliciting() == 0 {
            debug_assert!(!self.peer_completed_address_validation());
            let space = match self.highest_space {
                SpaceId::Handshake => SpaceId::Handshake,
                _ => SpaceId::Initial,
            };
            return Some((now + duration, space));
        }

        let mut result = None;
        for space in SpaceId::iter() {
            if !self.spaces[space].has_in_flight() {
                continue;
            }
            if space == SpaceId::Data {
                // Skip ApplicationData until handshake completes.
                if self.is_handshaking() {
                    return result;
                }
                // Include max_ack_delay and backoff for ApplicationData.
                duration += self.ack_frequency.max_ack_delay_for_pto() * backoff;
            }
            let last_ack_eliciting = match self.spaces[space].time_of_last_ack_eliciting_packet {
                Some(time) => time,
                None => continue,
            };
            let pto = last_ack_eliciting + duration;
            if result.is_none_or(|(earliest_pto, _)| pto < earliest_pto) {
                result = Some((pto, space));
            }
        }
        result
    }

    fn peer_completed_address_validation(&self) -> bool {
        if self.side.is_server() || self.state.is_closed() {
            return true;
        }
        // The server is guaranteed to have validated our address if any of our handshake or 1-RTT
        // packets are acknowledged or we've seen HANDSHAKE_DONE and discarded handshake keys.
        self.spaces[SpaceId::Handshake]
            .largest_acked_packet
            .is_some()
            || self.spaces[SpaceId::Data].largest_acked_packet.is_some()
            || (self.spaces[SpaceId::Data].crypto.is_some()
                && self.spaces[SpaceId::Handshake].crypto.is_none())
    }

    fn set_loss_detection_timer(&mut self, now: Instant) {
        if self.state.is_closed() {
            // No loss detection takes place on closed connections, and `close_common` already
            // stopped time timer. Ensure we don't restart it inadvertently, e.g. in response to a
            // reordered packet being handled by state-insensitive code.
            return;
        }

        if let Some((loss_time, _)) = self.loss_time_and_space() {
            // Time threshold loss detection.
            self.timers.set(Timer::LossDetection, loss_time);
            return;
        }

        if self.path.anti_amplification_blocked(1) {
            // We wouldn't be able to send anything, so don't bother.
            self.timers.stop(Timer::LossDetection);
            return;
        }

        if self.in_flight_ack_eliciting() == 0 && self.peer_completed_address_validation() {
            // There is nothing to detect lost, so no timer is set. However, the client needs to arm
            // the timer if the server might be blocked by the anti-amplification limit.
            self.timers.stop(Timer::LossDetection);
            return;
        }

        // Determine which PN space to arm PTO for.
        // Calculate PTO duration
        if let Some((timeout, _)) = self.pto_time_and_space(now) {
            self.timers.set(Timer::LossDetection, timeout);
        } else {
            self.timers.stop(Timer::LossDetection);
        }
    }

    /// Probe Timeout
    fn pto(&self, space: SpaceId) -> Duration {
        let max_ack_delay = match space {
            SpaceId::Initial | SpaceId::Handshake => Duration::ZERO,
            SpaceId::Data => self.ack_frequency.max_ack_delay_for_pto(),
        };
        self.path.rtt.pto_base() + max_ack_delay
    }

    fn on_packet_authenticated(
        &mut self,
        now: Instant,
        space_id: SpaceId,
        ecn: Option<EcnCodepoint>,
        packet: Option<u64>,
        spin: bool,
        is_1rtt: bool,
    ) {
        self.total_authed_packets += 1;
        self.reset_keep_alive(now);
        self.reset_idle_timeout(now, space_id);
        self.permit_idle_reset = true;
        self.receiving_ecn |= ecn.is_some();
        if let Some(x) = ecn {
            let space = &mut self.spaces[space_id];
            space.ecn_counters += x;

            if x.is_ce() {
                space.pending_acks.set_immediate_ack_required();
            }
        }

        let packet = match packet {
            Some(x) => x,
            None => return,
        };
        if self.side.is_server() {
            if self.spaces[SpaceId::Initial].crypto.is_some() && space_id == SpaceId::Handshake {
                // A server stops sending and processing Initial packets when it receives its first Handshake packet.
                self.discard_space(now, SpaceId::Initial);
            }
            if self.zero_rtt_crypto.is_some() && is_1rtt {
                // Discard 0-RTT keys soon after receiving a 1-RTT packet
                self.set_key_discard_timer(now, space_id)
            }
        }
        let space = &mut self.spaces[space_id];
        space.pending_acks.insert_one(packet, now);
        if packet >= space.rx_packet {
            space.rx_packet = packet;
            // Update outgoing spin bit, inverting iff we're the client
            self.spin = self.side.is_client() ^ spin;
        }

        self.config.qlog_sink.emit_packet_received(
            packet,
            space_id,
            !is_1rtt,
            now,
            self.orig_rem_cid,
        );
    }

    fn reset_idle_timeout(&mut self, now: Instant, space: SpaceId) {
        let timeout = match self.idle_timeout {
            None => return,
            Some(dur) => dur,
        };
        if self.state.is_closed() {
            self.timers.stop(Timer::Idle);
            return;
        }
        let dt = cmp::max(timeout, 3 * self.pto(space));
        self.timers.set(Timer::Idle, now + dt);
    }

    fn reset_keep_alive(&mut self, now: Instant) {
        let interval = match self.config.keep_alive_interval {
            Some(x) if self.state.is_established() => x,
            _ => return,
        };
        self.timers.set(Timer::KeepAlive, now + interval);
    }

    fn reset_cid_retirement(&mut self) {
        if let Some(t) = self.local_cid_state.next_timeout() {
            self.timers.set(Timer::PushNewCid, t);
        }
    }

    /// Handle the already-decrypted first packet from the client
    ///
    /// Decrypting the first packet in the `Endpoint` allows stateless packet handling to be more
    /// efficient.
    pub(crate) fn handle_first_packet(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        local: Option<SocketAddr>,
        ecn: Option<EcnCodepoint>,
        packet_number: u64,
        packet: InitialPacket,
        remaining: Option<BytesMut>,
    ) -> Result<(), ConnectionError> {
        let span = trace_span!("first recv");
        let _guard = span.enter();
        debug_assert!(self.side.is_server());
        let len = packet.header_data.len() + packet.payload.len();
        self.path.total_recvd = len as u64;

        match self.state {
            State::Handshake(ref mut state) => {
                state.expected_token = packet.header.token.clone();
            }
            #[expect(
                clippy::unreachable,
                reason = "the first-packet handling runs from `Connection::new`, whose state is `Handshake` until a packet is processed"
            )]
            _ => unreachable!("first packet must be delivered in Handshake state"),
        }

        self.on_packet_authenticated(
            now,
            SpaceId::Initial,
            ecn,
            Some(packet_number),
            false,
            false,
        );

        self.process_decrypted_packet(now, remote, local, Some(packet_number), packet.into())?;
        if let Some(data) = remaining {
            self.handle_coalesced(now, remote, local, ecn, data);
        }

        self.config.qlog_sink.emit_recovery_metrics(
            self.pto_count,
            &mut self.path,
            now,
            self.orig_rem_cid,
        );

        Ok(())
    }

    fn init_0rtt(&mut self) {
        let (header, packet) = match self.crypto.early_crypto() {
            Some(x) => x,
            None => return,
        };
        if self.side.is_client() {
            match self.crypto.transport_parameters() {
                Ok(params) => {
                    #[expect(
                        clippy::expect_used,
                        reason = "rustls only offers a resumption ticket after the handshake supplied the peer transport parameters (`transport_parameters()` is `Ok(Some)` then)"
                    )]
                    let params = params
                        .expect("crypto layer didn't supply transport parameters with ticket");
                    // Certain values must not be cached
                    let params = TransportParameters {
                        initial_src_cid: None,
                        original_dst_cid: None,
                        preferred_address: None,
                        retry_src_cid: None,
                        stateless_reset_token: None,
                        min_ack_delay: None,
                        ack_delay_exponent: TransportParameters::default().ack_delay_exponent,
                        max_ack_delay: TransportParameters::default().max_ack_delay,
                        ..params
                    };
                    self.set_peer_params(params);
                }
                Err(e) => {
                    error!("session ticket has malformed transport parameters: {}", e);
                    return;
                }
            }
        }
        trace!("0-RTT enabled");
        self.zero_rtt_enabled = true;
        self.zero_rtt_crypto = Some(ZeroRttCrypto { header, packet });
    }

    fn read_crypto(
        &mut self,
        space: SpaceId,
        crypto: &frame::Crypto,
        payload_len: usize,
    ) -> Result<(), TransportError> {
        let expected = if !self.state.is_handshake() {
            SpaceId::Data
        } else if self.highest_space == SpaceId::Initial {
            SpaceId::Initial
        } else {
            // On the server, self.highest_space can be Data after receiving the client's first
            // flight, but we expect Handshake CRYPTO until the handshake is complete.
            SpaceId::Handshake
        };
        // We can't decrypt Handshake packets when highest_space is Initial, CRYPTO frames in 0-RTT
        // packets are illegal, and we don't process 1-RTT packets until the handshake is
        // complete. Therefore, we will never see CRYPTO data from a later-than-expected space.
        debug_assert!(space <= expected, "received out-of-order CRYPTO data");

        let end = crypto.offset + crypto.data.len() as u64;
        if space < expected && end > self.spaces[space].crypto_stream.bytes_read() {
            warn!(
                "received new {:?} CRYPTO data when expecting {:?}",
                space, expected
            );
            return Err(TransportError::PROTOCOL_VIOLATION(
                "new data at unexpected encryption level",
            ));
        }

        let space = &mut self.spaces[space];
        let max = end.saturating_sub(space.crypto_stream.bytes_read());
        if max > self.config.crypto_buffer_size as u64 {
            return Err(TransportError::CRYPTO_BUFFER_EXCEEDED(""));
        }

        space
            .crypto_stream
            .insert(crypto.offset, crypto.data.clone(), payload_len)
            .map_err(|_| TransportError::INTERNAL_ERROR("too many gaps in crypto stream buffer"))?;

        while let Some(chunk) = space.crypto_stream.read(usize::MAX, true) {
            trace!("consumed {} CRYPTO bytes", chunk.bytes.len());
            if self.crypto.read_handshake(&chunk.bytes)? {
                self.events.push_back(Event::HandshakeDataReady);
            }
        }

        Ok(())
    }

    fn write_crypto(&mut self) {
        loop {
            let space = self.highest_space;
            let mut outgoing = Vec::new();
            if let Some(crypto) = self.crypto.write_handshake(&mut outgoing) {
                match space {
                    SpaceId::Initial => {
                        self.upgrade_crypto(SpaceId::Handshake, crypto);
                    }
                    SpaceId::Handshake => {
                        self.upgrade_crypto(SpaceId::Data, crypto);
                    }
                    #[expect(
                        clippy::unreachable,
                        reason = "`upgrade_crypto` is only called while `highest_space` is Initial or Handshake; 1-RTT key changes go through `update_keys`"
                    )]
                    _ => unreachable!("got updated secrets during 1-RTT"),
                }
            }
            if outgoing.is_empty() {
                if space == self.highest_space {
                    break;
                } else {
                    // Keys updated, check for more data to send
                    continue;
                }
            }
            let offset = self.spaces[space].crypto_offset;
            let outgoing = Bytes::from(outgoing);
            if let State::Handshake(ref mut state) = self.state {
                if space == SpaceId::Initial && offset == 0 && self.side.is_client() {
                    state.client_hello = Some(outgoing.clone());
                }
            }
            self.spaces[space].crypto_offset += outgoing.len() as u64;
            trace!("wrote {} {:?} CRYPTO bytes", outgoing.len(), space);
            self.spaces[space].pending.crypto.push_back(frame::Crypto {
                offset,
                data: outgoing,
            });
        }
    }

    /// Switch to stronger cryptography during handshake
    #[expect(
        clippy::expect_used,
        reason = "rustls exposes `next_1rtt_keys` as soon as 1-RTT secrets exist, which is the `space == SpaceId::Data` branch condition"
    )]
    fn upgrade_crypto(&mut self, space: SpaceId, crypto: Keys) {
        debug_assert!(
            self.spaces[space].crypto.is_none(),
            "already reached packet space {space:?}"
        );
        trace!("{:?} keys ready", space);
        if space == SpaceId::Data {
            // Precompute the first key update
            self.next_crypto = Some(
                self.crypto
                    .next_1rtt_keys()
                    .expect("handshake should be complete"),
            );
        }

        self.spaces[space].crypto = Some(crypto);
        debug_assert!(space as usize > self.highest_space as usize);
        self.highest_space = space;
        if space == SpaceId::Data && self.side.is_client() {
            // Discard 0-RTT keys because 1-RTT keys are available.
            self.zero_rtt_crypto = None;
        }
    }

    fn discard_space(&mut self, now: Instant, space_id: SpaceId) {
        debug_assert!(space_id != SpaceId::Data);
        trace!("discarding {:?} keys", space_id);
        if space_id == SpaceId::Initial {
            // No longer needed
            if let ConnectionSide::Client { token, .. } = &mut self.side {
                *token = Bytes::new();
            }
        }
        let space = &mut self.spaces[space_id];
        space.crypto = None;
        space.time_of_last_ack_eliciting_packet = None;
        space.loss_time = None;
        let sent_packets = mem::take(&mut space.sent_packets);
        for packet in sent_packets.into_values() {
            self.remove_in_flight(&packet);
        }
        self.set_loss_detection_timer(now)
    }

    fn handle_coalesced(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        local: Option<SocketAddr>,
        ecn: Option<EcnCodepoint>,
        data: BytesMut,
    ) {
        self.path.total_recvd = self.path.total_recvd.saturating_add(data.len() as u64);
        let mut remaining = Some(data);
        while let Some(data) = remaining {
            match PartialDecode::new(
                data,
                &FixedLengthConnectionIdParser::new(self.local_cid_state.cid_len()),
                &[self.version],
                self.endpoint_config.grease_quic_bit,
            ) {
                Ok((partial_decode, rest)) => {
                    remaining = rest;
                    self.handle_decode(now, remote, local, ecn, partial_decode);
                }
                Err(e) => {
                    trace!("malformed header: {}", e);
                    return;
                }
            }
        }
    }

    fn handle_decode(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        local: Option<SocketAddr>,
        ecn: Option<EcnCodepoint>,
        partial_decode: PartialDecode,
    ) {
        if let Some(decoded) = packet_crypto::unprotect_header(
            partial_decode,
            &self.spaces,
            self.zero_rtt_crypto.as_ref(),
            // A reset is only ours when it comes from an address this identifier was sent to.
            &self.used_reset_tokens(remote),
        ) {
            self.handle_packet(
                now,
                remote,
                local,
                ecn,
                decoded.packet,
                decoded.stateless_reset,
            );
        }
    }

    fn handle_packet(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        local: Option<SocketAddr>,
        ecn: Option<EcnCodepoint>,
        packet: Option<Packet>,
        stateless_reset: bool,
    ) {
        self.stats.udp_rx.ios += 1;
        if let Some(ref packet) = packet {
            trace!(
                "got {:?} packet ({} bytes) from {} using id {}",
                packet.header.space(),
                packet.payload.len() + packet.header_data.len(),
                remote,
                packet.header.dst_cid(),
            );
        }

        if self.is_handshaking() && remote != self.path.remote {
            debug!("discarding packet with unexpected remote during handshake");
            return;
        }

        let was_closed = self.state.is_closed();
        let was_drained = self.state.is_drained();

        let decrypted = match packet {
            None => Err(None),
            Some(mut packet) => self
                .decrypt_packet(now, &mut packet)
                .map(move |number| (packet, number)),
        };
        let result = match decrypted {
            _ if stateless_reset => {
                debug!("got stateless reset");
                Err(ConnectionError::Reset)
            }
            Err(Some(e)) => {
                warn!("illegal packet: {}", e);
                Err(e.into())
            }
            Err(None) => {
                debug!("failed to authenticate packet");
                self.authentication_failures += 1;
                #[expect(
                    clippy::unwrap_used,
                    reason = "a packet can only fail authentication after keys for `highest_space` were installed; earlier packets are dropped as undecryptable"
                )]
                let integrity_limit = self.spaces[self.highest_space]
                    .crypto
                    .as_ref()
                    .unwrap()
                    .packet
                    .local
                    .integrity_limit();
                if self.authentication_failures > integrity_limit {
                    Err(TransportError::AEAD_LIMIT_REACHED("integrity limit violated").into())
                } else {
                    return;
                }
            }
            Ok((packet, number)) => {
                let span = match number {
                    Some(pn) => trace_span!("recv", space = ?packet.header.space(), pn),
                    None => trace_span!("recv", space = ?packet.header.space()),
                };
                let _guard = span.enter();

                let is_duplicate = |n| self.spaces[packet.header.space()].dedup.insert(n);
                if number.is_some_and(is_duplicate) {
                    debug!("discarding possible duplicate packet");
                    return;
                } else if self.state.is_handshake() && packet.header.is_short() {
                    // TODO: SHOULD buffer these to improve reordering tolerance.
                    trace!("dropping short packet during handshake");
                    return;
                } else {
                    if let Header::Initial(InitialHeader { ref token, .. }) = packet.header {
                        if let State::Handshake(ref hs) = self.state {
                            if self.side.is_server() && token != &hs.expected_token {
                                // Clients must send the same retry token in every Initial. Initial
                                // packets can be spoofed, so we discard rather than killing the
                                // connection.
                                warn!("discarding Initial with invalid retry token");
                                return;
                            }
                        }
                    }

                    if !self.state.is_closed() {
                        let spin = match packet.header {
                            Header::Short { spin, .. } => spin,
                            _ => false,
                        };
                        self.on_packet_authenticated(
                            now,
                            packet.header.space(),
                            ecn,
                            number,
                            spin,
                            packet.header.is_1rtt(),
                        );
                    }

                    self.process_decrypted_packet(now, remote, local, number, packet)
                }
            }
        };

        // State transitions for error cases
        if let Err(conn_err) = result {
            self.error = Some(conn_err.clone());
            self.state = match conn_err {
                ConnectionError::ApplicationClosed(reason) => State::closed(reason),
                ConnectionError::ConnectionClosed(reason) => State::closed(reason),
                ConnectionError::Reset
                | ConnectionError::TransportError(TransportError {
                    code: TransportErrorCode::AEAD_LIMIT_REACHED,
                    ..
                }) => State::Drained,
                #[expect(
                    clippy::unreachable,
                    reason = "`conn_err` was produced by processing one received packet, which only yields peer-driven errors (transport error, close frames, version mismatch, reset)"
                )]
                ConnectionError::TimedOut => {
                    unreachable!("timeouts aren't generated by packet processing");
                }
                ConnectionError::TransportError(err) => {
                    debug!("closing connection due to transport error: {}", err);
                    State::closed(err)
                }
                ConnectionError::VersionMismatch => State::Draining,
                #[expect(
                    clippy::unreachable,
                    reason = "`conn_err` was produced by processing one received packet, which only yields peer-driven errors (transport error, close frames, version mismatch, reset)"
                )]
                ConnectionError::LocallyClosed => {
                    unreachable!("LocallyClosed isn't generated by packet processing");
                }
                #[expect(
                    clippy::unreachable,
                    reason = "`conn_err` was produced by processing one received packet, which only yields peer-driven errors (transport error, close frames, version mismatch, reset)"
                )]
                ConnectionError::CidsExhausted => {
                    unreachable!("CidsExhausted isn't generated by packet processing");
                }
            };
        }

        if !was_closed && self.state.is_closed() {
            self.close_common();
            if !self.state.is_drained() {
                self.set_close_timer(now);
            }
        }
        if !was_drained && self.state.is_drained() {
            self.endpoint_events.push_back(EndpointEventInner::Drained);
            // Close timer may have been started previously, e.g. if we sent a close and got a
            // stateless reset in response
            self.timers.stop(Timer::Close);
        }

        // Transmit CONNECTION_CLOSE if necessary
        if let State::Closed(_) = self.state {
            self.close = remote == self.path.remote;
        }
    }

    #[expect(
        clippy::unwrap_used,
        reason = "this branch is inside `if self.side.is_client()`, and the rustls client session always reports whether early data was accepted; 0-RTT long headers carry a packet number, so `decrypt_packet` yields `Some`"
    )]
    fn process_decrypted_packet(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        local: Option<SocketAddr>,
        number: Option<u64>,
        packet: Packet,
    ) -> Result<(), ConnectionError> {
        let state = match self.state {
            State::Established => {
                match packet.header.space() {
                    #[expect(
                        clippy::unwrap_used,
                        reason = "0-RTT and 1-RTT headers always carry a packet number and `decrypt_packet` returns it for exactly those"
                    )]
                    SpaceId::Data => {
                        self.process_payload(now, remote, local, number.unwrap(), packet)?
                    }
                    _ if packet.header.has_frames() => self.process_early_payload(now, packet)?,
                    _ => {
                        trace!("discarding unexpected pre-handshake packet");
                    }
                }
                return Ok(());
            }
            State::Closed(_) => {
                for result in frame::Iter::new(packet.payload.freeze())? {
                    let frame = match result {
                        Ok(frame) => frame,
                        Err(err) => {
                            debug!("frame decoding error: {err:?}");
                            continue;
                        }
                    };

                    if let Frame::Padding = frame {
                        continue;
                    };

                    self.stats.frame_rx.record(&frame);

                    if let Frame::Close(_) = frame {
                        trace!("draining");
                        self.state = State::Draining;
                        break;
                    }
                }
                return Ok(());
            }
            State::Draining | State::Drained => return Ok(()),
            State::Handshake(ref mut state) => state,
        };

        match packet.header {
            Header::Retry {
                src_cid: rem_cid, ..
            } => {
                if self.side.is_server() {
                    return Err(TransportError::PROTOCOL_VIOLATION("client sent Retry").into());
                }

                if self.total_authed_packets > 1
                            || packet.payload.len() <= 16 // token + 16 byte tag
                            || !self.crypto.is_valid_retry(
                                &self.rem_cids.active(),
                                &packet.header_data,
                                &packet.payload,
                            )
                {
                    trace!("discarding invalid Retry");
                    // - After the client has received and processed an Initial or Retry
                    //   packet from the server, it MUST discard any subsequent Retry
                    //   packets that it receives.
                    // - A client MUST discard a Retry packet with a zero-length Retry Token
                    //   field.
                    // - Clients MUST discard Retry packets that have a Retry Integrity Tag
                    //   that cannot be validated
                    return Ok(());
                }

                trace!("retrying with CID {}", rem_cid);
                #[expect(
                    clippy::unwrap_used,
                    reason = "a second Retry is discarded above (`total_authed_packets > 1`), so `client_hello` has not been taken yet"
                )]
                let client_hello = state.client_hello.take().unwrap();
                self.retry_src_cid = Some(rem_cid);
                self.rem_cids.update_initial_cid(rem_cid);
                self.rem_handshake_cid = rem_cid;

                let space = &mut self.spaces[SpaceId::Initial];
                if let Some(info) = space.take(0) {
                    self.on_packet_acked(now, info);
                };

                self.discard_space(now, SpaceId::Initial); // Make sure we clean up after any retransmitted Initials
                self.spaces[SpaceId::Initial] = PacketSpace {
                    crypto: Some(self.crypto.initial_keys(&rem_cid, self.side.side())),
                    next_packet_number: self.spaces[SpaceId::Initial].next_packet_number,
                    crypto_offset: client_hello.len() as u64,
                    ..PacketSpace::new(now)
                };
                self.spaces[SpaceId::Initial]
                    .pending
                    .crypto
                    .push_back(frame::Crypto {
                        offset: 0,
                        data: client_hello,
                    });

                // Retransmit all 0-RTT data
                let zero_rtt = mem::take(&mut self.spaces[SpaceId::Data].sent_packets);
                for info in zero_rtt.into_values() {
                    self.remove_in_flight(&info);
                    self.spaces[SpaceId::Data].pending |= info.retransmits;
                }
                self.streams.retransmit_all_for_0rtt();

                let token_len = packet.payload.len() - 16;
                #[expect(
                    clippy::unreachable,
                    reason = "servers returned `PROTOCOL_VIOLATION` for a Retry at the top of this arm"
                )]
                let ConnectionSide::Client { ref mut token, .. } = self.side else {
                    unreachable!("we already short-circuited if we're server");
                };
                *token = packet.payload.freeze().split_to(token_len);
                self.state = State::Handshake(state::Handshake {
                    expected_token: Bytes::new(),
                    rem_cid_set: false,
                    client_hello: None,
                });
                Ok(())
            }
            Header::Long {
                ty: LongType::Handshake,
                src_cid: rem_cid,
                ..
            } => {
                if rem_cid != self.rem_handshake_cid {
                    debug!(
                        "discarding packet with mismatched remote CID: {} != {}",
                        self.rem_handshake_cid, rem_cid
                    );
                    return Ok(());
                }
                self.on_path_validated();

                self.process_early_payload(now, packet)?;
                if self.state.is_closed() {
                    return Ok(());
                }

                if self.crypto.is_handshaking() {
                    trace!("handshake ongoing");
                    return Ok(());
                }

                if self.side.is_client() {
                    // Client-only because server params were set from the client's Initial
                    let params =
                        self.crypto
                            .transport_parameters()?
                            .ok_or_else(|| TransportError {
                                code: TransportErrorCode::crypto(0x6d),
                                frame: None,
                                reason: "transport parameters missing".into(),
                                crypto: None,
                            })?;

                    if self.has_0rtt() {
                        if !self.crypto.early_data_accepted().unwrap() {
                            debug_assert!(self.side.is_client());
                            debug!("0-RTT rejected");
                            self.accepted_0rtt = false;
                            self.streams.zero_rtt_rejected();

                            // Discard already-queued frames
                            self.spaces[SpaceId::Data].pending = Retransmits::default();

                            // Discard 0-RTT packets
                            let sent_packets =
                                mem::take(&mut self.spaces[SpaceId::Data].sent_packets);
                            for packet in sent_packets.into_values() {
                                self.remove_in_flight(&packet);
                            }
                        } else {
                            self.accepted_0rtt = true;
                            params.validate_resumption_from(&self.peer_params)?;
                        }
                    }
                    if let Some(token) = params.stateless_reset_token {
                        self.rem_cids.set_initial_reset_token(token);
                        self.set_reset_token(self.path.remote, token);
                    }
                    self.handle_peer_params(params)?;
                    self.issue_first_cids(now);
                } else {
                    // Server-only
                    self.queue_handshake_done();
                    self.discard_space(now, SpaceId::Handshake);
                    self.events.push_back(Event::HandshakeConfirmed);
                    trace!("handshake confirmed");
                }

                self.timers.stop(Timer::Handshake);
                self.events.push_back(Event::Connected);
                self.state = State::Established;
                trace!("established");
                Ok(())
            }
            Header::Initial(InitialHeader {
                src_cid: rem_cid, ..
            }) => {
                if !state.rem_cid_set {
                    trace!("switching remote CID to {}", rem_cid);
                    let mut state = state.clone();
                    self.rem_cids.update_initial_cid(rem_cid);
                    self.rem_handshake_cid = rem_cid;
                    self.orig_rem_cid = rem_cid;
                    state.rem_cid_set = true;
                    self.state = State::Handshake(state);
                } else if rem_cid != self.rem_handshake_cid {
                    debug!(
                        "discarding packet with mismatched remote CID: {} != {}",
                        self.rem_handshake_cid, rem_cid
                    );
                    return Ok(());
                }

                let starting_space = self.highest_space;
                self.process_early_payload(now, packet)?;

                if self.side.is_server()
                    && starting_space == SpaceId::Initial
                    && self.highest_space != SpaceId::Initial
                {
                    let params =
                        self.crypto
                            .transport_parameters()?
                            .ok_or_else(|| TransportError {
                                code: TransportErrorCode::crypto(0x6d),
                                frame: None,
                                reason: "transport parameters missing".into(),
                                crypto: None,
                            })?;
                    self.handle_peer_params(params)?;
                    self.issue_first_cids(now);
                    self.init_0rtt();
                }
                Ok(())
            }
            Header::Long {
                ty: LongType::ZeroRtt,
                ..
            } => {
                self.process_payload(now, remote, local, number.unwrap(), packet)?;
                Ok(())
            }
            Header::VersionNegotiate { .. } => {
                if self.total_authed_packets > 1 {
                    return Ok(());
                }
                let supported = packet
                    .payload
                    .chunks(4)
                    .any(|x| match <[u8; 4]>::try_from(x) {
                        Ok(version) => self.version == u32::from_be_bytes(version),
                        Err(_) => false,
                    });
                if supported {
                    return Ok(());
                }
                debug!("remote doesn't support our version");
                Err(ConnectionError::VersionMismatch)
            }
            #[expect(
                clippy::unreachable,
                reason = "`handle_packet` drops short-header packets while handshaking before dispatching here"
            )]
            Header::Short { .. } => unreachable!(
                "short packets received during handshake are discarded in handle_packet"
            ),
        }
    }

    /// Process an Initial or Handshake packet payload
    fn process_early_payload(
        &mut self,
        now: Instant,
        packet: Packet,
    ) -> Result<(), TransportError> {
        debug_assert_ne!(packet.header.space(), SpaceId::Data);
        let payload_len = packet.payload.len();
        let mut ack_eliciting = false;
        for result in frame::Iter::new(packet.payload.freeze())? {
            let frame = result?;
            let span = match frame {
                Frame::Padding => continue,
                _ => Some(trace_span!("frame", ty = %frame.ty())),
            };

            self.stats.frame_rx.record(&frame);

            let _guard = span.as_ref().map(|x| x.enter());
            ack_eliciting |= frame.is_ack_eliciting();

            // Process frames
            match frame {
                Frame::Padding | Frame::Ping => {}
                Frame::Crypto(frame) => {
                    self.read_crypto(packet.header.space(), &frame, payload_len)?;
                }
                Frame::Ack(ack) => {
                    self.on_ack_received(now, packet.header.space(), ack)?;
                }
                // Per RFC 9000 §12.4 Table 3, only a CONNECTION_CLOSE frame of type 0x1c may
                // appear in Initial or Handshake packets. An application close (0x1d) falls
                // through to the catch-all arm below.
                Frame::Close(reason @ Close::Connection(_)) => {
                    self.error = Some(reason.into());
                    self.state = State::Draining;
                    return Ok(());
                }
                _ => {
                    let mut err =
                        TransportError::PROTOCOL_VIOLATION("illegal frame type in handshake");
                    err.frame = Some(frame.ty());
                    return Err(err);
                }
            }
        }

        if ack_eliciting {
            // In the initial and handshake spaces, ACKs must be sent immediately
            self.spaces[packet.header.space()]
                .pending_acks
                .set_immediate_ack_required();
        }

        self.write_crypto();
        Ok(())
    }

    fn process_payload(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        local: Option<SocketAddr>,
        number: u64,
        packet: Packet,
    ) -> Result<(), TransportError> {
        let received_dcid = packet.header.dst_cid();
        let payload = packet.payload.freeze();
        let mut is_probing_packet = true;
        let mut close = None;
        let payload_len = payload.len();
        let mut ack_eliciting = false;
        for result in frame::Iter::new(payload)? {
            let frame = result?;
            let span = match frame {
                Frame::Padding => continue,
                _ => Some(trace_span!("frame", ty = %frame.ty())),
            };

            self.stats.frame_rx.record(&frame);
            // Crypto, Stream and Datagram frames are special cased in order no pollute
            // the log with payload data
            match &frame {
                Frame::Crypto(f) => {
                    trace!(offset = f.offset, len = f.data.len(), "got crypto frame");
                }
                Frame::Stream(f) => {
                    trace!(id = %f.id, offset = f.offset, len = f.data.len(), fin = f.fin, "got stream frame");
                }
                Frame::Datagram(f) => {
                    trace!(len = f.data.len(), "got datagram frame");
                }
                f => {
                    trace!("got frame {:?}", f);
                }
            }

            let _guard = span.as_ref().map(|x| x.enter());
            // RFC 9000 §12.5: CRYPTO frames cannot be sent in 0-RTT packets. Both
            // CONNECTION_CLOSE types are permitted there, as 0-RTT belongs to the application
            // data packet number space; see §12.4 Table 3.
            if packet.header.is_0rtt() && matches!(frame, Frame::Crypto(_)) {
                return Err(TransportError::PROTOCOL_VIOLATION(
                    "illegal frame type in 0-RTT",
                ));
            }
            ack_eliciting |= frame.is_ack_eliciting();

            // Check whether this could be a probing packet
            match frame {
                Frame::Padding
                | Frame::PathChallenge(_)
                | Frame::PathResponse(_)
                | Frame::NewConnectionId(_) => {}
                _ => {
                    is_probing_packet = false;
                }
            }
            match frame {
                Frame::Crypto(frame) => {
                    self.read_crypto(SpaceId::Data, &frame, payload_len)?;
                }
                Frame::Stream(frame) => {
                    if self.streams.received(frame, payload_len)?.should_transmit() {
                        self.spaces[SpaceId::Data].pending.max_data = true;
                    }
                }
                Frame::Ack(ack) => {
                    self.on_ack_received(now, SpaceId::Data, ack)?;
                }
                Frame::Padding | Frame::Ping => {}
                Frame::Close(reason) => {
                    close = Some(reason);
                }
                Frame::PathChallenge(token) => {
                    self.path_responses.push(number, token, remote, local);
                    if remote == self.path.remote && self.same_local(local) {
                        // PATH_CHALLENGE on active path, possible off-path packet forwarding
                        // attack. Send a non-probing packet to recover the active path.
                        match self.peer_supports_ack_frequency() {
                            true => self.immediate_ack(),
                            false => self.ping(),
                        }
                    }
                }
                Frame::PathResponse(token) => {
                    // A response validates the path its challenge was sent on, whichever path it
                    // arrives on (RFC 9000 §8.2.3); data that matches nothing validates nothing
                    // and leaves an attempt in progress alone.
                    if self.candidate.as_ref().is_some_and(|c| c.matches(token)) {
                        self.take_preferred_address(now);
                    } else if self.path.challenge == Some(token) {
                        trace!("new path validated");
                        self.timers.stop(Timer::PathValidation);
                        self.path.challenge = None;
                        self.path.validated = true;
                        self.drop_previous_path();
                    } else {
                        debug!(token, "ignoring unmatched PATH_RESPONSE");
                    }
                }
                Frame::MaxData(bytes) => {
                    self.streams.received_max_data(bytes);
                }
                Frame::MaxStreamData { id, offset } => {
                    self.streams.received_max_stream_data(id, offset)?;
                }
                Frame::MaxStreams { dir, count } => {
                    self.streams.received_max_streams(dir, count)?;
                }
                Frame::ResetStream(frame) => {
                    if self.streams.received_reset(frame)?.should_transmit() {
                        self.spaces[SpaceId::Data].pending.max_data = true;
                    }
                }
                Frame::DataBlocked { offset } => {
                    debug!(offset, "peer claims to be blocked at connection level");
                }
                Frame::StreamDataBlocked { id, offset } => {
                    if id.initiator() == self.side.side() && id.dir() == Dir::Uni {
                        debug!("got STREAM_DATA_BLOCKED on send-only {}", id);
                        return Err(TransportError::STREAM_STATE_ERROR(
                            "STREAM_DATA_BLOCKED on send-only stream",
                        ));
                    }
                    debug!(
                        stream = %id,
                        offset, "peer claims to be blocked at stream level"
                    );
                }
                Frame::StreamsBlocked { dir, limit } => {
                    if limit > MAX_STREAM_COUNT {
                        return Err(TransportError::FRAME_ENCODING_ERROR(
                            "unrepresentable stream limit",
                        ));
                    }
                    debug!(
                        "peer claims to be blocked opening more than {} {} streams",
                        limit, dir
                    );
                }
                Frame::StopSending(frame::StopSending { id, error_code }) => {
                    if id.initiator() != self.side.side() {
                        if id.dir() == Dir::Uni {
                            debug!("got STOP_SENDING on recv-only {}", id);
                            return Err(TransportError::STREAM_STATE_ERROR(
                                "STOP_SENDING on recv-only stream",
                            ));
                        }
                    } else if self.streams.is_local_unopened(id) {
                        return Err(TransportError::STREAM_STATE_ERROR(
                            "STOP_SENDING on unopened stream",
                        ));
                    }
                    self.streams.received_stop_sending(id, error_code);
                }
                Frame::RetireConnectionId { sequence } => {
                    let allow_more_cids = self
                        .local_cid_state
                        .on_cid_retirement(sequence, self.peer_params.issue_cids_limit())?;
                    self.endpoint_events
                        .push_back(EndpointEventInner::RetireConnectionId(
                            now,
                            sequence,
                            allow_more_cids,
                        ));
                }
                Frame::NewConnectionId(frame) => {
                    trace!(
                        sequence = frame.sequence,
                        id = %frame.id,
                        retire_prior_to = frame.retire_prior_to,
                    );
                    if self.rem_cids.active().is_empty() {
                        return Err(TransportError::PROTOCOL_VIOLATION(
                            "NEW_CONNECTION_ID when CIDs aren't in use",
                        ));
                    }
                    if frame.retire_prior_to > frame.sequence {
                        return Err(TransportError::PROTOCOL_VIOLATION(
                            "NEW_CONNECTION_ID retiring unissued CIDs",
                        ));
                    }

                    use crate::proto::cid_queue::InsertError;
                    // Identifiers kept aside for a path (RFC 9000 §9.5) that the peer retires
                    // now are given up first: a previous path then has no identifier of its own,
                    // and a candidate path cannot go on with one it may not send.
                    let aside = self.rem_cids.retire_aside(frame.retire_prior_to);
                    for seq in aside.iter() {
                        self.retire_rem_cid(seq)?;
                    }
                    for seq in aside.bound.iter().flatten() {
                        self.drop_path_cid(*seq);
                    }
                    let (held_retired, reserved_retired) = (aside.held, aside.reserved);
                    if held_retired.is_some()
                        && let Some(prev) = self.prev_path.as_mut()
                        && prev.cid == PrevCid::Held
                    {
                        prev.cid = PrevCid::Gone;
                    }
                    if reserved_retired.is_some() {
                        self.restart_candidate();
                    }
                    match self.rem_cids.insert(frame) {
                        Ok(None) => {}
                        Ok(Some((retired, reset_token))) => {
                            self.spaces[SpaceId::Data]
                                .pending
                                .retire_cids(retired.clone())?;
                            self.note_retired(retired);
                            self.set_reset_token(self.path.remote, reset_token);
                        }
                        Err(InsertError::ExceedsLimit) => {
                            return Err(TransportError::CONNECTION_ID_LIMIT_ERROR(""));
                        }
                        Err(InsertError::Retired) => {
                            trace!("discarding already-retired");
                            // RETIRE_CONNECTION_ID might not have been previously sent if e.g. a
                            // range of connection IDs larger than the active connection ID limit
                            // was retired all at once via retire_prior_to. The bounded queue
                            // keeps a peer that repeats retired identifiers from growing it.
                            self.spaces[SpaceId::Data]
                                .pending
                                .retire_cids(frame.sequence..frame.sequence + 1)?;
                            continue;
                        }
                    };
                    // A peer move that waited for an unused connection ID (RFC 9000 §9.5) is
                    // followed now, unless the path changed meanwhile or no ID is unused yet.
                    if let Some(deferred) = self.deferred_migration.take()
                        && deferred.generation == self.path_counter
                    {
                        trace!(
                            remote = %deferred.remote,
                            asked_by = deferred.number,
                            "following the deferred peer move"
                        );
                        if !self.follow_peer_move(
                            now,
                            deferred.remote,
                            deferred.local,
                            deferred.received_dcid,
                            false,
                        )? {
                            self.deferred_migration = Some(deferred);
                        }
                    }

                    if self.side.is_server() && self.rem_cids.active_seq() == 0 {
                        // We're a server still using the initial remote CID for the client, so
                        // let's switch immediately to enable clientside stateless resets.
                        self.update_rem_cid();
                    }
                }
                Frame::NewToken(NewToken { token }) => {
                    let ConnectionSide::Client {
                        token_store,
                        server_name,
                        ..
                    } = &self.side
                    else {
                        return Err(TransportError::PROTOCOL_VIOLATION("client sent NEW_TOKEN"));
                    };
                    if token.is_empty() {
                        return Err(TransportError::FRAME_ENCODING_ERROR("empty token"));
                    }
                    trace!("got new token");
                    token_store.insert(server_name, token);
                }
                Frame::Datagram(datagram) => {
                    if self
                        .datagrams
                        .received(datagram, &self.config.datagram_receive_buffer_size)?
                    {
                        self.events.push_back(Event::DatagramReceived);
                    }
                }
                Frame::AckFrequency(ack_frequency) => {
                    // This frame can only be sent in the Data space
                    let space = &mut self.spaces[SpaceId::Data];

                    if !self
                        .ack_frequency
                        .ack_frequency_received(&ack_frequency, &mut space.pending_acks)?
                    {
                        // The AckFrequency frame is stale (we have already received a more recent one)
                        continue;
                    }

                    // Our `max_ack_delay` has been updated, so we may need to adjust its associated
                    // timeout
                    if let Some(timeout) = space
                        .pending_acks
                        .max_ack_delay_timeout(self.ack_frequency.max_ack_delay)
                    {
                        self.timers.set(Timer::MaxAckDelay, timeout);
                    }
                }
                Frame::ImmediateAck => {
                    // This frame can only be sent in the Data space
                    self.spaces[SpaceId::Data]
                        .pending_acks
                        .set_immediate_ack_required();
                }
                Frame::HandshakeDone => {
                    if self.side.is_server() {
                        return Err(TransportError::PROTOCOL_VIOLATION(
                            "client sent HANDSHAKE_DONE",
                        ));
                    }
                    if self.spaces[SpaceId::Handshake].crypto.is_some() {
                        self.discard_space(now, SpaceId::Handshake);
                    }
                    self.events.push_back(Event::HandshakeConfirmed);
                    trace!("handshake confirmed");
                    // Migration, the preferred address included, waits for confirmation
                    // (RFC 9000 §9).
                    if self.preferred_state == PreferredAddressState::Armed {
                        self.begin_candidate();
                    }
                }
            }
        }

        let space = &mut self.spaces[SpaceId::Data];
        if space
            .pending_acks
            .packet_received(now, number, ack_eliciting, &space.dedup)
        {
            self.timers
                .set(Timer::MaxAckDelay, now + self.ack_frequency.max_ack_delay);
            self.next_bundled_ack_time = Some(now);
        }

        // Issue stream ID credit due to ACKs of outgoing finish/resets and incoming finish/resets
        // on stopped streams. Incoming finishes/resets on open streams are not handled here as they
        // are only freed, and hence only issue credit, once the application has been notified
        // during a read on the stream.
        let pending = &mut self.spaces[SpaceId::Data].pending;
        self.streams.queue_max_stream_id(pending);

        if let Some(reason) = close {
            self.error = Some(reason.into());
            self.state = State::Draining;
            self.close = true;
        }

        // A non-probing packet from a new path (the peer's address changed, or it reached a
        // different local socket, such as the server's preferred address) moves the connection.
        let local_changed = !self.same_local(local);
        let on_current_path = remote == self.path.remote && !local_changed;
        if on_current_path
            && !is_probing_packet
            && number == self.spaces[SpaceId::Data].rx_packet
            && self.deferred_migration.take().is_some()
        {
            // The peer is (still or again) on the current path: a move waiting for an unused
            // connection ID is obsolete.
            trace!("deferred peer move superseded by traffic on the current path");
        }
        if !on_current_path && !is_probing_packet && number == self.spaces[SpaceId::Data].rx_packet
        {
            let migration_allowed = match &self.side {
                ConnectionSide::Server { server_config } => Some(server_config.migration),
                ConnectionSide::Client { .. } => None,
            };
            if let Some(allowed) = migration_allowed {
                debug_assert!(
                    allowed,
                    "migration-initiating packets should have been dropped immediately"
                );
                // RFC 9000 §9.5: a connection ID is never reused towards more than one destination.
                // The one exception is a peer whose address changed without changing the connection
                // ID it sends to us while we keep our local address (a NAT rebinding): then we may
                // keep using the current connection ID. Otherwise the new path needs an unused one;
                // without it the move is deferred until the peer issues more and we keep sending on
                // the current path meanwhile.
                let nat_rebinding = remote != self.path.remote
                    && !local_changed
                    && self.path.received_dcid == Some(received_dcid);
                if !self.follow_peer_move(now, remote, local, received_dcid, nat_rebinding)? {
                    trace!(%remote, ?local, "peer moved without an unused connection ID: deferred");
                    self.deferred_migration = Some(DeferredMigration {
                        remote,
                        local,
                        received_dcid,
                        number,
                        generation: self.path_counter,
                    });
                    self.stats.path.deferred_migrations =
                        self.stats.path.deferred_migrations.saturating_add(1);
                }
            } else {
                // A client follows no peer address change; traffic from elsewhere than the
                // current path is only accepted while that address is being probed.
                trace!(%remote, "ignoring a client-side off-path packet");
            }
        } else if on_current_path {
            self.path.received_dcid = Some(received_dcid);
        }

        Ok(())
    }

    /// Follow a peer move to `remote`/`local` (RFC 9000 §9.3). A NAT rebinding keeps the current
    /// connection ID; any other move takes an unused one first, so nothing is ever sent to the new
    /// tuple with an identifier used elsewhere. Returns `Ok(false)`, changing nothing, when the
    /// move needs an identifier and none is unused.
    fn follow_peer_move(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        local: Option<SocketAddr>,
        received_dcid: ConnectionId,
        nat_rebinding: bool,
    ) -> Result<bool, TransportError> {
        if !nat_rebinding && !self.rem_cids.has_unused() {
            return Ok(false);
        }
        // The path being replaced is kept as a fallback only while it was validated: an
        // unvalidated one is dropped, and an older kept path stays as it is.
        let keep_replaced = self.path.challenge.is_none();
        let (prev_cid, token) = if nat_rebinding {
            (PrevCid::Active, self.rem_cids.active_reset_token())
        } else {
            // Keeping the replaced path needs an identifier set aside for it; without one the
            // path is simply not kept, which is always safe.
            let (token, retired, prev_cid) = match keep_replaced
                .then(|| self.rem_cids.next_holding())
                .flatten()
            {
                Some((token, retired)) => (token, retired, PrevCid::Held),
                None => match self.rem_cids.next() {
                    Some((token, retired)) => (token, retired, PrevCid::Gone),
                    None => return Ok(false),
                },
            };
            self.retire_rem_cids(&retired)?;
            // An older path that was being sent with the identifier this switch just left behind
            // has no identifier of its own any more.
            if let Some(prev) = self.prev_path.as_mut()
                && prev.cid == PrevCid::Active
            {
                prev.cid = PrevCid::Gone;
            }
            (prev_cid, Some(token))
        };
        self.migrate(now, remote, local, PreviousPath::Keep(prev_cid));
        self.path.received_dcid = Some(received_dcid);
        if let Some(token) = token {
            self.set_reset_token(remote, token);
        }
        self.deferred_migration = None;
        self.spin = false;
        Ok(true)
    }

    /// The current path is validated: the previous one is abandoned and the identifier kept for
    /// it is retired (RFC 9000 §9.5).
    fn drop_previous_path(&mut self) {
        if let Some(PrevPath { cid, .. }) = self.prev_path.take()
            && cid == PrevCid::Held
            && let Some(seq) = self.rem_cids.retire_held()
            && let Err(error) = self.retire_rem_cid(seq)
        {
            self.defer_error(error);
        }
    }

    /// The current path failed validation: return to the previous path when it is kept and has a
    /// connection ID to be sent with (RFC 9000 §9.5), otherwise stay on the current one.
    fn abandon_current_path(&mut self, now: Instant) {
        if let Some(PrevPath { path: prev, cid }) = self.prev_path.take() {
            let usable = match cid {
                PrevCid::Held => match self.rem_cids.restore_held() {
                    Some(abandoned) => {
                        // The restored identifier is bound to the previous address again; the
                        // one used towards the failed path is retired.
                        if let Err(error) = self.retire_rem_cid(abandoned) {
                            self.defer_error(error);
                        }
                        if let Some(token) = self.rem_cids.active_reset_token() {
                            self.set_reset_token(prev.remote, token);
                        }
                        true
                    }
                    None => false,
                },
                PrevCid::Active => {
                    if let Some(token) = self.rem_cids.active_reset_token() {
                        self.set_reset_token(prev.remote, token);
                    }
                    true
                }
                PrevCid::Gone => match self.rem_cids.next() {
                    // The peer retired the previous path's identifier: return with a fresh one.
                    Some((token, retired)) => {
                        if let Err(error) = self.retire_rem_cids(&retired) {
                            self.defer_error(error);
                        }
                        self.set_reset_token(prev.remote, token);
                        true
                    }
                    None => false,
                },
            };
            if usable {
                self.path = prev;
                self.set_loss_detection_timer(now);
            } else {
                trace!("no connection ID for the previous path: staying on the unvalidated one");
            }
        }
        self.path.challenge = None;
        self.path.challenge_pending = false;
    }

    /// Note the address a server advertises as preferred for the family in use (RFC 9000 §9.6.2),
    /// unless this client declines it. Probing waits for handshake confirmation.
    fn arm_preferred_address(&mut self, info: &PreferredAddress) {
        let policy = match &self.side {
            ConnectionSide::Client {
                preferred_address_policy,
                ..
            } => *preferred_address_policy,
            ConnectionSide::Server { .. } => return,
        };
        if policy == PreferredAddressPolicy::Decline {
            trace!("declining the server's preferred address");
            return;
        }
        // With connection IDs of our own the peer routes us by identifier; with none it routes us
        // by address, and a move would take us out of the tuple it knows (RFC 9000 §9).
        if self.local_cid_state.cid_len() == 0 {
            trace!("zero-length connection IDs: this connection cannot move");
            return;
        }
        let advertised = match self.path.remote {
            SocketAddr::V4(_) => info.address_v4.map(SocketAddr::V4),
            SocketAddr::V6(_) => info.address_v6.map(SocketAddr::V6),
        };
        match advertised {
            Some(remote) if remote != self.path.remote => {
                trace!(%remote, "the server prefers another address");
                self.preferred_address = Some(remote);
                self.preferred_state = PreferredAddressState::Armed;
            }
            Some(_) => trace!("the preferred address is the one in use"),
            None => trace!("no preferred address for the family in use"),
        }
    }

    /// Reserve an identifier for the candidate path and queue its first probe. The identifier the
    /// server bound to the address is used while it is unused; a `retire_prior_to` that took it
    /// leaves another unused one, and with none the attempt ends before anything is sent.
    fn begin_candidate(&mut self) {
        let Some(remote) = self.preferred_address else {
            return;
        };
        let Some(cid) = self
            .rem_cids
            .reserve_seq(PREFERRED_ADDRESS_CID_SEQ)
            .or_else(|| self.rem_cids.reserve())
        else {
            debug!("no unused connection ID for the preferred address");
            self.preferred_state = PreferredAddressState::Failed;
            return;
        };
        // The endpoint routes a reset carrying this identifier's token to us from now on, so no
        // answer can race the association; whether we treat such a reset as ours waits for a
        // probe carrying the identifier to have gone out (RFC 9000 §10.3.1).
        self.install_reset_route(cid.seq, remote);
        self.candidate = Some(PreferredCandidate {
            remote,
            cid: cid.id,
            seq: cid.seq,
            reset_token: cid.reset_token,
            sent: [0; MAX_PREFERRED_PROBES],
            transmitted: 0,
            pending: Some(self.rng.random()),
            in_flight: None,
        });
        self.preferred_state = PreferredAddressState::Probing;
    }

    /// Write one PATH_CHALLENGE towards the preferred address with the identifier reserved for it.
    /// The probe counts, and its identifier becomes one this connection has used, only when the
    /// sender reports the datagram gone ([`cid_sent`](Self::cid_sent)); the deadline is armed
    /// here, so a probe that cannot leave is bounded by the same interval as an unanswered one.
    fn send_preferred_probe(&mut self, now: Instant, buf: &mut Vec<u8>) -> Option<Transmit> {
        let candidate = self.candidate.as_ref()?;
        let token = candidate.pending?;
        let destination = candidate.remote;
        let cid = candidate.cid;
        if self.highest_space != SpaceId::Data {
            return None;
        }
        if self.timers.get(Timer::PathProbe).is_none() {
            self.timers
                .set(Timer::PathProbe, now + self.probe_interval());
        }
        buf.reserve(MIN_INITIAL_SIZE as usize);
        let buf_capacity = buf.capacity();
        let mut builder =
            PacketBuilder::new(now, SpaceId::Data, cid, buf, buf_capacity, 0, false, self)?;
        trace!(%destination, "probing the preferred address with PATH_CHALLENGE {:08x}", token);
        buf.write(frame::FrameType::PATH_CHALLENGE);
        buf.write(token);
        self.stats.frame_tx.path_challenge += 1;
        // An endpoint expands a datagram carrying a PATH_CHALLENGE to the smallest allowed
        // maximum datagram size.
        builder.pad_to(MIN_INITIAL_SIZE);
        builder.finish(self, now, buf);
        self.stats.udp_tx.on_sent(1, buf.len());
        let local = self.path.local;
        let candidate = self.candidate.as_mut()?;
        candidate.pending = None;
        candidate.in_flight = Some(token);
        let seq = candidate.seq;
        self.timers
            .set(Timer::PathProbe, now + self.probe_interval());
        Some(Transmit {
            destination,
            size: buf.len(),
            ecn: None,
            segment_size: None,
            local,
            cid_used: Some(seq),
        })
    }

    /// Whether the peer's connection ID with this sequence number is still one this connection
    /// may put on the wire. A datagram written before the identifier was retired, or before the
    /// attempt it belonged to was given up, must not go out afterwards (RFC 9000 §9.5).
    pub(crate) fn may_send_cid(&self, seq: u64, destination: SocketAddr) -> SendPermit {
        let known = seq == self.rem_cids.active_seq()
            || self.rem_cids.held().is_some_and(|held| held.seq == seq)
            || self.rem_cids.is_bound(seq)
            || self
                .candidate
                .as_ref()
                .is_some_and(|candidate| candidate.seq == seq && candidate.in_flight.is_some());
        if !known {
            // Retired, or bound to a path this datagram is not for: there is nothing to wait for.
            return SendPermit::Obsolete;
        }
        if self.rem_cids.is_installed(seq, destination) {
            return SendPermit::Sendable;
        }
        // The route is on its way to the endpoint. The datagram waits rather than going out
        // ahead of the way a reset answering it would come back (RFC 9000 §10.3.1).
        SendPermit::AwaitingInstallation
    }

    /// The sender has handed a datagram carrying the peer's connection ID with this sequence
    /// number to the network, so that identifier is one this connection has used and a stateless
    /// reset carrying its token belongs to us (RFC 9000 §10.3.1). A probe also counts here, and
    /// only here, against its attempt's bound.
    pub(crate) fn cid_sent(&mut self, seq: u64, destination: SocketAddr) {
        // Only what changed is published: an ordinary send, and a retry of one that was already
        // recorded, tell the endpoint nothing and allocate nothing.
        let generation = self.reset_generation;
        let owned = self.owned_remotes();
        if let Some((delta, token)) = self.rem_cids.mark_sent(seq, destination, generation, owned) {
            self.apply_route_delta(seq, token, delta, generation);
        }
        let Some(candidate) = self.candidate.as_mut().filter(|c| c.seq == seq) else {
            return;
        };
        let Some(token) = candidate.in_flight.take() else {
            return;
        };
        if let Some(slot) = candidate.sent.get_mut(candidate.transmitted) {
            *slot = token;
            candidate.transmitted += 1;
        }
        self.stats.path.preferred_address_probes += 1;
    }

    /// How long one preferred-address probe may go unanswered.
    fn probe_interval(&self) -> Duration {
        3 * self.pto(SpaceId::Data)
    }

    /// A probe went unanswered, or could not be sent within its own interval.
    fn on_probe_timeout(&mut self, now: Instant) {
        let Some((waiting, transmitted)) = self
            .candidate
            .as_ref()
            .map(|c| (c.outstanding(), c.transmitted))
        else {
            return;
        };
        if waiting {
            debug!("a preferred-address probe could not be sent in time");
            self.give_up_preferred_address();
            return;
        }
        if transmitted >= MAX_PREFERRED_PROBES {
            debug!("the preferred address did not answer");
            self.give_up_preferred_address();
            return;
        }
        // Each probe carries fresh data; the earlier ones stay valid until the attempt ends. This
        // is the only place a further probe is armed, which is what keeps the count at the bound.
        let token = self.rng.random();
        if let Some(candidate) = self.candidate.as_mut() {
            candidate.pending = Some(token);
        }
        self.timers
            .set(Timer::PathProbe, now + self.probe_interval());
    }

    /// Start the preferred-address attempt over: the identifier set aside for it is given up
    /// along with its challenge data, so nothing written with it can validate anything or go out,
    /// and a fresh identifier is reserved. Without one the attempt ends.
    fn restart_candidate(&mut self) {
        if self.candidate.take().is_none() {
            return;
        }
        self.timers.stop(Timer::PathProbe);
        if let Some(seq) = self.rem_cids.release_reserved()
            && let Err(error) = self.retire_rem_cid(seq)
        {
            self.defer_error(error);
        }
        trace!("the candidate path's identifier is gone: starting over");
        self.begin_candidate();
    }

    /// End the attempt: the reserved identifier is retired and the connection stays where it is.
    fn give_up_preferred_address(&mut self) {
        self.candidate = None;
        self.timers.stop(Timer::PathProbe);
        if let Some(seq) = self.rem_cids.release_reserved()
            && let Err(error) = self.retire_rem_cid(seq)
        {
            self.defer_error(error);
        }
        self.preferred_state = PreferredAddressState::Failed;
    }

    /// A probe was answered: move to the preferred address with the identifier reserved for it
    /// (RFC 9000 §9.6.2). The path left behind is not kept, so its identifier is retired.
    fn take_preferred_address(&mut self, now: Instant) {
        let Some(candidate) = self.candidate.take() else {
            return;
        };
        self.timers.stop(Timer::PathProbe);
        let Some((token, retired)) = self.rem_cids.promote_reserved() else {
            debug!("the preferred address answered, but its connection ID is gone");
            self.preferred_state = PreferredAddressState::Failed;
            return;
        };
        if let Err(error) = self.retire_rem_cids(&retired) {
            self.defer_error(error);
        }
        let local = self.path.local;
        self.migrate(now, candidate.remote, local, PreviousPath::Discard);
        // The candidate answered our challenge, so the path it stands for needs no validation.
        self.path.challenge = None;
        self.path.challenge_pending = false;
        self.path.validated = true;
        self.timers.stop(Timer::PathValidation);
        self.set_reset_token(candidate.remote, token);
        self.preferred_state = PreferredAddressState::Validated;
        debug!(remote = %candidate.remote, "moved to the server's preferred address");
    }

    /// The reset tokens that can reset this connection: the identifiers it sends with, which are
    /// the active one, one kept for a previous path, and one a probe has already gone out with
    /// (RFC 9000 §10.3.1).
    fn used_reset_tokens(&self, remote: SocketAddr) -> [Option<ResetToken>; CidQueue::PRESENT] {
        // Every identifier carries its own history, per address it was sent to, so this is simply
        // the ones a datagram has gone out with towards `remote`. A change of role neither grants
        // nor erases that, and a token used only at another address is not ours here
        // (RFC 9000 §10.3.1).
        self.rem_cids.used_reset_tokens(remote)
    }

    /// Whether a datagram received at `local` belongs to the current path's local address. An
    /// address unknown on either side tells us nothing, so only two known and different ones are
    /// off the current path.
    fn same_local(&self, local: Option<SocketAddr>) -> bool {
        match (local, self.path.local) {
            (Some(arrived), Some(current)) => arrived == current,
            _ => true,
        }
    }

    /// Whether `remote` is an address this client is probing: a response is accepted from there
    /// though the connection has not moved.
    fn probing_address(&self, remote: SocketAddr) -> bool {
        self.candidate.as_ref().is_some_and(|c| c.remote == remote)
    }

    /// Queue RETIRE_CONNECTION_ID for the identifiers in `retired` and forget their reset tokens,
    /// through the bounded queue: a peer that keeps us retiring cannot make it grow without end,
    /// and the connection fails with the protocol's own error when the bound is reached.
    fn retire_rem_cids(&mut self, retired: &Retired) -> Result<(), TransportError> {
        for range in retired.iter() {
            self.spaces[SpaceId::Data]
                .pending
                .retire_cids(range.clone())?;
            self.note_retired(range);
        }
        Ok(())
    }

    /// The same for the one identifier a path change lets go of.
    fn retire_rem_cid(&mut self, seq: u64) -> Result<(), TransportError> {
        self.spaces[SpaceId::Data]
            .pending
            .retire_cids(seq..seq + 1)?;
        self.note_retired(seq..seq + 1);
        Ok(())
    }

    /// Tests: refuse a retirement too wide to queue and carry the error the way every production
    /// site does, so the notification path can be exercised without arranging a full queue.
    #[cfg(test)]
    pub(crate) fn overflow_retirement_queue(&mut self) {
        if let Err(error) = self.spaces[SpaceId::Data].pending.retire_cids(0..u64::MAX) {
            self.defer_error(error);
        } else {
            panic!("a retirement of every sequence number should not be queued");
        }
    }

    /// Carry a protocol error out of a path that cannot return one; the first one wins, and the
    /// connection closes with it at the next transmit rather than losing what produced it.
    fn defer_error(&mut self, error: TransportError) {
        debug!(%error, "deferring a protocol error to the next transmit");
        if self.deferred_error.is_none() {
            self.deferred_error = Some(error);
        }
    }

    /// Tell the endpoint that the reset tokens of these retired identifiers no longer count.
    fn note_retired(&mut self, retired: Range<u64>) {
        if !retired.is_empty() {
            self.endpoint_events
                .push_back(EndpointEventInner::ResetTokensRetired(retired));
        }
    }

    fn migrate(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        local: Option<SocketAddr>,
        previous: PreviousPath,
    ) {
        trace!(%remote, ?local, "migration initiated");
        self.path_counter = self.path_counter.wrapping_add(1);
        // Reset rtt/congestion state for new path unless it looks like a NAT rebinding.
        // Note that the congestion window will not grow until validation terminates. Helps mitigate
        // amplification attacks performed by spoofing source addresses.
        let mut new_path = if remote.is_ipv4() && remote.ip() == self.path.remote.ip() {
            PathData::from_previous(remote, local, &self.path, self.path_counter, now)
        } else {
            let peer_max_udp_payload_size =
                u16::try_from(self.peer_params.max_udp_payload_size.into_inner())
                    .unwrap_or(u16::MAX);
            PathData::new(
                remote,
                local,
                self.allow_mtud,
                Some(peer_max_udp_payload_size),
                self.path_counter,
                now,
                &self.config,
            )
        };
        new_path.challenge = Some(self.rng.random());
        new_path.challenge_pending = true;
        let prev_pto = self.pto(SpaceId::Data);

        let mut prev = mem::replace(&mut self.path, new_path);
        match previous {
            // Don't clobber the original path if the previous one hasn't been validated yet
            PreviousPath::Keep(cid) if prev.challenge.is_none() => {
                prev.challenge = Some(self.rng.random());
                prev.challenge_pending = true;
                self.prev_path = Some(PrevPath { path: prev, cid });
            }
            PreviousPath::Keep(_) => {}
            // Our own move: the path we leave is not kept, nor is an older one.
            PreviousPath::Discard => self.drop_previous_path(),
        }

        self.timers.set(
            Timer::PathValidation,
            now + 3 * cmp::max(self.pto(SpaceId::Data), prev_pto),
        );
        // The path swap moves congestion state only: every ack-eliciting packet already sent, on
        // the path just replaced or on one dropped here, stays outstanding in its packet number
        // space and keeps driving the loss timer; re-evaluate it against that outstanding set.
        self.set_loss_detection_timer(now);
    }

    /// Whether this connection can start using a new local address now: RFC 9000 §9.5 forbids
    /// reusing a non-zero-length destination connection ID across local addresses, so an unused
    /// one must be available; a peer using zero-length connection IDs needs none.
    pub(crate) fn can_migrate_locally(&self) -> bool {
        self.rem_cids.active().is_empty() || self.rem_cids.has_unused()
    }

    /// Commit an active migration to a new local address: switch to an unused destination
    /// connection ID (retiring the current one) and probe the path. Returns `false`, changing
    /// nothing, when no unused connection ID is available and the peer's are not zero-length;
    /// the caller must then keep sending from the old address (see
    /// [`can_migrate_locally`](Self::can_migrate_locally)).
    pub(crate) fn migrate_local_address(&mut self) -> bool {
        if !self.rem_cids.active().is_empty() && !self.update_rem_cid() {
            return false;
        }
        // A candidate path's identifier may not be sent from another local address (RFC 9000
        // §9.5): the attempt starts over with a fresh identifier, or ends when none is unused.
        self.restart_candidate();
        self.ping();
        true
    }

    /// Whether the loss-detection (PTO) timer is armed (tests).
    #[cfg(test)]
    pub(crate) fn loss_detection_armed(&self) -> bool {
        self.timers.get(Timer::LossDetection).is_some()
    }

    /// Tests: whether a peer move is waiting for an unused destination connection ID.
    #[cfg(test)]
    pub(crate) fn deferred_move_pending(&self) -> bool {
        self.deferred_migration.is_some()
    }

    /// Tests: the destination connection ID kept aside for the previous path, if any.
    #[cfg(test)]
    pub(crate) fn held_rem_cid(&self) -> Option<ConnectionId> {
        self.rem_cids.held().map(|c| c.id)
    }

    /// Tests: whether a datagram carrying the active connection ID has gone out (RFC 9000
    /// §10.3.1: until one has, that identifier is not one we have used).
    #[cfg(test)]
    pub(crate) fn active_cid_confirmed(&self) -> bool {
        self.rem_cids.is_sent(self.rem_cids.active_seq())
    }

    /// Tests: the sequence number of the identifier kept for the previous path.
    #[cfg(test)]
    pub(crate) fn held_rem_cid_seq(&self) -> u64 {
        self.rem_cids.held().expect("an identifier is held").seq
    }

    /// Tests: whether a datagram carrying the identifier numbered `seq` has gone out.
    #[cfg(test)]
    pub(crate) fn cid_confirmed(&self, seq: u64) -> bool {
        self.rem_cids.is_sent(seq)
    }

    /// Tests: how far this client got with the server's preferred address.
    #[cfg(test)]
    pub(crate) fn preferred_address_state(&self) -> PreferredAddressState {
        self.preferred_state
    }

    /// Tests: the destination connection ID reserved for a candidate path, if any.
    #[cfg(test)]
    pub(crate) fn reserved_rem_cid(&self) -> Option<ConnectionId> {
        self.rem_cids.reserved().map(|c| c.id)
    }

    /// Tests: the destination connection IDs the peer issued that we have not used yet.
    #[cfg(test)]
    pub(crate) fn unused_rem_cids(&self) -> Vec<ConnectionId> {
        self.rem_cids.unused().into_iter().map(|c| c.id).collect()
    }

    /// Ack-eliciting packets in flight on the current path only (tests): the congestion view that
    /// a path swap resets, as opposed to the connection-wide outstanding set.
    #[cfg(test)]
    pub(crate) fn current_path_in_flight_ack_eliciting(&self) -> u64 {
        self.path.in_flight.ack_eliciting
    }

    /// Whether ack-driven time-threshold loss detection is pending in some packet number space
    /// (tests): a packet older than the largest acknowledged one is waiting to be declared lost.
    #[cfg(test)]
    pub(crate) fn loss_time_pending(&self) -> bool {
        SpaceId::iter().any(|space| self.spaces[space].loss_time.is_some())
    }

    /// Tests: the ack-eliciting in-flight count that loss recovery decides on, and the number of
    /// ack-eliciting packets actually outstanding in the packet number spaces. They must agree,
    /// whatever happened to the paths those packets were sent on.
    #[cfg(test)]
    pub(crate) fn loss_recovery_in_flight(&self) -> (u64, u64) {
        let outstanding = SpaceId::iter()
            .map(|space| {
                self.spaces[space]
                    .sent_packets
                    .values()
                    .filter(|packet| packet.ack_eliciting)
                    .count() as u64
            })
            .sum();
        (self.in_flight_ack_eliciting(), outstanding)
    }

    /// The active remote connection ID (tests observe it on the wire).
    #[cfg(test)]
    pub(crate) fn active_rem_cid(&self) -> ConnectionId {
        self.rem_cids.active()
    }

    /// Tests: hold HANDSHAKE_DONE back before it has been sent, so the peer stays complete but
    /// unconfirmed; clearing it queues the frame again for the next transmit.
    ///
    /// The fixture covers that phase only. It takes the frame out of the pending set rather than
    /// suppressing the write, so nothing announces a frame it will not write; it cannot recall one
    /// that has already gone, and a later loss requeues that one through retransmission like any
    /// other frame.
    #[cfg(test)]
    pub(crate) fn hold_handshake_done(&mut self, hold: bool) {
        self.hold_handshake_done = hold;
        if hold {
            self.withheld_handshake_done |=
                mem::take(&mut self.spaces[SpaceId::Data].pending.handshake_done);
        } else if mem::take(&mut self.withheld_handshake_done) {
            self.spaces[SpaceId::Data].pending.handshake_done = true;
        }
    }

    /// Queue HANDSHAKE_DONE for the peer. Withholding it keeps it out of the pending set: a frame
    /// that will not be written must not announce that there is something to send.
    fn queue_handshake_done(&mut self) {
        #[cfg(test)]
        if self.hold_handshake_done {
            self.withheld_handshake_done = true;
            return;
        }
        self.spaces[SpaceId::Data].pending.handshake_done = true;
    }

    /// Switch to a previously unused remote connection ID, if possible; `false` when none is
    /// available (nothing changes).
    fn update_rem_cid(&mut self) -> bool {
        let Some((reset_token, retired)) = self.rem_cids.next() else {
            return false;
        };

        // Retire the current remote CID and any CIDs we had to skip.
        if let Err(error) = self.retire_rem_cids(&retired) {
            self.defer_error(error);
        }
        self.set_reset_token(self.path.remote, reset_token);
        true
    }

    /// The active remote connection ID is now sent to `remote`: a stateless reset from there
    /// carrying `reset_token` is ours.
    fn set_reset_token(&mut self, remote: SocketAddr, reset_token: ResetToken) {
        let seq = self.rem_cids.active_seq();
        // The endpoint routes a reset carrying this token to us from now on; whether we treat it
        // as ours waits for a datagram with this identifier to have gone out, which the identifier
        // itself records.
        self.install_reset_route(seq, remote);
        self.peer_params.stateless_reset_token = Some(reset_token);
    }

    /// Tell the endpoint that the identifier with this sequence number is being sent to `remote`,
    /// so a stateless reset from there carrying its token reaches this connection.
    /// Install the route a reset for the identifier numbered `seq` at `remote` would arrive by,
    /// before anything is sent with it.
    fn install_reset_route(&mut self, seq: u64, remote: SocketAddr) {
        let generation = self.reset_generation;
        let owned = self.owned_remotes();
        if let Some((delta, token)) = self.rem_cids.install_route(seq, remote, generation, owned) {
            self.apply_route_delta(seq, token, delta, generation);
        }
    }

    /// The addresses a path role owns right now: where the current path sends, and where a
    /// retained previous or fallback path answers from. Nothing else is protected from being
    /// displaced by a newer address.
    fn owned_remotes(&self) -> OwnedRemotes {
        OwnedRemotes {
            current: Some(self.path.remote),
            fallback: self.prev_path.as_ref().map(|prev| prev.path.remote),
        }
    }

    /// Tell the endpoint what changed about one identifier's routes: the route it stopped using
    /// goes before the one that displaced it arrives, so the endpoint never holds more than the
    /// engine does.
    fn apply_route_delta(
        &mut self,
        seq: u64,
        token: ResetToken,
        delta: RouteDelta,
        generation: u64,
    ) {
        if let Some(released) = delta.released
            && let Some(installed) = released.generation()
        {
            self.release_reset_token(released.remote, seq, token, installed);
        }
        if let Some(added) = delta.added
            && let Some(installation) = added.generation()
        {
            self.note_reset_token(added.remote, seq, token, installation);
            if installation == generation {
                self.reset_generation = generation.wrapping_add(1);
            }
        }
    }

    fn note_reset_token(
        &mut self,
        remote: SocketAddr,
        seq: u64,
        reset_token: ResetToken,
        generation: u64,
    ) {
        self.endpoint_events
            .push_back(EndpointEventInner::ResetTokenUsed(
                remote,
                seq,
                reset_token,
                generation,
            ));
    }

    /// Tell the endpoint an association is no longer ours, naming the installation it belongs to
    /// so a newer one that reuses the same identifier and address is left alone.
    fn release_reset_token(
        &mut self,
        remote: SocketAddr,
        seq: u64,
        reset_token: ResetToken,
        generation: u64,
    ) {
        self.endpoint_events
            .push_back(EndpointEventInner::ResetTokenReleased(
                remote,
                seq,
                reset_token,
                generation,
            ));
    }

    /// Issue an initial set of connection IDs to the peer upon connection
    fn issue_first_cids(&mut self, now: Instant) {
        if self.local_cid_state.cid_len() == 0 {
            return;
        }

        // Subtract 1 to account for the CID we supplied while handshaking
        let mut n = self.peer_params.issue_cids_limit() - 1;
        if let ConnectionSide::Server { server_config } = &self.side {
            if server_config.has_preferred_address() {
                // We also sent a CID in the transport parameters
                n -= 1;
            }
        }
        self.endpoint_events
            .push_back(EndpointEventInner::NeedIdentifiers(now, n));
    }

    fn populate_packet(
        &mut self,
        now: Instant,
        space_id: SpaceId,
        buf: &mut Vec<u8>,
        max_size: usize,
        pn: u64,
    ) -> SentFrames {
        let mut sent = SentFrames::default();
        let space = &mut self.spaces[space_id];
        let is_0rtt = space_id == SpaceId::Data && space.crypto.is_none();
        space.pending_acks.maybe_ack_non_eliciting();

        let pre_payload_len = buf.len();

        // HANDSHAKE_DONE
        if !is_0rtt && mem::replace(&mut space.pending.handshake_done, false) {
            buf.write(frame::FrameType::HANDSHAKE_DONE);
            sent.retransmits.get_or_create().handshake_done = true;
            // This is just a u8 counter and the frame is typically just sent once
            self.stats.frame_tx.handshake_done =
                self.stats.frame_tx.handshake_done.saturating_add(1);
        }

        // PING
        if mem::replace(&mut space.ping_pending, false) {
            trace!("PING");
            buf.write(frame::FrameType::PING);
            sent.non_retransmits = true;
            self.stats.frame_tx.ping += 1;
        }

        // IMMEDIATE_ACK
        if mem::replace(&mut space.immediate_ack_pending, false) {
            trace!("IMMEDIATE_ACK");
            buf.write(frame::FrameType::IMMEDIATE_ACK);
            sent.non_retransmits = true;
            self.stats.frame_tx.immediate_ack += 1;
        }

        // ACK
        if space.pending_acks.can_send() {
            Self::try_populate_acks(
                now,
                self.receiving_ecn,
                &mut sent,
                space,
                buf,
                &mut self.stats,
                max_size,
            );
        }

        // ACK_FREQUENCY
        if mem::replace(&mut space.pending.ack_frequency, false) {
            let sequence_number = self.ack_frequency.next_sequence_number();

            // Safe to unwrap because this is always provided when ACK frequency is enabled
            #[expect(
                clippy::unwrap_used,
                reason = "`pending.ack_frequency` is only set when an `ack_frequency_config` is present (`AckFrequencyState::should_send_ack_frequency`)"
            )]
            let config = self.config.ack_frequency_config.as_ref().unwrap();

            // Ensure the delay is within bounds to avoid a PROTOCOL_VIOLATION error
            let max_ack_delay = self.ack_frequency.candidate_max_ack_delay(
                self.path.rtt.get(),
                config,
                &self.peer_params,
            );

            trace!(?max_ack_delay, "ACK_FREQUENCY");

            frame::AckFrequency {
                sequence: sequence_number,
                ack_eliciting_threshold: config.ack_eliciting_threshold,
                request_max_ack_delay: max_ack_delay.as_micros().try_into().unwrap_or(VarInt::MAX),
                reordering_threshold: config.reordering_threshold,
            }
            .encode(buf);

            sent.retransmits.get_or_create().ack_frequency = true;

            self.ack_frequency.ack_frequency_sent(pn, max_ack_delay);
            self.stats.frame_tx.ack_frequency += 1;
        }

        // PATH_CHALLENGE
        if buf.len() + 9 < max_size && space_id == SpaceId::Data {
            // Transmit challenges with every outgoing frame on an unvalidated path
            if let Some(token) = self.path.challenge {
                // But only send a packet solely for that purpose at most once
                self.path.challenge_pending = false;
                sent.non_retransmits = true;
                sent.requires_padding = true;
                trace!("PATH_CHALLENGE {:08x}", token);
                buf.write(frame::FrameType::PATH_CHALLENGE);
                buf.write(token);
                self.stats.frame_tx.path_challenge += 1;
            }
        }

        // PATH_RESPONSE
        if buf.len() + 9 < max_size && space_id == SpaceId::Data {
            if let Some(token) = self
                .path_responses
                .pop_on_path(self.path.remote, self.path.local)
            {
                sent.non_retransmits = true;
                sent.requires_padding = true;
                trace!("PATH_RESPONSE {:08x}", token);
                buf.write(frame::FrameType::PATH_RESPONSE);
                buf.write(token);
                self.stats.frame_tx.path_response += 1;
            }
        }

        // CRYPTO
        while buf.len() + frame::Crypto::SIZE_BOUND < max_size && !is_0rtt {
            let mut frame = match space.pending.crypto.pop_front() {
                Some(x) => x,
                None => break,
            };

            // Calculate the maximum amount of crypto data we can store in the buffer.
            // Since the offset is known, we can reserve the exact size required to encode it.
            // For length we reserve 2bytes which allows to encode up to 2^14,
            // which is more than what fits into normally sized QUIC frames.
            let max_crypto_data_size = max_size
                - buf.len()
                - 1 // Frame Type
                - VarInt::size(unsafe { VarInt::from_u64_unchecked(frame.offset) })
                - 2; // Maximum encoded length for frame size, given we send less than 2^14 bytes

            let len = frame
                .data
                .len()
                .min(2usize.pow(14) - 1)
                .min(max_crypto_data_size);

            let data = frame.data.split_to(len);
            let truncated = frame::Crypto {
                offset: frame.offset,
                data,
            };
            trace!(
                "CRYPTO: off {} len {}",
                truncated.offset,
                truncated.data.len()
            );
            truncated.encode(buf);
            self.stats.frame_tx.crypto += 1;
            sent.retransmits.get_or_create().crypto.push_back(truncated);
            if !frame.data.is_empty() {
                frame.offset += len as u64;
                space.pending.crypto.push_front(frame);
            }
        }

        if space_id == SpaceId::Data {
            self.streams.write_control_frames(
                buf,
                &mut space.pending,
                &mut sent.retransmits,
                &mut self.stats.frame_tx,
                max_size,
            );
        }

        // NEW_CONNECTION_ID
        while buf.len() + NewConnectionId::SIZE_BOUND < max_size {
            let issued = match space.pending.new_cids.pop() {
                Some(x) => x,
                None => break,
            };
            trace!(
                sequence = issued.sequence,
                id = %issued.id,
                "NEW_CONNECTION_ID"
            );
            frame::NewConnectionId {
                sequence: issued.sequence,
                retire_prior_to: self.local_cid_state.retire_prior_to(),
                id: issued.id,
                reset_token: issued.reset_token,
            }
            .encode(buf);
            sent.retransmits.get_or_create().new_cids.push(issued);
            self.stats.frame_tx.new_connection_id += 1;
        }

        // RETIRE_CONNECTION_ID
        while buf.len() + frame::RETIRE_CONNECTION_ID_SIZE_BOUND < max_size {
            let seq = match space.pending.retire_cids.pop() {
                Some(x) => x,
                None => break,
            };
            trace!(sequence = seq, "RETIRE_CONNECTION_ID");
            buf.write(frame::FrameType::RETIRE_CONNECTION_ID);
            buf.write_var(seq);
            sent.retransmits.get_or_create().retire_cids.push(seq);
            self.stats.frame_tx.retire_connection_id += 1;
        }

        // DATAGRAM
        let mut sent_datagrams = false;
        while buf.len() + Datagram::SIZE_BOUND < max_size && space_id == SpaceId::Data {
            match self.datagrams.write(buf, max_size) {
                true => {
                    sent_datagrams = true;
                    sent.non_retransmits = true;
                    self.stats.frame_tx.datagram += 1;
                }
                false => break,
            }
        }
        if self.datagrams.send_blocked && sent_datagrams {
            self.events.push_back(Event::DatagramsUnblocked);
            self.datagrams.send_blocked = false;
        }

        // NEW_TOKEN
        while let Some(remote_addr) = space.pending.new_tokens.pop() {
            debug_assert_eq!(space_id, SpaceId::Data);
            #[expect(
                clippy::panic,
                reason = "only server-side address validation queues `pending.new_tokens`"
            )]
            let ConnectionSide::Server { server_config } = &self.side else {
                panic!("NEW_TOKEN frames should not be enqueued by clients");
            };

            if remote_addr != self.path.remote {
                // NEW_TOKEN frames contain tokens bound to a client's IP address, and are only
                // useful if used from the same IP address.  Thus, we abandon enqueued NEW_TOKEN
                // frames upon an path change. Instead, when the new path becomes validated,
                // NEW_TOKEN frames may be enqueued for the new path instead.
                continue;
            }

            let token = Token::new(
                TokenPayload::Validation {
                    ip: remote_addr.ip(),
                    issued: server_config.time_source.now(),
                },
                &mut self.rng,
            );
            // NEW_TOKEN is an optimisation for the client's next connection: a provider
            // that cannot seal it costs that client a future validation, nothing else.
            let token = match token.encode(&*server_config.token_key) {
                Ok(token) => token,
                Err(error) => {
                    warn!(%error, "validation token could not be sealed; NEW_TOKEN skipped");
                    self.stats.frame_tx.new_token_failed += 1;
                    continue;
                }
            };
            let new_token = NewToken {
                token: token.into(),
            };

            if buf.len() + new_token.size() >= max_size {
                space.pending.new_tokens.push(remote_addr);
                break;
            }

            new_token.encode(buf);
            sent.retransmits
                .get_or_create()
                .new_tokens
                .push(remote_addr);
            self.stats.frame_tx.new_token += 1;
        }

        // STREAM
        if space_id == SpaceId::Data {
            sent.stream_frames =
                self.streams
                    .write_stream_frames(buf, max_size, self.config.send_fairness);
            self.stats.frame_tx.stream += sent.stream_frames.len() as u64;
        }

        // Bundle ACK with other frames when there is room for them.
        // We want to reuse encryption and underlying protocol overhead,
        // but sending multiple ACKs for a single incoming packet is a waste of peer's resources,
        // so we have next_bundled_ack_time to control when to send ACKs.
        let any_frames_sent = buf.len() > pre_payload_len;
        if any_frames_sent
            && sent.largest_acked.is_none()
            && self.next_bundled_ack_time.is_some_and(|time| time <= now)
            && space.pending_acks.can_send_with_other_frames()
        {
            Self::try_populate_acks(
                now,
                self.receiving_ecn,
                &mut sent,
                space,
                buf,
                &mut self.stats,
                max_size,
            );
        }

        sent
    }

    /// Tries to write pending ACKs into a buffer if there is enough space.
    ///
    /// If the ACK frame does not fit into the buffer, the ACK frame will not
    /// be sent at all.
    ///
    /// This method assumes ACKs are pending, and should only be called if
    /// `!PendingAcks::ranges().is_empty()` returns `true`.
    fn try_populate_acks(
        now: Instant,
        receiving_ecn: bool,
        sent: &mut SentFrames,
        space: &mut PacketSpace,
        buf: &mut Vec<u8>,
        stats: &mut ConnectionStats,
        max_size: usize,
    ) {
        debug_assert!(!space.pending_acks.ranges().is_empty());

        // 0-RTT packets must never carry acks (which would have to be of handshake packets)
        debug_assert!(space.crypto.is_some(), "tried to send ACK in 0-RTT");
        let ecn = if receiving_ecn {
            Some(&space.ecn_counters)
        } else {
            None
        };

        let delay_micros = space.pending_acks.ack_delay(now).as_micros() as u64;

        // TODO: This should come from `TransportConfig` if that gets configurable.
        let ack_delay_exp = TransportParameters::default().ack_delay_exponent;
        let delay = delay_micros >> ack_delay_exp.into_inner();

        trace!(
            "ACK {:?}, Delay = {}us",
            space.pending_acks.ranges(),
            delay_micros
        );

        let no_acks_len = buf.len();
        frame::Ack::encode(delay as _, space.pending_acks.ranges(), ecn, buf);
        if buf.len() > max_size {
            // The ACK frame is too large. Remove it.
            buf.truncate(no_acks_len);
            return;
        }
        sent.largest_acked = space.pending_acks.ranges().max();
        stats.frame_tx.acks += 1;
    }

    fn close_common(&mut self) {
        trace!("connection closed");
        for &timer in &Timer::VALUES {
            self.timers.stop(timer);
        }
    }

    fn set_close_timer(&mut self, now: Instant) {
        self.timers
            .set(Timer::Close, now + 3 * self.pto(self.highest_space));
    }

    /// Handle transport parameters received from the peer
    fn handle_peer_params(&mut self, params: TransportParameters) -> Result<(), TransportError> {
        if Some(self.orig_rem_cid) != params.initial_src_cid
            || (self.side.is_client()
                && (Some(self.initial_dst_cid) != params.original_dst_cid
                    || self.retry_src_cid != params.retry_src_cid))
        {
            return Err(TransportError::TRANSPORT_PARAMETER_ERROR(
                "CID authentication failure",
            ));
        }

        self.set_peer_params(params);

        Ok(())
    }

    fn set_peer_params(&mut self, params: TransportParameters) {
        self.streams.set_params(&params);
        self.idle_timeout =
            negotiate_max_idle_timeout(self.config.max_idle_timeout, Some(params.max_idle_timeout));
        trace!("negotiated max idle timeout {:?}", self.idle_timeout);
        if let Some(ref info) = params.preferred_address {
            #[expect(clippy::expect_used, reason = "`set_peer_params` runs once, right after the handshake, when the CID queue only holds sequence 0, so sequence 1 always fits")]
            self.rem_cids.insert(frame::NewConnectionId {
                sequence: 1,
                id: info.connection_id,
                reset_token: info.stateless_reset_token,
                retire_prior_to: 0,
            }).expect("preferred address CID is the first received, and hence is guaranteed to be legal");
            self.arm_preferred_address(info);
        }
        self.ack_frequency.peer_max_ack_delay = get_max_ack_delay(&params);
        self.peer_params = params;
        self.path.mtud.on_peer_max_udp_payload_size_received(
            u16::try_from(self.peer_params.max_udp_payload_size.into_inner()).unwrap_or(u16::MAX),
        );
    }

    fn decrypt_packet(
        &mut self,
        now: Instant,
        packet: &mut Packet,
    ) -> Result<Option<u64>, Option<TransportError>> {
        let result = packet_crypto::decrypt_packet_body(
            packet,
            &self.spaces,
            self.zero_rtt_crypto.as_ref(),
            self.key_phase,
            self.prev_crypto.as_ref(),
            self.next_crypto.as_ref(),
        )?;

        let result = match result {
            Some(r) => r,
            None => return Ok(None),
        };

        if result.outgoing_key_update_acked {
            if let Some(prev) = self.prev_crypto.as_mut() {
                prev.end_packet = Some((result.number, now));
                self.set_key_discard_timer(now, packet.header.space());
            }
        }

        if result.incoming_key_update {
            trace!("key update authenticated");
            self.update_keys(Some((result.number, now)), true);
            self.set_key_discard_timer(now, packet.header.space());
        }

        Ok(Some(result.number))
    }

    fn update_keys(&mut self, end_packet: Option<(u64, Instant)>, remote: bool) {
        trace!("executing key update");
        // Generate keys for the key phase after the one we're switching to, store them in
        // `next_crypto`, make the contents of `next_crypto` current, and move the current keys into
        // `prev_crypto`.
        #[expect(
            clippy::expect_used,
            reason = "a key update is only triggered by 1-RTT packets, i.e. after `upgrade_crypto(Data)` made `next_1rtt_keys` available"
        )]
        let new = self
            .crypto
            .next_1rtt_keys()
            .expect("only called for `Data` packets");
        self.key_phase_size = new
            .local
            .confidentiality_limit()
            .saturating_sub(KEY_UPDATE_MARGIN);
        #[expect(
            clippy::unwrap_used,
            reason = "1-RTT keys and `next_crypto` are installed together in `upgrade_crypto(Data)` before any key update can happen"
        )]
        let old = mem::replace(
            &mut self.spaces[SpaceId::Data]
                .crypto
                .as_mut()
                .unwrap() // safe because update_keys() can only be triggered by short packets
                .packet,
            mem::replace(self.next_crypto.as_mut().unwrap(), new),
        );
        self.spaces[SpaceId::Data].sent_with_keys = 0;
        self.prev_crypto = Some(PrevCrypto {
            crypto: old,
            end_packet,
            update_unacked: remote,
        });
        self.key_phase = !self.key_phase;
    }

    fn peer_supports_ack_frequency(&self) -> bool {
        self.peer_params.min_ack_delay.is_some()
    }

    /// Send an IMMEDIATE_ACK frame to the remote endpoint
    ///
    /// According to the spec, this will result in an error if the remote endpoint does not support
    /// the Acknowledgement Frequency extension
    pub(crate) fn immediate_ack(&mut self) {
        self.spaces[self.highest_space].immediate_ack_pending = true;
    }

    /// Decodes a packet, returning its decrypted payload, so it can be inspected in tests
    #[cfg(test)]
    pub(crate) fn decode_packet(&self, event: &ConnectionEvent) -> Option<Vec<u8>> {
        let (first_decode, remaining) = match &event.0 {
            ConnectionEventInner::Datagram(DatagramConnectionEvent {
                first_decode,
                remaining,
                ..
            }) => (first_decode, remaining),
            _ => return None,
        };

        if remaining.is_some() {
            panic!("Packets should never be coalesced in tests");
        }

        let decrypted_header = packet_crypto::unprotect_header(
            first_decode.clone(),
            &self.spaces,
            self.zero_rtt_crypto.as_ref(),
            &self.used_reset_tokens(self.path.remote),
        )?;

        let mut packet = decrypted_header.packet?;
        packet_crypto::decrypt_packet_body(
            &mut packet,
            &self.spaces,
            self.zero_rtt_crypto.as_ref(),
            self.key_phase,
            self.prev_crypto.as_ref(),
            self.next_crypto.as_ref(),
        )
        .ok()?;

        Some(packet.payload.to_vec())
    }

    /// The number of bytes of packets containing retransmittable frames that have not been
    /// acknowledged or declared lost.
    #[cfg(test)]
    pub(crate) fn bytes_in_flight(&self) -> u64 {
        self.path.in_flight.bytes
    }

    /// Number of bytes worth of non-ack-only packets that may be sent
    #[cfg(test)]
    pub(crate) fn congestion_window(&self) -> u64 {
        self.path
            .congestion
            .window()
            .saturating_sub(self.path.in_flight.bytes)
    }

    /// Whether only background and lifetime timers remain, so a test can stop driving traffic.
    #[cfg(test)]
    pub(crate) fn is_idle(&self) -> bool {
        Timer::VALUES
            .iter()
            .filter(|&&t| !matches!(t, Timer::KeepAlive | Timer::PushNewCid | Timer::KeyDiscard))
            .filter_map(|&t| Some((t, self.timers.get(t)?)))
            .min_by_key(|&(_, time)| time)
            .is_none_or(|(timer, _)| matches!(timer, Timer::Idle | Timer::Handshake))
    }

    /// Whether explicit congestion notification is in use on outgoing packets.
    #[cfg(test)]
    pub(crate) fn using_ecn(&self) -> bool {
        self.path.sending_ecn
    }

    /// The number of received bytes in the current path
    #[cfg(test)]
    pub(crate) fn total_recvd(&self) -> u64 {
        self.path.total_recvd
    }

    #[cfg(test)]
    pub(crate) fn active_local_cid_seq(&self) -> (u64, u64) {
        self.local_cid_state.active_seq()
    }

    /// Instruct the peer to replace previously issued CIDs by sending a NEW_CONNECTION_ID frame
    /// with updated `retire_prior_to` field set to `v`
    #[cfg(test)]
    pub(crate) fn rotate_local_cid(&mut self, v: u64, now: Instant) {
        let n = self.local_cid_state.assign_retire_seq(v);
        self.endpoint_events
            .push_back(EndpointEventInner::NeedIdentifiers(now, n));
    }

    /// Check the current active remote CID sequence
    #[cfg(test)]
    pub(crate) fn active_rem_cid_seq(&self) -> u64 {
        self.rem_cids.active_seq()
    }

    /// Returns the detected maximum udp payload size for the current path
    #[cfg(test)]
    pub(crate) fn path_mtu(&self) -> u16 {
        self.path.current_mtu()
    }

    /// Whether we have 1-RTT data to send
    ///
    /// See also `self.space(SpaceId::Data).can_send()`
    fn can_send_1rtt(&self, max_size: usize) -> bool {
        self.streams.can_send_stream_data()
            || self.path.challenge_pending
            || self
                .prev_path
                .as_ref()
                .is_some_and(|prev| prev.path.challenge_pending)
            || self.candidate.as_ref().is_some_and(|c| c.pending.is_some())
            || !self.path_responses.is_empty()
            || self.datagrams.outgoing.can_send_1rtt(max_size)
    }

    /// Update counters to account for a packet becoming acknowledged, lost, or abandoned
    fn remove_in_flight(&mut self, packet: &SentPacket) {
        if packet.ack_eliciting {
            self.in_flight_ack_eliciting = self.in_flight_ack_eliciting.saturating_sub(1);
        }
        // Visit known paths from newest to oldest to find the one `packet` was sent on; a packet
        // from a discarded path only leaves the connection-wide count above.
        for path in [&mut self.path]
            .into_iter()
            .chain(self.prev_path.as_mut().map(|prev| &mut prev.path))
        {
            if path.remove_in_flight(packet) {
                return;
            }
        }
    }

    /// Terminate the connection instantly, without sending a close packet
    fn kill(&mut self, reason: ConnectionError) {
        self.close_common();
        self.error = Some(reason);
        self.state = State::Drained;
        self.endpoint_events.push_back(EndpointEventInner::Drained);
    }

    /// Storage size required for the largest packet known to be supported by the current path
    ///
    /// Buffers passed to [`Connection::poll_transmit`] should be at least this large.
    pub(crate) fn current_mtu(&self) -> u16 {
        self.path.current_mtu()
    }

    /// Size of non-frame data for a 1-RTT packet
    ///
    /// Quantifies space consumed by the QUIC header and AEAD tag. All other bytes in a packet are
    /// frames. Changes if the length of the remote connection ID changes, which is expected to be
    /// rare. If `pn` is specified, may additionally change unpredictably due to variations in
    /// latency and packet loss.
    fn predict_1rtt_overhead(&self, pn: Option<u64>) -> usize {
        let pn_len = match pn {
            Some(pn) => PacketNumber::new(
                pn,
                self.spaces[SpaceId::Data].largest_acked_packet.unwrap_or(0),
            )
            .len(),
            // Upper bound
            None => 4,
        };

        // 1 byte for flags
        1 + self.rem_cids.active().len() + pn_len + self.tag_len_1rtt()
    }

    fn tag_len_1rtt(&self) -> usize {
        let key = match self.spaces[SpaceId::Data].crypto.as_ref() {
            Some(crypto) => Some(&*crypto.packet.local),
            None => self.zero_rtt_crypto.as_ref().map(|x| &*x.packet),
        };
        // If neither Data nor 0-RTT keys are available, make a reasonable tag length guess. As of
        // this writing, all QUIC cipher suites use 16-byte tags. We could return `None` instead,
        // but that would needlessly prevent sending datagrams during 0-RTT.
        key.map_or(16, |x| x.tag_len())
    }

    /// Mark the path as validated, and enqueue NEW_TOKEN frames to be sent as appropriate
    fn on_path_validated(&mut self) {
        self.path.validated = true;
        let ConnectionSide::Server { server_config } = &self.side else {
            return;
        };
        let new_tokens = &mut self.spaces[SpaceId::Data as usize].pending.new_tokens;
        new_tokens.clear();
        for _ in 0..server_config.validation_token.sent {
            new_tokens.push(self.path.remote);
        }
    }
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Connection")
            .field("handshake_cid", &self.handshake_cid)
            .finish()
    }
}

/// Fields of `Connection` specific to it being client-side or server-side
enum ConnectionSide {
    Client {
        /// Sent in every outgoing Initial packet. Always empty after Initial keys are discarded
        token: Bytes,
        token_store: Arc<dyn TokenStore>,
        server_name: String,
        /// What to do with an address the server advertises as preferred
        preferred_address_policy: PreferredAddressPolicy,
    },
    Server {
        server_config: Arc<ServerConfig>,
    },
}

impl ConnectionSide {
    fn remote_may_migrate(&self) -> bool {
        match self {
            Self::Server { server_config } => server_config.migration,
            Self::Client { .. } => false,
        }
    }

    fn is_client(&self) -> bool {
        self.side().is_client()
    }

    fn is_server(&self) -> bool {
        self.side().is_server()
    }

    fn side(&self) -> Side {
        match *self {
            Self::Client { .. } => Side::Client,
            Self::Server { .. } => Side::Server,
        }
    }
}

impl From<SideArgs> for ConnectionSide {
    fn from(side: SideArgs) -> Self {
        match side {
            SideArgs::Client {
                token_store,
                server_name,
                preferred_address_policy,
            } => Self::Client {
                token: token_store.take(&server_name).unwrap_or_default(),
                token_store,
                server_name,
                preferred_address_policy,
            },
            SideArgs::Server {
                server_config,
                pref_addr_cid: _,
                path_validated: _,
            } => Self::Server { server_config },
        }
    }
}

/// Parameters to `Connection::new` specific to it being client-side or server-side
pub(crate) enum SideArgs {
    Client {
        token_store: Arc<dyn TokenStore>,
        server_name: String,
        preferred_address_policy: PreferredAddressPolicy,
    },
    Server {
        server_config: Arc<ServerConfig>,
        pref_addr_cid: Option<ConnectionId>,
        path_validated: bool,
    },
}

impl SideArgs {
    pub(crate) fn pref_addr_cid(&self) -> Option<ConnectionId> {
        match *self {
            Self::Client { .. } => None,
            Self::Server { pref_addr_cid, .. } => pref_addr_cid,
        }
    }

    pub(crate) fn path_validated(&self) -> bool {
        match *self {
            Self::Client { .. } => true,
            Self::Server { path_validated, .. } => path_validated,
        }
    }

    pub(crate) fn side(&self) -> Side {
        match *self {
            Self::Client { .. } => Side::Client,
            Self::Server { .. } => Side::Server,
        }
    }
}

/// Reasons why a connection might be lost
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionError {
    /// The peer doesn't implement any supported version
    VersionMismatch,
    /// The peer violated the QUIC specification as understood by this implementation
    TransportError(TransportError),
    /// The peer's QUIC stack aborted the connection automatically
    ConnectionClosed(frame::ConnectionClose),
    /// The peer closed the connection
    ApplicationClosed(frame::ApplicationClose),
    /// The peer is unable to continue processing this connection, usually due to having restarted
    Reset,
    /// The handshake deadline or negotiated idle timeout elapsed.
    ///
    /// The local handshake deadline also applies when idle timeout is disabled.
    /// After connecting, a long enough idle period can time out even if the peer is
    /// still reachable. See [`TransportConfig::max_idle_timeout()`] and
    /// [`TransportConfig::keep_alive_interval()`].
    TimedOut,
    /// The local application closed the connection
    LocallyClosed,
    /// The connection could not be created because not enough of the CID space is available
    ///
    /// Try using longer connection IDs.
    CidsExhausted,
}

impl core::fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::VersionMismatch => f.write_str("peer doesn't implement any supported version"),
            Self::TransportError(inner) => core::fmt::Display::fmt(inner, f),
            Self::ConnectionClosed(field0) => write!(f, "aborted by peer: {field0}"),
            Self::ApplicationClosed(field0) => write!(f, "closed by peer: {field0}"),
            Self::Reset => f.write_str("reset by peer"),
            Self::TimedOut => f.write_str("timed out"),
            Self::LocallyClosed => f.write_str("closed"),
            Self::CidsExhausted => f.write_str("CIDs exhausted"),
        }
    }
}

impl std::error::Error for ConnectionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::TransportError(inner) => Some(inner),
            _ => None,
        }
    }
}

impl From<TransportError> for ConnectionError {
    fn from(value: TransportError) -> Self {
        Self::TransportError(value)
    }
}

impl From<Close> for ConnectionError {
    fn from(x: Close) -> Self {
        match x {
            Close::Connection(reason) => Self::ConnectionClosed(reason),
            Close::Application(reason) => Self::ApplicationClosed(reason),
        }
    }
}

// For compatibility with API consumers
impl From<ConnectionError> for io::Error {
    fn from(x: ConnectionError) -> Self {
        use ConnectionError::*;
        let kind = match x {
            TimedOut => io::ErrorKind::TimedOut,
            Reset => io::ErrorKind::ConnectionReset,
            ApplicationClosed(_) | ConnectionClosed(_) => io::ErrorKind::ConnectionAborted,
            TransportError(_) | VersionMismatch | LocallyClosed | CidsExhausted => {
                io::ErrorKind::Other
            }
        };
        Self::new(kind, x)
    }
}

#[cfg_attr(
    not(fuzzing),
    expect(
        unreachable_pub,
        reason = "reachable through `fuzzing` under cfg(fuzzing)"
    )
)]
#[derive(Clone)]
pub enum State {
    Handshake(state::Handshake),
    Established,
    Closed(state::Closed),
    Draining,
    /// Waiting for application to call close so we can dispose of the resources
    Drained,
}

impl State {
    fn closed<R: Into<Close>>(reason: R) -> Self {
        Self::Closed(state::Closed {
            reason: reason.into(),
        })
    }

    fn is_handshake(&self) -> bool {
        matches!(*self, Self::Handshake(_))
    }

    fn is_established(&self) -> bool {
        matches!(*self, Self::Established)
    }

    fn is_closed(&self) -> bool {
        matches!(*self, Self::Closed(_) | Self::Draining | Self::Drained)
    }

    fn is_drained(&self) -> bool {
        matches!(*self, Self::Drained)
    }
}

mod state {
    use super::*;

    #[cfg_attr(
        not(fuzzing),
        expect(
            unreachable_pub,
            reason = "reachable through `fuzzing` under cfg(fuzzing)"
        )
    )]
    #[derive(Clone)]
    pub struct Handshake {
        /// Whether the remote CID has been set by the peer yet
        ///
        /// Always set for servers
        pub(super) rem_cid_set: bool,
        /// Stateless retry token received in the first Initial by a server.
        ///
        /// Must be present in every Initial. Always empty for clients.
        pub(super) expected_token: Bytes,
        /// First cryptographic message
        ///
        /// Only set for clients
        pub(super) client_hello: Option<Bytes>,
    }

    #[cfg_attr(
        not(fuzzing),
        expect(
            unreachable_pub,
            reason = "reachable through `fuzzing` under cfg(fuzzing)"
        )
    )]
    #[derive(Clone)]
    pub struct Closed {
        pub(super) reason: Close,
    }
}

/// Events of interest to the application
#[derive(Debug)]
pub(crate) enum Event {
    /// The connection's handshake data is ready
    HandshakeDataReady,
    /// The connection was successfully established
    Connected,
    /// The TLS handshake was confirmed (RFC 9001 §4.1.2)
    HandshakeConfirmed,
    /// The connection was lost
    ///
    /// Emitted if the peer closes the connection or an error is encountered.
    ConnectionLost {
        /// Reason that the connection was closed
        reason: ConnectionError,
    },
    /// Stream events
    Stream(StreamEvent),
    /// One or more application datagrams have been received
    DatagramReceived,
    /// One or more application datagrams have been sent after blocking
    DatagramsUnblocked,
}

fn get_max_ack_delay(params: &TransportParameters) -> Duration {
    Duration::from_micros(params.max_ack_delay.0 * 1000)
}

// Prevents overflow and improves behavior in extreme circumstances
const MAX_BACKOFF_EXPONENT: u32 = 16;

/// Minimal remaining size to allow packet coalescing, excluding cryptographic tag
///
/// This must be at least as large as the header for a well-formed empty packet to be coalesced,
/// plus some space for frames. We only care about handshake headers because short header packets
/// necessarily have smaller headers, and initial packets are only ever the first packet in a
/// datagram (because we coalesce in ascending packet space order and the only reason to split a
/// packet is when packet space changes).
const MIN_PACKET_SPACE: usize = MAX_HANDSHAKE_OR_0RTT_HEADER_SIZE + 32;

/// Largest amount of space that could be occupied by a Handshake or 0-RTT packet's header
///
/// Excludes packet-type-specific fields such as packet number or Initial token
// https://www.rfc-editor.org/rfc/rfc9000.html#name-0-rtt: flags + version + dcid len + dcid +
// scid len + scid + length + pn
const MAX_HANDSHAKE_OR_0RTT_HEADER_SIZE: usize =
    1 + 4 + 1 + MAX_CID_SIZE + 1 + MAX_CID_SIZE + VarInt::from_u32(u16::MAX as u32).size() + 4;

/// Perform key updates this many packets before the AEAD confidentiality limit.
///
/// Chosen arbitrarily, intended to be large enough to prevent spurious connection loss.
const KEY_UPDATE_MARGIN: u64 = 10_000;

#[derive(Default)]
struct SentFrames {
    retransmits: ThinRetransmits,
    largest_acked: Option<u64>,
    stream_frames: StreamMetaVec,
    /// Whether the packet contains non-retransmittable frames (like datagrams)
    non_retransmits: bool,
    requires_padding: bool,
}

impl SentFrames {
    /// Returns whether the packet contains only ACKs
    fn is_ack_only(&self, streams: &StreamsState) -> bool {
        self.largest_acked.is_some()
            && !self.non_retransmits
            && self.stream_frames.is_empty()
            && self.retransmits.is_empty(streams)
    }
}

/// Compute the negotiated idle timeout based on local and remote max_idle_timeout transport parameters.
///
/// According to the definition of max_idle_timeout, a value of `0` means the timeout is disabled; see <https://www.rfc-editor.org/rfc/rfc9000#section-18.2-4.4.1.>
///
/// According to the negotiation procedure, either the minimum of the timeouts or one specified is used as the negotiated value; see <https://www.rfc-editor.org/rfc/rfc9000#section-10.1-2.>
///
/// Returns the negotiated idle timeout as a `Duration`, or `None` when both endpoints have opted out of idle timeout.
fn negotiate_max_idle_timeout(x: Option<VarInt>, y: Option<VarInt>) -> Option<Duration> {
    match (x, y) {
        (Some(VarInt(0)) | None, Some(VarInt(0)) | None) => None,
        (Some(VarInt(0)) | None, Some(y)) => Some(Duration::from_millis(y.0)),
        (Some(x), Some(VarInt(0)) | None) => Some(Duration::from_millis(x.0)),
        (Some(x), Some(y)) => Some(Duration::from_millis(cmp::min(x, y).0)),
    }
}

fn persistent_congestion_period(pto: Duration, threshold: u32) -> Duration {
    pto.saturating_mul(threshold)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persistent_congestion_period_saturates() {
        assert_eq!(
            persistent_congestion_period(Duration::from_millis(500), 3),
            Duration::from_millis(1500)
        );
        assert_eq!(
            persistent_congestion_period(Duration::MAX, 0),
            Duration::ZERO
        );
        assert_eq!(
            persistent_congestion_period(Duration::MAX, 1),
            Duration::MAX
        );
        let pto = Duration::from_secs(u64::MAX / u64::from(u32::MAX) + 1);
        assert!(pto.checked_mul(u32::MAX).is_none());
        assert_eq!(persistent_congestion_period(pto, u32::MAX), Duration::MAX);
    }

    #[test]
    fn negotiate_max_idle_timeout_commutative() {
        let test_params = [
            (None, None, None),
            (None, Some(VarInt(0)), None),
            (None, Some(VarInt(2)), Some(Duration::from_millis(2))),
            (Some(VarInt(0)), Some(VarInt(0)), None),
            (
                Some(VarInt(2)),
                Some(VarInt(0)),
                Some(Duration::from_millis(2)),
            ),
            (
                Some(VarInt(1)),
                Some(VarInt(4)),
                Some(Duration::from_millis(1)),
            ),
        ];

        for (left, right, result) in test_params {
            assert_eq!(negotiate_max_idle_timeout(left, right), result);
            assert_eq!(negotiate_max_idle_timeout(right, left), result);
        }
    }
}
