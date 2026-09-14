use std::{
    collections::{BTreeSet, hash_map},
    convert::TryFrom,
    fmt,
    net::{IpAddr, SocketAddr},
    ops::{Index, IndexMut, Range},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use ahash::HashMap;
use rama_core::bytes::{BufMut, Bytes, BytesMut};
use rama_core::telemetry::tracing::{debug, error, trace, warn};
use rand::{
    Rng, RngExt, SeedableRng,
    rngs::{StdRng, SysRng},
};
use rustc_hash::FxHashMap;
use slab::Slab;

use crate::proto::{
    Duration, INITIAL_MTU, Instant, MAX_CID_SIZE, MIN_INITIAL_SIZE, RESET_TOKEN_SIZE, ResetToken,
    Side, Transmit, TransportConfig, TransportError,
    cid_generator::ConnectionIdGenerator,
    cid_queue::{CidQueue, RemCid},
    coding::BufMutExt,
    config::{ClientConfig, EndpointConfig, ServerConfig},
    connection::{Connection, ConnectionError, SideArgs},
    crypto::{self, Keys},
    frame,
    packet::{
        FixedLengthConnectionIdParser, Header, InitialHeader, InitialPacket, PacketDecodeError,
        PacketNumber, PartialDecode, ProtectedInitialHeader,
    },
    shared::{
        ConnectionEvent, ConnectionEventInner, ConnectionId, DatagramConnectionEvent, EcnCodepoint,
        EndpointEvent, EndpointEventInner, IssuedCid,
    },
    token::{IncomingToken, Token, TokenPayload},
    transport_parameters::{PreferredAddress, TransportParameters},
};

/// The main entry point to the library
///
/// This object performs no I/O whatsoever. Instead, it consumes incoming packets and
/// connection-generated events via `handle` and `handle_event`.
pub(crate) struct Endpoint {
    rng: StdRng,
    index: ConnectionIndex,
    connections: Slab<ConnectionMeta>,
    local_cid_generator: Box<dyn ConnectionIdGenerator>,
    config: Arc<EndpointConfig>,
    server_config: Option<Arc<ServerConfig>>,
    /// Whether the underlying UDP socket promises not to fragment packets
    allow_mtud: bool,
    /// Time at which a stateless reset was most recently sent
    last_stateless_reset: Option<Instant>,
    /// Buffered Initial and 0-RTT messages for pending incoming connections
    incoming_buffers: Slab<IncomingBuffer>,
    incoming_deadlines: BTreeSet<(Instant, usize)>,
    all_incoming_buffers_total_bytes: u64,
}

impl Endpoint {
    /// Create a new endpoint
    ///
    /// `allow_mtud` enables path MTU detection when requested by `Connection` configuration for
    /// better performance. This requires that outgoing packets are never fragmented, which can be
    /// achieved via e.g. the `IPV6_DONTFRAG` socket option.
    ///
    /// If `rng_seed` is provided, it will be used to initialize the endpoint's rng (having priority
    /// over the rng seed configured in [`EndpointConfig`]). Note that the `rng_seed` parameter will
    /// be removed in a future release, so prefer setting it to `None` and configuring rng seeds
    /// using [`EndpointConfig::rng_seed`].
    #[expect(
        clippy::expect_used,
        reason = "an endpoint cannot operate without randomness; failing to read the OS RNG is not recoverable here"
    )]
    pub(crate) fn new(
        config: Arc<EndpointConfig>,
        server_config: Option<Arc<ServerConfig>>,
        allow_mtud: bool,
        rng_seed: Option<[u8; 32]>,
    ) -> Self {
        Self {
            rng: match rng_seed.or(config.rng_seed) {
                Some(seed) => StdRng::from_seed(seed),
                None => StdRng::try_from_rng(&mut SysRng)
                    .expect("failed to seed random number generator from system"),
            },
            index: ConnectionIndex::default(),
            connections: Slab::new(),
            local_cid_generator: (config.connection_id_generator_factory.as_ref())(),
            config,
            server_config,
            allow_mtud,
            last_stateless_reset: None,
            incoming_buffers: Slab::new(),
            incoming_deadlines: BTreeSet::new(),
            all_incoming_buffers_total_bytes: 0,
        }
    }

    /// Replace the server configuration, affecting new incoming connections only
    pub(crate) fn set_server_config(&mut self, server_config: Option<Arc<ServerConfig>>) {
        self.server_config = server_config;
    }

    /// Stop advertising `address` as preferred: the endpoint no longer owns a usable socket there,
    /// so connections that have not handshaked yet must not be sent to it. Connections already
    /// established keep whatever path they have; their transport parameters are long since sent.
    pub(crate) fn stop_advertising(&mut self, address: SocketAddr) {
        let Some(config) = self.server_config.as_ref() else {
            return;
        };
        let advertises = match address {
            SocketAddr::V4(address) => config.preferred_address_v4 == Some(address),
            SocketAddr::V6(address) => config.preferred_address_v6 == Some(address),
        };
        if !advertises {
            return;
        }
        let mut updated = ServerConfig::clone(config);
        match address {
            SocketAddr::V4(_) => updated.preferred_address_v4 = None,
            SocketAddr::V6(_) => updated.preferred_address_v6 = None,
        }
        self.server_config = Some(Arc::new(updated));
    }

    /// Tests: the addresses this endpoint advertises as preferred.
    #[cfg(test)]
    pub(crate) fn advertised_preferred(&self) -> Vec<SocketAddr> {
        let Some(config) = self.server_config.as_ref() else {
            return Vec::new();
        };
        config
            .preferred_address_v4
            .map(SocketAddr::V4)
            .into_iter()
            .chain(config.preferred_address_v6.map(SocketAddr::V6))
            .collect()
    }

    /// How long a Retry token issued now stays valid, when configured to serve.
    pub(crate) fn retry_token_lifetime(&self) -> Option<Duration> {
        self.server_config
            .as_ref()
            .map(|config| config.retry_token_lifetime)
    }

    /// Tests: which connection a reset carrying `token` from `remote` would reach.
    #[cfg(test)]
    pub(crate) fn reset_route_for(
        &self,
        remote: SocketAddr,
        token: ResetToken,
    ) -> Option<ConnectionHandle> {
        self.index
            .connection_reset_tokens
            .0
            .get(&remote)
            .and_then(|tokens| tokens.get(&token))
            .copied()
    }

    /// Tests: how many stateless-reset routes the endpoint's index holds.
    #[cfg(test)]
    pub(crate) fn reset_route_count(&self) -> usize {
        self.index
            .connection_reset_tokens
            .0
            .values()
            .map(|tokens| tokens.len())
            .sum()
    }

    /// Process `EndpointEvent`s emitted from related `Connection`s
    ///
    /// In turn, processing this event may return a `ConnectionEvent` for the same `Connection`.
    pub(crate) fn handle_event(
        &mut self,
        ch: ConnectionHandle,
        event: EndpointEvent,
    ) -> Option<ConnectionEvent> {
        match event.0 {
            EndpointEventInner::NeedIdentifiers(now, n) => {
                return Some(self.send_new_identifiers(now, ch, n));
            }
            EndpointEventInner::ResetTokenUsed(remote, seq, token, generation) => {
                // An identifier can be recognised at more than one address, since a rebinding
                // keeps it while the previous path may still answer. Associations are therefore
                // keyed by identifier and address, and installing one does not delete another
                // (RFC 9000 §10.3.1). The engine releases what it stops using, which bounds this
                // table by what the engine holds.
                match self.connections[ch]
                    .reset_tokens
                    .insert(seq, remote, token, generation)
                {
                    Installed::New => {
                        if self.index.connection_reset_tokens.insert(remote, token, ch) {
                            warn!("duplicate reset token");
                        }
                    }
                    Installed::Refreshed => {}
                    // No room, so there is no route. Saying so is the only honest answer: an
                    // acknowledgement would open the gate onto a route that does not exist.
                    Installed::Full => {
                        return Some(ConnectionEvent(ConnectionEventInner::ResetRouteRefused(
                            remote, seq, generation,
                        )));
                    }
                }
                // The route exists now, which is what the connection is waiting for before it
                // sends anything with this identifier to this address.
                return Some(ConnectionEvent(ConnectionEventInner::ResetRouteInstalled(
                    remote, seq, generation,
                )));
            }
            EndpointEventInner::ResetTokenReleased(remote, seq, token, generation) => {
                if self.connections[ch]
                    .reset_tokens
                    .release(seq, remote, generation)
                {
                    self.index.connection_reset_tokens.remove(remote, token);
                }
            }
            EndpointEventInner::ResetTokensRetired(seqs) => {
                for (remote, token) in self.connections[ch].reset_tokens.remove_range(seqs) {
                    self.index.connection_reset_tokens.remove(remote, token);
                }
            }
            EndpointEventInner::RetireConnectionId(now, seq, allow_more_cids) => {
                if let Some(cid) = self.connections[ch].loc_cids.remove(&seq) {
                    trace!("peer retired CID {}: {}", seq, cid);
                    self.index.retire(cid);
                    if allow_more_cids {
                        return Some(self.send_new_identifiers(now, ch, 1));
                    }
                }
            }
            EndpointEventInner::Drained => {
                if let Some(conn) = self.connections.try_remove(ch.0) {
                    self.index.remove(&conn);
                } else {
                    // This indicates a bug in downstream code, which could cause spurious
                    // connection loss instead of this error if the CID was (re)allocated prior to
                    // the illegal call.
                    error!(id = ch.0, "unknown connection drained");
                }
            }
        }
        None
    }

    /// Process an incoming UDP datagram
    pub(crate) fn handle(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        local: Option<SocketAddr>,
        ecn: Option<EcnCodepoint>,
        data: BytesMut,
        buf: &mut Vec<u8>,
    ) -> Option<DatagramEvent> {
        // Partially decode packet or short-circuit if unable
        let datagram_len = data.len();
        let event = match PartialDecode::new(
            data,
            &FixedLengthConnectionIdParser::new(self.local_cid_generator.cid_len()),
            &self.config.supported_versions,
            self.config.grease_quic_bit,
        ) {
            Ok((first_decode, remaining)) => DatagramConnectionEvent {
                now,
                remote,
                local,
                ecn,
                first_decode,
                remaining,
            },
            Err(PacketDecodeError::UnsupportedVersion {
                src_cid,
                dst_cid,
                version,
            }) => {
                if self.server_config.is_none() {
                    debug!("dropping packet with unsupported version");
                    return None;
                }
                // RFC 9000 §5.2.2: "Servers MUST drop smaller packets that specify unsupported
                // versions." Responding to short packets would let a spoofed source elicit a
                // Version Negotiation packet larger than the datagram that triggered it.
                if datagram_len < MIN_INITIAL_SIZE as usize {
                    debug!("dropping short packet with unsupported version");
                    return None;
                }
                trace!("sending version negotiation");
                // Negotiate versions
                Header::VersionNegotiate {
                    random: self.rng.random::<u8>() | 0x40,
                    src_cid: dst_cid,
                    dst_cid: src_cid,
                }
                .encode(buf);
                // Grease with a reserved version
                buf.write::<u32>(match version {
                    0x0a1a_2a3a => 0x0a1a_2a4a,
                    _ => 0x0a1a_2a3a,
                });
                for &version in &self.config.supported_versions {
                    buf.write(version);
                }
                return Some(DatagramEvent::Response(Transmit {
                    destination: remote,
                    ecn: None,
                    size: buf.len(),
                    segment_size: None,
                    local,
                    // A response the endpoint sends itself carries no identifier of ours.
                    cid_used: None,
                }));
            }
            Err(e) => {
                trace!("malformed header: {}", e);
                return None;
            }
        };

        let addresses = FourTuple { remote, local };
        let dst_cid = event.first_decode.dst_cid();

        if let Some(route_to) = self.index.get(&addresses, &event.first_decode) {
            // Handle packet on existing connection
            match route_to {
                RouteDatagramTo::Incoming(incoming_idx) => {
                    let incoming_buffer = &mut self.incoming_buffers[incoming_idx];
                    #[expect(
                        clippy::unwrap_used,
                        reason = "`RouteDatagramTo::Incoming` entries are only created by `handle_first_packet` on endpoints with a server config"
                    )]
                    let config = &self.server_config.as_ref().unwrap();

                    if incoming_buffer
                        .total_bytes
                        .checked_add(datagram_len as u64)
                        .is_some_and(|n| n <= config.incoming_buffer_size)
                        && self
                            .all_incoming_buffers_total_bytes
                            .checked_add(datagram_len as u64)
                            .is_some_and(|n| n <= config.incoming_buffer_size_total)
                    {
                        incoming_buffer.datagrams.push(event);
                        incoming_buffer.total_bytes += datagram_len as u64;
                        self.all_incoming_buffers_total_bytes += datagram_len as u64;
                    }

                    None
                }
                RouteDatagramTo::Connection(ch) => Some(DatagramEvent::ConnectionEvent(
                    ch,
                    ConnectionEvent(ConnectionEventInner::Datagram(event)),
                )),
            }
        } else if event.first_decode.initial_header().is_some() {
            // Potentially create a new connection

            self.handle_first_packet(datagram_len, event, addresses, buf)
        } else if event.first_decode.has_long_header() {
            debug!(
                "ignoring non-initial packet for unknown connection {}",
                dst_cid
            );
            None
        } else if !event.first_decode.is_initial()
            && self.local_cid_generator.validate(dst_cid).is_err()
        {
            debug!("dropping packet with invalid CID");
            None
        } else if dst_cid.is_empty() {
            trace!("dropping unrecognized short packet without ID");
            None
        } else {
            // If we got this far, we're receiving a seemingly valid packet for an unknown
            // connection. Send a stateless reset if possible.
            self.stateless_reset(now, datagram_len, addresses, *dst_cid, buf)
                .map(DatagramEvent::Response)
        }
    }

    fn stateless_reset(
        &mut self,
        now: Instant,
        inciting_dgram_len: usize,
        addresses: FourTuple,
        dst_cid: ConnectionId,
        buf: &mut Vec<u8>,
    ) -> Option<Transmit> {
        if self
            .last_stateless_reset
            .is_some_and(|last| last + self.config.min_reset_interval > now)
        {
            debug!("ignoring unexpected packet within minimum stateless reset interval");
            return None;
        }

        /// Minimum amount of padding for the stateless reset to look like a short-header packet
        const MIN_PADDING_LEN: usize = 5;

        // Prevent amplification attacks and reset loops by ensuring we pad to at most 1 byte
        // smaller than the inciting packet.
        let max_padding_len = match inciting_dgram_len.checked_sub(RESET_TOKEN_SIZE) {
            Some(headroom) if headroom > MIN_PADDING_LEN => headroom - 1,
            _ => {
                debug!(
                    "ignoring unexpected {} byte packet: not larger than minimum stateless reset size",
                    inciting_dgram_len
                );
                return None;
            }
        };

        debug!(
            "sending stateless reset for {} to {}",
            dst_cid, addresses.remote
        );
        self.last_stateless_reset = Some(now);
        // Resets with at least this much padding can't possibly be distinguished from real packets
        const IDEAL_MIN_PADDING_LEN: usize = MIN_PADDING_LEN + MAX_CID_SIZE;
        let padding_len = if max_padding_len <= IDEAL_MIN_PADDING_LEN {
            max_padding_len
        } else {
            self.rng
                .random_range(IDEAL_MIN_PADDING_LEN..max_padding_len)
        };
        buf.reserve(padding_len + RESET_TOKEN_SIZE);
        buf.resize(padding_len, 0);
        self.rng.fill_bytes(&mut buf[0..padding_len]);
        buf[0] = 0b0100_0000 | (buf[0] >> 2);
        buf.extend_from_slice(&ResetToken::new(&self.config.reset_key, dst_cid));

        debug_assert!(buf.len() < inciting_dgram_len);

        Some(Transmit {
            destination: addresses.remote,
            ecn: None,
            size: buf.len(),
            segment_size: None,
            local: addresses.local,
            cid_used: None,
        })
    }

    /// Initiate a connection
    pub(crate) fn connect(
        &mut self,
        now: Instant,
        config: ClientConfig,
        remote: SocketAddr,
        server_name: &str,
    ) -> Result<(ConnectionHandle, Connection), ConnectError> {
        if self.cids_exhausted() {
            return Err(ConnectError::CidsExhausted);
        }
        if remote.port() == 0 || remote.ip().is_unspecified() {
            return Err(ConnectError::InvalidRemoteAddress(remote));
        }
        if !self.config.supported_versions.contains(&config.version) {
            return Err(ConnectError::UnsupportedVersion);
        }

        let remote_id = (config.initial_dst_cid_provider)();
        trace!(initial_dcid = %remote_id);

        let ch = ConnectionHandle(self.connections.vacant_key());
        let loc_cid = self.new_cid(ch);
        let params = TransportParameters::new(
            &config.transport,
            &self.config,
            self.local_cid_generator.as_ref(),
            loc_cid,
            None,
            &mut self.rng,
        );
        let tls = match config
            .crypto
            .start_session(config.version, server_name, &params)
        {
            Ok(tls) => tls,
            Err(error) => {
                self.index.connection_ids.remove(&loc_cid);
                return Err(error);
            }
        };

        let conn = self
            .add_connection(
                ch,
                config.version,
                remote_id,
                loc_cid,
                remote_id,
                FourTuple {
                    remote,
                    local: None,
                },
                now,
                tls,
                config.transport,
                SideArgs::Client {
                    token_store: config.token_store,
                    server_name: server_name.into(),
                    preferred_address_policy: config.preferred_address_policy,
                },
            )
            .map_err(|error| {
                self.index.connection_ids.remove(&loc_cid);
                ConnectError::Crypto(error)
            })?;
        conn.qlog_local_parameters(now, &params);
        Ok((ch, conn))
    }

    fn send_new_identifiers(
        &mut self,
        now: Instant,
        ch: ConnectionHandle,
        num: u64,
    ) -> ConnectionEvent {
        let mut ids = vec![];
        for _ in 0..num {
            let id = self.new_cid(ch);
            let meta = &mut self.connections[ch];
            let sequence = meta.cids_issued;
            meta.cids_issued += 1;
            meta.loc_cids.insert(sequence, id);
            ids.push(IssuedCid {
                sequence,
                id,
                reset_token: ResetToken::new(&self.config.reset_key, id),
            });
        }
        ConnectionEvent(ConnectionEventInner::NewIdentifiers(ids, now))
    }

    /// Generate a connection ID for `ch`
    fn new_cid(&mut self, ch: ConnectionHandle) -> ConnectionId {
        loop {
            let cid = self.local_cid_generator.generate_cid();
            if cid.is_empty() {
                // Zero-length CID; nothing to track
                debug_assert_eq!(self.local_cid_generator.cid_len(), 0);
                return cid;
            }
            if let hash_map::Entry::Vacant(e) = self.index.connection_ids.entry(cid) {
                e.insert(ch);
                break cid;
            }
        }
    }

    fn handle_first_packet(
        &mut self,
        datagram_len: usize,
        event: DatagramConnectionEvent,
        addresses: FourTuple,
        buf: &mut Vec<u8>,
    ) -> Option<DatagramEvent> {
        let dst_cid = event.first_decode.dst_cid();
        #[expect(
            clippy::unwrap_used,
            reason = "`handle` only dispatches here for Initial packets (`first_decode.is_initial()`)"
        )]
        let header = event.first_decode.initial_header().unwrap();

        let Some(server_config) = &self.server_config else {
            debug!("packet for unrecognized connection {}", dst_cid);
            return self
                .stateless_reset(event.now, datagram_len, addresses, *dst_cid, buf)
                .map(DatagramEvent::Response);
        };

        if datagram_len < MIN_INITIAL_SIZE as usize {
            debug!("ignoring short initial for connection {}", dst_cid);
            return None;
        }

        // Saturation only happens under heavy load, where deriving initial keys per Initial just to
        // reply with CONNECTION_REFUSED would starve packet processing for existing connections.
        if self.cids_exhausted() || self.incoming_buffers.len() >= server_config.max_incoming {
            debug!(
                "ignoring initial for connection {} due to saturation",
                dst_cid
            );
            return None;
        }

        let crypto = match server_config.crypto.initial_keys(header.version, dst_cid) {
            Ok(keys) => keys,
            Err(error) => {
                match error {
                    crypto::InitialKeysError::UnsupportedVersion => debug!(
                        "ignoring initial packet version {:#x} unsupported by cryptographic layer",
                        header.version
                    ),
                    #[cfg(feature = "boring")]
                    crypto::InitialKeysError::Crypto(error) => {
                        debug!(%error, "unable to derive Initial packet keys")
                    }
                }
                return None;
            }
        };

        if let Err(reason) = self.early_validate_first_packet(header) {
            return self
                .initial_close(
                    header.version,
                    addresses,
                    &crypto,
                    &header.src_cid,
                    reason,
                    buf,
                )
                .map(DatagramEvent::Response);
        }

        let packet = match event
            .first_decode
            .finish(crypto.remote.as_ref().map(|keys| keys.header.as_ref()))
        {
            Ok(packet) => packet,
            Err(e) => {
                trace!("unable to decode initial packet: {}", e);
                return None;
            }
        };

        if !packet.reserved_bits_valid() {
            debug!("dropping connection attempt with invalid reserved bits");
            return None;
        }

        #[expect(
            clippy::panic,
            reason = "`handle_first_packet` is only called for Initial packets, so `finish` decoded an Initial header"
        )]
        let Header::Initial(header) = packet.header else {
            panic!("non-initial packet in handle_first_packet()");
        };

        #[expect(
            clippy::unwrap_used,
            reason = "the `let Some(server_config)` check at the top of this function returned when no server config is set"
        )]
        let server_config = self.server_config.as_ref().unwrap().clone();

        let Ok(token) = IncomingToken::from_header(&header, &server_config, addresses.remote)
        else {
            debug!("rejecting invalid retry token");
            return self
                .initial_close(
                    header.version,
                    addresses,
                    &crypto,
                    &header.src_cid,
                    TransportError::INVALID_TOKEN(""),
                    buf,
                )
                .map(DatagramEvent::Response);
        };

        let deadline = event.now.checked_add(self.config.handshake_timeout)?;
        let live = Arc::new(AtomicBool::new(true));
        let incoming_idx = self.incoming_buffers.insert(IncomingBuffer {
            deadline,
            dst_cid: header.dst_cid,
            live: live.clone(),
            datagrams: Vec::new(),
            total_bytes: 0,
        });
        self.incoming_deadlines.insert((deadline, incoming_idx));
        self.index
            .insert_initial_incoming(header.dst_cid, incoming_idx);

        Some(DatagramEvent::NewConnection(Incoming {
            received_at: event.now,
            addresses,
            ecn: event.ecn,
            packet: InitialPacket {
                header,
                header_data: packet.header_data,
                payload: packet.payload,
            },
            rest: event.remaining,
            crypto,
            token,
            incoming_idx,
            live,
            deadline,
            improper_drop_warner: IncomingImproperDropWarner::armed(),
        }))
    }

    /// Attempt to accept this incoming connection (an error may still occur)
    // AcceptError cannot be made smaller without semver breakage
    pub(crate) fn accept(
        &mut self,
        mut incoming: Incoming,
        now: Instant,
        buf: &mut Vec<u8>,
        server_config: Option<Arc<ServerConfig>>,
    ) -> Result<(ConnectionHandle, Connection), AcceptError> {
        let remote_address_validated = incoming.remote_address_validated();
        if incoming.is_expired() || now >= incoming.deadline {
            self.clean_up_incoming(&incoming);
            incoming.improper_drop_warner.dismiss();
            return Err(AcceptError {
                cause: ConnectionError::TimedOut,
                response: None,
            });
        }
        let Some(server_config) = server_config.or_else(|| self.server_config.clone()) else {
            self.clean_up_incoming(&incoming);
            incoming.improper_drop_warner.dismiss();
            return Err(AcceptError {
                cause: ConnectionError::LocallyClosed,
                response: None,
            });
        };
        // Keep initial routing until accept succeeds or its existing error paths remove it.
        let incoming_buffer = self.take_incoming_buffer(&incoming);
        incoming.improper_drop_warner.dismiss();
        let incoming_buffer = incoming_buffer.ok_or(AcceptError {
            cause: ConnectionError::TimedOut,
            response: None,
        })?;

        let packet_number = incoming.packet.header.number.expand(0);
        let InitialHeader {
            src_cid,
            dst_cid,
            version,
            ..
        } = incoming.packet.header;
        if server_config
            .transport
            .max_idle_timeout
            .is_some_and(|timeout| {
                incoming.received_at + Duration::from_millis(timeout.into()) <= now
            })
        {
            debug!("abandoning accept of stale initial");
            self.index.remove_initial(dst_cid);
            return Err(AcceptError {
                cause: ConnectionError::TimedOut,
                response: None,
            });
        }

        if self.cids_exhausted() {
            debug!("refusing connection");
            self.index.remove_initial(dst_cid);
            return Err(AcceptError {
                cause: ConnectionError::CidsExhausted,
                response: self.initial_close(
                    version,
                    incoming.addresses,
                    &incoming.crypto,
                    &src_cid,
                    TransportError::CONNECTION_REFUSED(""),
                    buf,
                ),
            });
        }

        if incoming.crypto.remote.as_ref().is_none_or(|keys| {
            keys.packet
                .decrypt(
                    packet_number,
                    &incoming.packet.header_data,
                    &mut incoming.packet.payload,
                )
                .is_err()
        }) {
            debug!(packet_number, "failed to authenticate initial packet");
            self.index.remove_initial(dst_cid);
            return Err(AcceptError {
                cause: TransportError::PROTOCOL_VIOLATION("authentication failed").into(),
                response: None,
            });
        };

        let ch = ConnectionHandle(self.connections.vacant_key());
        let loc_cid = self.new_cid(ch);
        let mut params = TransportParameters::new(
            &server_config.transport,
            &self.config,
            self.local_cid_generator.as_ref(),
            loc_cid,
            Some(&server_config),
            &mut self.rng,
        );
        params.stateless_reset_token = Some(ResetToken::new(&self.config.reset_key, loc_cid));
        params.original_dst_cid = Some(incoming.token.orig_dst_cid);
        params.retry_src_cid = incoming.token.retry_src_cid;
        let mut pref_addr_cid = None;
        // A preferred address needs an identifier of its own (RFC 9000 §5.1.1), so an endpoint
        // whose connection IDs are zero length keeps its clients where they are.
        if server_config.has_preferred_address() && self.local_cid_generator.cid_len() != 0 {
            let cid = self.new_cid(ch);
            pref_addr_cid = Some(cid);
            params.preferred_address = Some(PreferredAddress {
                address_v4: server_config.preferred_address_v4,
                address_v6: server_config.preferred_address_v6,
                connection_id: cid,
                stateless_reset_token: ResetToken::new(&self.config.reset_key, cid),
            });
        }

        let tls = match server_config.crypto.clone().start_session(version, &params) {
            Ok(tls) => tls,
            Err(error) => {
                self.index.connection_ids.remove(&loc_cid);
                if let Some(cid) = pref_addr_cid {
                    self.index.connection_ids.remove(&cid);
                }
                self.index.remove_initial(dst_cid);
                let response = self.initial_close(
                    version,
                    incoming.addresses,
                    &incoming.crypto,
                    &src_cid,
                    error.clone(),
                    buf,
                );
                return Err(AcceptError {
                    cause: error.into(),
                    response,
                });
            }
        };
        let transport_config = server_config.transport.clone();
        let mut conn = self
            .add_connection(
                ch,
                version,
                dst_cid,
                loc_cid,
                src_cid,
                incoming.addresses,
                incoming.received_at,
                tls,
                transport_config,
                SideArgs::Server {
                    server_config,
                    pref_addr_cid,
                    path_validated: remote_address_validated,
                    orig_dst_cid: incoming.token.orig_dst_cid,
                },
            )
            .map_err(|error| {
                self.index.connection_ids.remove(&loc_cid);
                if let Some(cid) = pref_addr_cid {
                    self.index.connection_ids.remove(&cid);
                }
                self.index.remove_initial(dst_cid);
                let response = self.initial_close(
                    version,
                    incoming.addresses,
                    &incoming.crypto,
                    &src_cid,
                    error.clone(),
                    buf,
                );
                AcceptError {
                    cause: error.into(),
                    response,
                }
            })?;
        self.index.insert_initial(dst_cid, ch);
        conn.qlog_local_parameters(incoming.received_at, &params);

        match conn.handle_first_packet(
            incoming.received_at,
            incoming.addresses.remote,
            incoming.addresses.local,
            incoming.ecn,
            packet_number,
            incoming.packet,
            incoming.rest,
        ) {
            Ok(()) => {
                trace!(id = ch.0, icid = %dst_cid, "new connection");

                for event in incoming_buffer.datagrams {
                    conn.handle_event(ConnectionEvent(ConnectionEventInner::Datagram(event)))
                }

                Ok((ch, conn))
            }
            Err(e) => {
                debug!("handshake failed: {}", e);
                self.handle_event(ch, EndpointEvent(EndpointEventInner::Drained));
                let response = match e {
                    ConnectionError::TransportError(ref e) => self.initial_close(
                        version,
                        incoming.addresses,
                        &incoming.crypto,
                        &src_cid,
                        e.clone(),
                        buf,
                    ),
                    _ => None,
                };
                Err(AcceptError { cause: e, response })
            }
        }
    }

    /// Check if we should refuse a connection attempt regardless of the packet's contents
    fn early_validate_first_packet(
        &self,
        header: &ProtectedInitialHeader,
    ) -> Result<(), TransportError> {
        // RFC9000 §7.2 dictates that initial (client-chosen) destination CIDs must be at least 8
        // bytes. If this is a Retry packet, then the length must instead match our usual CID
        // length. If we ever issue non-Retry address validation tokens via `NEW_TOKEN`, then we'll
        // also need to validate CID length for those after decoding the token.
        if header.dst_cid.len() < 8
            && (header.token_pos.is_empty()
                || header.dst_cid.len() != self.local_cid_generator.cid_len())
        {
            debug!(
                "rejecting connection due to invalid DCID length {}",
                header.dst_cid.len()
            );
            return Err(TransportError::PROTOCOL_VIOLATION(
                "invalid destination CID length",
            ));
        }

        Ok(())
    }

    /// Reject this incoming connection attempt
    pub(crate) fn refuse(&mut self, incoming: Incoming, buf: &mut Vec<u8>) -> Option<Transmit> {
        self.clean_up_incoming(&incoming);
        incoming.improper_drop_warner.dismiss();

        self.initial_close(
            incoming.packet.header.version,
            incoming.addresses,
            &incoming.crypto,
            &incoming.packet.header.src_cid,
            TransportError::CONNECTION_REFUSED(""),
            buf,
        )
    }

    /// Respond with a retry packet, requiring the client to retry with address validation
    ///
    /// Errors if `incoming.may_retry()` is false.
    pub(crate) fn retry(
        &mut self,
        incoming: Incoming,
        buf: &mut Vec<u8>,
    ) -> Result<Transmit, RetryError> {
        if !incoming.may_retry() {
            return Err(RetryError::new(incoming, RetryRefused::AlreadyRetried));
        }

        let Some(server_config) = self.server_config.clone() else {
            return Err(RetryError::new(incoming, RetryRefused::NoServerConfig));
        };

        // The token is sealed before the attempt is touched, so a provider failure hands the
        // attempt back intact for the application to accept, refuse or ignore instead.
        let payload = TokenPayload::Retry {
            address: incoming.addresses.remote,
            orig_dst_cid: incoming.packet.header.dst_cid,
            issued: server_config.time_source.now(),
        };
        let token = match Token::new(payload, &mut self.rng).encode(&*server_config.token_key) {
            Ok(token) => token,
            Err(error) => {
                warn!(%error, "retry token could not be sealed; the attempt is left to the application");
                return Err(RetryError::new(incoming, RetryRefused::TokenSealing));
            }
        };

        // First Initial
        // The peer will use this as the DCID of its following Initials. Initial DCIDs are
        // looked up separately from Handshake/Data DCIDs, so there is no risk of collision
        // with established connections. In the unlikely event that a collision occurs
        // between two connections in the initial phase, both will fail fast and may be
        // retried by the application layer.
        let loc_cid = self.local_cid_generator.generate_cid();

        let header = Header::Retry {
            src_cid: loc_cid,
            dst_cid: incoming.packet.header.src_cid,
            version: incoming.packet.header.version,
        };

        let original_len = buf.len();
        header.encode(buf);
        buf.put_slice(&token);
        let tag = match server_config.crypto.retry_tag(
            incoming.packet.header.version,
            &incoming.packet.header.dst_cid,
            &buf[original_len..],
        ) {
            Ok(tag) => tag,
            Err(error) => {
                warn!(%error, "retry integrity protection failed; the attempt is left to the application");
                buf.truncate(original_len);
                return Err(RetryError::new(incoming, RetryRefused::IntegrityProtection));
            }
        };
        buf.extend_from_slice(&tag);
        self.clean_up_incoming(&incoming);
        incoming.improper_drop_warner.dismiss();

        Ok(Transmit {
            destination: incoming.addresses.remote,
            ecn: None,
            size: buf.len(),
            segment_size: None,
            local: incoming.addresses.local,
            cid_used: None,
        })
    }

    /// Ignore this incoming connection attempt, not sending any packet in response
    ///
    /// This promptly retires the endpoint's pending state. Otherwise that state
    /// remains until the handshake deadline or endpoint shutdown.
    pub(crate) fn ignore(&mut self, incoming: Incoming) {
        self.clean_up_incoming(&incoming);
        incoming.improper_drop_warner.dismiss();
    }

    /// Clean up endpoint data structures associated with an `Incoming`.
    fn clean_up_incoming(&mut self, incoming: &Incoming) {
        if self.take_incoming_buffer(incoming).is_some() {
            self.index.remove_initial(incoming.packet.header.dst_cid);
        }
    }

    fn take_incoming_buffer(&mut self, incoming: &Incoming) -> Option<IncomingBuffer> {
        // An expired Incoming may outlive this slot and must never remove its replacement.
        if !incoming.live.swap(false, Ordering::AcqRel) {
            return None;
        }
        let buffer = self.incoming_buffers.remove(incoming.incoming_idx);
        self.incoming_deadlines
            .remove(&(buffer.deadline, incoming.incoming_idx));
        self.all_incoming_buffers_total_bytes -= buffer.total_bytes;
        Some(buffer)
    }

    pub(crate) fn pending_incoming(&self) -> usize {
        self.incoming_buffers.len()
    }

    /// Earliest pending admission deadline, for the endpoint driver's real timer.
    pub(crate) fn poll_incoming_timeout(&self) -> Option<Instant> {
        self.incoming_deadlines.first().map(|entry| entry.0)
    }

    /// Expire a bounded number of pending handshakes without requiring application polling.
    pub(crate) fn expire_incoming(&mut self, now: Instant, limit: usize) -> usize {
        let mut expired = 0;
        while expired < limit {
            let Some(&(deadline, index)) = self.incoming_deadlines.first() else {
                break;
            };
            if deadline > now {
                break;
            }
            self.incoming_deadlines.pop_first();
            self.discard_incoming_buffer(index);
            expired += 1;
        }
        expired
    }

    /// Retire pending admission state during shutdown; application-held handles become stale.
    pub(crate) fn discard_incoming(&mut self, limit: usize) {
        for _ in 0..limit {
            let Some((_, index)) = self.incoming_deadlines.pop_first() else {
                break;
            };
            self.discard_incoming_buffer(index);
        }
    }

    /// Release every pending admission regardless of the deadline index.
    ///
    /// Only the shutdown supervisor uses this, after `discard_incoming` stopped making
    /// progress; the work is bounded by the number of live admissions.
    pub(crate) fn discard_all_incoming(&mut self) {
        self.incoming_deadlines.clear();
        let indices: Vec<usize> = self
            .incoming_buffers
            .iter()
            .map(|(index, _)| index)
            .collect();
        for index in indices {
            self.discard_incoming_buffer(index);
        }
    }

    /// Test seam: break the invariant that every pending admission has a deadline entry.
    #[cfg(test)]
    pub(crate) fn forget_incoming_deadlines(&mut self) {
        self.incoming_deadlines.clear();
    }

    fn discard_incoming_buffer(&mut self, index: usize) {
        let buffer = self.incoming_buffers.remove(index);
        buffer.live.store(false, Ordering::Release);
        self.all_incoming_buffers_total_bytes -= buffer.total_bytes;
        self.index.remove_initial(buffer.dst_cid);
    }

    fn add_connection(
        &mut self,
        ch: ConnectionHandle,
        version: u32,
        init_cid: ConnectionId,
        loc_cid: ConnectionId,
        rem_cid: ConnectionId,
        addresses: FourTuple,
        now: Instant,
        tls: Box<dyn crypto::Session>,
        transport_config: Arc<TransportConfig>,
        side_args: SideArgs,
    ) -> Result<Connection, TransportError> {
        let mut rng_seed = [0; 32];
        self.rng.fill_bytes(&mut rng_seed);
        let side = side_args.side();
        let pref_addr_cid = side_args.pref_addr_cid();
        let conn = Connection::new(
            self.config.clone(),
            transport_config,
            init_cid,
            loc_cid,
            rem_cid,
            addresses.remote,
            addresses.local,
            tls,
            self.local_cid_generator.as_ref(),
            now,
            version,
            self.allow_mtud,
            rng_seed,
            side_args,
        )?;

        let mut cids_issued = 0;
        let mut loc_cids = FxHashMap::default();

        loc_cids.insert(cids_issued, loc_cid);
        cids_issued += 1;

        if let Some(cid) = pref_addr_cid {
            debug_assert_eq!(cids_issued, 1, "preferred address cid seq must be 1");
            loc_cids.insert(cids_issued, cid);
            cids_issued += 1;
        }

        let id = self.connections.insert(ConnectionMeta {
            init_cid,
            cids_issued,
            loc_cids,
            addresses,
            side,
            reset_tokens: UsedResetTokens::default(),
        });
        debug_assert_eq!(id, ch.0, "connection handle allocation out of sync");

        self.index.insert_conn(addresses, loc_cid, ch, side);

        Ok(conn)
    }

    fn initial_close(
        &mut self,
        version: u32,
        addresses: FourTuple,
        crypto: &Keys,
        remote_id: &ConnectionId,
        reason: TransportError,
        buf: &mut Vec<u8>,
    ) -> Option<Transmit> {
        // We don't need to worry about CID collisions in initial closes because the peer
        // shouldn't respond, and if it does, and the CID collides, we'll just drop the
        // unexpected response.
        let local_id = self.local_cid_generator.generate_cid();
        let number = PacketNumber::U8(0);
        let header = Header::Initial(InitialHeader {
            dst_cid: *remote_id,
            src_cid: local_id,
            number,
            token: Bytes::new(),
            version,
        });

        let partial_encode = header.encode(buf);
        let max_len =
            INITIAL_MTU as usize - partial_encode.header_len - crypto.local.packet.tag_len();
        frame::Close::from(reason).encode(buf, max_len);
        buf.resize(buf.len() + crypto.local.packet.tag_len(), 0);
        if let Err(error) =
            partial_encode.finish(buf, &*crypto.local.header, Some((0, &*crypto.local.packet)))
        {
            debug!(%error, "cannot encrypt initial close");
            buf.clear();
            return None;
        }
        Some(Transmit {
            destination: addresses.remote,
            ecn: None,
            size: buf.len(),
            segment_size: None,
            local: addresses.local,
            cid_used: None,
        })
    }

    /// Access the configuration used by this endpoint
    pub(crate) fn config(&self) -> &EndpointConfig {
        &self.config
    }

    /// Number of connections that are currently open
    pub(crate) fn open_connections(&self) -> usize {
        self.connections.len()
    }

    #[cfg(all(test, feature = "rustls", any(feature = "aws-lc", feature = "ring")))]
    /// Counter for the number of bytes currently used
    /// in the buffers for Initial and 0-RTT messages for pending incoming connections
    pub(crate) fn incoming_buffer_bytes(&self) -> u64 {
        self.all_incoming_buffers_total_bytes
    }

    #[cfg(test)]
    pub(crate) fn known_connections(&self) -> usize {
        let x = self.connections.len();
        debug_assert_eq!(x, self.index.connection_ids_initial.len());
        // Not all connections have known reset tokens
        debug_assert!(x >= self.index.connection_reset_tokens.0.len());
        // Not all connections have unique remotes, and 0-length CIDs might not be in use.
        debug_assert!(x >= self.index.incoming_connection_remotes.len());
        debug_assert!(x >= self.index.outgoing_connection_remotes.len());
        x
    }

    #[cfg(test)]
    pub(crate) fn known_cids(&self) -> usize {
        self.index.connection_ids.len()
    }

    /// Tests: the connection IDs a datagram can be addressed to to reach `ch`.
    #[cfg(test)]
    pub(crate) fn cids_routing_to(&self, ch: ConnectionHandle) -> Vec<ConnectionId> {
        self.index
            .connection_ids
            .iter()
            .filter(|&(_, &handle)| handle == ch)
            .map(|(&cid, _)| cid)
            .collect()
    }

    /// Whether we've used up 3/4 of the available CID space
    ///
    /// We leave some space unused so that `new_cid` can be relied upon to finish quickly. We don't
    /// bother to check when CID longer than 4 bytes are used because 2^40 connections is a lot.
    fn cids_exhausted(&self) -> bool {
        cid_space_exhausted(
            self.local_cid_generator.cid_len(),
            self.index.connection_ids.len(),
        )
    }
}

/// Whether `in_use` local connection IDs of `cid_len` bytes leave less than a quarter of the ID
/// space free
///
/// Zero-length IDs address a single connection and IDs longer than 4 bytes have a space too large
/// to exhaust, so neither is ever reported exhausted. The arithmetic is 64-bit so 32-bit targets
/// cannot overflow on 4-byte IDs.
fn cid_space_exhausted(cid_len: usize, in_use: usize) -> bool {
    if cid_len == 0 || cid_len > 4 {
        return false;
    }
    let bits = (cid_len * 8) as u32;
    let space = 1u64 << bits;
    let reserve = 1u64 << (bits - 2);
    in_use as u64 > space - reserve
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::{Installed, RESET_TOKEN_SIZE, ResetToken, UsedResetTokens, cid_space_exhausted};

    fn addr(last: u8) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, last], 4433))
    }

    fn token(n: u8) -> ResetToken {
        ResetToken::from([n; RESET_TOKEN_SIZE])
    }

    /// The routing table follows the engine: a release frees the slot it took, an installation of
    /// a pair already held is not a second route, and a release still naming an older
    /// installation cannot take away the one that replaced it.
    #[test]
    fn a_route_is_released_only_by_the_installation_that_owns_it() {
        let mut routes = UsedResetTokens::default();
        assert_eq!(
            routes.insert(1, addr(1), token(1), 10),
            Installed::New,
            "a new route"
        );
        assert_eq!(
            routes.insert(1, addr(1), token(1), 11),
            Installed::Refreshed,
            "the same pair again is not a second route"
        );
        assert!(
            !routes.release(1, addr(1), 10),
            "a release naming the installation that was replaced does nothing"
        );
        assert_eq!(routes.iter().count(), 1, "so the live route is still there");
        assert!(
            routes.release(1, addr(1), 11),
            "the installation that owns it can release it"
        );
        assert_eq!(routes.iter().count(), 0);
        assert!(
            !routes.release(1, addr(1), 11),
            "and releasing it twice is not a route"
        );

        // The same identifier at two addresses is two routes, and one does not remove the other.
        assert_eq!(routes.insert(2, addr(1), token(2), 20), Installed::New);
        assert_eq!(routes.insert(2, addr(2), token(2), 21), Installed::New);
        assert_eq!(routes.iter().count(), 2);
        assert!(routes.release(2, addr(1), 20));
        assert_eq!(routes.iter().count(), 1);
        assert!(
            routes.iter().any(|(remote, _)| remote == addr(2)),
            "the other address keeps its route"
        );

        // Retirement takes every route the identifier had, at every address.
        assert_eq!(routes.insert(3, addr(3), token(3), 30), Installed::New);
        assert_eq!(routes.insert(3, addr(4), token(3), 31), Installed::New);
        let removed = routes.remove_range(3..4).count();
        assert_eq!(removed, 2, "both of the retired identifier's routes go");
        assert_eq!(routes.iter().count(), 1);
    }

    /// A table with no room reports it, so the caller can refuse rather than acknowledge a route
    /// that is not there. This is the `Full` the endpoint turns into a refusal.
    #[test]
    fn a_full_table_reports_that_it_installed_nothing() {
        let mut routes = UsedResetTokens::default();
        let slots = super::CidQueue::PRESENT * super::RemCid::REMOTES;
        for step in 0..slots {
            assert_eq!(
                routes.insert(step as u64, addr(1), token(step as u8), step as u64),
                Installed::New,
                "slot {step} of {slots}"
            );
        }
        assert_eq!(routes.iter().count(), slots, "the table is full");
        assert_eq!(
            routes.insert(9_999, addr(2), token(7), 9_999),
            Installed::Full,
            "one more route is refused, not squeezed in"
        );
        assert_eq!(
            routes.iter().count(),
            slots,
            "and nothing live was evicted to make room"
        );
        // Releasing one makes room again, so a refusal is about the moment, not the connection.
        assert!(routes.release(0, addr(1), 0));
        assert_eq!(
            routes.insert(9_999, addr(2), token(7), 9_999),
            Installed::New
        );
    }

    /// The engine releases what it displaces, so far more moves than this table has slots still
    /// leave it holding only what is live. This is the endpoint half of the accumulation the
    /// review reproduced: a queue invariant alone cannot show it.
    #[test]
    fn releasing_before_installing_keeps_the_table_from_filling() {
        let mut routes = UsedResetTokens::default();
        let slots = super::CidQueue::PRESENT * super::RemCid::REMOTES;
        let home = addr(1);
        assert_eq!(routes.insert(1, home, token(1), 0), Installed::New);
        // One identifier, forty different addresses, two of them always live.
        let mut previous: Option<(SocketAddr, u64)> = None;
        for step in 0..40u64 {
            let remote = addr(10 + step as u8);
            let generation = step + 1;
            assert_eq!(
                routes.insert(1, remote, token(1), generation),
                Installed::New,
                "step {step} installs"
            );
            if let Some((old, old_generation)) = previous.replace((remote, generation)) {
                assert!(
                    routes.release(1, old, old_generation),
                    "step {step} releases the one it displaced"
                );
            }
            assert!(
                routes.iter().count() <= 3,
                "step {step} left {} routes in a table of {slots}",
                routes.iter().count()
            );
        }
        assert!(routes.iter().any(|(remote, _)| remote == home));
    }

    #[test]
    fn cid_space_exhaustion_thresholds() {
        // A quarter of the space is always kept in reserve so `new_cid` stays fast
        for (len, threshold) in [
            (1usize, 192usize),
            (2, 49_152),
            (3, 12_582_912),
            (4, 3_221_225_472),
        ] {
            assert!(!cid_space_exhausted(len, 0));
            assert!(
                !cid_space_exhausted(len, threshold),
                "{len}-byte IDs: {threshold} in use still fit"
            );
            assert!(
                cid_space_exhausted(len, threshold + 1),
                "{len}-byte IDs: {} exhaust the space",
                threshold + 1
            );
        }
        // Zero-length and longer IDs are never exhausted, whatever the count
        for len in [0usize, 5, 8, 20] {
            assert!(!cid_space_exhausted(len, 0));
            assert!(!cid_space_exhausted(len, usize::MAX));
        }
    }
}

impl fmt::Debug for Endpoint {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("Endpoint")
            .field("rng", &self.rng)
            .field("index", &self.index)
            .field("connections", &self.connections)
            .field("config", &self.config)
            .field("server_config", &self.server_config)
            // incoming_buffers too large
            .field("incoming_buffers.len", &self.incoming_buffers.len())
            .field(
                "all_incoming_buffers_total_bytes",
                &self.all_incoming_buffers_total_bytes,
            )
            .finish()
    }
}

/// Buffered Initial and 0-RTT messages for a pending incoming connection
struct IncomingBuffer {
    deadline: Instant,
    dst_cid: ConnectionId,
    live: Arc<AtomicBool>,
    datagrams: Vec<DatagramConnectionEvent>,
    total_bytes: u64,
}

/// Part of protocol state incoming datagrams can be routed to
#[derive(Copy, Clone, Debug)]
enum RouteDatagramTo {
    Incoming(usize),
    Connection(ConnectionHandle),
}

/// Maps packets to existing connections
#[derive(Default, Debug)]
struct ConnectionIndex {
    /// Identifies connections based on the initial DCID the peer utilized
    ///
    /// Uses a standard `HashMap` to protect against hash collision attacks.
    ///
    /// Used by the server, not the client.
    connection_ids_initial: HashMap<ConnectionId, RouteDatagramTo>,
    /// Identifies connections based on locally created CIDs
    ///
    /// Uses a cheaper hash function since keys are locally created
    connection_ids: FxHashMap<ConnectionId, ConnectionHandle>,
    /// Identifies incoming connections with zero-length CIDs
    ///
    /// Uses a standard `HashMap` to protect against hash collision attacks.
    incoming_connection_remotes: HashMap<FourTuple, ConnectionHandle>,
    /// Identifies outgoing connections with zero-length CIDs
    ///
    /// We don't yet support explicit source addresses for client connections, and zero-length CIDs
    /// require a unique four-tuple, so at most one client connection with zero-length local CIDs
    /// may be established per remote. We must omit the local address from the key because we don't
    /// necessarily know what address we're sending from, and hence receiving at.
    ///
    /// Uses a standard `HashMap` to protect against hash collision attacks.
    outgoing_connection_remotes: HashMap<SocketAddr, ConnectionHandle>,
    /// Reset tokens provided by the peer for the CID each connection is currently sending to
    ///
    /// Incoming stateless resets do not have correct CIDs, so we need this to identify the correct
    /// recipient, if any.
    connection_reset_tokens: ResetTokenTable,
}

impl ConnectionIndex {
    /// Associate an incoming connection with its initial destination CID
    fn insert_initial_incoming(&mut self, dst_cid: ConnectionId, incoming_key: usize) {
        if dst_cid.is_empty() {
            return;
        }
        self.connection_ids_initial
            .insert(dst_cid, RouteDatagramTo::Incoming(incoming_key));
    }

    /// Remove an association with an initial destination CID
    fn remove_initial(&mut self, dst_cid: ConnectionId) {
        if dst_cid.is_empty() {
            return;
        }
        let removed = self.connection_ids_initial.remove(&dst_cid);
        debug_assert!(removed.is_some());
    }

    /// Associate a connection with its initial destination CID
    fn insert_initial(&mut self, dst_cid: ConnectionId, connection: ConnectionHandle) {
        if dst_cid.is_empty() {
            return;
        }
        self.connection_ids_initial
            .insert(dst_cid, RouteDatagramTo::Connection(connection));
    }

    /// Associate a connection with its first locally-chosen destination CID if used, or otherwise
    /// its current 4-tuple
    fn insert_conn(
        &mut self,
        addresses: FourTuple,
        dst_cid: ConnectionId,
        connection: ConnectionHandle,
        side: Side,
    ) {
        match dst_cid.len() {
            0 => match side {
                Side::Server => {
                    self.incoming_connection_remotes
                        .insert(addresses, connection);
                }
                Side::Client => {
                    self.outgoing_connection_remotes
                        .insert(addresses.remote, connection);
                }
            },
            _ => {
                self.connection_ids.insert(dst_cid, connection);
            }
        }
    }

    /// Discard a connection ID
    fn retire(&mut self, dst_cid: ConnectionId) {
        self.connection_ids.remove(&dst_cid);
    }

    /// Remove all references to a connection
    fn remove(&mut self, conn: &ConnectionMeta) {
        if conn.side.is_server() {
            self.remove_initial(conn.init_cid);
        }
        for cid in conn.loc_cids.values() {
            self.connection_ids.remove(cid);
        }
        self.incoming_connection_remotes.remove(&conn.addresses);
        self.outgoing_connection_remotes
            .remove(&conn.addresses.remote);
        for (remote, token) in conn.reset_tokens.iter() {
            self.connection_reset_tokens.remove(remote, token);
        }
    }

    /// Find the existing connection that `datagram` should be routed to, if any
    fn get(&self, addresses: &FourTuple, datagram: &PartialDecode) -> Option<RouteDatagramTo> {
        if !datagram.dst_cid().is_empty()
            && let Some(&ch) = self.connection_ids.get(datagram.dst_cid())
        {
            return Some(RouteDatagramTo::Connection(ch));
        }
        if (datagram.is_initial() || datagram.is_0rtt())
            && let Some(&ch) = self.connection_ids_initial.get(datagram.dst_cid())
        {
            return Some(ch);
        }
        if datagram.dst_cid().is_empty() {
            if let Some(&ch) = self.incoming_connection_remotes.get(addresses) {
                return Some(RouteDatagramTo::Connection(ch));
            }
            if let Some(&ch) = self.outgoing_connection_remotes.get(&addresses.remote) {
                return Some(RouteDatagramTo::Connection(ch));
            }
        }
        let data = datagram.data();
        if data.len() < RESET_TOKEN_SIZE {
            return None;
        }
        self.connection_reset_tokens
            .get(addresses.remote, &data[data.len() - RESET_TOKEN_SIZE..])
            .cloned()
            .map(RouteDatagramTo::Connection)
    }
}

#[derive(Debug)]
pub(crate) struct ConnectionMeta {
    init_cid: ConnectionId,
    /// Number of local connection IDs that have been issued in NEW_CONNECTION_ID frames.
    cids_issued: u64,
    loc_cids: FxHashMap<u64, ConnectionId>,
    /// Remote/local addresses the connection began with
    ///
    /// Only needed to support connections with zero-length CIDs, which cannot migrate, so we don't
    /// bother keeping it up to date.
    addresses: FourTuple,
    side: Side,
    /// The reset tokens this connection may be reset with, one per used, unretired remote CID.
    reset_tokens: UsedResetTokens,
}

/// The reset tokens a connection may be reset with (RFC 9000 §10.3.1): one entry for each
/// (connection ID, address) pair a datagram has actually gone out for and that is not retired.
///
/// An identifier is recognised at more than one address while a rebinding or a fallback keeps the
/// previous path relevant, so the sequence number alone does not identify an entry. The engine
/// bounds the identifiers it holds at once and the addresses it keeps per identifier, so this
/// table is sized for every association the engine can report and does not evict a live route.
#[derive(Debug)]
struct UsedResetTokens {
    entries: [Option<Association>; CidQueue::PRESENT * RemCid::REMOTES],
}

impl Default for UsedResetTokens {
    fn default() -> Self {
        Self {
            entries: [None; CidQueue::PRESENT * RemCid::REMOTES],
        }
    }
}

/// What installing a route did. Only `Full` means the route is absent.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum Installed {
    /// The route is in the table under this installation, and the index needs it.
    New,
    /// The table already had this route with this token; its installation name is updated.
    Refreshed,
    /// There was no room, so the route is **not** installed.
    Full,
}

/// One installed route: the identifier, the address it is sent to, the token a reset would carry,
/// and the name of this installation.
#[derive(Debug, Copy, Clone)]
struct Association {
    seq: u64,
    remote: SocketAddr,
    token: ResetToken,
    generation: u64,
}

impl UsedResetTokens {
    /// Record that the ID with `seq` is sent to `remote`. `true` when this is a new association;
    /// a repetition of one already held changes nothing.
    fn insert(
        &mut self,
        seq: u64,
        remote: SocketAddr,
        token: ResetToken,
        generation: u64,
    ) -> Installed {
        if let Some(held) = self
            .entries
            .iter_mut()
            .flatten()
            .find(|held| held.seq == seq && held.remote == remote)
        {
            // The same pair installed again: this installation's name replaces the older one, so
            // a release still carrying that older name cannot take this route away.
            let known = held.token == token;
            held.generation = generation;
            held.token = token;
            return if known {
                Installed::Refreshed
            } else {
                Installed::New
            };
        }
        let Some(slot) = self.entries.iter().position(Option::is_none) else {
            // The engine releases the association it stops using before installing the one that
            // displaced it, so it cannot ask for more routes than there are slots. Refusing keeps
            // every live route instead of dropping one, and is reported to the connection rather
            // than logged and forgotten.
            warn!(seq, %remote, "reset association table full; route not installed");
            return Installed::Full;
        };
        self.entries[slot] = Some(Association {
            seq,
            remote,
            token,
            generation,
        });
        Installed::New
    }

    /// Release the route for `seq` at `remote`, when it is still the installation `generation`
    /// names. `true` when a route was removed.
    fn release(&mut self, seq: u64, remote: SocketAddr, generation: u64) -> bool {
        let Some(slot) = self.entries.iter().position(|e| {
            e.is_some_and(|held| {
                held.seq == seq && held.remote == remote && held.generation == generation
            })
        }) else {
            return false;
        };
        self.entries[slot] = None;
        true
    }

    /// Forget the associations of the IDs with sequence numbers in `seqs`.
    fn remove_range(&mut self, seqs: Range<u64>) -> impl Iterator<Item = (SocketAddr, ResetToken)> {
        self.entries.iter_mut().filter_map(move |entry| {
            if entry.is_some_and(|held| seqs.contains(&held.seq)) {
                entry.take().map(|held| (held.remote, held.token))
            } else {
                None
            }
        })
    }

    fn iter(&self) -> impl Iterator<Item = (SocketAddr, ResetToken)> {
        self.entries
            .iter()
            .flatten()
            .map(|held| (held.remote, held.token))
    }
}

/// Internal identifier for a `Connection` currently associated with an endpoint
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub(crate) struct ConnectionHandle(pub(crate) usize);

impl From<ConnectionHandle> for usize {
    fn from(x: ConnectionHandle) -> Self {
        x.0
    }
}

impl Index<ConnectionHandle> for Slab<ConnectionMeta> {
    type Output = ConnectionMeta;
    fn index(&self, ch: ConnectionHandle) -> &ConnectionMeta {
        &self[ch.0]
    }
}

impl IndexMut<ConnectionHandle> for Slab<ConnectionMeta> {
    fn index_mut(&mut self, ch: ConnectionHandle) -> &mut ConnectionMeta {
        &mut self[ch.0]
    }
}

/// Event resulting from processing a single datagram
pub(crate) enum DatagramEvent {
    /// The datagram is redirected to its `Connection`
    ConnectionEvent(ConnectionHandle, ConnectionEvent),
    /// The datagram may result in starting a new `Connection`
    NewConnection(Incoming),
    /// Response generated directly by the endpoint
    Response(Transmit),
}

/// An incoming connection for which the server has not yet begun its part of the handshake.
pub(crate) struct Incoming {
    received_at: Instant,
    addresses: FourTuple,
    ecn: Option<EcnCodepoint>,
    packet: InitialPacket,
    rest: Option<BytesMut>,
    crypto: Keys,
    token: IncomingToken,
    incoming_idx: usize,
    live: Arc<AtomicBool>,
    deadline: Instant,
    improper_drop_warner: IncomingImproperDropWarner,
}

impl Incoming {
    /// Whether this admission has expired or already been consumed by the endpoint.
    pub(crate) fn is_expired(&self) -> bool {
        !self.live.load(Ordering::Acquire)
    }

    /// The local IP address which was used when the peer established the connection
    ///
    /// This has the same behavior as [`Connection::local_ip`].
    pub(crate) fn local_ip(&self) -> Option<IpAddr> {
        self.addresses
            .local
            .map(|local| local.ip())
            .filter(|ip| !ip.is_unspecified())
    }

    /// The peer's UDP address
    pub(crate) fn remote_address(&self) -> SocketAddr {
        self.addresses.remote
    }

    /// Whether the socket address that is initiating this connection has been validated
    ///
    /// This means that the sender of the initial packet has proved that they can receive traffic
    /// sent to `self.remote_address()`.
    ///
    /// Before expiry, an unvalidated address can be challenged with Retry.
    /// Expired attempts cannot be retried through this handle.
    pub(crate) fn remote_address_validated(&self) -> bool {
        self.token.validated
    }

    /// Whether it is legal to respond with a retry packet
    ///
    /// Before expiry, an unvalidated address can be challenged with Retry.
    /// Expired attempts cannot be retried through this handle.
    pub(crate) fn may_retry(&self) -> bool {
        !self.is_expired() && self.token.retry_src_cid.is_none()
    }

    /// The original destination connection ID sent by the client
    pub(crate) fn orig_dst_cid(&self) -> &ConnectionId {
        &self.token.orig_dst_cid
    }
}

impl fmt::Debug for Incoming {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Incoming")
            .field("addresses", &self.addresses)
            .field("ecn", &self.ecn)
            // packet doesn't implement debug
            // rest is too big and not meaningful enough
            .field("token", &self.token)
            .field("incoming_idx", &self.incoming_idx)
            // improper drop warner contains no information
            .finish_non_exhaustive()
    }
}

/// Warns when an incoming attempt is dropped without being answered. It is armed while the
/// attempt is unanswered and disarmed by whoever answers it, so the warning is a state of this
/// guard rather than a drop that has to be skipped.
struct IncomingImproperDropWarner {
    armed: bool,
}

impl IncomingImproperDropWarner {
    fn armed() -> Self {
        Self { armed: true }
    }

    fn dismiss(mut self) {
        self.armed = false;
    }
}

impl Drop for IncomingImproperDropWarner {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        warn!(
            "Incoming dropped without passing to Endpoint::accept/refuse/retry/ignore \
               (may cause memory leak and eventual inability to accept new connections)"
        );
    }
}

/// Errors in the parameters being used to create a new connection
///
/// These arise before any I/O has been performed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectError {
    /// The endpoint can no longer create new connections
    ///
    /// Indicates that a necessary component of the endpoint has been dropped or otherwise disabled.
    EndpointStopping,
    /// The connection could not be created because not enough of the CID space is available
    ///
    /// Try using longer connection IDs
    CidsExhausted,
    /// The given server name was malformed
    InvalidServerName(String),
    /// The remote [`SocketAddr`] supplied was malformed
    ///
    /// Examples include attempting to connect to port 0, or using an inappropriate address family.
    InvalidRemoteAddress(SocketAddr),
    /// No default client configuration was set up
    ///
    /// Use `Endpoint::connect_with` to specify a client configuration.
    NoDefaultClientConfig,
    /// The cryptographic session could not be initialized
    Crypto(TransportError),
    /// The local endpoint does not support the QUIC version specified in the client configuration
    UnsupportedVersion,
}

impl core::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EndpointStopping => f.write_str("endpoint stopping"),
            Self::CidsExhausted => f.write_str("CIDs exhausted"),
            Self::InvalidServerName(field0) => write!(f, "invalid server name: {field0}"),
            Self::InvalidRemoteAddress(field0) => write!(f, "invalid remote address: {field0}"),
            Self::NoDefaultClientConfig => f.write_str("no default client config"),
            Self::Crypto(error) => write!(f, "initialize cryptographic session: {error}"),
            Self::UnsupportedVersion => f.write_str("unsupported QUIC version"),
        }
    }
}

impl std::error::Error for ConnectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Crypto(error) => Some(error),
            _ => None,
        }
    }
}

/// Error type for attempting to accept an [`Incoming`]
#[derive(Debug)]
pub(crate) struct AcceptError {
    /// Underlying error describing reason for failure
    pub(crate) cause: ConnectionError,
    /// Optional response to transmit back
    pub(crate) response: Option<Transmit>,
}

/// Error for a Retry that was not sent; the [`Incoming`] is handed back untouched
#[derive(Debug)]
pub(crate) struct RetryError {
    incoming: Box<Incoming>,
    reason: RetryRefused,
}

/// Why a Retry was not sent
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RetryRefused {
    /// The attempt already bears a token from a previous Retry
    AlreadyRetried,
    /// The endpoint has no server configuration
    NoServerConfig,
    /// The token key's provider failed to seal the retry token
    TokenSealing,
    /// The crypto provider failed to authenticate the Retry packet.
    IntegrityProtection,
    /// The configured retry token lifetime cannot be represented on the clock that would bound
    /// the return route, so no Retry is issued and the attempt is kept
    LifetimeUnrepresentable,
}

impl core::fmt::Display for RetryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.reason {
            RetryRefused::AlreadyRetried => f.write_str("retry() with validated Incoming"),
            RetryRefused::NoServerConfig => f.write_str("retry() without a server config"),
            RetryRefused::TokenSealing => f.write_str("retry token could not be sealed"),
            RetryRefused::IntegrityProtection => {
                f.write_str("retry packet could not be authenticated")
            }
            RetryRefused::LifetimeUnrepresentable => {
                f.write_str("retry token lifetime exceeds the clock")
            }
        }
    }
}

impl std::error::Error for RetryError {}

impl RetryError {
    pub(crate) fn new(incoming: Incoming, reason: RetryRefused) -> Self {
        Self {
            incoming: Box::new(incoming),
            reason,
        }
    }

    /// Why the Retry was not sent
    pub(crate) fn reason(&self) -> RetryRefused {
        self.reason
    }

    /// Get the [`Incoming`]
    pub(crate) fn into_incoming(self) -> Incoming {
        *self.incoming
    }
}

/// Reset Tokens which are associated with peer socket addresses
///
/// The standard `HashMap` is used since both `SocketAddr` and `ResetToken` are
/// peer generated and might be usable for hash collision attacks.
#[derive(Default, Debug)]
struct ResetTokenTable(HashMap<SocketAddr, HashMap<ResetToken, ConnectionHandle>>);

impl ResetTokenTable {
    fn insert(&mut self, remote: SocketAddr, token: ResetToken, ch: ConnectionHandle) -> bool {
        self.0
            .entry(remote)
            .or_default()
            .insert(token, ch)
            .is_some()
    }

    fn remove(&mut self, remote: SocketAddr, token: ResetToken) {
        use std::collections::hash_map::Entry;
        match self.0.entry(remote) {
            Entry::Vacant(_) => {}
            Entry::Occupied(mut e) => {
                e.get_mut().remove(&token);
                if e.get().is_empty() {
                    e.remove_entry();
                }
            }
        }
    }

    fn get(&self, remote: SocketAddr, token: &[u8]) -> Option<&ConnectionHandle> {
        let token = ResetToken::from(<[u8; RESET_TOKEN_SIZE]>::try_from(token).ok()?);
        self.0.get(&remote)?.get(&token)
    }
}

/// Identifies a connection by the combination of remote and local addresses
///
/// Including the local ensures good behavior when the host has multiple IP addresses on the same
/// subnet and zero-length connection IDs are in use.
#[derive(Hash, Eq, PartialEq, Debug, Copy, Clone)]
struct FourTuple {
    remote: SocketAddr,
    /// The receiving local socket address (ip and port); an endpoint may own several sockets.
    local: Option<SocketAddr>,
}
