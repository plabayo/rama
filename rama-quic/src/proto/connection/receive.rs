//! Taking a datagram apart: dispatch by space, decryption, the packets coalesced behind the
//! first, and what an authenticated packet settles.

use std::{mem, net::SocketAddr};

use rama_core::{
    bytes::{Bytes, BytesMut},
    telemetry::tracing::{debug, trace, trace_span, warn},
};

use crate::proto::{
    Frame, Instant, TransportError, TransportErrorCode,
    connection::{
        Connection, ConnectionError, ConnectionSide, Event, State, packet_crypto,
        spaces::{PacketSpace, Retransmits},
        state,
        timer::Timer,
    },
    frame::{self, Close},
    packet::{
        FixedLengthConnectionIdParser, Header, InitialHeader, LongType, Packet, PartialDecode,
        SpaceId,
    },
    shared::{EcnCodepoint, EndpointEventInner},
};

#[cfg(test)]
use crate::proto::shared::{ConnectionEvent, ConnectionEventInner, DatagramConnectionEvent};

impl Connection {
    pub(super) fn on_packet_authenticated(
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

        let Some(packet) = packet else { return };
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

        self.config
            .qlog_sink
            .emit_packet_received(packet, space_id, !is_1rtt, now, self.trace_cid);
    }

    pub(super) fn handle_coalesced(
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

    pub(super) fn handle_decode(
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
                    if let Header::Initial(InitialHeader { ref token, .. }) = packet.header
                        && let State::Handshake(ref hs) = self.state
                        && self.side.is_server()
                        && token != &hs.expected_token
                    {
                        // Clients must send the same retry token in every Initial. Initial
                        // packets can be spoofed, so we discard rather than killing the
                        // connection.
                        warn!("discarding Initial with invalid retry token");
                        return;
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

        // Answer with CONNECTION_CLOSE if this packet has earned one. A close already waiting
        // to be sent stays waiting, and only packets on this connection's own path count
        // towards the next one.
        if let State::Closed(_) = self.state
            && remote == self.path.remote
            && !self.close
            && self.close_responses.arrived()
        {
            self.close = true;
        }
    }

    #[expect(
        clippy::unwrap_used,
        reason = "this branch is inside `if self.side.is_client()`, and the rustls client session always reports whether early data was accepted; 0-RTT long headers carry a packet number, so `decrypt_packet` yields `Some`"
    )]
    pub(super) fn process_decrypted_packet(
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

                    if matches!(frame, Frame::Padding) {
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
                                cause: None,
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
                        // Every address this identifier has already been sent to needs a route
                        // now, not just the one in use.
                        let seq = self.rem_cids.active_seq();
                        self.announce_reset_routes(seq);
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
                                cause: None,
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
                    self.on_ack_received(now, packet.header.space(), &ack)?;
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

        let Some(result) = result else {
            return Ok(None);
        };

        if result.outgoing_key_update_acked
            && let Some(prev) = self.prev_crypto.as_mut()
        {
            prev.end_packet = Some((result.number, now));
            self.set_key_discard_timer(now, packet.header.space());
        }

        if result.incoming_key_update {
            trace!("key update authenticated");
            self.update_keys(Some((result.number, now)), true);
            self.set_key_discard_timer(now, packet.header.space());
        }

        Ok(Some(result.number))
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
        let ConnectionEventInner::Datagram(DatagramConnectionEvent {
            first_decode,
            remaining,
            ..
        }) = &event.0
        else {
            return None;
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
}
