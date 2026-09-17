//! The frames of an established packet: what each one means for this connection, and the
//! identifiers a NEW_CONNECTION_ID brings with it.

use std::net::SocketAddr;

use rama_core::telemetry::tracing::{debug, trace, trace_span};

use crate::proto::{
    Dir, Frame, Instant, MAX_STREAM_COUNT, StoredToken, TransportError,
    cid_queue::Retired,
    connection::{
        Connection, ConnectionSide, Event, State,
        migration::{DeferredMigration, PrevCid},
        preferred::PreferredAddressState,
        timer::Timer,
    },
    frame::{self, NewToken},
    packet::{Packet, SpaceId},
    shared::EndpointEventInner,
};

impl Connection {
    /// Apply one NEW_CONNECTION_ID frame (RFC 9000 §5.1.1, §5.1.2, §9.5): give up the identifiers
    /// the frame retires, record the new one, and retire with the peer every sequence number that
    /// leaves this connection's hands.
    pub(super) fn handle_new_cid(
        &mut self,
        now: Instant,
        frame: frame::NewConnectionId,
    ) -> Result<(), TransportError> {
        let old_remote_cid = self.rem_cids.active();
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
        // RFC 9000 §19.15. The frame decoder refuses such a frame, so this covers
        // the ones built inside this crate.
        if frame.retire_prior_to > frame.sequence {
            return Err(TransportError::FRAME_ENCODING_ERROR(
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
        // The numbers this frame retires that never reached us are retired too; the
        // peer holds them until RETIRE_CONNECTION_ID names them.
        self.retire_rem_cids(&Retired {
            previous: 0..0,
            skipped: aside.skipped.clone(),
        })?;
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
            self.restart_candidate(now);
        }
        match self.rem_cids.insert(frame) {
            Ok(inserted) => {
                // Unused identifiers this frame retired are ours no longer; the peer
                // holds them until RETIRE_CONNECTION_ID names them.
                for seq in inserted.dropped.iter().flatten() {
                    self.retire_rem_cid(*seq)?;
                }
                if let Some((retired, reset_token)) = inserted.switched {
                    self.retire_rem_cids(&retired)?;
                    self.set_reset_token(self.path.remote, reset_token);
                    self.qlog_remote_cid_updated(now, old_remote_cid);
                }
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
                return Ok(());
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
            self.update_rem_cid(now);
        }
        Ok(())
    }

    pub(super) fn process_payload(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        local: Option<SocketAddr>,
        number: u64,
        packet: Packet,
        received_bytes: Option<usize>,
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
                    trace!(len = f.datagram.data.len(), "got datagram frame");
                }
                f => {
                    trace!("got frame {:?}", f);
                }
            }

            let _guard = span.as_ref().map(|x| x.enter());
            // RFC 9000 §12.5: CRYPTO frames cannot be sent in 0-RTT packets. Both
            // CONNECTION_CLOSE types are permitted there, as 0-RTT belongs to the application
            // data packet number space; see §12.4 Table 3.
            // ACK frequency support cannot be remembered for 0-RTT either (draft-ietf-quic-
            // ack-frequency-11 §3), so its frames require 1-RTT as well.
            if packet.header.is_0rtt()
                && matches!(
                    frame,
                    Frame::Crypto(_) | Frame::AckFrequency(_) | Frame::ImmediateAck
                )
            {
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
                    self.on_ack_received(now, SpaceId::Data, &ack)?;
                }
                Frame::Padding | Frame::Ping => {}
                Frame::Close(reason) => {
                    close = Some(reason);
                }
                Frame::PathChallenge(token) => {
                    self.path_responses.push(
                        number,
                        token,
                        remote,
                        local,
                        received_bytes.unwrap_or(0),
                    );
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
                    } else if !self.on_path_response(now, token) {
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
                Frame::NewConnectionId(frame) => self.handle_new_cid(now, frame)?,
                Frame::NewToken(NewToken { token }) => {
                    let ConnectionSide::Client {
                        token_store,
                        server_name,
                        time_source,
                        ..
                    } = &self.side
                    else {
                        return Err(TransportError::PROTOCOL_VIOLATION("client sent NEW_TOKEN"));
                    };
                    if token.is_empty() {
                        return Err(TransportError::FRAME_ENCODING_ERROR("empty token"));
                    }
                    trace!("got new token");
                    let stored = StoredToken::new(token, time_source.now())
                        .with_peer_greasing_quic_bit(self.peer_params.grease_quic_bit);
                    token_store.insert(server_name, self.version, stored);
                }
                Frame::Datagram(datagram) => {
                    if self
                        .datagrams
                        .received(datagram, self.config.datagram_receive_buffer_size)?
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
                    self.qlog_observe_state(now);
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
                // The peer reaching another of our own addresses with its own address unchanged
                // is not the active migration `disable_active_migration` forbids (RFC 9000
                // §18.2); a change of its address is, unless it is on the address advertised as
                // preferred (RFC 9000 §9.6.3).
                ConnectionSide::Server { .. } => {
                    Some(remote == self.path.remote || self.may_follow_peer_move(local))
                }
                ConnectionSide::Client { .. } => None,
            };
            if let Some(allowed) = migration_allowed {
                debug_assert!(
                    allowed,
                    "a packet from a new peer address is dropped before it reaches here when \
                     migration is disabled"
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
            self.qlog_local_cid_updated(now, self.path.received_dcid, received_dcid);
            self.path.received_dcid = Some(received_dcid);
        }

        Ok(())
    }
}

#[cfg(all(
    test,
    any(
        feature = "boring",
        all(feature = "rustls", any(feature = "aws-lc", feature = "ring"))
    )
))]
mod tests {
    use super::*;
    use crate::proto::{
        TransportErrorCode, VarInt, Version,
        coding::Codec,
        packet::{Header, LongType, PacketNumber},
        tests::Pair,
    };

    #[test]
    fn ack_frequency_frames_require_one_rtt() {
        for immediate in [false, true] {
            for early in [true, false] {
                let mut pair = Pair::default();
                let (_, server) = pair.connect();
                let now = pair.time;
                let conn = pair.server_conn_mut(server);
                let mut payload = Vec::new();
                if immediate {
                    frame::FrameType::IMMEDIATE_ACK.encode(&mut payload);
                } else {
                    frame::AckFrequency {
                        sequence: VarInt(1_000),
                        ack_eliciting_threshold: VarInt(1),
                        request_max_ack_delay: VarInt(25_000),
                        reordering_threshold: VarInt(1),
                    }
                    .encode(&mut payload);
                }
                // Exercise the decoded-packet dispatch boundary; keys and packet-number
                // deduplication are checked before this method in production.
                let header = if early {
                    Header::Long {
                        ty: LongType::ZeroRtt,
                        dst_cid: conn.handshake_cid,
                        src_cid: conn.orig_rem_cid,
                        number: PacketNumber::U8(0),
                        version: Version::V1,
                    }
                } else {
                    Header::Short {
                        spin: false,
                        key_phase: false,
                        dst_cid: conn.handshake_cid,
                        number: PacketNumber::U8(0),
                    }
                };
                let packet = Packet {
                    header,
                    header_data: Default::default(),
                    payload: payload.as_slice().into(),
                };
                let result =
                    conn.process_payload(now, conn.path.remote, conn.path.local, 0, packet, None);
                if early {
                    let error = result.unwrap_err();
                    assert_eq!(error.code, TransportErrorCode::PROTOCOL_VIOLATION);
                    assert_eq!(error.reason, "illegal frame type in 0-RTT");
                } else {
                    result.unwrap();
                }
            }
        }
    }
}
