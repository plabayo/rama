//! The handshake: crypto progression, the packet spaces and keys it installs and discards,
//! the peer's transport parameters, and 0-RTT.

use std::{cmp, mem, net::SocketAddr};

use rama_core::{
    bytes::{Bytes, BytesMut},
    telemetry::tracing::{debug, error, trace, trace_span, warn},
};

use crate::proto::{
    Duration, Instant, TransportError, VarInt,
    connection::{
        Connection, ConnectionError, ConnectionSide, Event, State,
        packet_crypto::{PrevCrypto, ZeroRttCrypto},
        timer::Timer,
    },
    crypto::{self, Keys},
    frame,
    packet::{InitialPacket, SpaceId},
    shared::EcnCodepoint,
    transport_parameters::TransportParameters,
};

impl Connection {
    /// The negotiated TLS key exchange group, if the session exposes it (test observation point)
    #[cfg(test)]
    pub(crate) fn negotiated_key_exchange_group(&self) -> Option<u16> {
        self.crypto.negotiated_key_exchange_group()
    }

    /// Enforce the handshake lifetime before processing queued packets in the async driver.
    pub(crate) fn expire_handshake(&mut self, now: Instant) {
        if self.timers.is_expired(Timer::Handshake, now) {
            self.qlog_handshake_timeout(now);
            self.kill(now, ConnectionError::TimedOut);
        }
    }

    /// Update traffic keys now. Answers whether an update was started.
    ///
    /// An update is initiated only once the handshake is confirmed (RFC 9001 §6.1) and only when
    /// no update is in flight (§6). Answering the peer's update is a different path and is not
    /// bound by the first of those.
    pub(crate) fn force_key_update(&mut self, now: Instant) -> bool {
        if !self.state.is_established() {
            debug!("ignoring forced key update in illegal state");
            return false;
        }
        if !self.handshake_confirmed() {
            debug!("ignoring forced key update before the handshake is confirmed");
            return false;
        }
        if self.prev_crypto.is_some() {
            // We already just updated, or are currently updating, the keys. Concurrent key updates
            // are illegal.
            debug!("ignoring redundant forced key update");
            return false;
        }
        self.update_keys(now, None, false);
        true
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
        // What bounds the response is what arrived on the wire, and the decrypted payload is
        // shorter than the ciphertext by the AEAD tag (RFC 9000 §8.1).
        let tag_len = self.spaces[SpaceId::Initial]
            .crypto
            .as_ref()
            .map_or(0, |crypto| crypto.packet.remote.tag_len());
        let len = packet.header_data.len() + packet.payload.len() + tag_len;
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

        self.process_decrypted_packet(now, remote, local, Some(packet_number), packet.into())
            .inspect_err(|error| {
                self.qlog_connection_error(now, error);
                self.qlog_discarded(now);
            })?;
        self.qlog_observe_state(now);
        if let Some(data) = remaining {
            self.handle_coalesced(now, remote, local, ecn, data);
        }

        self.qlog_sink
            .emit_recovery_metrics(self.pto_count, &mut self.path, now, self.trace_cid);

        Ok(())
    }

    pub(super) fn init_0rtt(&mut self, now: Instant) {
        let Some((header, packet)) = self.crypto.early_crypto() else {
            return;
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
                    self.qlog_restored_parameters(now, &params);
                    self.set_peer_params(now, params);
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
        self.qlog_zero_rtt_key(now, false);
    }

    pub(super) fn read_crypto(
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

        // As above: the assembler reports only that it holds too many spans.
        if space
            .crypto_stream
            .insert(crypto.offset, crypto.data.clone(), payload_len)
            .is_err()
        {
            return Err(TransportError::INTERNAL_ERROR(
                "too many gaps in crypto stream buffer",
            ));
        }

        while let Some(chunk) = space.crypto_stream.read(usize::MAX, true) {
            trace!("consumed {} CRYPTO bytes", chunk.bytes.len());
            if self.crypto.read_handshake(&chunk.bytes)? {
                self.events.push_back(Event::HandshakeDataReady);
            }
        }

        Ok(())
    }

    pub(super) fn write_crypto(&mut self, now: Instant) {
        loop {
            let space = self.highest_space;
            let mut outgoing = Vec::new();
            if let Some(crypto) = self.crypto.write_handshake(&mut outgoing) {
                match space {
                    SpaceId::Initial => {
                        self.upgrade_crypto(now, SpaceId::Handshake, crypto);
                    }
                    SpaceId::Handshake => {
                        self.upgrade_crypto(now, SpaceId::Data, crypto);
                    }
                    #[expect(
                        clippy::unreachable,
                        reason = "`upgrade_crypto` is only called while `highest_space` is Initial or Handshake; 1-RTT key changes go through `update_keys`"
                    )]
                    SpaceId::Data => unreachable!("got updated secrets during 1-RTT"),
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
            if let State::Handshake(ref mut state) = self.state
                && space == SpaceId::Initial
                && offset == 0
                && self.side.is_client()
            {
                state.client_hello = Some(outgoing.clone());
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
    fn upgrade_crypto(&mut self, now: Instant, space: SpaceId, crypto: Keys) {
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
        self.qlog_key_change(now, space, false, Some("tls"));
        if space == SpaceId::Data {
            self.qlog_negotiated_alpn(now);
        }
        debug_assert!(space as usize > self.highest_space as usize);
        self.highest_space = space;
        if space == SpaceId::Data && self.side.is_client() {
            // Discard 0-RTT keys because 1-RTT keys are available.
            if self.zero_rtt_crypto.take().is_some() {
                self.qlog_zero_rtt_key(now, true);
            }
        }
    }

    pub(super) fn discard_space(&mut self, now: Instant, space_id: SpaceId) {
        debug_assert!(space_id != SpaceId::Data);
        trace!("discarding {:?} keys", space_id);
        if space_id == SpaceId::Initial {
            // No longer needed
            if let ConnectionSide::Client { token, .. } = &mut self.side {
                *token = Bytes::new();
            }
        }
        if self.spaces[space_id].crypto.take().is_some() {
            self.qlog_key_change(now, space_id, true, Some("tls"));
        }
        let space = &mut self.spaces[space_id];
        space.time_of_last_ack_eliciting_packet = None;
        space.loss_time = None;
        let sent_packets = mem::take(&mut space.sent_packets);
        for packet in sent_packets.into_values() {
            self.remove_in_flight(&packet);
        }
        self.set_loss_detection_timer(now)
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
    pub(super) fn queue_handshake_done(&mut self) {
        #[cfg(test)]
        if self.hold_handshake_done {
            self.withheld_handshake_done = true;
            return;
        }
        self.spaces[SpaceId::Data].pending.handshake_done = true;
    }

    /// Handle transport parameters received from the peer
    pub(super) fn handle_peer_params(
        &mut self,
        now: Instant,
        params: TransportParameters,
    ) -> Result<(), TransportError> {
        if Some(self.orig_rem_cid) != params.initial_src_cid
            || (self.side.is_client()
                && (Some(self.initial_dst_cid) != params.original_dst_cid
                    || self.retry_src_cid != params.retry_src_cid))
        {
            return Err(TransportError::TRANSPORT_PARAMETER_ERROR(
                "CID authentication failure",
            ));
        }

        self.qlog_remote_parameters(now, &params);
        self.set_peer_params(now, params);

        Ok(())
    }

    fn set_peer_params(&mut self, now: Instant, params: TransportParameters) {
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
        let old_mtu = self.path.current_mtu();
        self.path.mtud.on_peer_max_udp_payload_size_received(
            u16::try_from(self.peer_params.max_udp_payload_size.into_inner()).unwrap_or(u16::MAX),
        );
        self.qlog_mtu_updated(now, old_mtu);
    }

    pub(super) fn update_keys(
        &mut self,
        now: Instant,
        end_packet: Option<(u64, Instant)>,
        remote: bool,
    ) {
        trace!("executing key update");
        self.qlog_discard_previous_keys(now);
        self.stats.key_updates = self.stats.key_updates.saturating_add(1);
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
        self.qlog_key_change(
            now,
            SpaceId::Data,
            false,
            Some(if remote {
                "remote_update"
            } else {
                "local_update"
            }),
        );
    }

    pub(super) fn peer_supports_ack_frequency(&self) -> bool {
        self.peer_params.min_ack_delay.is_some()
    }
}

pub(super) fn get_max_ack_delay(params: &TransportParameters) -> Duration {
    Duration::from_micros(params.max_ack_delay.0 * 1000)
}

/// Perform key updates this many packets before the AEAD confidentiality limit.
///
/// Chosen arbitrarily, intended to be large enough to prevent spurious connection loss.
const KEY_UPDATE_MARGIN: u64 = 10_000;

/// Compute the negotiated idle timeout based on local and remote max_idle_timeout transport parameters.
///
/// According to the definition of max_idle_timeout, a value of `0` means the timeout is disabled; see <https://www.rfc-editor.org/rfc/rfc9000#section-18.2-4.4.1.>
///
/// According to the negotiation procedure, either the minimum of the timeouts or one specified is used as the negotiated value; see <https://www.rfc-editor.org/rfc/rfc9000#section-10.1-2.>
///
/// Returns the negotiated idle timeout as a `Duration`, or `None` when both endpoints have opted out of idle timeout.
pub(super) fn negotiate_max_idle_timeout(x: Option<VarInt>, y: Option<VarInt>) -> Option<Duration> {
    match (x, y) {
        (Some(VarInt(0)) | None, Some(VarInt(0)) | None) => None,
        (Some(VarInt(0)) | None, Some(y)) => Some(Duration::from_millis(y.0)),
        (Some(x), Some(VarInt(0)) | None) => Some(Duration::from_millis(x.0)),
        (Some(x), Some(y)) => Some(Duration::from_millis(cmp::min(x, y).0)),
    }
}

#[cfg(test)]
mod tests;
