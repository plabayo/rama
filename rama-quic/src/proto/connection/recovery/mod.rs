//! Loss recovery: what acknowledgements settle, what the time and packet thresholds declare
//! lost, and the timers that drive both.

use std::cmp;

use rama_core::telemetry::tracing::{debug, error, trace};

use crate::proto::{
    Duration, Instant, TIMER_GRANULARITY, TransportError,
    connection::{Connection, Event, spaces::SentPacket, timer::Timer},
    frame,
    packet::SpaceId,
    range_set::ArrayRangeSet,
};

impl Connection {
    /// Returns the next time at which `handle_timeout` should be called
    ///
    /// The value returned may change after:
    /// - the application performed some I/O on the connection
    /// - a call was made to `handle_event`
    /// - a call to `poll_transmit` returned `Some`
    /// - a call was made to `handle_timeout`
    #[must_use]
    ///   Expiry of the loss detection timer, if armed (test observation point)
    #[cfg(test)]
    pub(crate) fn loss_detection_timer(&self) -> Option<Instant> {
        self.timers.get(Timer::LossDetection)
    }

    pub(super) fn on_ack_received(
        &mut self,
        now: Instant,
        space: SpaceId,
        ack: &frame::Ack,
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
                let old_mtu = self.path.current_mtu();
                let mtu_updated = self.path.mtud.on_acked(space, packet, info.size);
                if mtu_updated {
                    self.qlog_mtu_updated(now, old_mtu);
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
    pub(super) fn on_packet_acked(&mut self, now: Instant, info: SentPacket) {
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

    pub(super) fn set_key_discard_timer(&mut self, now: Instant, space: SpaceId) {
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

    pub(super) fn on_loss_detection_timeout(&mut self, now: Instant) {
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
        let Some((_, space)) = self.pto_time_and_space(now) else {
            error!("PTO expired while unset");
            return;
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
                    self.trace_cid,
                );
                self.remove_in_flight(&info);
                for frame in info.stream_frames {
                    self.streams.retransmit(frame);
                }
                self.spaces[pn_space].pending |= info.retransmits;
                self.path.mtud.on_non_probe_lost(packet, info.size);
            }

            let old_mtu = self.path.current_mtu();
            if self.path.mtud.black_hole_detected(now) {
                self.qlog_mtu_updated(now, old_mtu);
                self.stats.path.black_holes_detected += 1;
                self.path
                    .congestion
                    .on_mtu_update(self.path.mtud.current_mtu());
                if let Some(max_datagram_size) = self.datagrams().max_size()
                    && self.datagrams.drop_oversized(max_datagram_size)
                    && self.datagrams.send_blocked
                {
                    self.datagrams.send_blocked = false;
                    self.events.push_back(Event::DatagramsUnblocked);
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
    pub(super) fn in_flight_ack_eliciting(&self) -> u64 {
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
            let Some(last_ack_eliciting) = self.spaces[space].time_of_last_ack_eliciting_packet
            else {
                continue;
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

    pub(super) fn set_loss_detection_timer(&mut self, now: Instant) {
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

        if self.amplification_stalled() {
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
    pub(super) fn pto(&self, space: SpaceId) -> Duration {
        let max_ack_delay = match space {
            SpaceId::Initial | SpaceId::Handshake => Duration::ZERO,
            SpaceId::Data => self.ack_frequency.max_ack_delay_for_pto(),
        };
        self.path.rtt.pto_base() + max_ack_delay
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

    /// Whether explicit congestion notification is in use on outgoing packets.
    #[cfg(test)]
    pub(crate) fn using_ecn(&self) -> bool {
        self.path.sending_ecn
    }

    /// Update counters to account for a packet becoming acknowledged, lost, or abandoned
    pub(super) fn remove_in_flight(&mut self, packet: &SentPacket) {
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
}

// Prevents overflow and improves behavior in extreme circumstances
const MAX_BACKOFF_EXPONENT: u32 = 16;

pub(super) fn persistent_congestion_period(pto: Duration, threshold: u32) -> Duration {
    pto.saturating_mul(threshold)
}

#[cfg(test)]
mod tests;
