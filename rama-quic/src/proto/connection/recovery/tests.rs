use crate::proto::{Duration, connection::recovery::persistent_congestion_period};
use rama_quic_proto::{
    frame::{self, EcnCounts},
    packet::SpaceId,
};

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
fn loss_delay_respects_granularity_and_saturates_extreme_factors() {
    use super::loss_delay;
    use crate::proto::TIMER_GRANULARITY;

    assert_eq!(
        loss_delay(Duration::from_millis(8), 1.125),
        Duration::from_millis(9)
    );
    for factor in [0.0, f32::MIN_POSITIVE, 0.01] {
        assert_eq!(
            loss_delay(Duration::from_millis(1), factor),
            TIMER_GRANULARITY
        );
    }
    assert_eq!(loss_delay(Duration::from_secs(1), f32::MAX), Duration::MAX);
    assert_eq!(loss_delay(Duration::MAX, f32::MAX), Duration::MAX);
}

impl super::Connection {
    pub(crate) fn acknowledge_handshake_for_pto_test(&mut self, now: crate::proto::Instant) {
        let Some((&largest, _)) = self.spaces[SpaceId::Handshake]
            .sent_packets
            .last_key_value()
        else {
            return;
        };
        let mut ranges = rama_quic_proto::range_set::ArrayRangeSet::new();
        ranges.insert(0..largest + 1);
        self.on_ack_received(
            now,
            SpaceId::Handshake,
            &frame::Ack::from_ranges(0, &ranges, None).unwrap(),
        )
        .unwrap();
    }

    /// Simulate the recovery-state replacement at completion of path validation while
    /// retaining connection-wide sent packets, just as migration does.
    pub(crate) fn replace_recovery_path_for_test(&mut self, now: crate::proto::Instant) {
        self.path_counter += 1;
        self.path = crate::proto::connection::paths::PathData::new(
            self.path.remote,
            self.path.local,
            false,
            None,
            self.path_counter,
            now,
            &self.config,
        );
        self.path.validated = true;
        self.path.mtu_validated = true;
        // A busy new path must not grow its congestion window from old-path ACKs.
        self.app_limited = false;
    }

    pub(crate) fn assert_rebinding_restarts_pending_mtu_probe(
        &mut self,
        now: crate::proto::Instant,
    ) {
        let mut mtud = crate::proto::connection::mtud::MtuDiscovery::new(
            1300,
            1200,
            Some(1400),
            crate::proto::MtuDiscoveryConfig::default(),
        );
        assert!(mtud.poll_transmit(now, 100).is_some());
        assert_eq!(mtud.in_flight_mtu_probe(), Some(100));
        self.path.mtud = mtud;
        let mut next = crate::proto::connection::paths::PathData::from_previous(
            self.path.remote,
            self.path.local,
            &self.path,
            self.path.generation() + 1,
            now,
        );
        assert_eq!(next.current_mtu(), 1300);
        assert_eq!(next.mtud.in_flight_mtu_probe(), None);
        let size = next.mtud.poll_transmit(now, 101).unwrap();
        assert!((1301..=1400).contains(&size));
        assert_eq!(next.mtud.in_flight_mtu_probe(), Some(101));
        assert_eq!(self.path.mtud.in_flight_mtu_probe(), Some(100));
    }
}

type RecordedLoss = (crate::proto::Instant, bool, u64);

#[derive(Clone, Default)]
struct LossRecorder(std::sync::Arc<parking_lot::Mutex<Vec<RecordedLoss>>>);

impl crate::proto::congestion::Controller for LossRecorder {
    fn on_congestion_event(
        &mut self,
        _: crate::proto::Instant,
        sent: crate::proto::Instant,
        persistent: bool,
        bytes: u64,
    ) {
        self.0.lock().push((sent, persistent, bytes));
    }

    fn on_mtu_update(&mut self, _: u16) {}

    fn window(&self) -> u64 {
        12000
    }

    fn initial_window(&self) -> u64 {
        12000
    }

    fn clone_box(&self) -> Box<dyn crate::proto::congestion::Controller> {
        Box::new(self.clone())
    }
}

impl super::Connection {
    pub(crate) fn assert_mixed_path_loss_is_scoped(&mut self, now: crate::proto::Instant) {
        use crate::proto::connection::spaces::SentPacket;
        self.replace_recovery_path_for_test(now);
        let recorder = LossRecorder::default();
        self.path.congestion = Box::new(recorder.clone());
        let space = SpaceId::Data;
        let base = self.spaces[space].next_packet_number;
        let current_sent = now.checked_sub(Duration::from_millis(3)).unwrap();
        let old_sent = now.checked_sub(Duration::from_millis(1)).unwrap();
        let lost_probes = self.stats.path.lost_plpmtud_probes;
        for (offset, generation, sent, probe, size) in [
            (0, self.path.generation(), current_sent, false, 1200),
            (1, self.path.generation() - 1, old_sent, false, 1300),
            (2, self.path.generation() - 1, old_sent, true, 1400),
        ] {
            let info = SentPacket {
                path_generation: generation,
                time_sent: sent,
                size,
                ack_eliciting: true,
                is_0rtt: false,
                is_mtu_probe_packet: probe,
                largest_acked: None,
                retransmits: Default::default(),
                stream_frames: Default::default(),
            };
            self.in_flight_ack_eliciting += 1;
            if generation == self.path.generation() {
                self.path.sent(base + offset, info, &mut self.spaces[space]);
            } else {
                assert!(self.spaces[space].sent(base + offset, info).is_none());
            }
        }
        self.spaces[space].next_packet_number = base + 11;
        self.spaces[space].largest_acked_packet = Some(base + 10);
        self.detect_lost_packets(now, space, true);
        assert_eq!(*recorder.0.lock(), vec![(current_sent, false, 1200)]);
        assert_eq!(self.path.in_flight.bytes, 0);
        assert_eq!(self.stats.path.lost_plpmtud_probes, lost_probes + 1);
        for pn in base..base + 3 {
            assert!(!self.spaces[space].sent_packets.contains_key(&pn));
        }
    }
}

impl super::Connection {
    pub(crate) fn assert_old_path_ecn_only_advances_feedback(
        &mut self,
        now: crate::proto::Instant,
    ) {
        self.replace_recovery_path_for_test(now);
        let recorder = LossRecorder::default();
        self.path.congestion = Box::new(recorder.clone());
        let space = SpaceId::Data;
        let mut counts = self.spaces[space].ecn_feedback;

        // Two old-path packets were acknowledged, but only one retained its ECN
        // marking. Count verification fails; its monotonic CE observation must
        // still be consumed before a clean current-path ACK arrives.
        counts.ce += 1;
        self.process_ecn(now, space, 2, counts, None);
        assert!(self.path.sending_ecn);
        assert_eq!(self.spaces[space].ecn_feedback.ce, counts.ce);
        counts.ect0 += 1;
        self.process_ecn(now, space, 1, counts, Some(now));
        assert!(recorder.0.lock().is_empty());

        counts.ce += 1;
        self.process_ecn(now, space, 1, counts, None);
        assert!(recorder.0.lock().is_empty());
        assert!(self.path.sending_ecn);
        assert_eq!(self.spaces[space].ecn_feedback.ce, counts.ce);

        // Invalid old-path feedback must not disable ECN on the replacement path.
        self.process_ecn(now, space, 1, EcnCounts::ZERO, None);
        assert!(self.path.sending_ecn);
        assert_eq!(self.spaces[space].ecn_feedback.ce, counts.ce);

        // A subsequent clean current-path ACK does not rediscover the old CE mark.
        counts.ect0 += 1;
        self.process_ecn(now, space, 1, counts, Some(now));
        assert!(recorder.0.lock().is_empty());
        counts.ce += 1;
        self.process_ecn(now, space, 1, counts, Some(now));
        assert_eq!(*recorder.0.lock(), vec![(now, false, 0)]);
    }
}
impl super::Connection {
    pub(crate) fn assert_ack_delay_tracks_handshake_confirmation(
        &mut self,
        now: crate::proto::Instant,
    ) {
        use crate::proto::connection::{paths::RttEstimator, spaces::SentPacket};

        self.skip_no_packet_number();
        self.path.rtt = RttEstimator::new(Duration::from_millis(50));
        self.path
            .rtt
            .update(Duration::ZERO, Duration::from_millis(50));
        self.ack_frequency.peer_max_ack_delay = Duration::from_millis(25);
        self.peer_params.ack_delay_exponent = rama_quic_proto::VarInt::from_u32(3);
        let packet = self.spaces[SpaceId::Data].get_tx_number();
        self.path.sent(
            packet,
            SentPacket {
                path_generation: self.path.generation(),
                time_sent: now.checked_sub(Duration::from_millis(150)).unwrap(),
                size: 1200,
                ack_eliciting: true,
                is_0rtt: false,
                is_mtu_probe_packet: false,
                largest_acked: None,
                retransmits: Default::default(),
                stream_frames: Default::default(),
            },
            &mut self.spaces[SpaceId::Data],
        );
        self.in_flight_ack_eliciting += 1;
        let mut ranges = rama_quic_proto::range_set::ArrayRangeSet::new();
        ranges.insert_one(packet);
        self.on_ack_received(
            now,
            SpaceId::Data,
            // 12_500 µs delay = 100 ms with exponent 3.
            &frame::Ack::from_ranges(12_500, &ranges, None).unwrap(),
        )
        .unwrap();
        let expected = if self.handshake_confirmed() {
            Duration::from_micros(59_375) // (7 * 50 + (150 - 25)) / 8
        } else {
            Duration::from_millis(50) // (7 * 50 + (150 - 100)) / 8
        };
        assert_eq!(self.path.rtt.get(), expected);
        assert_eq!(self.path.rtt.min(), Duration::from_millis(50));
    }
}
