//! Packets declared lost that an acknowledgement may still arrive for, which tells a congestion
//! window reduced in error, for packets that were only late, from one reduced for a real loss.

use std::{collections::BTreeMap, ops::RangeInclusive};

use crate::proto::{Duration, Instant, congestion::Controller};
use rama_quic_proto::packet::SpaceId;

/// Packets remembered at most; the oldest makes room and counts as lost for good.
const CAPACITY: usize = 256;

/// Probe timeouts after it was sent within which a packet declared lost may still be
/// acknowledged; other stacks wait as long.
const PATIENCE: u32 = 2;

/// The most later packets waited for before one is declared lost, however late packets
/// arrive; beyond it the time threshold decides, as in other stacks.
const MAX_PACKET_THRESHOLD: u64 = 20;

/// Round trips a packet may stay unacknowledged on a path seen to deliver packets late, the
/// larger threshold RFC 9002 section 6.1.2 notes for the same purpose.
const LATE_TIME_THRESHOLD: f32 = 1.25;

/// The packets declared lost on a path and not settled yet, with when each was sent, and how
/// far out of order the late ones among them arrived.
#[derive(Default)]
pub(in crate::proto::connection) struct DeclaredLost {
    packets: BTreeMap<(SpaceId, u64), Instant>,
    /// Packets the latest packet was ahead of a late one, at most; zero while none was late.
    reordering: u64,
}

impl DeclaredLost {
    /// Remembers a packet whose loss is reported to `controller` as a congestion event.
    pub(in crate::proto::connection) fn on_lost(
        &mut self,
        space: SpaceId,
        packet: u64,
        sent: Instant,
        controller: &mut dyn Controller,
    ) {
        if self.packets.len() >= CAPACITY {
            self.packets.pop_first();
            controller.on_loss_confirmed();
        }
        self.packets.insert((space, packet), sent);
    }

    /// Settles the remembered packets against the packets an acknowledgement received at `now`
    /// covers, and returns how many of them it covers.
    ///
    /// A packet sent longer ago than the patience allows is lost for good, which the controller
    /// learns. One the acknowledgement covers was only late; once that leaves none to wait
    /// for, the controller learns that its reduction was made in error.
    pub(in crate::proto::connection) fn on_ack(
        &mut self,
        now: Instant,
        pto: Duration,
        space: SpaceId,
        largest_acked: u64,
        acknowledged: impl IntoIterator<Item = RangeInclusive<u64>>,
        controller: &mut dyn Controller,
    ) -> u64 {
        if self.packets.is_empty() {
            return 0;
        }
        let patience = pto.saturating_mul(PATIENCE);
        let remembered = self.packets.len();
        self.packets
            .retain(|_, sent| now.saturating_duration_since(*sent) <= patience);
        if self.packets.len() < remembered {
            controller.on_loss_confirmed();
        }

        let mut late = 0;
        for range in acknowledged {
            let range = (space, *range.start())..=(space, *range.end());
            while let Some((&key, _)) = self.packets.range(range.clone()).next() {
                self.packets.remove(&key);
                late += 1;
                let overtaken_by = largest_acked.saturating_sub(key.1).saturating_add(1);
                self.reordering = self.reordering.max(overtaken_by.min(MAX_PACKET_THRESHOLD));
            }
            if self.packets.is_empty() {
                break;
            }
        }
        if late > 0 && self.packets.is_empty() {
            controller.on_spurious_congestion_event();
        }
        late
    }

    /// Later packets acknowledged before a packet is declared lost: the `configured` number,
    /// or more on a path that delivered packets further out of order than that
    /// (RFC 9002 section 6.1).
    pub(in crate::proto::connection) fn packet_threshold(&self, configured: u64) -> u64 {
        configured.max(self.reordering)
    }

    /// Round trips after which an unacknowledged packet is declared lost: the `configured`
    /// factor, or a larger one on a path that delivered packets late.
    pub(in crate::proto::connection) fn time_threshold(&self, configured: f32) -> f32 {
        if self.reordering > 0 {
            configured.max(LATE_TIME_THRESHOLD)
        } else {
            configured
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Counts what recovery concludes about the losses it reported.
    #[derive(Clone, Default)]
    struct Verdicts {
        in_error: u32,
        confirmed: u32,
    }

    impl Controller for Verdicts {
        fn on_congestion_event(&mut self, _: Instant, _: Instant, _: bool, _: u64) {}

        fn on_spurious_congestion_event(&mut self) {
            self.in_error += 1;
        }

        fn on_loss_confirmed(&mut self) {
            self.confirmed += 1;
        }

        fn on_mtu_update(&mut self, _: u16) {}

        fn window(&self) -> u64 {
            12000
        }

        fn in_slow_start(&self) -> bool {
            false
        }

        fn clone_box(&self) -> Box<dyn Controller> {
            Box::new(self.clone())
        }

        fn initial_window(&self) -> u64 {
            12000
        }
    }

    const PTO: Duration = Duration::from_millis(100);
    const SPACE: SpaceId = SpaceId::Data;

    /// Settles `lost` against an acknowledgement of the packets from each first to each last
    /// number given, and returns how many of them it covered.
    fn settle(
        lost: &mut DeclaredLost,
        verdicts: &mut Verdicts,
        now: Instant,
        space: SpaceId,
        largest_acked: u64,
        acknowledged: &[(u64, u64)],
    ) -> u64 {
        let ranges = acknowledged.iter().map(|&(first, last)| first..=last);
        lost.on_ack(now, PTO, space, largest_acked, ranges, verdicts)
    }

    #[test]
    fn a_reduction_is_made_in_error_once_every_packet_declared_lost_is_acknowledged() {
        let sent = Instant::now();
        let now = sent + Duration::from_millis(50);
        let mut verdicts = Verdicts::default();
        let mut lost = DeclaredLost::default();
        for packet in [3, 4, 7] {
            lost.on_lost(SPACE, packet, sent, &mut verdicts);
        }

        // Another space numbers its packets on its own.
        assert_eq!(
            settle(
                &mut lost,
                &mut verdicts,
                now,
                SpaceId::Handshake,
                9,
                &[(3, 7)]
            ),
            0
        );
        assert_eq!(
            settle(&mut lost, &mut verdicts, now, SPACE, 9, &[(5, 6)]),
            0
        );
        assert_eq!(
            settle(&mut lost, &mut verdicts, now, SPACE, 9, &[(3, 4)]),
            2
        );
        assert_eq!(verdicts.in_error, 0, "packet 7 may still be lost");
        assert_eq!(
            settle(&mut lost, &mut verdicts, now, SPACE, 9, &[(0, 1), (7, 9)]),
            1
        );
        assert_eq!((verdicts.in_error, verdicts.confirmed), (1, 0));

        // Nothing is left to settle, so a repeated acknowledgement concludes nothing.
        assert_eq!(
            settle(&mut lost, &mut verdicts, now, SPACE, 9, &[(0, 9)]),
            0
        );
        assert_eq!((verdicts.in_error, verdicts.confirmed), (1, 0));
    }

    #[test]
    fn a_packet_not_acknowledged_in_time_is_lost_and_keeps_the_reduction() {
        let sent = Instant::now();
        let mut verdicts = Verdicts::default();
        let mut lost = DeclaredLost::default();
        lost.on_lost(SPACE, 3, sent, &mut verdicts);
        lost.on_lost(SPACE, 4, sent + PTO, &mut verdicts);

        // Packet 3 ran out of time before this acknowledgement of packet 4.
        let now = sent + 2 * PTO + Duration::from_millis(1);
        assert_eq!(
            settle(&mut lost, &mut verdicts, now, SPACE, 9, &[(4, 4)]),
            1
        );
        assert_eq!(verdicts.confirmed, 1);
        // The controller dropped what it could return to, and is told about packet 4 alone.
        assert_eq!(verdicts.in_error, 1);

        // An acknowledgement that arrives too late for packet 3 no longer counts.
        assert_eq!(
            settle(&mut lost, &mut verdicts, now, SPACE, 9, &[(3, 3)]),
            0
        );
        assert_eq!((verdicts.in_error, verdicts.confirmed), (1, 1));
    }

    #[test]
    fn more_losses_than_are_remembered_count_as_lost_for_good() {
        let sent = Instant::now();
        let mut verdicts = Verdicts::default();
        let mut lost = DeclaredLost::default();
        for packet in 0..100_000 {
            lost.on_lost(SPACE, packet, sent, &mut verdicts);
        }
        assert!(verdicts.confirmed > 0);
        assert!(lost.packets.len() <= CAPACITY);

        // The oldest were forgotten, the newest are still settled.
        assert_eq!(
            settle(&mut lost, &mut verdicts, sent, SPACE, 0, &[(0, 9)]),
            0
        );
        assert_eq!(
            settle(
                &mut lost,
                &mut verdicts,
                sent,
                SPACE,
                0,
                &[(99_990, 99_999)]
            ),
            10
        );
    }

    #[test]
    fn late_packets_raise_the_thresholds_to_how_late_they_were() {
        let sent = Instant::now();
        let mut verdicts = Verdicts::default();
        let mut lost = DeclaredLost::default();
        assert_eq!(lost.packet_threshold(3), 3);
        assert_eq!(lost.time_threshold(1.125).to_bits(), 1.125f32.to_bits());

        // Declaring a packet lost changes nothing until it turns out to have been late.
        lost.on_lost(SPACE, 10, sent, &mut verdicts);
        assert_eq!(lost.packet_threshold(3), 3);

        // Six later packets were acknowledged before packet 10, so a seventh is waited for.
        settle(&mut lost, &mut verdicts, sent, SPACE, 16, &[(10, 10)]);
        assert_eq!(lost.packet_threshold(3), 7);
        assert!(lost.time_threshold(1.125) > 1.125);
        // Thresholds configured above what the path showed stay as configured.
        assert_eq!(lost.packet_threshold(9), 9);
        assert_eq!(lost.time_threshold(2.0).to_bits(), 2.0f32.to_bits());

        // A packet less late than that leaves the threshold where it is.
        lost.on_lost(SPACE, 20, sent, &mut verdicts);
        settle(&mut lost, &mut verdicts, sent, SPACE, 23, &[(20, 20)]);
        assert_eq!(lost.packet_threshold(3), 7);

        // However late a packet is, the time threshold still bounds how long it is waited for.
        lost.on_lost(SPACE, 30, sent, &mut verdicts);
        settle(&mut lost, &mut verdicts, sent, SPACE, 5000, &[(30, 30)]);
        let bounded = lost.packet_threshold(3);
        assert!((7..100).contains(&bounded), "{bounded}");
    }
}
