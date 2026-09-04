#!/usr/bin/env python3
"""Regression tests for the on-device soak pressure-log schema."""

import unittest

from soak_pressure_log import (
    is_no_headroom,
    no_headroom_event,
    pressure_counters,
    pressure_episode,
    selected_count,
    selection_event,
    settled_final_flow_gauge,
    soak_evidence_issues,
    summarize_pressure_rows,
)


class SoakPressureLogTests(unittest.TestCase):
    def test_current_selection_line(self):
        message = (
            "flow pressure: occupancy 460 over soft cap 450; selected 100 "
            "idle flow(s) toward low-water 350 (100 pending teardown)"
        )
        self.assertEqual(selected_count(message), 100)
        self.assertEqual(
            selection_event(message),
            {"occupancy": 460, "soft_cap": 450, "selected": 100},
        )

    def test_current_no_headroom_line(self):
        message = (
            "flow pressure: occupancy 451, soft cap 450, but no flow idle "
            "past 120000ms floor; admitting without reap"
        )
        self.assertTrue(is_no_headroom(message))
        self.assertEqual(
            no_headroom_event(message),
            {"occupancy": 451, "soft_cap": 450},
        )

    def test_periodic_outcomes_are_authoritative(self):
        message = (
            "tproxy live-flow counts tcp=351 udp=0 total=351 peak=460 "
            "softCap=450 pressure[triggers=12 scans=2 skipped=10 "
            "selected=100 evicted=96 spared=2 canceled=1 expired=1 pending=0]"
        )
        self.assertEqual(
            pressure_counters(message),
            {
                "triggers": 12,
                "scans": 2,
                "skipped": 10,
                "selected": 100,
                "evicted": 96,
                "spared": 2,
                "canceled": 1,
                "expired": 1,
                "pending": 0,
            },
        )

    def test_obsolete_messages_do_not_match(self):
        self.assertIsNone(
            selected_count(
                "flow pressure: occupancy 460 over soft cap 450; reaping 100 idle"
            )
        )
        self.assertFalse(
            is_no_headroom(
                "flow pressure: over soft cap (450) at occupancy 451 but no flow idle"
            )
        )

    def test_episode_summary_preserves_detach_interrupted_outcomes(self):
        message = (
            "flow pressure episode interrupted: startEpochMs=100250 "
            "durationMs=1250 "
            "peakOccupancy=478 softCap=450 scans=3 skipped=7 selected=28 "
            "evicted=18 spared=4 canceled=5 expired=1 startEpochUs=100250999"
        )
        self.assertEqual(
            pressure_episode(message),
            {
                "outcome": "interrupted",
                "start_epoch_ms": 100250,
                "start_epoch_us": 100250999,
                "duration_ms": 1250,
                "peak_occupancy": 478,
                "soft_cap": 450,
                "scans": 3,
                "skipped": 7,
                "selected": 28,
                "evicted": 18,
                "spared": 4,
                "canceled": 5,
                "expired": 1,
            },
        )

    def test_fast_burst_uses_event_peak_and_keeps_outcomes_separate(self):
        rows = [
            (
                95,
                "tproxy live-flow counts tcp=20 udp=0 total=20 peak=600 "
                "softCap=450 pressure[triggers=9 scans=1 skipped=0 selected=0 "
                "evicted=9 spared=0 canceled=0 expired=0 pending=0]",
            ),
            (
                110,
                "flow pressure: occupancy 470 over soft cap 450; selected 120 "
                "idle flow(s) toward low-water 350 (120 pending teardown)",
            ),
            (
                115,
                "flow pressure episode ended: startEpochMs=110000 "
                "durationMs=4000 "
                "peakOccupancy=470 softCap=450 scans=1 skipped=0 selected=120 "
                "evicted=120 spared=0 canceled=0 expired=0",
            ),
            (
                160,
                "tproxy live-flow counts tcp=350 udp=0 total=350 peak=600 "
                "softCap=450 pressure[triggers=1 scans=1 skipped=0 selected=120 "
                "evicted=120 spared=0 canceled=0 expired=0 pending=0]",
            ),
        ]
        evidence = summarize_pressure_rows(rows, baseline_end_epoch=100)
        self.assertEqual(evidence["observed_peak"], 470)
        self.assertTrue(evidence["eviction_observed"])
        self.assertEqual(
            evidence["periodic"]["evicted"],
            0,
            "the first post-baseline periodic interval straddles baseline",
        )
        self.assertEqual(evidence["episode"]["evicted"], 120)

    def test_open_episode_periodic_delta_still_proves_eviction(self):
        rows = [
            (
                100,
                "tproxy live-flow counts tcp=20 udp=0 total=20 peak=20 "
                "softCap=450 pressure[triggers=0 scans=0 skipped=0 selected=0 "
                "evicted=0 spared=0 canceled=0 expired=0 pending=0]",
            ),
            (
                120,
                "tproxy live-flow counts tcp=350 udp=0 total=350 peak=350 "
                "softCap=450 pressure[triggers=1 scans=1 skipped=0 selected=2 "
                "evicted=2 spared=0 canceled=0 expired=0 pending=0]",
            )
        ]
        evidence = summarize_pressure_rows(rows, baseline_end_epoch=100)
        self.assertEqual(evidence["observed_peak"], 350)
        self.assertEqual(evidence["episodes"], 0)
        self.assertTrue(evidence["eviction_observed"])

    def test_episode_uses_producer_start_instead_of_derived_duration(self):
        rows = [
            (
                110,
                "flow pressure episode ended: startEpochMs=101000 "
                "durationMs=20000 "
                "peakOccupancy=470 softCap=450 scans=1 skipped=0 selected=20 "
                "evicted=20 spared=0 canceled=0 expired=0",
            )
        ]
        evidence = summarize_pressure_rows(rows, baseline_end_epoch=100)
        self.assertEqual(evidence["episodes"], 1)
        self.assertTrue(evidence["eviction_observed"])

    def test_episode_started_before_subsecond_baseline_is_not_run_evidence(self):
        rows = [
            (
                100.751,
                "flow pressure episode ended: startEpochMs=100500 "
                "durationMs=1 peakOccupancy=470 softCap=450 scans=1 skipped=0 "
                "selected=20 evicted=20 spared=0 canceled=0 expired=0",
            )
        ]
        evidence = summarize_pressure_rows(rows, baseline_end_epoch=100.5005)
        self.assertEqual(evidence["episodes"], 0)
        self.assertFalse(evidence["eviction_observed"])

    def test_precise_episode_boundary_includes_only_post_boundary_start(self):
        def episode(start_us):
            return (
                100.751,
                "flow pressure episode ended: startEpochMs=100500 "
                "durationMs=1 peakOccupancy=470 softCap=450 scans=1 "
                "skipped=0 selected=1 evicted=1 spared=0 canceled=0 "
                f"expired=0 startEpochUs={start_us}",
            )

        before = summarize_pressure_rows(
            [episode(100_500_100)],
            baseline_end_epoch=100.5005,
            baseline_end_epoch_us=100_500_500,
        )
        after = summarize_pressure_rows(
            [episode(100_500_900)],
            baseline_end_epoch=100.5005,
            baseline_end_epoch_us=100_500_500,
        )
        self.assertEqual(before["episodes"], 0)
        self.assertEqual(after["episodes"], 1)
        self.assertTrue(after["eviction_observed"])

    def test_legacy_episode_in_boundary_millisecond_is_conservative(self):
        rows = [
            (
                100.751,
                "flow pressure episode ended: startEpochMs=100500 "
                "durationMs=1 peakOccupancy=470 softCap=450 scans=1 "
                "skipped=0 selected=1 evicted=1 spared=0 canceled=0 "
                "expired=0",
            )
        ]
        evidence = summarize_pressure_rows(
            rows,
            baseline_end_epoch=100.5005,
            baseline_end_epoch_us=100_500_500,
        )
        self.assertEqual(evidence["episodes"], 0)

    def test_settled_final_gauge_requires_two_fresh_tail_samples(self):
        def gauge(epoch, total):
            return (
                epoch,
                f"live-flow counts tcp={total} udp=0 total={total} "
                f"peak={total} softCap=450",
            )

        self.assertIsNone(settled_final_flow_gauge(
            [gauge(90, 10)], 100, 235))
        self.assertIsNone(settled_final_flow_gauge(
            [gauge(120, 10)], 100, 235))
        accepted = settled_final_flow_gauge(
            [gauge(120, 10), gauge(180, 8)], 100, 235)
        self.assertEqual(accepted["total"], 8)
        bounded = settled_final_flow_gauge(
            [gauge(180, 8), gauge(500, 1), gauge(120, 10)], 100, 235)
        self.assertEqual(bounded["total"], 8)
        self.assertIsNone(settled_final_flow_gauge(
            [gauge(500, 1), gauge(501, 0)], 100, 235))
        self.assertIsNone(settled_final_flow_gauge(
            [gauge(180, 8), gauge(180, 7)], 100, 235))
        self.assertIsNone(settled_final_flow_gauge(
            [gauge(105, 10), gauge(120, 8)], 100, 235))
        self.assertIsNone(settled_final_flow_gauge(
            [gauge(100, 0), gauge(100, 0)], 100, 100))

    def test_baseline_occupancy_is_not_run_peak_evidence(self):
        rows = [
            (
                90,
                "tproxy live-flow counts tcp=480 udp=0 total=480 peak=480 "
                "softCap=450 pressure[triggers=1 scans=1 skipped=0 selected=10 "
                "evicted=10 spared=0 canceled=0 expired=0 pending=0]",
            ),
            (
                120,
                "tproxy live-flow counts tcp=25 udp=0 total=25 peak=480 "
                "softCap=450 pressure[triggers=0 scans=0 skipped=0 selected=0 "
                "evicted=0 spared=0 canceled=0 expired=0 pending=0]",
            ),
        ]
        evidence = summarize_pressure_rows(rows, baseline_end_epoch=100)
        self.assertEqual(evidence["observed_peak"], 25)
        self.assertFalse(evidence["eviction_observed"])

    def test_missing_baseline_gauge_does_not_claim_lifecycle_peak(self):
        rows = [
            (
                100.25,
                "tproxy live-flow counts tcp=25 udp=0 total=25 peak=480 "
                "softCap=450 pressure[triggers=0 scans=0 skipped=0 selected=0 "
                "evicted=0 spared=0 canceled=0 expired=0 pending=0]",
            )
        ]
        evidence = summarize_pressure_rows(rows, baseline_end_epoch=100.125)
        self.assertEqual(evidence["observed_peak"], 25)

    def test_first_post_baseline_lifecycle_peak_is_a_floor(self):
        rows = [
            (
                99.75,
                "tproxy live-flow counts tcp=20 udp=0 total=20 peak=100 "
                "softCap=450 pressure[triggers=0 scans=0 skipped=0 selected=0 "
                "evicted=0 spared=0 canceled=0 expired=0 pending=0]",
            ),
            (
                100.25,
                "tproxy live-flow counts tcp=25 udp=0 total=25 peak=480 "
                "softCap=450 pressure[triggers=0 scans=0 skipped=0 selected=0 "
                "evicted=0 spared=0 canceled=0 expired=0 pending=0]",
            ),
            (
                100.75,
                "tproxy live-flow counts tcp=30 udp=0 total=30 peak=500 "
                "softCap=450 pressure[triggers=0 scans=0 skipped=0 selected=0 "
                "evicted=0 spared=0 canceled=0 expired=0 pending=0]",
            ),
        ]
        evidence = summarize_pressure_rows(rows, baseline_end_epoch=100.125)
        self.assertEqual(evidence["observed_peak"], 500)

    def test_periodic_interval_straddling_subsecond_boundary_is_excluded(self):
        def tick(epoch, evicted):
            return (
                epoch,
                "tproxy live-flow counts tcp=25 udp=0 total=25 peak=25 "
                "softCap=450 pressure[triggers=1 scans=1 skipped=0 selected=1 "
                f"evicted={evicted} spared=0 canceled=0 expired=0 pending=0]",
            )

        evidence = summarize_pressure_rows(
            [tick(99.75, 0), tick(100.25, 7), tick(100.75, 3)],
            baseline_end_epoch=100.125,
        )
        self.assertEqual(evidence["periodic_intervals"], 1)
        self.assertEqual(evidence["periodic"]["evicted"], 3)

    def test_complete_soak_evidence_has_no_issues(self):
        meta = {
            "log_stream_started": "1",
            "log_stream_alive_end": "1",
            "baseline_gauge_seen": "1",
            "probe_monitor_alive_end": "1",
            "provider_continuous": "1",
        }
        self.assertEqual(
            soak_evidence_issues(
                meta,
                rows_count=20,
                gauge_count=3,
                probe_count=20,
                phase_coverage=[("stress", 180, 20, 3)],
                final_gauge_present=True,
            ),
            [],
        )

    def test_empty_or_restarted_soak_evidence_is_inconclusive(self):
        issues = soak_evidence_issues(
            {},
            rows_count=0,
            gauge_count=0,
            probe_count=0,
            incomplete_phases=["idle-tail"],
            phase_coverage=[("stress", 180, 0, 0)],
            final_gauge_present=False,
        )
        self.assertIn("provider process identity changed or disappeared", issues)
        self.assertIn("system log contains no parseable rows", issues)
        self.assertIn("phase 'idle-tail' has no end marker", issues)
        self.assertIn("phase 'stress' has no liveness probe coverage", issues)
        self.assertIn("phase 'stress' has no flow-gauge coverage", issues)
        self.assertIn("idle tail has no trustworthy final flow gauge", issues)

    def test_short_phase_does_not_require_periodic_samples(self):
        meta = {
            "log_stream_started": "1",
            "log_stream_alive_end": "1",
            "baseline_gauge_seen": "1",
            "probe_monitor_alive_end": "1",
            "provider_continuous": "1",
        }
        self.assertEqual(
            soak_evidence_issues(
                meta,
                rows_count=2,
                gauge_count=2,
                probe_count=2,
                phase_coverage=[("real-download", 3, 0, 0)],
                final_gauge_required=False,
            ),
            [],
        )


if __name__ == "__main__":
    unittest.main()
