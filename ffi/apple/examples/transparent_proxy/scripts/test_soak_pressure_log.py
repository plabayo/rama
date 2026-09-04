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
            "flow pressure episode interrupted: durationMs=1250 "
            "peakOccupancy=478 softCap=450 scans=3 skipped=7 selected=28 "
            "evicted=18 spared=4 canceled=5 expired=1"
        )
        self.assertEqual(
            pressure_episode(message),
            {
                "outcome": "interrupted",
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
                "flow pressure episode ended: durationMs=4000 "
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
        self.assertEqual(evidence["periodic"]["evicted"], 120)
        self.assertEqual(evidence["episode"]["evicted"], 120)

    def test_open_episode_periodic_delta_still_proves_eviction(self):
        rows = [
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

    def test_episode_that_started_before_baseline_is_not_run_evidence(self):
        rows = [
            (
                110,
                "flow pressure episode ended: durationMs=20000 "
                "peakOccupancy=470 softCap=450 scans=1 skipped=0 selected=20 "
                "evicted=20 spared=0 canceled=0 expired=0",
            )
        ]
        evidence = summarize_pressure_rows(rows, baseline_end_epoch=100)
        self.assertEqual(evidence["episodes"], 0)
        self.assertFalse(evidence["eviction_observed"])

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


if __name__ == "__main__":
    unittest.main()
