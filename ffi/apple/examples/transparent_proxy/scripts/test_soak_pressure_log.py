#!/usr/bin/env python3
"""Regression tests for the on-device soak pressure-log schema."""

import unittest

from soak_pressure_log import is_no_headroom, pressure_counters, selected_count


class SoakPressureLogTests(unittest.TestCase):
    def test_current_selection_line(self):
        message = (
            "flow pressure: occupancy 460 over soft cap 450; selected 100 "
            "idle flow(s) toward low-water 350 (100 pending teardown)"
        )
        self.assertEqual(selected_count(message), 100)

    def test_current_no_headroom_line(self):
        message = (
            "flow pressure: occupancy 451, soft cap 450, but no flow idle "
            "past 120000ms floor; admitting without reap"
        )
        self.assertTrue(is_no_headroom(message))

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


if __name__ == "__main__":
    unittest.main()
