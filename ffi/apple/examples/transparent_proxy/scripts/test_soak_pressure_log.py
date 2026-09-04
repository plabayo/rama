#!/usr/bin/env python3
"""Regression tests for the on-device soak pressure-log schema."""

import os
from pathlib import Path
import json
import re
import socket
import subprocess
import tempfile
import threading
import unittest

from soak_pressure_log import (
    ceiling_configuration_issues,
    ceiling_probe_evidence_issues,
    ceiling_outage_window,
    classify_soak_result,
    engine_lifecycle_event,
    filter_provider_ndjson_records,
    flow_pool_evidence_issues,
    flow_pool_status,
    flow_gauge,
    is_no_headroom,
    leak_evidence,
    lifecycle_category_issue,
    no_headroom_event,
    parse_epoch,
    parse_evidence_status_lines,
    parse_ceiling_probe_lines,
    parse_leaks_output,
    parse_ndjson_lines,
    parse_oslog_timestamp,
    parse_phase_marker_lines,
    parse_probe_lines,
    phase_for_epoch,
    pressure_counters,
    pressure_episode,
    pressure_reaper_status,
    probe_succeeded,
    selected_count,
    selection_event,
    sleep_wake_evidence,
    settled_final_flow_gauge,
    soak_evidence_issues,
    summarize_pressure_rows,
    unexpected_probe_failure_count,
)


class SoakPressureLogTests(unittest.TestCase):
    @staticmethod
    def complete_meta(mode="stress-only"):
        return {
            "log_stream_started": "1",
            "log_stream_alive_end": "1",
            "baseline_gauge_seen": "1",
            "probe_monitor_alive_end": "1",
            "provider_continuous": "1",
            "mode": mode,
            "download_host_preflight_ok": "1",
            "stress_ok": "1",
            "fanout_ok": "1",
            "idle_holders_ok": "1",
            "real_download_ok": "1",
            "post_wake_ok": "skipped",
            "sleep_command_ok": "skipped",
        }

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
            "softCap=450 hardCap=0 pressure[triggers=12 scans=2 skipped=10 "
            "selected=100 evicted=96 spared=2 canceled=1 expired=1 pending=0]"
        )
        self.assertEqual(
            flow_gauge(message),
            {
                "tcp": 351,
                "udp": 0,
                "total": 351,
                "peak": 460,
                "soft_cap": 450,
                "hard_cap": 0,
            },
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

    def test_legacy_gauge_exposes_missing_hard_cap(self):
        gauge = flow_gauge(
            "live-flow counts tcp=1 udp=2 total=3 peak=4 softCap=5"
        )
        self.assertIsNotNone(gauge)
        self.assertIsNone(gauge["hard_cap"])

    def test_ceiling_search_requires_both_caps_to_be_observed_and_disabled(self):
        self.assertEqual(ceiling_configuration_issues(0, 0), [])
        self.assertEqual(
            ceiling_configuration_issues(None, 500),
            [
                "flow-pressure soft cap was not observed",
                "live-flow hard cap is enabled (500)",
            ],
        )
        self.assertEqual(
            ceiling_configuration_issues(450, None),
            [
                "flow-pressure soft cap is enabled (450)",
                "live-flow hard cap was not observed",
            ],
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

    def test_reaper_good_requires_an_attributable_post_boundary_episode(self):
        delayed_pre_baseline = [
            (
                99,
                "live-flow counts tcp=20 udp=0 total=20 peak=480 softCap=450 "
                "pressure[triggers=0 scans=0 skipped=0 selected=0 evicted=0 "
                "spared=0 canceled=0 expired=0 pending=0]",
            ),
            (
                120,
                "live-flow counts tcp=20 udp=0 total=20 peak=480 softCap=450 "
                "pressure[triggers=0 scans=0 skipped=0 selected=0 evicted=0 "
                "spared=0 canceled=0 expired=0 pending=0]",
            ),
            (
                180,
                "live-flow counts tcp=20 udp=0 total=20 peak=480 softCap=450 "
                "pressure[triggers=1 scans=1 skipped=0 selected=1 evicted=1 "
                "spared=0 canceled=0 expired=0 pending=0]",
            ),
        ]
        pressure = summarize_pressure_rows(
            delayed_pre_baseline, baseline_end_epoch=100
        )
        self.assertTrue(pressure["eviction_observed"])
        self.assertEqual(pressure["validated_eviction_episodes"], 0)
        self.assertEqual(
            pressure_reaper_status(pressure, 450, True), "not-observed"
        )

        attributable = summarize_pressure_rows(
            [
                (
                    101,
                    "flow pressure episode ended: startEpochMs=100500 "
                    "durationMs=500 peakOccupancy=470 softCap=450 scans=1 "
                    "skipped=0 selected=20 evicted=20 spared=0 canceled=0 "
                    "expired=0 startEpochUs=100500501",
                )
            ],
            baseline_end_epoch=100.5005,
            baseline_end_epoch_us=100_500_500,
        )
        self.assertEqual(attributable["validated_eviction_episodes"], 1)
        self.assertEqual(
            pressure_reaper_status(attributable, 450, True), "good"
        )

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

    def test_final_gauge_excludes_the_exact_phase_end(self):
        def gauge(epoch, total):
            return (
                epoch,
                f"live-flow counts tcp={total} udp=0 total={total} "
                f"peak={total} softCap=450 hardCap=0",
            )

        self.assertIsNone(
            settled_final_flow_gauge(
                [gauge(120, 10), gauge(235, 0)], 100, 235
            )
        )

    def test_phase_attribution_is_microsecond_precise_and_half_open(self):
        phases = [
            (
                "stress",
                parse_epoch("100.100000"),
                parse_epoch("101.100000"),
            )
        ]
        self.assertEqual(phase_for_epoch(parse_epoch("100.099999"), phases), "-")
        self.assertEqual(
            phase_for_epoch(parse_epoch("100.100000"), phases), "stress"
        )
        self.assertEqual(
            phase_for_epoch(parse_epoch("101.099999"), phases), "stress"
        )
        self.assertEqual(phase_for_epoch(parse_epoch("101.100000"), phases), "-")

    def test_every_malformed_ndjson_record_is_incomplete(self):
        decoded, issues = parse_ndjson_lines(
            ['{"eventMessage":"a"}\n', '{broken}\n', '{"eventMessage":"b"}\n']
        )
        self.assertEqual([row["eventMessage"] for row in decoded], ["a", "b"])
        self.assertEqual(
            issues, ["malformed NDJSON record at line 2"]
        )

        decoded, issues = parse_ndjson_lines(
            ['{"eventMessage":"a"}\n', '{"eventMessage":']
        )
        self.assertEqual([row["eventMessage"] for row in decoded], ["a"])
        self.assertEqual(issues, ["malformed NDJSON record at line 2"])

    def test_oslog_timestamp_requires_a_complete_known_format(self):
        self.assertEqual(
            parse_oslog_timestamp("1970-01-01 00:01:40.000001+0000"),
            parse_epoch("100.000001"),
        )
        self.assertEqual(
            parse_oslog_timestamp("1970-01-01 01:01:40+0100"),
            parse_epoch("100.000000"),
        )
        self.assertIsNone(parse_oslog_timestamp("1970-01-01 00:01:40garbage"))
        self.assertIsNone(
            parse_oslog_timestamp("1970-01-01 00:01:40-0700-malformed")
        )
        self.assertIsNone(parse_oslog_timestamp("1970-01-01 00:01:40"))

    def test_provider_records_require_numeric_matching_pid_and_subsystem(self):
        valid = {
            "processID": 10,
            "subsystem": "org.example.provider",
            "eventMessage": "gauge",
        }
        accepted, issues = filter_provider_ndjson_records(
            [
                valid,
                {**valid, "processID": "10"},
                {**valid, "processID": 11},
                {**valid, "subsystem": "org.example.host"},
            ],
            10,
            "org.example.provider",
        )
        self.assertEqual(accepted, [valid])
        self.assertEqual(
            issues,
            [
                "1 NDJSON record(s) have no numeric processID",
                "1 NDJSON record(s) came from a different processID",
                "1 NDJSON record(s) came from a different subsystem",
            ],
        )

    def test_phase_markers_must_be_monotonic_and_nonoverlapping(self):
        phases, incomplete, _, _, issues = parse_phase_marker_lines(
            [
                "baseline\tstart\t100\tx\n",
                "stress\tstart\t101\tx\n",
                "baseline\tend\t102\tx\n",
                "stress\tend\t103\tx\n",
            ],
            ["baseline", "stress"],
        )
        self.assertEqual(incomplete, set())
        self.assertEqual([phase[0] for phase in phases], ["baseline", "stress"])
        self.assertTrue(any("started before" in issue for issue in issues))
        self.assertTrue(any("overlaps" in issue for issue in issues))

        _, _, _, _, reversed_issues = parse_phase_marker_lines(
            [
                "stress\tstart\t100\tx\n",
                "stress\tend\t101\tx\n",
                "baseline\tstart\t101\tx\n",
                "baseline\tend\t102\tx\n",
            ],
            ["baseline", "stress"],
        )
        self.assertTrue(any("out of order" in issue for issue in reversed_issues))

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
        start = parse_epoch("100")
        end = parse_epoch("280")
        self.assertEqual(
            soak_evidence_issues(
                self.complete_meta(),
                rows_count=20,
                gauge_count=3,
                probe_count=20,
                phase_coverage=[
                    (
                        "stress",
                        start,
                        end,
                        [parse_epoch(str(value)) for value in range(110, 280, 10)],
                        [parse_epoch("160"), parse_epoch("220")],
                    )
                ],
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
            phase_coverage=[
                ("stress", parse_epoch("0"), parse_epoch("180"), [], [])
            ],
            final_gauge_present=False,
        )
        self.assertIn("provider process identity changed or disappeared", issues)
        self.assertIn("system log contains no parseable rows", issues)
        self.assertIn("phase 'idle-tail' has no end marker", issues)
        self.assertIn("phase 'stress' has no liveness probe coverage", issues)
        self.assertIn("phase 'stress' has no flow-gauge coverage", issues)
        self.assertIn("idle tail has no trustworthy final flow gauge", issues)

    def test_short_phase_does_not_require_periodic_samples(self):
        self.assertEqual(
            soak_evidence_issues(
                self.complete_meta(),
                rows_count=2,
                gauge_count=2,
                probe_count=2,
                phase_coverage=[
                    (
                        "real-download",
                        parse_epoch("10"),
                        parse_epoch("13"),
                        [],
                        [],
                    )
                ],
                final_gauge_required=False,
            ),
            [],
        )

    def test_phase_coverage_rejects_large_interior_and_edge_gaps(self):
        issues = soak_evidence_issues(
            self.complete_meta(),
            rows_count=20,
            gauge_count=3,
            probe_count=20,
            phase_coverage=[
                (
                    "stress",
                    parse_epoch("100"),
                    parse_epoch("280"),
                    [parse_epoch("110"), parse_epoch("275")],
                    [parse_epoch("105"), parse_epoch("270")],
                )
            ],
            final_gauge_present=True,
        )
        self.assertIn(
            "phase 'stress' has a liveness probe gap of 165.000s (maximum 20s)",
            issues,
        )
        self.assertIn(
            "phase 'stress' has a flow-gauge gap of 165.000s (maximum 70s)",
            issues,
        )

    def test_required_phase_cannot_vanish_without_making_evidence_incomplete(self):
        issues = soak_evidence_issues(
            self.complete_meta("find-ceiling"),
            rows_count=20,
            gauge_count=3,
            probe_count=20,
            phase_coverage=[],
            required_phases={"baseline", "ceiling"},
            final_gauge_required=False,
        )
        self.assertIn("phase 'baseline' has no complete marker pair", issues)
        self.assertIn("phase 'ceiling' has no complete marker pair", issues)

    def test_result_classification_separates_incomplete_from_failed(self):
        passed = classify_soak_result(
            self.complete_meta(),
            [],
            probe_failures=0,
            body_errors=0,
            reaper_status="disabled",
        )
        self.assertTrue(passed["complete"])
        self.assertTrue(passed["passed"])
        self.assertEqual(passed["exit_code"], 0)

        failed = classify_soak_result(
            self.complete_meta(),
            [],
            probe_failures=2,
            body_errors=0,
            reaper_status="disabled",
        )
        self.assertTrue(failed["complete"])
        self.assertFalse(failed["passed"])
        self.assertEqual(failed["exit_code"], 1)

        workload_meta = self.complete_meta()
        workload_meta["stress_ok"] = "0"
        workload_failed = classify_soak_result(
            workload_meta,
            [],
            probe_failures=0,
            body_errors=0,
            reaper_status="disabled",
        )
        self.assertTrue(workload_failed["complete"])
        self.assertEqual(workload_failed["exit_code"], 1)
        self.assertIn("stress workload failed", workload_failed["failures"])

        incomplete = classify_soak_result(
            self.complete_meta(),
            ["malformed interior NDJSON record at line 2"],
            probe_failures=2,
            body_errors=0,
            reaper_status="inconclusive",
        )
        self.assertFalse(incomplete["complete"])
        self.assertFalse(incomplete["passed"])
        self.assertEqual(incomplete["exit_code"], 2)

        incomplete_cap = classify_soak_result(
            self.complete_meta("cap-validate"),
            ["log stream did not cover the complete run"],
            probe_failures=0,
            body_errors=0,
            reaper_status="inconclusive",
        )
        self.assertEqual(incomplete_cap["exit_code"], 2)
        self.assertEqual(
            incomplete_cap["failures"], [],
            "missing evidence must not be relabeled as a product failure",
        )

    def test_cap_validation_and_ceiling_outcomes_are_failures_not_gaps(self):
        cap_meta = self.complete_meta("cap-validate")
        not_crossed = classify_soak_result(
            cap_meta,
            [],
            probe_failures=0,
            body_errors=0,
            reaper_status="not-observed",
        )
        self.assertTrue(not_crossed["complete"])
        self.assertEqual(not_crossed["exit_code"], 1)

        hard_limited = classify_soak_result(
            self.complete_meta("cap-hard-limited"),
            [],
            probe_failures=0,
            body_errors=0,
            reaper_status="not-observed",
        )
        self.assertTrue(hard_limited["complete"])
        self.assertEqual(hard_limited["exit_code"], 1)
        self.assertIn(
            "live-flow hard cap prevents pressure-cap validation",
            hard_limited["failures"],
        )

        ceiling_meta = self.complete_meta("find-ceiling")
        ceiling_meta.update(ceiling_found="0", ceiling_recovered="1")
        no_ceiling = classify_soak_result(
            ceiling_meta,
            [],
            probe_failures=0,
            body_errors=0,
            reaper_status="disabled",
        )
        self.assertTrue(no_ceiling["complete"])
        self.assertEqual(no_ceiling["exit_code"], 1)

        ceiling_meta["ceiling_found"] = "1"
        found = classify_soak_result(
            ceiling_meta,
            [],
            probe_failures=0,
            body_errors=0,
            reaper_status="disabled",
        )
        self.assertTrue(found["passed"])
        self.assertEqual(found["exit_code"], 0)

        del ceiling_meta["ceiling_recovered"]
        missing = classify_soak_result(
            ceiling_meta,
            [],
            probe_failures=0,
            body_errors=0,
            reaper_status="disabled",
        )
        self.assertFalse(missing["complete"])
        self.assertEqual(missing["exit_code"], 2)

    def test_reaper_good_is_cap_matched_and_requires_an_ended_episode(self):
        def episode(outcome, cap):
            return (
                parse_epoch("101.000001"),
                f"flow pressure episode {outcome}: startEpochMs=100501 "
                f"durationMs=10 peakOccupancy=520 softCap={cap} scans=1 "
                "skipped=0 selected=1 evicted=1 spared=0 canceled=0 expired=0 "
                "startEpochUs=100501000",
            )

        mismatched = summarize_pressure_rows(
            [episode("ended", 450)],
            baseline_end_epoch=parse_epoch("100.500500"),
            baseline_end_epoch_us=100_500_500,
        )
        self.assertEqual(
            pressure_reaper_status(mismatched, 500, True),
            "crossed-without-attributable-eviction",
        )
        interrupted = summarize_pressure_rows(
            [episode("interrupted", 500)],
            baseline_end_epoch=parse_epoch("100.500500"),
            baseline_end_epoch_us=100_500_500,
        )
        self.assertEqual(interrupted["validated_eviction_episodes"], 0)
        self.assertEqual(
            pressure_reaper_status(interrupted, 500, True),
            "crossed-without-attributable-eviction",
        )

    def test_same_pid_engine_lifecycle_messages_change_generation(self):
        self.assertEqual(engine_lifecycle_event("extension startProxy requested"), "startProxy")
        self.assertEqual(engine_lifecycle_event("proxy engine detached cleanly"), "engine detached")
        self.assertIsNone(engine_lifecycle_event("periodic live-flow counts"))
        self.assertEqual(
            lifecycle_category_issue("system wake", "tproxy"),
            "lifecycle evidence used non-lifecycle category 'tproxy'",
        )
        self.assertIsNone(lifecycle_category_issue("system wake", "lifecycle"))
        self.assertIsNone(
            lifecycle_category_issue(
                "established egress path not satisfied after system wake", "tproxy"
            )
        )

    def test_flow_pool_requires_bracketed_provider_rise_and_post_kill_fall(self):
        phase = ("fanout", parse_epoch("100"), parse_epoch("200"))
        gauges = [
            (parse_epoch("105"), 5),
            (parse_epoch("115"), 105),
            (parse_epoch("140"), 5),
        ]
        bracket = ("105", 5, "115", 105, "140", 5, 100)
        self.assertEqual(
            flow_pool_status(
                "1", 100, gauges, gauges, 0, 0,
                [("110", "120")], phase, bracket
            ),
            "1",
        )
        cap_gauges = [
            (parse_epoch("105"), 5),
            (parse_epoch("115"), 80),
            (parse_epoch("140"), 5),
        ]
        self.assertEqual(
            flow_pool_status(
                "1",
                100,
                cap_gauges,
                cap_gauges,
                80,
                0,
                [("110", "120")],
                phase,
                ("105", 5, "115", 80, "140", 5, 75),
            ),
            "1",
            "cap validation documents only the aggregate delta needed to reach softCap",
        )
        self.assertIsNone(
            flow_pool_status(
                "1", 100,
                [(parse_epoch("105"), 5), (parse_epoch("115"), 55),
                 (parse_epoch("140"), 5)],
                [(parse_epoch("105"), 5), (parse_epoch("115"), 55),
                 (parse_epoch("140"), 5)],
                80, 0, [("110", "120")], phase,
                ("105", 5, "115", 55, "140", 5, 75),
            ),
            "a smaller provider delta cannot satisfy the documented threshold",
        )
        self.assertIsNone(
            flow_pool_status(
                "1", 100, gauges[:-1], gauges[:-1], 0, 0,
                [("110", "120")], phase, bracket
            ),
            "missing post-kill provider evidence is inconclusive",
        )
        self.assertIsNone(
            flow_pool_status(
                "1", 100, gauges, gauges, 0, 0, [("110", "120")], phase,
                ("105", 5, "115", 105, "140", 20, 100),
            ),
            "the post-kill fall must account for the full target",
        )
        self.assertEqual(
            flow_pool_status("0", 100, gauges, gauges, 0, 0, [], phase, bracket),
            "0",
            "missing establishment is a workload failure",
        )
        self.assertIsNone(
            flow_pool_status("0", 100, gauges, gauges, 0, 0, [], phase, None),
            "missing bracket evidence remains incomplete when establishment failed",
        )
        self.assertEqual(
            flow_pool_status("skipped", None, [], [], 0, 0, [], None, None),
            "skipped",
        )
        later_gauges = [
            (parse_epoch("105"), 5),
            (parse_epoch("135"), 105),
            (parse_epoch("150"), 5),
        ]
        self.assertEqual(
            flow_pool_status(
                "1", 100, later_gauges, later_gauges, 0, 0,
                [("110", "120"), ("130", "140")], phase,
                ("105", 5, "135", 105, "150", 5, 100),
            ),
            "1",
            "a later correlated sustained interval can replace an earlier miss",
        )
        hard_cap_gauges = [
            (parse_epoch("105"), 5),
            (parse_epoch("115"), 80),
            (parse_epoch("140"), 5),
        ]
        self.assertEqual(
            flow_pool_status(
                "1", 100, hard_cap_gauges, hard_cap_gauges, 0, 80,
                [("110", "120")], phase,
                ("105", 5, "115", 80, "140", 5, 75),
            ),
            "1",
            "with softCap disabled, an enabled hardCap bounds the attributable delta",
        )
        self.assertIsNone(
            flow_pool_status(
                "1", 100, cap_gauges, cap_gauges, 80, 0,
                [("110", "120")], phase,
                ("105", 5, "115", 80, "140", 5, 100),
            ),
            "the persisted delta must equal the value recomputed from caps and baseline",
        )
        self.assertIsNone(
            flow_pool_status(
                "1", 100, cap_gauges, cap_gauges, 80, 60,
                [("110", "120")], phase,
                ("105", 5, "115", 80, "140", 5, 55),
            ),
            "a hard cap below softCap cannot prove cap-validation occupancy",
        )
        self.assertIsNone(
            flow_pool_status(
                "1", 100, gauges, [(parse_epoch("115"), 105)], 0, 0,
                [("110", "120")], phase, bracket,
            ),
            "generic occupancy events cannot stand in for baseline/post gauges",
        )
        self.assertEqual(
            flow_pool_evidence_issues("fanout", "0", "0", False),
            ["fanout has no provider flow-pool bracket"],
            "failed establishment and missing evidence remain orthogonal",
        )
        self.assertEqual(
            flow_pool_evidence_issues("fanout", "0", "0", True), []
        )

    def test_sleep_wake_requires_ordered_command_local_events_and_recovery(self):
        skipped = sleep_wake_evidence(
            "skipped", "skipped", None, None, [], [], [], None
        )
        self.assertEqual(skipped, {"issues": [], "outage_window": None})

        recovered = sleep_wake_evidence(
            "1", "1", "100", "151", ["110"], ["150"],
            [(parse_epoch("151.1"), parse_epoch("152"), 0, "200")],
            ("sleep-wake", parse_epoch("90"), parse_epoch("160")),
        )
        self.assertEqual(recovered["issues"], [])
        self.assertEqual(
            recovered["outage_window"],
            (parse_epoch("110"), parse_epoch("150")),
            "only the actual asleep interval is waived",
        )

        reversed_events = sleep_wake_evidence(
            "1", "1", "100", "151", ["110"], ["105"],
            [(parse_epoch("151"), parse_epoch("152"), 0, "200")],
            ("sleep-wake", parse_epoch("90"), parse_epoch("160")),
        )
        self.assertTrue(any("ordered" in issue for issue in reversed_events["issues"]))

        later_cycle = sleep_wake_evidence(
            "1", "1", "100", "151", ["170"], ["180"],
            [(parse_epoch("181"), parse_epoch("182"), 0, "200")],
            ("sleep-wake", parse_epoch("90"), parse_epoch("160")),
        )
        self.assertTrue(any("ordered" in issue for issue in later_cycle["issues"]))

        truncated_200 = sleep_wake_evidence(
            "1", "1", "100", "151", ["110"], ["150"],
            [(parse_epoch("151"), parse_epoch("152"), 18, "200")],
            ("sleep-wake", parse_epoch("90"), parse_epoch("160")),
        )
        self.assertTrue(
            any("successful paired probe" in issue for issue in truncated_200["issues"])
        )

        failed_command = sleep_wake_evidence(
            "0", "1", "100", "101", [], [],
            [(parse_epoch("102"), parse_epoch("103"), 0, "200")],
            ("sleep-wake", parse_epoch("90"), parse_epoch("110")),
        )
        self.assertEqual(failed_command["issues"], [])
        self.assertIsNone(failed_command["outage_window"])

    def test_ceiling_proof_is_microsecond_precise_half_open_and_consecutive(self):
        records, issues = parse_ceiling_probe_lines(
            [
                "100.090000\t100.099999\t28\t000\t510\t100.089999\n",
                "100.100000\t100.100010\t18\t200\t510\t100.100000\n",
                "100.100011\t100.100020\t28\t000\t511\t100.100010\n",
                "100.500000\t100.500010\t0\t200\t511\t100.400000\n",
                "101.099999\t101.100000\t28\t000\t512\t101.099999\n",
            ]
        )
        self.assertEqual(issues, [])
        phase = ("ceiling", parse_epoch("100.100000"), parse_epoch("101.100000"))
        self.assertEqual(
            ceiling_probe_evidence_issues(records, "1", 500, phase, "1"), []
        )
        self.assertNotEqual(
            ceiling_probe_evidence_issues(records[:2], "1", 500, phase), []
        )
        low = [
            (parse_epoch("100.2"), parse_epoch("100.21"), 28, "000", 500,
             parse_epoch("100.2")),
            (parse_epoch("100.3"), parse_epoch("100.31"), 28, "000", 501,
             parse_epoch("100.3")),
        ]
        self.assertNotEqual(ceiling_probe_evidence_issues(low, "1", 500, phase), [])
        stale = [
            (parse_epoch("100.2"), parse_epoch("100.21"), 28, "000", 510,
             parse_epoch("99.9")),
            (parse_epoch("100.3"), parse_epoch("100.31"), 28, "000", 511,
             parse_epoch("99.9")),
        ]
        self.assertNotEqual(ceiling_probe_evidence_issues(stale, "1", 500, phase), [])
        window = ceiling_outage_window(records, 500, phase)
        self.assertEqual(
            window, (parse_epoch("100.100010"), parse_epoch("100.500010"))
        )
        failures = [
            parse_epoch("100.100009"),
            parse_epoch("100.100010"),
            parse_epoch("100.500009"),
            parse_epoch("100.500010"),
        ]
        self.assertEqual(
            unexpected_probe_failure_count(failures, window),
            2,
            "failures before proof and at/after direct recovery stay reportable",
        )

    def test_paired_probe_requires_ordered_timing_rc_and_status(self):
        records, issues = parse_probe_lines(
            [
                "100.000000\t100.100000\tiso\t0\t200\n",
                "101.000000\t101.100000\tiso\t18\t200\n",
            ]
        )
        self.assertEqual(issues, [])
        self.assertTrue(probe_succeeded(records[0]))
        self.assertFalse(probe_succeeded(records[1]))

        _, malformed = parse_probe_lines(
            ["102\t101\tiso\t0\t200\n", "100\t101\tiso\tnan\t200\n"]
        )
        self.assertEqual(len(malformed), 2)

    def test_leaks_output_requires_one_parseable_summary(self):
        self.assertEqual(
            parse_leaks_output("Process 42: 0 leaks for 0 total leaked bytes."),
            {"leaks": 0, "bytes": 0},
        )
        self.assertEqual(
            parse_leaks_output(
                "Process 42: 1,234 leaks for 56,789 total leaked bytes."
            ),
            {"leaks": 1234, "bytes": 56789},
        )
        self.assertIsNone(parse_leaks_output("leaks could not examine process"))
        self.assertIsNone(
            parse_leaks_output(
                "0 leaks for 0 total leaked bytes\n1 leak for 8 total leaked bytes"
            )
        )

        self.assertEqual(
            leak_evidence(0, "Process 42: 0 leaks for 0 total leaked bytes."),
            {"issues": [], "leaks": 0, "bytes": 0},
        )
        self.assertEqual(
            leak_evidence(1, "Process 42: 2 leaks for 64 total leaked bytes."),
            {"issues": [], "leaks": 2, "bytes": 64},
        )
        self.assertTrue(
            leak_evidence(0, "Process 42: 2 leaks for 64 total leaked bytes.")[
                "issues"
            ]
        )
        self.assertTrue(
            leak_evidence(1, "Process 42: 0 leaks for 0 total leaked bytes.")[
                "issues"
            ]
        )
        self.assertIn(
            "leaks output has inconsistent allocation and byte totals",
            leak_evidence(0, "Process 42: 0 leaks for 64 total leaked bytes.")[
                "issues"
            ],
        )
        self.assertIn(
            "leaks command failed with exit 2",
            leak_evidence(2, "fatal error")["issues"],
        )
        self.assertIn(
            "leaks output is missing or unparseable",
            leak_evidence(0, "not a report")["issues"],
        )

        result = classify_soak_result(
            self.complete_meta(),
            [],
            probe_failures=0,
            body_errors=0,
            reaper_status="good",
            leak_count=2,
        )
        self.assertTrue(result["complete"])
        self.assertEqual(result["exit_code"], 1)
        self.assertIn("leaks reported 2 leaked allocation(s)", result["failures"])

    def test_evidence_status_requires_last_sentinel_and_consistent_tuple(self):
        self.assertEqual(
            parse_evidence_status_lines(
                ["complete\t1\n", "passed\t1\n", "exit_code\t0\n", "schema_complete\t1\n"]
            ),
            0,
        )
        self.assertEqual(
            parse_evidence_status_lines(
                ["complete\t1\n", "passed\t0\n", "exit_code\t1\n", "schema_complete\t1\n"]
            ),
            1,
        )
        self.assertEqual(
            parse_evidence_status_lines(
                ["complete\t0\n", "passed\t0\n", "exit_code\t2\n", "schema_complete\t1\n"]
            ),
            2,
        )
        self.assertIsNone(parse_evidence_status_lines(["complete\t1\n", "passed\t1\n"]))
        self.assertIsNone(
            parse_evidence_status_lines(
                ["complete\t0\n", "passed\t1\n", "exit_code\t0\n", "schema_complete\t1\n"]
            )
        )
        self.assertIsNone(
            parse_evidence_status_lines(
                [
                    "complete\t1\n", "passed\t1\n", "exit_code\t0\n",
                    "unknown\tvalue\n", "schema_complete\t1\n",
                ]
            )
        )

    def test_invalid_timestamp_samples_are_capture_issues_not_coverage(self):
        issues = soak_evidence_issues(
            self.complete_meta(),
            rows_count=2,
            gauge_count=0,
            probe_count=0,
            capture_issues=[
                "2 NDJSON record(s) have invalid timestamps",
                "invalid liveness-probe timestamp at line 1",
            ],
            final_gauge_required=False,
        )
        self.assertIn("fewer than two flow-gauge samples were captured", issues)
        self.assertIn("fewer than two non-sleep liveness probes were captured", issues)
        self.assertIn("2 NDJSON record(s) have invalid timestamps", issues)

    def test_stress_refused_targets_exit_nonzero_without_negative_counts(self):
        script = Path(__file__).with_name("stress_traffic.sh")
        with tempfile.TemporaryDirectory() as log_dir:
            env = os.environ.copy()
            env.update(
                STRESS_DURATION="1",
                STRESS_CONCURRENCY="1",
                STRESS_POST_BYTES="1024",
                STRESS_SKIP_LIVENESS="1",
                STRESS_LOG_DIR=log_dir,
                STRESS_HTTP_TARGET="http://127.0.0.1:1",
                STRESS_HTTPS_TARGET="http://127.0.0.1:1",
                STRESS_LARGE_TARGET="http://127.0.0.1:1",
                STRESS_POST_TARGET="http://127.0.0.1:1",
            )
            result = subprocess.run(
                ["bash", str(script)],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=30,
            )
            self.assertNotEqual(result.returncode, 0, result.stdout)
            summaries = list(Path(log_dir).glob("*.summary"))
            self.assertEqual(len(summaries), 8, result.stdout)
            for summary in summaries:
                text = summary.read_text()
                match = re.search(r"iters=(\d+) ok=(\d+) fail=(\d+)", text)
                self.assertIsNotNone(match, text)
                iterations, ok, failed = map(int, match.groups())
                self.assertEqual(iterations, ok + failed)
                self.assertGreater(failed, 0)

    def test_stress_truncated_http_200_body_is_a_failed_transfer(self):
        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen()
        server.settimeout(0.1)
        port = server.getsockname()[1]
        stopped = threading.Event()

        def serve_truncated_responses():
            while not stopped.is_set():
                try:
                    connection, _ = server.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                with connection:
                    try:
                        connection.recv(65536)
                        connection.sendall(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n"
                            b"Connection: close\r\n\r\nx"
                        )
                    except OSError:
                        pass

        thread = threading.Thread(target=serve_truncated_responses, daemon=True)
        thread.start()
        script = Path(__file__).with_name("stress_traffic.sh")
        try:
            with tempfile.TemporaryDirectory() as log_dir:
                env = os.environ.copy()
                target = f"http://127.0.0.1:{port}/truncated"
                env.update(
                    STRESS_DURATION="1",
                    STRESS_CONCURRENCY="1",
                    STRESS_POST_BYTES="1",
                    STRESS_SKIP_LIVENESS="1",
                    STRESS_LOG_DIR=log_dir,
                    STRESS_HTTP_TARGET=target,
                    STRESS_HTTPS_TARGET=target,
                    STRESS_LARGE_TARGET=target,
                    STRESS_POST_TARGET=target,
                )
                result = subprocess.run(
                    ["bash", str(script)],
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=30,
                )
                self.assertEqual(result.returncode, 1, result.stdout)
                large_summary = Path(log_dir, "large_get.summary").read_text()
                self.assertRegex(large_summary, r"fail=[1-9][0-9]*")
                pool_summary = Path(log_dir, "parallel_pool.summary").read_text()
                self.assertRegex(pool_summary, r"fail=[1-9][0-9]*")
                self.assertRegex(
                    Path(log_dir, "large_get.log").read_text(),
                    r"200 curl_exit=[1-9][0-9]*",
                )
        finally:
            stopped.set()
            server.close()
            thread.join(timeout=2)

    def test_stress_rejects_zero_concurrency_before_starting_workers(self):
        script = Path(__file__).with_name("stress_traffic.sh")
        env = os.environ.copy()
        env.update(STRESS_DURATION="0", STRESS_CONCURRENCY="0")
        result = subprocess.run(
            ["bash", str(script)],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=5,
        )
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn("CONCURRENCY must be greater than zero", result.stdout)

    def test_embedded_extractor_wires_provider_ceiling_and_leak_verdicts(self):
        script_dir = Path(__file__).parent
        shell = (script_dir / "soak_test.sh").read_text()
        marker = "<<'PYEOF'\n"
        extractor = shell.split(marker, 1)[1].split("\nPYEOF", 1)[0]
        gauge = (
            "live-flow counts tcp=0 udp=0 total=0 peak=0 softCap=0 hardCap=0 "
            "pressure[triggers=0 scans=0 skipped=0 selected=0 evicted=0 "
            "spared=0 canceled=0 expired=0 pending=0]"
        )
        with tempfile.TemporaryDirectory() as artifact_dir:
            out = Path(artifact_dir)
            def write_meta(leaks_rc, provider_end_pid=10):
                (out / "run-meta.tsv").write_text(
                    "log_stream_started\t1\n"
                    "log_stream_alive_end\t1\n"
                    "baseline_gauge_seen\t1\n"
                    "probe_monitor_alive_end\t1\n"
                    "provider_continuous\t1\n"
                    "provider_start_pid\t10\nprovider_start_time\tstart\n"
                    f"provider_end_pid\t{provider_end_pid}\nprovider_end_time\tstart\n"
                    "provider_bundle\torg.example.provider\n"
                    "log_stream_pid\t20\nprobe_monitor_pid\t30\n"
                    f"leaks_command_rc\t{leaks_rc}\n"
                    "mode\tfind-ceiling\n"
                    "softcap\t0\nhardcap\t0\nbaseline_total\t0\n"
                    "ceiling_found\t1\nceiling_recovered\t1\n"
                    "ceiling_outage_start\t101.110000\n"
                    "ceiling_outage_end\t101.410000\n"
                )

            write_meta(0)
            (out / "phases.tsv").write_text(
                "baseline\tstart\t100.000000\tx\n"
                "baseline\tend\t101.000000\tx\n"
                "ceiling\tstart\t101.000000\tx\n"
                "ceiling\tend\t102.000000\tx\n"
            )
            rows = [
                {
                    "timestamp": "1970-01-01 00:01:40.200000+0000",
                    "processID": 10,
                    "subsystem": "org.example.provider",
                    "category": "tproxy",
                    "eventMessage": gauge,
                    "messageType": "Debug",
                },
                {
                    "timestamp": "1970-01-01 00:01:41.050000+0000",
                    "processID": 10,
                    "subsystem": "org.example.provider",
                    "category": "tproxy",
                    "eventMessage": gauge,
                    "messageType": "Debug",
                },
            ]
            (out / "system.ndjson").write_text(
                "".join(json.dumps(row) + "\n" for row in rows)
            )
            (out / "probe-timeline.txt").write_text(
                "100.200000\t100.300000\tx\t0\t200\n"
                "101.200000\t101.300000\tx\t0\t200\n"
            )
            (out / "ceiling-probes.tsv").write_text(
                "101.100000\t101.110000\t28\t000\t1\t101.050000\n"
                "101.200000\t101.210000\t28\t000\t1\t101.050000\n"
                "101.400000\t101.410000\t0\t200\t0\t101.050000\n"
            )
            (out / "leaks.txt").write_text(
                "Process 10: 0 leaks for 0 total leaked bytes.\n"
            )

            def run_extractor():
                result = subprocess.run(
                    ["python3", "-c", extractor, str(out), str(script_dir)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(result.returncode, 0, result.stdout)
                status = (out / "evidence-status.tsv").read_text().splitlines(True)
                return parse_evidence_status_lines(status), result.stdout

            status, output = run_extractor()
            self.assertEqual(status, 0, output)

            write_meta(1)
            (out / "leaks.txt").write_text(
                "Process 10: 2 leaks for 64 total leaked bytes.\n"
            )
            status, output = run_extractor()
            self.assertEqual(status, 1, output)

            write_meta(2)
            (out / "leaks.txt").write_text("leaks could not inspect process\n")
            status, output = run_extractor()
            self.assertEqual(status, 2, output)

            write_meta(0)
            (out / "leaks.txt").write_text(
                "Process 10: 0 leaks for 0 total leaked bytes.\n"
            )
            rows[1]["processID"] = 999
            (out / "system.ndjson").write_text(
                "".join(json.dumps(row) + "\n" for row in rows)
            )
            status, output = run_extractor()
            self.assertEqual(status, 2, output)

            rows[1]["processID"] = 10
            (out / "system.ndjson").write_text(
                "".join(json.dumps(row) + "\n" for row in rows)
            )
            write_meta(0, provider_end_pid=11)
            status, output = run_extractor()
            self.assertEqual(status, 2, output)


if __name__ == "__main__":
    unittest.main()
