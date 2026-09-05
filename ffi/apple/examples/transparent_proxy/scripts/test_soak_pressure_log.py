#!/usr/bin/env python3
"""Regression tests for the on-device soak pressure-log schema."""

import hashlib
import os
from pathlib import Path
import json
import re
import socket
import signal
import sys
import subprocess
import tempfile
import threading
import unittest
from decimal import Decimal

from soak_pressure_log import (
    artifact_identity_issues,
    cap_validation_hard_limited,
    canonical_release_soak_profile_lines,
    ceiling_configuration_issues,
    ceiling_probe_evidence_issues,
    ceiling_outage_window,
    classify_soak_result,
    cpu_sample_diagnostic_issues,
    crash_snapshot_evidence,
    dial9_diagnostic_collection_issues,
    dial9_evidence_issues,
    dial9_diagnostic_claim_issues,
    engine_lifecycle_event,
    filter_provider_ndjson_records,
    flow_pool_evidence_issues,
    flow_pool_status as _flow_pool_status,
    final_provider_observation_issues,
    flow_gauge,
    flow_gauge_issue,
    is_no_headroom,
    idle_cpu_evidence,
    idle_cpu_comparison_evidence,
    leak_evidence,
    lifecycle_category_issue,
    memory_diagnostic_issues,
    no_headroom_event,
    parse_artifact_epoch,
    parse_artifact_uint,
    parse_epoch,
    parse_evidence_status_lines,
    parse_ceiling_probe_lines,
    parse_leaks_output,
    parse_ndjson_lines,
    parse_oslog_timestamp,
    parse_phase_marker_lines,
    parse_provider_identity_lines,
    parse_probe_lines,
    phase_for_epoch,
    post_boundary_forensic_issues,
    producer_source_issues,
    pressure_counters,
    pressure_episode,
    pressure_telemetry_issue,
    pressure_reaper_status,
    provider_allocation_failure,
    probe_succeeded,
    release_soak_profile_issues,
    selected_count,
    selection_event,
    sleep_wake_evidence,
    settled_final_flow_gauge,
    soak_evidence_issues,
    soak_workload_claim_issues,
    top_cpu_collection_issues,
    top_cpu_sample_rows,
    summarize_pressure_rows,
    summarize_udp_pressure_rows,
    summarize_writer_memory_pressure_rows,
    udp_pressure_event,
    unexpected_probe_failure_count,
    unexpected_probe_failure_count_across_outages,
    writer_memory_pressure_event,
)


def flow_pool_status(*args, **kwargs):
    """Keep legacy fixtures explicit about their five-second hold."""
    kwargs.setdefault("required_hold_seconds", 5)
    return _flow_pool_status(*args, **kwargs)


def require_loopback_round_trip(testcase):
    """Skip quickly when bind works but sandboxed loopback traffic is blackholed."""
    listener = socket.socket()
    listener.settimeout(0.25)
    worker = None
    try:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)

        def respond():
            try:
                connection, _ = listener.accept()
                with connection:
                    connection.sendall(b"ok")
            except OSError:
                pass

        worker = threading.Thread(target=respond, daemon=True)
        worker.start()
        with socket.create_connection(listener.getsockname(), timeout=0.25) as client:
            client.settimeout(0.25)
            if client.recv(2) != b"ok":
                raise OSError("loopback response mismatch")
    except OSError as error:
        testcase.skipTest(f"host sandbox has no end-to-end loopback reachability: {error}")
    finally:
        listener.close()
        if worker is not None:
            worker.join(timeout=0.5)


class SoakPressureLogTests(unittest.TestCase):
    @staticmethod
    def complete_meta(mode="stress-only"):
        return {
            "log_stream_started": "1",
            "log_stream_alive_end": "1",
            "log_stream_child_rc": "143",
            "log_stream_joined": "1",
            "baseline_gauge_seen": "1",
            "baseline_gauge_phase_local": "1",
            "probe_monitor_alive_end": "1",
            "probe_monitor_child_rc": "143",
            "probe_monitor_joined": "1",
            "provider_continuous": "1",
            "holder_cleanup_ok": "1",
            "udp_workload_exercised": "0",
            "mode": mode,
            "download_host_preflight_ok": "1",
            "stress_ok": "1",
            "fanout_ok": "1",
            "fanout_established_target_sustained": "1",
            "idle_holders_ok": "1",
            "idle_holders_established_target_sustained": "1",
            "real_download_ok": "1",
            "post_wake_ok": "skipped",
            "sleep_command_ok": "skipped",
            "baseline_total": "5",
            "final_total": "5",
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
            "softCap=450 hardCap=0 retiring=0 retirementOverlap=0 "
            "pressure[triggers=12 scans=2 skipped=10 "
            "selected=100 evicted=96 spared=2 canceled=1 expired=1 pending=0]"
        )
        self.assertEqual(
            flow_gauge(message),
            {
                "tcp": 351,
                "udp": 0,
                "registered": 351,
                "retiring": 0,
                "retirement_overlap": 0,
                "allocated": 351,
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

    def test_legacy_gauge_requires_explicit_schema_version(self):
        message = "live-flow counts tcp=1 udp=2 total=3 peak=4 softCap=5"
        self.assertIsNone(flow_gauge(message))
        self.assertIn("missing a current-schema field", flow_gauge_issue(message))
        gauge = flow_gauge(message, schema_version=1)
        self.assertIsNotNone(gauge)
        self.assertIsNone(flow_gauge_issue(message, schema_version=1))
        self.assertIsNone(gauge["hard_cap"])
        self.assertIsNone(gauge["retiring"])

    def test_current_gauge_fails_closed_when_any_field_is_absent(self):
        fields = (
            "tcp=1", "udp=2", "total=3", "peak=4", "softCap=5",
            "hardCap=6", "retiring=0", "retirementOverlap=0",
        )
        valid = "live-flow counts " + " ".join(fields)
        self.assertIsNotNone(flow_gauge(valid))
        for missing in fields:
            with self.subTest(missing=missing):
                malformed = valid.replace(missing, "", 1)
                self.assertIsNone(flow_gauge(malformed))
                self.assertIn(
                    "missing a current-schema field", flow_gauge_issue(malformed)
                )

    def test_flow_gauge_separates_registered_and_allocated_and_validates_retiring(self):
        message = (
            "live-flow counts tcp=4 udp=3 total=10 peak=15 softCap=10 "
            "hardCap=20 retiring=5 retirementOverlap=2"
        )
        gauge = flow_gauge(message)
        self.assertEqual(gauge["registered"], 7)
        self.assertEqual(gauge["allocated"], 10)
        self.assertEqual(gauge["retiring"], 5)
        self.assertEqual(gauge["retirement_overlap"], 2)
        self.assertIsNone(flow_gauge_issue(message))

        inconsistent = message.replace("total=10", "total=11")
        self.assertIsNone(flow_gauge(inconsistent))
        self.assertIn("inconsistent", flow_gauge_issue(inconsistent))
        impossible_overlap = message.replace("retirementOverlap=2", "retirementOverlap=6")
        self.assertIsNone(flow_gauge(impossible_overlap))
        over_hard = message.replace("hardCap=20", "hardCap=9")
        self.assertIsNone(flow_gauge(over_hard))
        self.assertIn("hard-cap", flow_gauge_issue(over_hard))
        self.assertIn(
            "missing a current-schema field",
            flow_gauge_issue(
                "live-flow counts tcp=4 udp=3 total=7 peak=15 softCap=10 hardCap=20"
            ),
        )

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

    def test_cap_validation_mode_uses_allocated_effective_headroom(self):
        self.assertFalse(cap_validation_hard_limited(80, 80, 5, 5))
        self.assertTrue(cap_validation_hard_limited(80, 80, 5, 6))
        self.assertTrue(cap_validation_hard_limited(80, 79, 5, 5))
        self.assertFalse(cap_validation_hard_limited(80, 90, 5, 6))
        self.assertFalse(cap_validation_hard_limited(80, 0, 5, 80))
        self.assertIsNone(cap_validation_hard_limited("080", "80", "5", "5"))
        self.assertIsNone(cap_validation_hard_limited(80, 80, 6, 5))
        self.assertIsNone(cap_validation_hard_limited(80, 80, 5, 81))

    def test_artifact_numbers_require_canonical_bounded_text(self):
        self.assertEqual(parse_artifact_uint("0"), 0)
        self.assertEqual(parse_artifact_uint("18446744073709551615"), 2**64 - 1)
        for value in (0, True, "", "00", "+1", "1.0", "1e2", " 1", "1 "):
            with self.subTest(value=value):
                self.assertIsNone(parse_artifact_uint(value))
        self.assertIsNone(parse_artifact_uint("18446744073709551616"))
        self.assertEqual(parse_artifact_epoch("100.000001"), parse_epoch("100.000001"))
        for value in (100, "00", "1.", "1.0000000", "1e2", "-1", "nan"):
            with self.subTest(epoch=value):
                self.assertIsNone(parse_artifact_epoch(value))

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

    def test_ended_episode_rejects_impossible_counters_and_timestamps(self):
        inconsistent_counters = (
            "flow pressure episode ended: startEpochMs=100250 durationMs=1250 "
            "peakOccupancy=478 softCap=450 scans=3 skipped=7 selected=0 "
            "evicted=1 spared=0 canceled=0 expired=0 startEpochUs=100250999"
        )
        inconsistent_timestamp = (
            "flow pressure episode ended: startEpochMs=100251 durationMs=1250 "
            "peakOccupancy=478 softCap=450 scans=3 skipped=7 selected=1 "
            "evicted=1 spared=0 canceled=0 expired=0 startEpochUs=100250999"
        )
        self.assertIsNone(pressure_episode(inconsistent_counters))
        self.assertIsNone(pressure_episode(inconsistent_timestamp))

        future_start = (
            "flow pressure episode ended: startEpochMs=200000 durationMs=10 "
            "peakOccupancy=451 softCap=450 scans=1 skipped=0 selected=1 "
            "evicted=1 spared=0 canceled=0 expired=0 startEpochUs=200000000"
        )
        pressure = summarize_pressure_rows([(100, future_start)])
        self.assertEqual(pressure["validated_eviction_episodes"], 0)
        self.assertEqual(
            pressure["issues"],
            ["pressure episode start timestamp is later than its log record"],
        )

    def test_pressure_telemetry_is_fail_closed_and_lifecycle_only(self):
        inconsistent = (
            "flow pressure episode ended: startEpochMs=100250 durationMs=1250 "
            "peakOccupancy=478 softCap=450 scans=3 skipped=7 selected=0 "
            "evicted=1 spared=0 canceled=0 expired=0 startEpochUs=100250999"
        )
        malformed_counter = (
            "pressure[triggers=1 scans=x skipped=0 selected=0 evicted=0 "
            "spared=0 canceled=0 expired=0 pending=0]"
        )
        contradictory_selection = (
            "flow pressure: occupancy 449 over soft cap 450; selected 1 idle flow(s)"
        )
        duplicated_gauge = (
            "live-flow counts tcp=1 udp=0 total=1 peak=1 softCap=10 hardCap=20 "
            "retiring=0 live-flow counts tcp=1 udp=0 total=1 peak=1 softCap=10 "
            "hardCap=20 retiring=0"
        )
        for message in (
            inconsistent,
            malformed_counter,
            contradictory_selection,
            duplicated_gauge,
        ):
            with self.subTest(message=message):
                self.assertIsNotNone(pressure_telemetry_issue(message))
                self.assertIsNotNone(lifecycle_category_issue(message, "tproxy"))

        valid_gauge = (
            "tproxy live-flow counts tcp=1 udp=2 total=3 peak=3 softCap=10 "
            "hardCap=20 retiring=0 retirementOverlap=0 "
            "pressure[triggers=0 scans=0 skipped=0 "
            "selected=0 evicted=0 spared=0 canceled=0 expired=0 pending=0]"
        )
        self.assertIsNone(pressure_telemetry_issue(valid_gauge))
        self.assertIsNone(lifecycle_category_issue(valid_gauge, "lifecycle"))
        self.assertIsNotNone(lifecycle_category_issue(valid_gauge, "tproxy"))

    def test_soft_cap_boundary_is_pressure_for_every_event_schema(self):
        selection = (
            "flow pressure: occupancy 450 over soft cap 450; selected 1 idle flow(s)"
        )
        no_headroom = (
            "flow pressure: occupancy 450, soft cap 450, but no flow idle long enough"
        )
        episode = (
            "flow pressure episode ended: startEpochMs=100250 durationMs=1250 "
            "peakOccupancy=450 softCap=450 scans=1 skipped=0 selected=1 "
            "evicted=1 spared=0 canceled=0 expired=0 startEpochUs=100250000"
        )
        for message in (selection, no_headroom, episode):
            with self.subTest(message=message):
                self.assertIsNone(pressure_telemetry_issue(message))
        summarized = summarize_pressure_rows(
            [(101, selection), (102, no_headroom), (103, episode)]
        )
        self.assertEqual(summarized["observed_peak"], 450)
        self.assertEqual(summarized["validated_eviction_episodes"], 1)

    def test_writer_memory_pressure_schema_and_stateful_recovery(self):
        entered = (
            'writer memory pressure entered protocol="udp" '
            'reason="aggregate_bytes" retainedBytes=8192 maxBytes=8192 '
            'retainedItems=4 maxItems=8'
        )
        recovered = (
            'writer memory pressure recovered protocol="aggregate" '
            'reason="low_water" retainedBytes=4096 maxBytes=8192 '
            'retainedItems=2 maxItems=8'
        )
        event = writer_memory_pressure_event(entered)
        self.assertEqual(event["schema_version"], 1)
        self.assertEqual(event["reason"], "aggregate_bytes")
        self.assertIsNone(pressure_telemetry_issue(entered))
        self.assertIsNone(lifecycle_category_issue(entered, "lifecycle"))
        self.assertIsNotNone(lifecycle_category_issue(entered, "tproxy"))
        result = summarize_writer_memory_pressure_rows(
            [(100, entered), (101, recovered)]
        )
        self.assertEqual(result["status"], "GOOD")
        self.assertEqual(result["entered_reasons"], ["aggregate_bytes"])
        self.assertEqual(result["recovered_reasons"], ["aggregate_bytes"])
        self.assertEqual(result["unrecovered"], [])

    def test_writer_memory_pressure_fails_closed_and_never_counts_rows_as_recovery(self):
        entered = (
            'writer memory pressure entered protocol="tcp" '
            'reason="tcp_waiter_gate" retainedBytes=6 maxBytes=8 '
            'retainedItems=6 maxItems=8'
        )
        for malformed in (
            'writer memory pressure entered protocol="<private>" '
            'reason="aggregate_bytes" retainedBytes=8 maxBytes=8 '
            'retainedItems=8 maxItems=8',
            entered.replace("retainedItems=6", "retainedItems=9"),
            entered.replace("maxItems=8", "maxItems=8 source_app=secret"),
            entered + " " + entered,
            entered.replace("entered", "recovered"),
            (
                'writer memory pressure recovered protocol="aggregate" '
                'reason="low_water" retainedBytes=7 maxBytes=8 '
                'retainedItems=1 maxItems=8'
            ),
        ):
            with self.subTest(malformed=malformed):
                self.assertIsNone(writer_memory_pressure_event(malformed))
                self.assertIsNotNone(pressure_telemetry_issue(malformed))
        result = summarize_writer_memory_pressure_rows([(100, entered), (101, entered)])
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertEqual(result["recovered_reasons"], [])
        self.assertEqual(result["unrecovered"], ["tcp_waiter_gate"])

    def test_udp_pressure_schema_and_normal_mode_drop_failure(self):
        drop = (
            'UDP ingress pressure dropped datagram flow_id=41 pressure="flow_bytes" '
            "cumulative_drops=1 global_retained_bytes=4096 "
            "global_max_retained_bytes=8192"
        )
        parsed = udp_pressure_event(drop)
        self.assertEqual(parsed["transition"], "drop")
        self.assertEqual(parsed["flow_id"], 41)
        self.assertEqual(parsed["pressure"], "flow_bytes")
        self.assertIsNone(lifecycle_category_issue(drop, "lifecycle"))
        self.assertIsNotNone(lifecycle_category_issue(drop, "tproxy"))
        result = summarize_udp_pressure_rows(
            [(101, drop)], workload_exercised=True, mode="stress-only"
        )
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(result["drop_transitions"], 1)
        self.assertTrue(result["failures"])

    def test_udp_pressure_ceiling_requires_later_recovery(self):
        drop = (
            'UDP ingress pressure dropped datagram flow_id=42 pressure="global_bytes" '
            "cumulative_drops=2 global_retained_bytes=8192 "
            "global_max_retained_bytes=8192"
        )
        resume = (
            'UDP ingress pressure resumed flow flow_id=42 pressure="global_bytes" '
            "cumulative_resumptions=1 global_retained_bytes=1024 "
            "global_max_retained_bytes=8192"
        )
        failed = summarize_udp_pressure_rows(
            [(101, drop)], workload_exercised=True, mode="find-ceiling"
        )
        self.assertEqual(failed["status"], "FAILED")
        self.assertEqual(failed["unrecovered"], ["global_bytes"])
        self.assertEqual(failed["drop_reasons"], ["global_bytes"])
        self.assertEqual(failed["recovered_reasons"], [])
        recovered = summarize_udp_pressure_rows(
            [(101, drop), (102, resume)],
            workload_exercised=True,
            mode="find-ceiling",
        )
        self.assertEqual(recovered["status"], "GOOD")
        self.assertEqual(recovered["unrecovered"], [])
        self.assertEqual(recovered["recovered_reasons"], ["global_bytes"])

    def test_udp_pressure_recovery_is_reason_state_not_row_count(self):
        rows = [
            (101, 'UDP ingress pressure dropped datagram flow_id=43 pressure="flow_bytes" '
                  'cumulative_drops=10 global_retained_bytes=8192 '
                  'global_max_retained_bytes=16384'),
            (102, 'UDP ingress pressure dropped datagram flow_id=43 pressure="global_bytes" '
                  'cumulative_drops=11 global_retained_bytes=16384 '
                  'global_max_retained_bytes=16384'),
            (103, 'UDP ingress pressure resumed flow flow_id=43 pressure="flow_bytes" '
                  'cumulative_resumptions=4 global_retained_bytes=4096 '
                  'global_max_retained_bytes=16384'),
        ]
        result = summarize_udp_pressure_rows(
            rows, workload_exercised=True, mode="find-ceiling"
        )
        self.assertEqual(result["drop_transitions"], 2)
        self.assertEqual(result["resume_transitions"], 1)
        self.assertEqual(result["drop_reasons"], ["flow_bytes", "global_bytes"])
        self.assertEqual(result["recovered_reasons"], ["flow_bytes"])
        self.assertEqual(result["unrecovered"], ["global_bytes"])
        self.assertEqual(result["status"], "FAILED")

    def test_udp_pressure_ceiling_is_bound_to_one_required_flow(self):
        drop = (
            'UDP ingress pressure dropped datagram flow_id=77 '
            'pressure="channel_count" cumulative_drops=1 '
            'global_retained_bytes=64 global_max_retained_bytes=64'
        )
        resume = (
            'UDP ingress pressure resumed flow flow_id=77 '
            'pressure="channel_count" cumulative_resumptions=1 '
            'global_retained_bytes=0 global_max_retained_bytes=64'
        )
        matching = summarize_udp_pressure_rows(
            [(101, drop), (102, resume)],
            workload_exercised=True,
            mode="find-ceiling",
            required_flow_id=77,
        )
        self.assertEqual(matching["status"], "GOOD")

        for rows in (
            [(101, drop), (102, resume.replace("flow_id=77", "flow_id=78"))],
            [
                (101, drop.replace("flow_id=77", "flow_id=78")),
                (102, resume.replace("flow_id=77", "flow_id=78")),
            ],
        ):
            with self.subTest(rows=rows):
                foreign = summarize_udp_pressure_rows(
                    rows,
                    workload_exercised=True,
                    mode="find-ceiling",
                    required_flow_id=77,
                )
                self.assertEqual(foreign["status"], "INCOMPLETE")
                self.assertTrue(
                    any("different flow" in issue for issue in foreign["issues"])
                )

        for invalid in (None, True, 0, -1, 2**64):
            if invalid is None:
                continue
            with self.subTest(invalid=invalid):
                result = summarize_udp_pressure_rows(
                    [(101, drop)], workload_exercised=True,
                    mode="find-ceiling", required_flow_id=invalid,
                )
                self.assertEqual(result["status"], "INCOMPLETE")

        self.assertIsNone(udp_pressure_event(drop.replace("flow_id=77", "flow_id=0")))
        self.assertIsNone(udp_pressure_event(drop + " flow_id=77"))

    def test_swift_udp_staging_drop_is_distinct_and_always_unhealthy(self):
        drop = (
            'UDP Swift ingress staging dropped datagrams reason="generation_bytes" '
            "cumulative_drop_events=1 cumulative_dropped_items=3 "
            "cumulative_dropped_bytes_lower_bound=1200 "
            "generation_retained_items=8 generation_max_retained_items=8 "
            "generation_retained_bytes=8192 generation_max_retained_bytes=8192"
        )
        parsed = udp_pressure_event(drop)
        self.assertEqual(parsed["layer"], "swift_staging")
        self.assertEqual(parsed["cumulative"], 1)
        self.assertEqual(parsed["cumulative_dropped_items"], 3)
        generation_items = drop.replace(
            'reason="generation_bytes"', 'reason="generation_items"'
        )
        self.assertEqual(
            udp_pressure_event(generation_items)["pressure"], "generation_items"
        )
        for mode in ("stress-only", "find-ceiling"):
            with self.subTest(mode=mode):
                result = summarize_udp_pressure_rows(
                    [(101, drop)], workload_exercised=True, mode=mode
                )
                self.assertEqual(result["status"], "FAILED")
                self.assertEqual(result["swift_staging_drop_samples"], 1)
                self.assertEqual(result["drop_transitions"], 0)
                self.assertTrue(
                    any("Swift UDP ingress staging" in failure
                        for failure in result["failures"])
                )

    def test_swift_udp_staging_schema_and_counters_fail_closed(self):
        first = (
            'UDP Swift ingress staging dropped datagrams reason="flow_items" '
            "cumulative_drop_events=2 cumulative_dropped_items=4 "
            "cumulative_dropped_bytes_lower_bound=10 "
            "generation_retained_items=1 generation_max_retained_items=8192 "
            "generation_retained_bytes=1 generation_max_retained_bytes=8192"
        )
        rollback = first.replace(
            "cumulative_drop_events=2", "cumulative_drop_events=1"
        )
        result = summarize_udp_pressure_rows(
            [(101, first), (102, rollback)],
            workload_exercised=True,
            mode="stress-only",
        )
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertTrue(any("Swift UDP staging" in issue for issue in result["issues"]))
        for malformed in (
            first.replace("cumulative_drop_events=2", "cumulative_drop_events=3"),
            first.replace("cumulative_dropped_items=4", "cumulative_dropped_items=1"),
            first.replace("generation_retained_items=1", "generation_retained_items=8193"),
            first.replace('reason="flow_items"', 'reason="<private>"'),
            first.replace('reason="flow_items"', 'reason="closed"'),
            first + " cumulative_drop_events=4",
        ):
            with self.subTest(malformed=malformed):
                self.assertIsNone(udp_pressure_event(malformed))
                self.assertIsNotNone(pressure_telemetry_issue(malformed))

    def test_udp_pressure_rejects_malformed_and_counter_rollback(self):
        malformed = (
            'UDP ingress pressure dropped datagram flow_id=44 pressure="global_bytes" '
            "cumulative_drops=1 global_retained_bytes=8193 "
            "global_max_retained_bytes=8192"
        )
        self.assertIsNone(udp_pressure_event(malformed))
        self.assertIsNotNone(pressure_telemetry_issue(malformed))
        first = (
            'UDP ingress pressure dropped datagram flow_id=44 pressure="channel_count" '
            "cumulative_drops=4 global_retained_bytes=1 "
            "global_max_retained_bytes=8192"
        )
        rollback = first.replace("cumulative_drops=4", "cumulative_drops=2")
        result = summarize_udp_pressure_rows(
            [(101, first), (102, rollback)],
            workload_exercised=True,
            mode="stress-only",
        )
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertTrue(any("rolled back" in issue for issue in result["issues"]))
        duplicated = first + " cumulative_drops=8"
        self.assertIsNone(udp_pressure_event(duplicated))
        self.assertIsNotNone(pressure_telemetry_issue(duplicated))

    def test_udp_pressure_without_udp_workload_is_not_exercised(self):
        result = summarize_udp_pressure_rows(
            [(101, "UDP ingress pressure dropped datagram")],
            workload_exercised=False,
            mode="stress-only",
        )
        self.assertEqual(result["status"], "NOT EXERCISED")
        self.assertEqual(result["failures"], [])
        self.assertEqual(result["issues"], [])

    def test_udp_pressure_parser_matches_engine_emitter_schema(self):
        repository = Path(__file__).resolve().parents[5]
        source = (
            repository
            / "rama-net-apple-networkextension/src/tproxy/engine/udp_ingress.rs"
        ).read_text()
        for public_body in (
            '"UDP ingress pressure dropped datagram flow_id={} pressure=\\"{}\\" '
            'cumulative_drops={} global_retained_bytes={} '
            'global_max_retained_bytes={}"',
            '"UDP ingress pressure resumed flow flow_id={} pressure=\\"{}\\" '
            'cumulative_resumptions={} global_retained_bytes={} '
            'global_max_retained_bytes={}"',
        ):
            with self.subTest(public_body=public_body):
                self.assertIn(public_body, source)
        for reason in ("channel_count", "flow_bytes", "global_bytes"):
            self.assertIn(f'"{reason}"', source)
        self.assertIn("global_retained_bytes", source)
        self.assertIn("global_max_retained_bytes", source)

        swift_source = (
            repository
            / "ffi/apple/RamaAppleNetworkExtension/Sources/"
            "RamaAppleNetworkExtension/Provider/Session/UdpFlowSession.swift"
        ).read_text()
        self.assertIn(
            '"UDP Swift ingress staging dropped datagrams reason=\\"'
            "\\(sample.reason.rawValue)\\\" ",
            swift_source,
        )
        for field in (
            "cumulative_drop_events",
            "cumulative_dropped_items",
            "cumulative_dropped_bytes_lower_bound",
            "generation_retained_items",
            "generation_max_retained_items",
            "generation_retained_bytes",
            "generation_max_retained_bytes",
        ):
            self.assertIn(field, swift_source)
        swift_staging_source = (
            repository
            / "ffi/apple/RamaAppleNetworkExtension/Sources/"
            "RamaAppleNetworkExtension/Provider/UdpIngressStaging.swift"
        ).read_text()
        self.assertIn(
            "guard reason.isRetryableCapacityPressure else { return nil }",
            swift_staging_source,
        )
        self.assertIn('case generationItems = "generation_items"', swift_staging_source)

    def test_udp_pressure_redacted_or_incomplete_public_message_fails_closed(self):
        for message in (
            "UDP ingress pressure dropped datagram",
            'UDP ingress pressure dropped datagram pressure="<private>" '
            "cumulative_drops=<private> global_retained_bytes=<private> "
            "global_max_retained_bytes=<private>",
            'UDP ingress pressure resumed flow pressure="global_bytes"',
            "UDP Swift ingress staging dropped datagrams",
            'UDP Swift ingress staging dropped datagrams reason="<private>" '
            "cumulative_drop_events=<private>",
        ):
            with self.subTest(message=message):
                self.assertIsNone(udp_pressure_event(message))
                self.assertIsNotNone(pressure_telemetry_issue(message))
                verdict = summarize_udp_pressure_rows(
                    [(101, message)], workload_exercised=True, mode="stress-only"
                )
                self.assertEqual(verdict["status"], "INCOMPLETE")
                self.assertTrue(verdict["issues"])

    def test_only_explicit_provider_exhaustion_is_an_allocation_failure_signal(self):
        signal = "kernel flow allocation exhausted: resource=nexus"
        self.assertTrue(provider_allocation_failure(signal))
        self.assertIsNone(pressure_telemetry_issue(signal))
        self.assertIsNone(lifecycle_category_issue(signal, "lifecycle"))
        self.assertIsNotNone(lifecycle_category_issue(signal, "tproxy"))
        for malformed in (
            "kernel flow allocation exhausted: resource=socket",
            signal + "; kernel flow allocation exhausted: resource=necp",
        ):
            self.assertIsNotNone(pressure_telemetry_issue(malformed), malformed)
        for message in (
            "curl: (60) SSL certificate problem",
            "egress NWConnection failed before flow opened: dns failure",
            "egress NWConnection failed before flow opened: "
            "POSIXErrorCode(rawValue: 55): No buffer space available",
            "egress NWConnection failed after flow opened: rawValue: 54",
            "origin returned HTTP 503",
        ):
            self.assertFalse(provider_allocation_failure(message), message)

    def test_fast_burst_uses_event_peak_and_keeps_outcomes_separate(self):
        rows = [
            (
                95,
                "tproxy live-flow counts tcp=20 udp=0 total=20 peak=600 "
                "softCap=450 hardCap=0 retiring=0 retirementOverlap=0 "
                "pressure[triggers=9 scans=1 skipped=0 selected=0 "
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
                "softCap=450 hardCap=0 retiring=0 retirementOverlap=0 "
                "pressure[triggers=1 scans=1 skipped=0 selected=120 "
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
                "softCap=450 hardCap=0 retiring=0 retirementOverlap=0 "
                "pressure[triggers=0 scans=0 skipped=0 selected=0 "
                "evicted=0 spared=0 canceled=0 expired=0 pending=0]",
            ),
            (
                120,
                "tproxy live-flow counts tcp=350 udp=0 total=350 peak=350 "
                "softCap=450 hardCap=0 retiring=0 retirementOverlap=0 "
                "pressure[triggers=1 scans=1 skipped=0 selected=2 "
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
                "hardCap=0 retiring=0 retirementOverlap=0 "
                "pressure[triggers=0 scans=0 skipped=0 selected=0 evicted=0 "
                "spared=0 canceled=0 expired=0 pending=0]",
            ),
            (
                120,
                "live-flow counts tcp=20 udp=0 total=20 peak=480 softCap=450 "
                "hardCap=0 retiring=0 retirementOverlap=0 "
                "pressure[triggers=0 scans=0 skipped=0 selected=0 evicted=0 "
                "spared=0 canceled=0 expired=0 pending=0]",
            ),
            (
                180,
                "live-flow counts tcp=20 udp=0 total=20 peak=480 softCap=450 "
                "hardCap=0 retiring=0 retirementOverlap=0 "
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
                f"peak={total} softCap=450 hardCap=0 retiring=0 retirementOverlap=0",
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
                f"peak={total} softCap=450 hardCap=0 retiring=0 retirementOverlap=0",
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

    def test_ndjson_rejects_duplicate_keys_without_discarding_unique_unknown_fields(self):
        record = {
            "processID": 10,
            "subsystem": "org.example.provider",
            "timestamp": "1970-01-01 00:01:40+0000",
            "eventMessage": "gauge",
            "future_field": {"nested": [1, True, None]},
        }
        encoded = json.dumps(record)
        decoded, issues = parse_ndjson_lines([encoded + "\n"])
        self.assertEqual(decoded, [record])
        self.assertEqual(issues, [])
        for key, original in record.items():
            for duplicate in (original, "foreign", 999, True, None, [], {}):
                field = json.dumps(key) + ":" + json.dumps(duplicate)
                for line in ("{" + field + "," + encoded[1:], encoded[:-1] + "," + field + "}"):
                    with self.subTest(key=key, duplicate=duplicate, line=line):
                        decoded, issues = parse_ndjson_lines([encoded + "\n", line + "\n"])
                        self.assertEqual(decoded, [record])
                        self.assertEqual(issues, ["malformed NDJSON record at line 2"])
        for nested in ('{"key":0,"key":1}', '[{"key":0,"key":1}]'):
            line = encoded[:-1] + ',"future_nested":' + nested + "}"
            with self.subTest(nested=nested):
                decoded, issues = parse_ndjson_lines([line + "\n"])
                self.assertEqual(decoded, [])
                self.assertEqual(issues, ["malformed NDJSON record at line 1"])

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
        for invalid_pid in (True, "010", "10.0", -1):
            with self.subTest(provider_pid=invalid_pid):
                accepted, issues = filter_provider_ndjson_records(
                    [valid], invalid_pid, "org.example.provider"
                )
                self.assertEqual(accepted, [])
                self.assertEqual(
                    issues, ["provider identity is missing or invalid"]
                )

    def test_provider_identity_timeline_detects_death_reuse_and_malformed_rows(self):
        identity = "a" * 64
        epochs, issues = parse_provider_identity_lines(
            [f"100.000001\t{identity}\n", f"101.000001\t{identity}\n"],
            identity,
        )
        self.assertEqual(issues, [])
        self.assertEqual(epochs, [parse_epoch("100.000001"), parse_epoch("101.000001")])

        _, issues = parse_provider_identity_lines(
            [
                f"100.000001\t{identity}\n",
                f"101.000001\t{'b' * 64}\n",
                "102.000001\tgone\n",
            ],
            identity,
        )
        self.assertIn("provider identity changed at line 2", issues)
        self.assertIn("malformed provider identity sample at line 3", issues)

    def test_idle_cpu_requires_ten_exact_pid_one_second_samples(self):
        identity = "a" * 64

        def rows(cpus, *, pid=42, row_identity=identity):
            return [
                f"{index}\t{100 + index:.6f}\t{pid}\t{row_identity}\t{cpu}\n"
                for index, cpu in enumerate(cpus, 1)
            ]

        cool = idle_cpu_evidence(
            rows(["0.0", "1.0", "2.0", "3.0", "4.0"] * 2),
            expected_pid="42",
            expected_identity=identity,
        )
        self.assertEqual(cool["issues"], [])
        self.assertEqual(cool["failures"], [])
        self.assertEqual(cool["sample_count"], 10)
        self.assertEqual(cool["maximum_percent"], Decimal("4.0"))
        self.assertEqual(cool["mean_percent"], Decimal("2.0"))

        missing = idle_cpu_evidence(
            rows(["0.0"] * 9), expected_pid=42, expected_identity=identity
        )
        self.assertIn(
            "idle CPU evidence has 9 sample(s); expected exactly 10",
            missing["issues"],
        )

        malformed_rows = rows(["0.0"] * 10)
        malformed_rows[4] = f"5\t105.000000\t42\t{identity}\tnan\n"
        malformed = idle_cpu_evidence(
            malformed_rows, expected_pid=42, expected_identity=identity
        )
        self.assertIn("malformed idle CPU sample at line 5", malformed["issues"])

        changed_pid_rows = rows(["0.0"] * 10)
        changed_pid_rows[6] = f"7\t107.000000\t43\t{identity}\t0.0\n"
        changed_pid = idle_cpu_evidence(
            changed_pid_rows, expected_pid=42, expected_identity=identity
        )
        self.assertIn("idle CPU provider PID changed at line 7", changed_pid["issues"])

        changed_identity = idle_cpu_evidence(
            rows(["0.0"] * 10, row_identity="b" * 64),
            expected_pid=42,
            expected_identity=identity,
        )
        self.assertIn(
            "idle CPU provider identity changed at line 1",
            changed_identity["issues"],
        )

    def test_idle_cpu_hot_streak_requires_five_consecutive_full_core_samples(self):
        identity = "c" * 64

        def evaluate(cpus):
            return idle_cpu_evidence(
                [
                    f"{index}\t{200 + index:.6f}\t77\t{identity}\t{cpu}\n"
                    for index, cpu in enumerate(cpus, 1)
                ],
                expected_pid=77,
                expected_identity=identity,
            )

        bursty = evaluate([90, 90, 90, 90, 0, 90, 90, 90, 90, 0])
        self.assertEqual(bursty["failures"], [])
        self.assertEqual(bursty["maximum_hot_streak"], 4)
        hot = evaluate([0, 89.9, 90.0, 91, 100, 99, 90, 0, 0, 0])
        self.assertEqual(hot["maximum_hot_streak"], 5)
        self.assertEqual(len(hot["failures"]), 1)
        result = classify_soak_result(
            self.complete_meta(),
            [],
            probe_failures=0,
            body_errors=0,
            reaper_status="good",
            no_spin_failures=hot["failures"],
        )
        self.assertTrue(result["complete"])
        self.assertEqual(result["exit_code"], 1)

    def test_idle_cpu_comparison_rejects_false_green_patterns_and_outside_window(self):
        identity = "d" * 64

        def rows(cpus, start):
            return [
                f"{index}\t{start + index:.6f}\t88\t{identity}\t{cpu}\n"
                for index, cpu in enumerate(cpus, 1)
            ]

        def compare(
            post, *, baseline=None, post_start="200", post_end="211",
            minimum_quiescence=0,
        ):
            return idle_cpu_comparison_evidence(
                rows(["1.0"] * 10 if baseline is None else baseline, 100),
                rows(post, 200),
                expected_pid=88,
                expected_identity=identity,
                baseline_start_epoch="100",
                baseline_end_epoch="111",
                post_start_epoch=post_start,
                post_end_epoch=post_end,
                run_start_epoch_ms="100000",
                run_end_epoch_ms="211000",
                minimum_post_quiescence_seconds=minimum_quiescence,
            )

        cool = compare(["9.0"] * 10)
        self.assertEqual(cool["issues"], [])
        self.assertEqual(cool["failures"], [])
        self.assertEqual(cool["post_mean_limit_percent"], Decimal("10.0"))

        for hot in (["89.9"] * 10, ["90.0"] * 8 + ["0"] * 2):
            with self.subTest(hot=hot):
                result = compare(hot)
                self.assertEqual(result["issues"], [])
                self.assertTrue(result["failures"])
                self.assertGreaterEqual(result["post_warm_sample_count"], 5)

        regression = compare(["11.0"] * 10)
        self.assertTrue(any("baseline-derived" in f for f in regression["failures"]))

        hot_baseline = compare(["1.0"] * 10, baseline=["80.0"] * 10)
        self.assertTrue(any(
            "baseline mean" in failure for failure in hot_baseline["failures"]
        ))
        self.assertTrue(any(
            "idle CPU baseline evidence has 10 sample(s) at or above 80.0%"
            in failure
            for failure in hot_baseline["failures"]
        ))

        spinning_baseline = compare(
            ["1.0"] * 10,
            baseline=["0", "90", "90", "90", "90", "90", "0", "0", "0", "0"],
        )
        self.assertTrue(any(
            "idle CPU baseline provider CPU stayed at or above 90.0%"
            in failure
            for failure in spinning_baseline["failures"]
        ))

        outside = compare(["1.0"] * 10, post_start="202", post_end="211")
        self.assertIn(
            "idle CPU post-load sample at line 1 is before its phase",
            outside["issues"],
        )
        too_early = compare(["1.0"] * 10, minimum_quiescence=2)
        self.assertIn(
            "idle CPU post-load sampling began before the declared quiescence completed",
            too_early["issues"],
        )

    def test_cpu_sample_diagnostic_forced_or_unreaped_is_incomplete(self):
        self.assertEqual(
            cpu_sample_diagnostic_issues({
                "cpu_sample_command_rc": "0",
                "cpu_sample_joined": "1",
                "cpu_sample_forced": "0",
                "cpu_sample_privilege": "sudo",
                "cpu_sample_ownership_normalized": "1",
            }),
            [],
        )
        issues = cpu_sample_diagnostic_issues({
            "cpu_sample_command_rc": "137",
            "cpu_sample_joined": "0",
            "cpu_sample_forced": "1",
            "cpu_sample_privilege": "unavailable",
            "cpu_sample_ownership_normalized": "0",
        })
        self.assertIn("CPU sample diagnostic child was not reaped", issues)
        self.assertIn("CPU sample diagnostic exceeded its bounded deadline", issues)
        self.assertIn(
            "CPU sample diagnostic command failed or has no valid outcome", issues
        )
        self.assertIn(
            "CPU sample diagnostic did not use cached sudo privilege", issues
        )

    @staticmethod
    def valid_memory_diagnostic_meta():
        return {
            "provider_start_pid": "42",
            "provider_start_identity": "e" * 64,
            "run_start_epoch_ms": "100000",
            "run_end_epoch_ms": "200000",
            "baseline_mem_child_rc": "0",
            "baseline_mem_joined": "1",
            "baseline_mem_forced": "0",
            "baseline_mem_privilege": "sudo",
            "baseline_mem_sudo_rc": "0",
            "baseline_mem_ps_rc": "0",
            "baseline_mem_vmmap_rc": "0",
            "baseline_mem_start_epoch_ms": "110000",
            "baseline_mem_end_epoch_ms": "120000",
            "baseline_mem_provider_pid": "42",
            "baseline_mem_identity_before": "e" * 64,
            "baseline_mem_identity_after": "e" * 64,
            "final_mem_child_rc": "0",
            "final_mem_joined": "1",
            "final_mem_forced": "0",
            "final_mem_privilege": "sudo",
            "final_mem_sudo_rc": "0",
            "final_mem_ps_rc": "0",
            "final_mem_vmmap_rc": "0",
            "final_mem_heap_rc": "0",
            "final_mem_heap_filter_rc": "0",
        }

    @staticmethod
    def write_memory_diagnostic_artifacts(directory, *, artifact_pid=42):
        baseline = Path(directory) / "baseline-mem.txt"
        final = Path(directory) / "final-mem.txt"
        baseline.write_text(
            f"=== baseline provider pid={artifact_pid} @ now ===\n"
            "  PID    RSS      VSZ  %CPU STAT\n"
            f"  {artifact_pid}  12000  900000   0.0 S\n"
            "\n--- vmmap --summary ---\n"
            f"Process: Provider [{artifact_pid}]\n"
            "Physical footprint: 12.0M\n"
        )
        final.write_text(
            f"=== final snapshot provider pid={artifact_pid} @ now ===\n"
            "  PID    RSS      VSZ  %CPU STAT\n"
            f"  {artifact_pid}  12500  900000   0.0 S\n"
            "\n--- vmmap --summary ---\n"
            f"Process: Provider [{artifact_pid}]\n"
            "Physical footprint: 12.5M\n"
            "\n--- heap totals ---\n"
            f"Process {artifact_pid}: 12500 zones\n"
            "All zones: 12500 nodes malloced\n"
        )
        return baseline, final

    def test_memory_diagnostic_rejects_failing_sudo(self):
        with tempfile.TemporaryDirectory() as artifact_dir:
            baseline, final = self.write_memory_diagnostic_artifacts(artifact_dir)
            meta = self.valid_memory_diagnostic_meta()
            meta.update({
                "baseline_mem_child_rc": "1",
                "baseline_mem_privilege": "unavailable",
                "baseline_mem_sudo_rc": "1",
                "baseline_mem_vmmap_rc": "1",
            })
            issues = memory_diagnostic_issues(
                meta, baseline_artifact=baseline, final_artifact=final)
        self.assertIn(
            "baseline memory diagnostic did not prove cached sudo privilege",
            issues,
        )
        self.assertIn(
            "baseline memory diagnostic sudo command failed or has no valid outcome",
            issues,
        )
        self.assertIn(
            "baseline memory diagnostic vmmap command failed or has no valid outcome",
            issues,
        )

    def test_memory_diagnostic_rejects_forced_final_snapshot(self):
        with tempfile.TemporaryDirectory() as artifact_dir:
            baseline, final = self.write_memory_diagnostic_artifacts(artifact_dir)
            meta = self.valid_memory_diagnostic_meta()
            meta.update({
                "final_mem_child_rc": "143",
                "final_mem_forced": "1",
            })
            issues = memory_diagnostic_issues(
                meta, baseline_artifact=baseline, final_artifact=final)
        self.assertIn(
            "final memory diagnostic exceeded its bounded deadline", issues
        )
        self.assertIn(
            "final memory diagnostic child failed or has no valid outcome", issues
        )

    def test_memory_diagnostic_rejects_missing_or_empty_artifacts(self):
        with tempfile.TemporaryDirectory() as artifact_dir:
            baseline = Path(artifact_dir) / "baseline-mem.txt"
            final = Path(artifact_dir) / "final-mem.txt"
            baseline.touch()
            issues = memory_diagnostic_issues(
                self.valid_memory_diagnostic_meta(),
                baseline_artifact=baseline,
                final_artifact=final,
            )
        self.assertIn(
            "baseline memory diagnostic artifact is missing or empty", issues
        )
        self.assertIn(
            "final memory diagnostic artifact is missing or empty", issues
        )

    def test_memory_diagnostic_rejects_other_process_artifacts(self):
        with tempfile.TemporaryDirectory() as artifact_dir:
            baseline, final = self.write_memory_diagnostic_artifacts(
                artifact_dir, artifact_pid=99)
            issues = memory_diagnostic_issues(
                self.valid_memory_diagnostic_meta(),
                baseline_artifact=baseline,
                final_artifact=final,
            )
        for message in (
            "baseline memory diagnostic header has the wrong PID",
            "baseline memory diagnostic ps row has the wrong PID",
            "baseline memory diagnostic vmmap output has the wrong PID",
            "final memory diagnostic header has the wrong PID",
            "final memory diagnostic ps row has the wrong PID",
            "final memory diagnostic vmmap output has the wrong PID",
            "final memory diagnostic heap output has the wrong PID",
        ):
            self.assertIn(message, issues)

    def test_top_cpu_parser_discards_decayed_row_and_keeps_ten_intervals(self):
        identity = "e" * 64
        raw = []
        for index in range(11):
            raw.extend([
                "-\tPID  %CPU\n",
                f"{100 + index:.6f}\t42  {99 if index == 0 else index}.0\n",
            ])
        rows, issues = top_cpu_sample_rows(
            raw, expected_pid=42, expected_identity=identity)
        self.assertEqual(issues, [])
        self.assertEqual(len(rows), 10)
        self.assertEqual(rows[0], f"1\t101.000000\t42\t{identity}\t1.0\n")
        self.assertNotIn("99.0", "".join(rows))

        changed = list(raw)
        changed[-1] = "110.000000\t43  10.0\n"
        rows, issues = top_cpu_sample_rows(
            changed, expected_pid=42, expected_identity=identity)
        self.assertEqual(rows, [])
        self.assertTrue(any("exact PID" in issue for issue in issues))

    def test_top_cpu_collection_requires_bounded_sudo_and_stable_identity(self):
        identity = "f" * 64
        meta = {"provider_start_identity": identity}
        for label in ("baseline", "post"):
            meta.update({
                f"idle_cpu_{label}_top_command_rc": "0",
                f"idle_cpu_{label}_top_joined": "1",
                f"idle_cpu_{label}_top_forced": "0",
                f"idle_cpu_{label}_top_privilege": "sudo",
                f"idle_cpu_{label}_identity_before": identity,
                f"idle_cpu_{label}_identity_after": identity,
            })
        self.assertEqual(top_cpu_collection_issues(meta), [])
        bad = dict(meta, idle_cpu_post_top_joined="0",
                   idle_cpu_post_top_forced="1",
                   idle_cpu_post_identity_after="a" * 64)
        issues = top_cpu_collection_issues(bad)
        self.assertIn("post top CPU collector was not reaped", issues)
        self.assertIn("post top CPU collector exceeded its bounded deadline", issues)
        self.assertIn("post top CPU provider identity changed", issues)

    def test_dial9_diagnostic_collection_is_bounded_even_without_coverage(self):
        self.assertEqual(
            dial9_diagnostic_collection_issues({
                "dial9_collection_attempted": "0",
            }),
            [],
        )
        self.assertEqual(
            dial9_diagnostic_collection_issues({
                "dial9_collection_attempted": "1",
                "dial9_collect_child_rc": "0",
                "dial9_collect_joined": "1",
                "dial9_collect_forced": "0",
            }),
            [],
        )
        issues = dial9_diagnostic_collection_issues({
            "dial9_collection_attempted": "1",
            "dial9_collect_child_rc": "137",
            "dial9_collect_joined": "0",
            "dial9_collect_forced": "1",
        })
        self.assertIn("Dial9 diagnostic collection child was not reaped", issues)
        self.assertIn(
            "Dial9 diagnostic collection exceeded its bounded deadline", issues
        )

    def test_arbitrary_dial9_artifacts_never_become_soak_coverage(self):
        self.assertEqual(
            dial9_diagnostic_claim_issues({
                "dial9_diagnostic_only": "1",
                "dial9_coverage_claimed": "0",
            }),
            [],
        )
        self.assertIn(
            "soak evidence must not claim Dial9 workload coverage",
            dial9_diagnostic_claim_issues({
                "dial9_diagnostic_only": "1",
                "dial9_coverage_claimed": "1",
            }),
        )
        self.assertIn(
            "Dial9 evidence is not marked diagnostic-only",
            dial9_diagnostic_claim_issues({
                "dial9_coverage_claimed": "0",
            }),
        )

    def test_soak_workload_claims_are_exact_and_tcp_only(self):
        run_uuid = "11111111-2222-3333-8444-555555555555"
        claims = [
            "evidence_kind\tsoak\n",
            f"run_uuid\t{run_uuid}\n",
            "dial9_claim\tunattributed-diagnostic\n",
            "dial9_diagnostic_only\t1\n",
            "dial9_workload_coverage\t0\n",
            "tcp_workload_exercised\t1\n",
            "udp_workload_exercised\t0\n",
            "schema_complete\t1\n",
        ]
        self.assertEqual(
            soak_workload_claim_issues(claims, expected_run_uuid=run_uuid), [])
        self.assertTrue(soak_workload_claim_issues(claims[:-1]))
        self.assertTrue(
            soak_workload_claim_issues(
                claims[:-1] + ["udp_workload_exercised\t1\n"]
            )
        )
        self.assertTrue(soak_workload_claim_issues(list(reversed(claims))))

    def test_crash_snapshots_distinguish_new_crashes_from_unavailable_evidence(self):
        product_name = "org.ramaproxy.example.tproxy.dev.provider"
        run_uuid = "11111111-2222-3333-8444-555555555555"
        generation = "4" * 64
        def snapshot(epoch, count, digest):
            return [
                "schema_version\t2\n",
                f"run_uuid\t{run_uuid}\n",
                f"provider_generation_identity\t{generation}\n",
                "since_epoch_ms\t100000\n",
                f"snapshot_epoch_ms\t{epoch}\n",
                f"process_names\t{product_name}\n",
                f"crash_count\t{count}\n",
                f"crash_names_sha256\t{digest}\n",
                "schema_complete\t1\n",
            ]

        clean = crash_snapshot_evidence(
            snapshot(100001, 0, "a" * 64),
            snapshot(110000, 0, "a" * 64),
            run_start_epoch_ms="100000",
            run_end_epoch_ms="109000",
            expected_process_names=product_name,
            expected_run_uuid=run_uuid,
            expected_provider_generation_identity=generation,
        )
        self.assertEqual(clean["issues"], [])
        self.assertEqual(clean["failures"], [])
        display_name = list(snapshot(100001, 0, "a" * 64))
        display_name[5] = "process_names\tRamaTransparentProxyExampleExtension\n"
        wrong_filter = crash_snapshot_evidence(
            display_name,
            snapshot(110000, 0, "a" * 64),
            run_start_epoch_ms="100000",
            run_end_epoch_ms="109000",
            expected_process_names=product_name,
            expected_run_uuid=run_uuid,
            expected_provider_generation_identity=generation,
        )
        self.assertIn(
            "crash snapshots do not target the exact provider process",
            wrong_filter["issues"],
        )

        wrong_generation = list(snapshot(110000, 0, "a" * 64))
        wrong_generation[2] = f"provider_generation_identity\t{'9' * 64}\n"
        substituted = crash_snapshot_evidence(
            snapshot(100001, 0, "a" * 64),
            wrong_generation,
            run_start_epoch_ms="100000",
            run_end_epoch_ms="109000",
            expected_process_names=product_name,
            expected_run_uuid=run_uuid,
            expected_provider_generation_identity=generation,
        )
        self.assertIn(
            "crash snapshots do not match the exact provider generation",
            substituted["issues"],
        )

        crashed = crash_snapshot_evidence(
            snapshot(100001, 0, "a" * 64),
            snapshot(110000, 1, "b" * 64),
            run_start_epoch_ms="100000",
            run_end_epoch_ms="110000",
            expected_process_names=product_name,
            expected_run_uuid=run_uuid,
            expected_provider_generation_identity=generation,
        )
        self.assertEqual(crashed["issues"], [])
        self.assertEqual(
            crashed["failures"],
            ["1 provider crash report(s) were created during the soak"],
        )

        unavailable = crash_snapshot_evidence(
            [], [], run_start_epoch_ms="100000", run_end_epoch_ms="110000",
            expected_process_names=product_name,
            expected_run_uuid=run_uuid,
            expected_provider_generation_identity=generation,
        )
        self.assertTrue(unavailable["issues"])
        self.assertEqual(unavailable["failures"], [])

        gap = crash_snapshot_evidence(
            snapshot(100001, 0, "a" * 64),
            snapshot(110000, 0, "a" * 64),
            run_start_epoch_ms="100000",
            run_end_epoch_ms="110001",
            expected_process_names=product_name,
            expected_run_uuid=run_uuid,
            expected_provider_generation_identity=generation,
        )
        self.assertIn(
            "post-workload crash snapshot does not cover the exact run end",
            gap["issues"],
        )

    def test_final_provider_observation_spans_crash_scan_generation(self):
        identity = "a" * 64
        meta = {
            "provider_start_pid": "42",
            "provider_start_identity": identity,
            "run_end_epoch_ms": "200000",
            "final_provider_observation_epoch_ms": "200000",
            "final_provider_observation_pid": "42",
            "final_provider_observation_identity": identity,
            "final_provider_observation_ok": "1",
            "crash_snapshot_epoch_ms": "205000",
            "post_snapshot_provider_observation_epoch_ms": "206000",
            "post_snapshot_provider_observation_pid": "42",
            "post_snapshot_provider_observation_identity": identity,
            "post_snapshot_provider_observation_ok": "1",
        }
        self.assertEqual(final_provider_observation_issues(meta), [])

        changed = dict(
            meta,
            post_snapshot_provider_observation_identity="b" * 64,
        )
        self.assertIn(
            "provider generation changed during the post-workload crash scan",
            final_provider_observation_issues(changed),
        )

        mismatched_end = dict(meta, run_end_epoch_ms="200001")
        self.assertIn(
            "final provider observation does not define the exact run end",
            final_provider_observation_issues(mismatched_end),
        )

    def test_post_boundary_forensics_require_order_and_exact_generation(self):
        identity = "a" * 64
        meta = {
            "provider_start_pid": "42",
            "provider_start_identity": identity,
            "run_end_epoch_ms": "200000",
            "final_mem_start_epoch_ms": "200100",
            "final_mem_end_epoch_ms": "200200",
            "final_mem_provider_pid": "42",
            "final_mem_identity_before": identity,
            "final_mem_identity_after": identity,
            "leaks_start_epoch_ms": "200200",
            "leaks_end_epoch_ms": "200300",
            "leaks_provider_pid": "42",
            "leaks_identity_before": identity,
            "leaks_identity_after": identity,
        }
        self.assertEqual(post_boundary_forensic_issues(meta), [])

        before_end = dict(meta, final_mem_start_epoch_ms="199999")
        self.assertIn(
            "final memory snapshot does not follow the declared run boundary",
            post_boundary_forensic_issues(before_end),
        )

        overlapping = dict(meta, leaks_start_epoch_ms="200199")
        self.assertIn(
            "leaks snapshot does not follow the declared run boundary",
            post_boundary_forensic_issues(overlapping),
        )

        changed = dict(meta, leaks_identity_after="b" * 64)
        self.assertIn(
            "leaks snapshot is not bound to the exact run generation",
            post_boundary_forensic_issues(changed),
        )

    def test_artifact_identity_requires_git_script_binary_and_signing_tuple(self):
        meta = {
            "repo_head": "1" * 40,
            "repo_dirty": "1",
            "soak_script_sha256": "2" * 64,
            "stress_script_sha256": "3" * 64,
            "pressure_parser_sha256": "6" * 64,
            "signed_evidence_helper_sha256": "7" * 64,
            "provider_binary_sha256": "4" * 64,
            "provider_executable": "/Applications/Proxy.app/Contents/MacOS/Proxy",
            "provider_executable_name": "Proxy",
            "crash_process_name": "Proxy",
            "provider_start_identity": "8" * 64,
            "common_provider_generation_identity": "8" * 64,
            "provider_bundle": "org.example.provider",
            "provider_codesign_identifier": "org.example.provider",
            "provider_codesign_cdhash": "5" * 40,
            "provider_codesign_team": "TEAM123",
        }
        self.assertEqual(artifact_identity_issues(meta), [])
        meta["provider_codesign_identifier"] = "org.example.other"
        meta["provider_binary_sha256"] = "unavailable"
        issues = artifact_identity_issues(meta)
        self.assertIn(
            "provider code-signing identifier does not match its log subsystem",
            issues,
        )
        self.assertIn(
            "provider binary SHA-256 identity is missing or invalid", issues
        )

    @staticmethod
    def valid_release_profile_meta():
        profile = "".join(canonical_release_soak_profile_lines()).encode()
        return {
            "release_profile_sha256": hashlib.sha256(profile).hexdigest(),
            "release_profile_eligible": "1",
            "mode": "cap-validate",
            "configured_skip_stress": "0",
            "configured_skip_fanout": "0",
            "configured_skip_idle": "0",
            "configured_skip_sleep": "0",
            "configured_allow_unsafe_load": "0",
            "configured_live_hard_cap_enabled": "1",
            "configured_stress_seconds": "180",
            "configured_stress_concurrency": "24",
            "configured_fanout_target": "40",
            "configured_fanout_hold_seconds": "90",
            "configured_idle_target": "40",
            "configured_idle_hold_seconds": "150",
            "configured_idle_tail_seconds": "135",
            "configured_max_safe_flows": "300",
            "configured_file_descriptor_limit": "16384",
            "configured_no_spin_quiescence_seconds": "60",
        }

    def test_release_profile_rejects_weakened_or_skipped_release_claims(self):
        lines = canonical_release_soak_profile_lines()
        meta = self.valid_release_profile_meta()
        self.assertEqual(release_soak_profile_issues(lines, meta), [])

        weakened = dict(
            meta, configured_stress_seconds="179", release_profile_eligible="1")
        self.assertIn(
            "release soak eligibility contradicts the captured configuration",
            release_soak_profile_issues(lines, weakened),
        )
        skipped = dict(
            meta, configured_skip_sleep="1", release_profile_eligible="1")
        self.assertIn(
            "release soak eligibility contradicts the captured configuration",
            release_soak_profile_issues(lines, skipped),
        )
        diagnostic = dict(
            meta, configured_skip_sleep="1", release_profile_eligible="0")
        self.assertEqual(release_soak_profile_issues(lines, diagnostic), [])

    def test_release_profile_mutation_is_rejected_even_with_updated_hash(self):
        mutated = canonical_release_soak_profile_lines()
        mutated[7] = "minimum_stress_seconds\t1\n"
        meta = self.valid_release_profile_meta()
        meta["release_profile_sha256"] = hashlib.sha256(
            "".join(mutated).encode()).hexdigest()
        self.assertIn(
            "release soak profile is missing, mutated, or non-canonical",
            release_soak_profile_issues(mutated, meta),
        )

    def test_sealed_producer_sources_are_hash_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = {}
            meta = {}
            for source_key, hash_key in (
                ("soak_test", "soak_script_sha256"),
                ("stress_traffic", "stress_script_sha256"),
                ("soak_pressure_log", "pressure_parser_sha256"),
                ("signed_run_evidence", "signed_evidence_helper_sha256"),
            ):
                path = root / source_key
                content = (source_key + "\n").encode()
                path.write_bytes(content)
                paths[source_key] = path
                meta[hash_key] = hashlib.sha256(content).hexdigest()
            self.assertEqual(producer_source_issues(meta, paths), [])
            paths["signed_run_evidence"].write_text("tampered\n")
            self.assertIn(
                "sealed signed evidence helper source hash does not match metadata",
                producer_source_issues(meta, paths),
            )

    def test_phase_markers_must_be_monotonic_and_nonoverlapping(self):
        phases, incomplete, _, _, issues = parse_phase_marker_lines(
            [
                "baseline\tstart\t100\t1970-01-01T00:01:40Z\n",
                "stress\tstart\t101\t1970-01-01T00:01:41Z\n",
                "baseline\tend\t102\t1970-01-01T00:01:42Z\n",
                "stress\tend\t103\t1970-01-01T00:01:43Z\n",
            ],
            ["baseline", "stress"],
        )
        self.assertEqual(incomplete, set())
        self.assertEqual([phase[0] for phase in phases], ["baseline", "stress"])
        self.assertTrue(any("started before" in issue for issue in issues))
        self.assertTrue(any("overlaps" in issue for issue in issues))

        _, _, _, _, reversed_issues = parse_phase_marker_lines(
            [
                "stress\tstart\t100\t1970-01-01T00:01:40Z\n",
                "stress\tend\t101\t1970-01-01T00:01:41Z\n",
                "baseline\tstart\t101\t1970-01-01T00:01:41Z\n",
                "baseline\tend\t102\t1970-01-01T00:01:42Z\n",
            ],
            ["baseline", "stress"],
        )
        self.assertTrue(any("out of order" in issue for issue in reversed_issues))

    def test_phase_markers_require_exact_schema_and_matching_utc_iso(self):
        expected = ["baseline"]
        for row in (
            "baseline\tstart\t100\n",
            "baseline\tstart\t100\t1970-01-01T00:01:40Z\textra\n",
        ):
            phases, _, _, _, issues = parse_phase_marker_lines([row], expected)
            self.assertEqual(phases, [])
            self.assertIn("malformed phase marker at line 1", issues)

        _, _, _, _, invalid_iso = parse_phase_marker_lines(
            ["baseline\tstart\t100\t1970-01-01 00:01:40Z\n"], expected
        )
        self.assertIn("invalid phase ISO timestamp at line 1", invalid_iso)
        _, _, _, _, mismatch = parse_phase_marker_lines(
            ["baseline\tstart\t100.5\t1970-01-01T00:01:41Z\n"], expected
        )
        self.assertIn("phase epoch/ISO mismatch at line 1", mismatch)
        _, _, _, _, negative = parse_phase_marker_lines(
            ["baseline\tstart\t-1\t1969-12-31T23:59:59Z\n"], expected
        )
        self.assertIn("invalid phase timestamp at line 1", negative)

    def test_baseline_occupancy_is_not_run_peak_evidence(self):
        rows = [
            (
                90,
                "tproxy live-flow counts tcp=480 udp=0 total=480 peak=480 "
                "softCap=450 hardCap=0 retiring=0 retirementOverlap=0 "
                "pressure[triggers=1 scans=1 skipped=0 selected=10 "
                "evicted=10 spared=0 canceled=0 expired=0 pending=0]",
            ),
            (
                120,
                "tproxy live-flow counts tcp=25 udp=0 total=25 peak=480 "
                "softCap=450 hardCap=0 retiring=0 retirementOverlap=0 "
                "pressure[triggers=0 scans=0 skipped=0 selected=0 "
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
                "softCap=450 hardCap=0 retiring=0 retirementOverlap=0 "
                "pressure[triggers=0 scans=0 skipped=0 selected=0 "
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
                "softCap=450 hardCap=0 retiring=0 retirementOverlap=0 "
                "pressure[triggers=0 scans=0 skipped=0 selected=0 "
                "evicted=0 spared=0 canceled=0 expired=0 pending=0]",
            ),
            (
                100.25,
                "tproxy live-flow counts tcp=25 udp=0 total=25 peak=480 "
                "softCap=450 hardCap=0 retiring=0 retirementOverlap=0 "
                "pressure[triggers=0 scans=0 skipped=0 selected=0 "
                "evicted=0 spared=0 canceled=0 expired=0 pending=0]",
            ),
            (
                100.75,
                "tproxy live-flow counts tcp=30 udp=0 total=30 peak=500 "
                "softCap=450 hardCap=0 retiring=0 retirementOverlap=0 "
                "pressure[triggers=0 scans=0 skipped=0 selected=0 "
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
                "softCap=450 hardCap=0 retiring=0 retirementOverlap=0 "
                "pressure[triggers=1 scans=1 skipped=0 selected=1 "
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

    def test_unjoined_capture_children_and_stale_baseline_are_incomplete(self):
        meta = self.complete_meta()
        meta.update(
            log_stream_joined="0",
            probe_monitor_joined="0",
            baseline_gauge_phase_local="0",
        )
        issues = soak_evidence_issues(
            meta,
            rows_count=2,
            gauge_count=2,
            probe_count=2,
            final_gauge_required=False,
        )
        self.assertIn("log stream capture was not quiesced and joined", issues)
        self.assertIn("probe monitor capture was not quiesced and joined", issues)
        self.assertIn(
            "baseline gauge was not captured within the baseline phase", issues
        )

        bad_outcomes = self.complete_meta()
        bad_outcomes.update(
            log_stream_child_rc="137",
            probe_monitor_child_rc="missing",
        )
        outcome_issues = soak_evidence_issues(
            bad_outcomes,
            rows_count=2,
            gauge_count=2,
            probe_count=2,
            final_gauge_required=False,
        )
        self.assertIn("log stream child outcome is missing or invalid", outcome_issues)
        self.assertIn(
            "probe monitor child outcome is missing or invalid", outcome_issues
        )

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

    def test_phase_probe_coverage_uses_full_request_intervals(self):
        issues = soak_evidence_issues(
            self.complete_meta(),
            rows_count=20,
            gauge_count=3,
            probe_count=2,
            phase_coverage=[
                (
                    "stress",
                    parse_epoch("100"),
                    parse_epoch("140"),
                    [
                        (parse_epoch("105"), parse_epoch("125")),
                        (parse_epoch("130"), parse_epoch("139")),
                    ],
                    [],
                )
            ],
            final_gauge_required=False,
            maximum_probe_gap=6,
        )
        self.assertNotIn("phase 'stress' has no liveness probe coverage", issues)
        self.assertFalse(any("liveness probe gap" in issue for issue in issues))

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

        fanout_failed = classify_soak_result(
            self.complete_meta(),
            [],
            probe_failures=0,
            body_errors=0,
            reaper_status="disabled",
            fanout_failures=2,
        )
        self.assertTrue(fanout_failed["complete"])
        self.assertEqual(fanout_failed["exit_code"], 1)
        self.assertIn(
            "2 active fanout transfer failure(s) were observed",
            fanout_failed["failures"],
        )

        udp_failed = classify_soak_result(
            self.complete_meta(),
            [],
            probe_failures=0,
            body_errors=0,
            reaper_status="disabled",
            udp_pressure_failures=[
                "1 UDP ingress pressure drop transition(s) were observed"
            ],
        )
        self.assertEqual(udp_failed["exit_code"], 1)
        self.assertTrue(udp_failed["failures"])

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

    def test_result_rejects_unknown_mode_and_noncanonical_numeric_inputs(self):
        invalid_mode = self.complete_meta("typo-mode")
        result = classify_soak_result(
            invalid_mode,
            [],
            probe_failures=0,
            body_errors=0,
            reaper_status="disabled",
        )
        self.assertEqual(result["exit_code"], 2)
        self.assertIn("run mode is missing or invalid", result["evidence_issues"])

        result = classify_soak_result(
            self.complete_meta(),
            [],
            probe_failures="1.0",
            body_errors=-1,
            reaper_status="disabled",
            leak_count=True,
        )
        self.assertEqual(result["exit_code"], 2)
        self.assertIn("probe failure count is missing or invalid", result["evidence_issues"])
        self.assertIn("body error count is missing or invalid", result["evidence_issues"])
        self.assertIn("leak count is missing or invalid", result["evidence_issues"])

    def test_final_allocated_flows_must_settle_to_baseline(self):
        result = classify_soak_result(
            self.complete_meta(),
            [],
            probe_failures=0,
            body_errors=0,
            reaper_status="disabled",
            baseline_total=5,
            final_total=500,
            settlement_tolerance=5,
        )
        self.assertTrue(result["complete"])
        self.assertEqual(result["exit_code"], 1)

        log_failure = classify_soak_result(
            self.complete_meta(),
            [],
            probe_failures=0,
            body_errors=0,
            reaper_status="good",
            provider_faults=1,
            unknown_provider_errors=2,
        )
        self.assertTrue(log_failure["complete"])
        self.assertEqual(log_failure["exit_code"], 1)
        self.assertIn("1 provider Fault log(s) were observed", log_failure["failures"])
        self.assertIn(
            "2 unclassified provider Error log(s) were observed",
            log_failure["failures"],
        )
        self.assertIn(
            "final allocated-flow total did not settle to the baseline tolerance "
            "(500 > 5 + 5)",
            result["failures"],
        )

        missing = classify_soak_result(
            {**self.complete_meta(), "final_total": "missing"},
            [],
            probe_failures=0,
            body_errors=0,
            reaper_status="disabled",
        )
        self.assertEqual(missing["exit_code"], 2)
        self.assertIn(
            "final allocated-flow total is missing or invalid",
            missing["evidence_issues"],
        )

    def test_known_raw_pool_failure_survives_missing_correlation(self):
        for correlated_key, raw_key, label in (
            ("fanout_ok", "fanout_established_target_sustained", "fanout target"),
            (
                "idle_holders_ok",
                "idle_holders_established_target_sustained",
                "idle-holder target",
            ),
        ):
            with self.subTest(label=label):
                meta = self.complete_meta()
                meta[raw_key] = "0"
                meta[correlated_key] = None
                result = classify_soak_result(
                    meta,
                    [f"{label} has no provider flow-pool bracket"],
                    probe_failures=0,
                    body_errors=0,
                    reaper_status="disabled",
                )
                self.assertEqual(result["exit_code"], 2)
                self.assertIn(f"{label} failed", result["failures"])
                self.assertIn(
                    f"{label} outcome is missing", result["evidence_issues"]
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

    def test_flow_pool_uses_registered_or_allocated_cap_metric(self):
        phase = ("fanout", parse_epoch("100"), parse_epoch("200"))

        def samples(*rows):
            gauges = [
                (parse_epoch(epoch), registered, allocated)
                for epoch, registered, allocated in rows
            ]
            occupancy = [(epoch, registered) for epoch, registered, _ in gauges]
            return occupancy, gauges

        def bracket(baseline, peak, post, contribution):
            return (
                baseline[0], baseline[1], baseline[2],
                peak[0], peak[1], peak[2],
                post[0], post[1], post[2], contribution,
            )

        base_rows = (("105", 5, 5), ("115", 105, 105), ("140", 5, 5))
        occupancy, gauges = samples(*base_rows)
        base_bracket = bracket(*base_rows, 100)
        self.assertEqual(
            flow_pool_status(
                "1", 100, occupancy, gauges, 0, 0,
                [("110", "120")], phase, base_bracket
            ),
            "1",
        )

        cap_rows = (("105", 5, 5), ("115", 80, 80), ("140", 5, 5))
        cap_occupancy, cap_gauges = samples(*cap_rows)
        self.assertEqual(
            flow_pool_status(
                "1", 100, cap_occupancy, cap_gauges, 80, 0,
                [("110", "120")], phase, bracket(*cap_rows, 75)
            ),
            "1",
            "soft-cap correlation uses registered flows",
        )
        self.assertEqual(
            flow_pool_status(
                "1", 100, cap_occupancy, cap_gauges, 80, 80,
                [("110", "120")], phase, bracket(*cap_rows, 75)
            ),
            "1",
            "an equal hard cap still admits the transition that reaches softCap",
        )
        self.assertEqual(
            flow_pool_status(
                "0", 100, cap_occupancy, cap_gauges, 80, 80,
                [], phase, bracket(*cap_rows, 75)
            ),
            "0",
            "equal caps preserve a validated raw workload failure",
        )

        cleared_retiring_rows = (
            ("105", 5, 6), ("115", 80, 80), ("140", 5, 5),
        )
        cleared_occupancy, cleared_gauges = samples(*cleared_retiring_rows)
        self.assertEqual(
            flow_pool_status(
                "1", 100, cleared_occupancy, cleared_gauges, 80, 80,
                [("110", "120")], phase,
                bracket(*cleared_retiring_rows, 74),
            ),
            "1",
            "baseline retirement may clear before the equal-cap peak",
        )

        over_hard_rows = (
            ("105", 5, 5), ("115", 80, 81), ("140", 5, 5),
        )
        over_hard_occupancy, over_hard_gauges = samples(*over_hard_rows)
        self.assertIsNone(
            flow_pool_status(
                "1", 100, over_hard_occupancy, over_hard_gauges, 80, 80,
                [("110", "120")], phase,
                bracket(*over_hard_rows, 75),
            ),
            "allocated resources cannot exceed an enabled hard cap",
        )

        strict_hard_limit_rows = (
            ("105", 5, 5), ("115", 55, 55), ("140", 5, 5),
        )
        strict_limit_occupancy, strict_limit_gauges = samples(
            *strict_hard_limit_rows
        )
        self.assertIsNone(
            flow_pool_status(
                "1", 50, strict_limit_occupancy, strict_limit_gauges, 80, 60,
                [("110", "120")], phase,
                bracket(*strict_hard_limit_rows, 50),
            ),
            "a hard cap strictly below softCap cannot reach the trigger",
        )

        retiring_only_rows = (
            ("105", 60, 60), ("115", 60, 80), ("140", 60, 60),
        )
        retiring_occupancy, retiring_gauges = samples(*retiring_only_rows)
        self.assertIsNone(
            flow_pool_status(
                "1", 20, retiring_occupancy, retiring_gauges, 80, 0,
                [("110", "120")], phase,
                bracket(*retiring_only_rows, 20),
            ),
            "retiring allocations cannot masquerade as soft-cap worker growth",
        )

        equality_blocked_rows = (
            ("105", 5, 6), ("115", 79, 80), ("140", 5, 5),
        )
        equality_blocked_occupancy, equality_blocked_gauges = samples(
            *equality_blocked_rows
        )
        self.assertEqual(
            flow_pool_status(
                "1", 74, equality_blocked_occupancy, equality_blocked_gauges,
                80, 80, [("110", "120")], phase,
                bracket(*equality_blocked_rows, 74),
            ),
            "1",
            "correlation can prove only the effective headroom while mode logic "
            "separately marks the trigger unreachable",
        )

        hard_rows = (("105", 5, 5), ("115", 75, 80), ("140", 5, 5))
        hard_occupancy, hard_gauges = samples(*hard_rows)
        self.assertEqual(
            flow_pool_status(
                "1", 100, hard_occupancy, hard_gauges, 0, 80,
                [("110", "120")], phase, bracket(*hard_rows, 75),
            ),
            "1",
            "with softCap disabled, hardCap correlation uses allocated flows",
        )

        smaller_rows = (("105", 5, 5), ("115", 55, 55), ("140", 5, 5))
        smaller_occupancy, smaller_gauges = samples(*smaller_rows)
        self.assertIsNone(
            flow_pool_status(
                "1", 100, smaller_occupancy, smaller_gauges, 80, 0,
                [("110", "120")], phase,
                bracket(*smaller_rows, 75),
            )
        )
        self.assertIsNone(
            flow_pool_status(
                "1", 100, occupancy[:-1], gauges[:-1], 0, 0,
                [("110", "120")], phase, base_bracket
            ),
            "missing post-kill provider evidence is inconclusive",
        )

        bad_post = (("105", 5, 5), ("115", 105, 105), ("140", 20, 20))
        bad_occupancy, bad_gauges = samples(*bad_post)
        self.assertIsNone(
            flow_pool_status(
                "1", 100, bad_occupancy, bad_gauges, 0, 0,
                [("110", "120")], phase, bracket(*bad_post, 100),
            )
        )
        self.assertIsNone(
            flow_pool_status(
                "1", 100, occupancy, [gauges[1]], 0, 0,
                [("110", "120")], phase, base_bracket,
            ),
            "event occupancy cannot replace missing baseline/post gauges",
        )

        later_rows = (("105", 5, 5), ("135", 105, 105), ("150", 5, 5))
        later_occupancy, later_gauges = samples(*later_rows)
        self.assertEqual(
            flow_pool_status(
                "1", 100, later_occupancy, later_gauges, 0, 0,
                [("110", "120"), ("130", "140")], phase,
                bracket(*later_rows, 100),
            ),
            "1",
        )

        self.assertIsNone(
            flow_pool_status(
                "1", 100, cap_occupancy, cap_gauges, 80, 0,
                [("110", "120")], phase, bracket(*cap_rows, 100),
            )
        )
        self.assertIsNone(
            flow_pool_status(
                "1", 100, cap_occupancy, cap_gauges, 80, 60,
                [("110", "120")], phase, bracket(*cap_rows, 55),
            )
        )

    def test_known_pool_failure_cannot_bypass_correlation_validation(self):
        self.assertIsNone(
            flow_pool_status("0", None, [], [], 0, 0, [], None, None),
        )

    def test_pool_success_requires_the_full_configured_hold(self):
        phase = ("fanout", parse_epoch("100"), parse_epoch("250"))
        rows = (("105", 5, 5), ("115", 105, 105), ("220", 5, 5))
        gauges = [
            (parse_epoch(epoch), registered, allocated)
            for epoch, registered, allocated in rows
        ]
        occupancy = [(epoch, registered) for epoch, registered, _ in gauges]
        bracket = (
            "105", 5, 5, "115", 105, 105, "220", 5, 5, 100,
        )
        common = (
            "1", 100, occupancy, gauges, 0, 0,
        )
        self.assertIsNone(
            _flow_pool_status(*common, [("110", "200")], phase, bracket),
            "artifact validation must not invent an omitted hold duration",
        )
        self.assertEqual(
            flow_pool_status(
                *common, [("110", "200")], phase, bracket,
                required_hold_seconds=90,
            ),
            "1",
        )
        self.assertIsNone(
            flow_pool_status(
                *common, [("110", "199.999999")], phase, bracket,
                required_hold_seconds=90,
            )
        )
        self.assertEqual(
            flow_pool_evidence_issues("fanout", "0", None, False),
            ["fanout has no provider flow-pool bracket"],
        )

        phase = ("fanout", parse_epoch("100"), parse_epoch("200"))
        occupancy = [(parse_epoch("115"), 5)]
        gauges = [
            (parse_epoch("105"), 5, 5),
            (parse_epoch("115"), 5, 5),
            (parse_epoch("140"), 5, 5),
        ]
        bracket = ("105", 5, 5, "115", 5, 5, "140", 5, 5, 100)
        self.assertEqual(
            flow_pool_status(
                "0", 100, occupancy, gauges, 0, 0, [], phase, bracket
            ),
            "0",
            "the raw workload failure survives once its provider bracket validates",
        )
        self.assertIsNone(
            flow_pool_status(
                "0", 100, occupancy, gauges, 0, 0, [], phase,
                (*bracket[:-1], 99),
            ),
            "a raw failure cannot bless a contradictory contribution field",
        )

    def test_sleep_wake_requires_ordered_command_local_events_and_recovery(self):
        skipped = sleep_wake_evidence(
            "skipped", "skipped", None, None, [], [], [], None
        )
        self.assertEqual(skipped, {"issues": [], "outage_window": None})

        workload = {
            "started": "91",
            "established": "95",
            "http_code": "200",
            "alive_at_command": "1",
            "established_nonzero_bytes": "1",
            "established_bytes": "64",
            "child_rc": "143",
            "joined": "1",
        }

        recovered = sleep_wake_evidence(
            "1", "1", "100", "151", ["110"], ["150"],
            [(parse_epoch("151.1"), parse_epoch("152"), 0, "200")],
            ("sleep-wake", parse_epoch("90"), parse_epoch("160")),
            workload_evidence=workload,
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
            workload_evidence=workload,
        )
        self.assertTrue(any("ordered" in issue for issue in reversed_events["issues"]))

        later_cycle = sleep_wake_evidence(
            "1", "1", "100", "151", ["170"], ["180"],
            [(parse_epoch("181"), parse_epoch("182"), 0, "200")],
            ("sleep-wake", parse_epoch("90"), parse_epoch("160")),
            workload_evidence=workload,
        )
        self.assertTrue(any("ordered" in issue for issue in later_cycle["issues"]))

        truncated_200 = sleep_wake_evidence(
            "1", "1", "100", "151", ["110"], ["150"],
            [(parse_epoch("151"), parse_epoch("152"), 18, "200")],
            ("sleep-wake", parse_epoch("90"), parse_epoch("160")),
            workload_evidence=workload,
        )
        self.assertTrue(
            any("successful paired probe" in issue for issue in truncated_200["issues"])
        )

        failed_command = sleep_wake_evidence(
            "0", "1", "100", "101", [], [],
            [(parse_epoch("102"), parse_epoch("103"), 0, "200")],
            ("sleep-wake", parse_epoch("90"), parse_epoch("110")),
            workload_evidence=workload,
        )
        self.assertEqual(failed_command["issues"], [])
        self.assertIsNone(failed_command["outage_window"])

        missing_workload = sleep_wake_evidence(
            "1", "1", "100", "151", ["110"], ["150"],
            [(parse_epoch("151.1"), parse_epoch("152"), 0, "200")],
            ("sleep-wake", parse_epoch("90"), parse_epoch("160")),
        )
        self.assertIn(
            "sleep-wake phase has no in-flight workload evidence",
            missing_workload["issues"],
        )

        empty_body = sleep_wake_evidence(
            "1", "1", "100", "151", ["110"], ["150"],
            [(parse_epoch("151.1"), parse_epoch("152"), 0, "200")],
            ("sleep-wake", parse_epoch("90"), parse_epoch("160")),
            workload_evidence={
                **workload,
                "established_nonzero_bytes": "0",
                "established_bytes": "0",
            },
        )
        self.assertIn(
            "sleep-wake workload lacks established nonzero body bytes",
            empty_body["issues"],
        )

    def test_sleep_wake_binds_actual_wake_and_one_bounded_lifecycle_pair(self):
        workload = {
            "started": "91", "established": "95", "http_code": "200",
            "alive_at_command": "1", "established_nonzero_bytes": "1",
            "established_bytes": "64", "child_rc": "143", "joined": "1",
        }
        def proof(sleeps=("110",), wakes=("150",), probe_start="151", probe_end="152"):
            return sleep_wake_evidence(
                "1", "1", "100", "101", sleeps, wakes,
                [(parse_epoch(probe_start), parse_epoch(probe_end), 0, "200")],
                ("sleep-wake", parse_epoch("90"), parse_epoch("300")),
                workload_evidence=workload,
            )
        # pmset's successful return precedes both genuine lifecycle edges.
        recovered = proof()
        self.assertEqual(recovered["issues"], [])
        self.assertEqual(recovered["outage_window"], (parse_epoch("110"), parse_epoch("150")))
        self.assertEqual(proof(wakes=("230",), probe_start="231", probe_end="232")["issues"], [])
        for arguments, reason in (
            ({"sleeps": ("110", "111")}, "exactly one ordered"),
            ({"wakes": ("150", "151")}, "exactly one ordered"),
            ({"wakes": ()}, "exactly one ordered"),
            ({"sleeps": ("invalid",)}, "exactly one ordered"),
            ({"wakes": ("105",)}, "exactly one ordered"),
            ({"wakes": ("300",)}, "exactly one ordered"),
            ({"wakes": ("230.000001",), "probe_start": "231", "probe_end": "232"}, "120-second bound"),
            ({"probe_start": "102", "probe_end": "103"}, "after the wake marker"),
            ({"probe_start": "149", "probe_end": "151"}, "after the wake marker"),
        ):
            with self.subTest(arguments=arguments):
                result = proof(**arguments)
                self.assertIsNone(result["outage_window"])
                self.assertTrue(any(reason in issue for issue in result["issues"]), result)

    def test_ceiling_proof_is_microsecond_precise_half_open_and_consecutive(self):
        records, issues = parse_ceiling_probe_lines(
            [
                "100.090000\t100.099999\t28\t000\t510\t100.089999\n",
                "100.100000\t100.100010\t28\t000\t510\t100.100000\n",
                "100.100011\t100.100020\t28\t000\t511\t100.100010\n",
                "100.500000\t100.500010\t0\t200\t511\t100.400000\n",
                "101.099999\t101.100000\t28\t000\t512\t101.099999\n",
            ]
        )
        self.assertEqual(issues, [])
        phase = ("ceiling", parse_epoch("100.100000"), parse_epoch("101.100000"))
        gauges = [(record[5], record[4]) for record in records]
        allocation_epochs = [parse_epoch("100.100015")]
        self.assertEqual(
            ceiling_probe_evidence_issues(
                records, "1", 500, phase, "1", gauges, allocation_epochs
            ),
            [],
        )
        self.assertNotEqual(
            ceiling_probe_evidence_issues(
                records[:2], "1", 500, phase, None, gauges, allocation_epochs
            ),
            [],
        )
        low = [
            (parse_epoch("100.2"), parse_epoch("100.21"), 28, "000", 500,
             parse_epoch("100.2")),
            (parse_epoch("100.3"), parse_epoch("100.31"), 28, "000", 501,
             parse_epoch("100.3")),
        ]
        self.assertNotEqual(
            ceiling_probe_evidence_issues(
                low, "1", 500, phase, None,
                [(record[5], record[4]) for record in low], allocation_epochs,
            ),
            [],
        )
        stale = [
            (parse_epoch("100.2"), parse_epoch("100.21"), 28, "000", 510,
             parse_epoch("99.9")),
            (parse_epoch("100.3"), parse_epoch("100.31"), 28, "000", 511,
             parse_epoch("99.9")),
        ]
        self.assertNotEqual(
            ceiling_probe_evidence_issues(
                stale, "1", 500, phase, None,
                [(record[5], record[4]) for record in stale], allocation_epochs,
            ),
            [],
        )
        window = ceiling_outage_window(
            records, 500, phase, gauges, allocation_epochs
        )
        self.assertEqual(
            window, (parse_epoch("100.100010"), parse_epoch("100.500010"))
        )
        application_failures = [
            (parse_epoch("100.2"), parse_epoch("100.21"), 0, "503", 510,
             parse_epoch("100.2")),
            (parse_epoch("100.3"), parse_epoch("100.31"), 0, "503", 511,
             parse_epoch("100.3")),
            (parse_epoch("100.4"), parse_epoch("100.41"), 0, "200", 511,
             parse_epoch("100.4")),
        ]
        self.assertIsNone(
            ceiling_outage_window(
                application_failures,
                500,
                phase,
                [(record[5], record[4]) for record in application_failures],
                allocation_epochs,
            )
        )
        self.assertNotEqual(
            ceiling_probe_evidence_issues(
                application_failures,
                "1",
                500,
                phase,
                "1",
                [(record[5], record[4]) for record in application_failures],
                allocation_epochs,
            ),
            [],
        )
        self.assertIsNone(
            ceiling_outage_window(records, 500, phase, gauges, []),
            "transport failures without provider allocation telemetry are heuristic",
        )
        mismatched_gauges = [(epoch, occupancy + 1) for epoch, occupancy in gauges]
        self.assertIsNone(
            ceiling_outage_window(
                records, 500, phase, mismatched_gauges, allocation_epochs
            ),
            "probe occupancy must be an exact accepted provider gauge tuple",
        )
        tls_failures = [
            (parse_epoch("100.2"), parse_epoch("100.21"), 60, "000", 510,
             parse_epoch("100.2")),
            (parse_epoch("100.3"), parse_epoch("100.31"), 60, "000", 511,
             parse_epoch("100.3")),
        ]
        self.assertIsNone(
            ceiling_outage_window(
                tls_failures,
                500,
                phase,
                [(record[5], record[4]) for record in tls_failures],
                [parse_epoch("100.25")],
            ),
            "TLS failures cannot prove a kernel ceiling even near ENOBUFS",
        )
        failures = [
            (parse_epoch("100.000000"), parse_epoch("100.100009"), 28, "000"),
            (parse_epoch("100.000000"), parse_epoch("100.100010"), 28, "000"),
            (parse_epoch("100.400000"), parse_epoch("100.600000"), 28, "000"),
            (parse_epoch("100.500010"), parse_epoch("100.600000"), 28, "000"),
        ]
        self.assertEqual(
            unexpected_probe_failure_count(failures, window),
            2,
            "straddling failures overlap the outage; failures wholly before or "
            "starting at recovery stay reportable",
        )

        later_window = (parse_epoch("100.550000"), parse_epoch("100.700000"))
        self.assertEqual(
            unexpected_probe_failure_count_across_outages(
                failures, [window, later_window]
            ),
            1,
            "each full failed request is waived once if it overlaps any proved outage",
        )

        overlapping, overlap_issues = parse_ceiling_probe_lines(
            [
                "100.000000\t100.200000\t28\t000\t501\t99.900000\n",
                "100.100000\t100.300000\t28\t000\t502\t100.050000\n",
            ]
        )
        self.assertEqual(len(overlapping), 1)
        self.assertIn("out-of-order ceiling probe at line 2", overlap_issues)

        _, whitespace_issues = parse_ceiling_probe_lines(
            [" 100.000000\t100.100000\t28\t000\t501\t99.900000\n"]
        )
        self.assertIn("malformed ceiling probe at line 1", whitespace_issues)

    def test_paired_probe_requires_ordered_timing_rc_and_status(self):
        records, issues = parse_probe_lines(
            [
                "100.000000\t100.100000\t1970-01-01T00:01:40Z\t0\t200\n",
                "101.000000\t101.100000\t1970-01-01T00:01:41Z\t18\t200\n",
            ]
        )
        self.assertEqual(issues, [])
        self.assertTrue(probe_succeeded(records[0]))
        self.assertFalse(probe_succeeded(records[1]))

        _, malformed = parse_probe_lines(
            [
                "102\t101\t1970-01-01T00:01:41Z\t0\t200\n",
                "100\t101\t1970-01-01T00:01:41Z\tnan\t200\n",
                "100\t101\tnot-iso\t0\t200\n",
                "100\t101\t1970-01-01T00:01:40Z\t0\t200\n",
                "1e2\t101\t1970-01-01T00:01:41Z\t0\t200\n",
            ]
        )
        self.assertEqual(len(malformed), 5)

        overlapping, overlap_issues = parse_probe_lines(
            [
                "100.000000\t101.000000\t1970-01-01T00:01:41Z\t0\t200\n",
                "100.500000\t102.000000\t1970-01-01T00:01:42Z\t0\t200\n",
            ]
        )
        self.assertEqual(len(overlapping), 1)
        self.assertIn("out-of-order liveness probe at line 2", overlap_issues)

    def test_leaks_output_requires_one_parseable_summary(self):
        self.assertEqual(
            parse_leaks_output("Process 42: 0 leaks for 0 total leaked bytes."),
            {"process_pid": 42, "leaks": 0, "bytes": 0},
        )
        self.assertEqual(
            parse_leaks_output(
                "Process 42: 1,234 leaks for 56,789 total leaked bytes."
            ),
            {"process_pid": 42, "leaks": 1234, "bytes": 56789},
        )
        self.assertIsNone(parse_leaks_output("leaks could not examine process"))
        self.assertIsNone(
            parse_leaks_output(
                "0 leaks for 0 total leaked bytes\n1 leak for 8 total leaked bytes"
            )
        )

        self.assertEqual(
            leak_evidence(0, "Process 42: 0 leaks for 0 total leaked bytes."),
            {"issues": [], "process_pid": 42, "leaks": 0, "bytes": 0},
        )
        self.assertEqual(
            leak_evidence(1, "Process 42: 2 leaks for 64 total leaked bytes."),
            {"issues": [], "process_pid": 42, "leaks": 2, "bytes": 64},
        )
        self.assertIn(
            "leaks output is not attributed to the exact provider PID",
            leak_evidence(
                0,
                "Process 99: 0 leaks for 0 total leaked bytes.",
                expected_pid="42",
            )["issues"],
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
                [
                    "complete\t1\n", "passed\t0\n", "exit_code\t1\n",
                    "failure\tworkload failed\n", "schema_complete\t1\n",
                ]
            ),
            1,
        )
        self.assertEqual(
            parse_evidence_status_lines(
                [
                    "complete\t0\n", "passed\t0\n", "exit_code\t2\n",
                    "issue\tmissing evidence\n", "schema_complete\t1\n",
                ]
            ),
            2,
        )
        self.assertIsNone(
            parse_evidence_status_lines(
                [
                    "complete\t1\n", "passed\t1\n", "exit_code\t0\n",
                    "issue\tcontradiction\n", "schema_complete\t1\n",
                ]
            )
        )
        self.assertIsNone(
            parse_evidence_status_lines(
                [
                    "passed\t0\n", "complete\t0\n", "exit_code\t2\n",
                    "issue\tmissing\n", "schema_complete\t1\n",
                ]
            )
        )
        self.assertIsNone(
            parse_evidence_status_lines(
                [
                    "complete\t0\n", "passed\t0\n", "exit_code\t2\n",
                    "issue\t\n", "schema_complete\t1\n",
                ]
            )
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
        require_loopback_round_trip(self)
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
                STRESS_HTTPS_TARGET="https://127.0.0.1:1",
                STRESS_LARGE_TARGET="https://127.0.0.1:1/refused-large",
                STRESS_POST_TARGET="https://127.0.0.1:1/refused-post",
            )
            result = subprocess.run(
                ["bash", str(script)],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=15,
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
        require_loopback_round_trip(self)
        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind(("127.0.0.1", 0))
        except PermissionError:
            server.close()
            self.skipTest("host sandbox does not permit loopback sockets")
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
            with tempfile.TemporaryDirectory() as log_dir, tempfile.TemporaryDirectory() as tool_dir:
                env = os.environ.copy()
                http_target = f"http://127.0.0.1:{port}/truncated"
                https_target = f"https://127.0.0.1:{port}/truncated"
                curl_wrapper = Path(tool_dir) / "test-curl"
                curl_wrapper.write_text(
                    "#!/usr/bin/env bash\n"
                    "[[ \"$1\" == --disable && \"$2\" == --noproxy "
                    "&& \"$3\" == '*' && \"$4\" == --proxy && -z \"$5\" ]] || exit 91\n"
                    "[[ -z \"${HTTP_PROXY:-}${HTTPS_PROXY:-}${ALL_PROXY:-}"
                    "${http_proxy:-}${https_proxy:-}${all_proxy:-}\" ]] || exit 92\n"
                    "args=()\n"
                    "for arg in \"$@\"; do\n"
                    "  if [[ \"$arg\" == https://127.0.0.1:* ]]; then\n"
                    "    arg=\"http://${arg#https://}\"\n"
                    "  fi\n"
                    "  args+=(\"$arg\")\n"
                    "done\n"
                    "exec /usr/bin/curl \"${args[@]}\"\n"
                )
                curl_wrapper.chmod(0o755)
                curl_home = Path(tool_dir) / "home"
                curl_home.mkdir()
                (curl_home / ".curlrc").write_text(
                    "--proxy http://127.0.0.1:1\n--request DELETE\n"
                )
                env.update(
                    STRESS_DURATION="1",
                    STRESS_CONCURRENCY="1",
                    STRESS_POST_BYTES="1",
                    STRESS_SKIP_LIVENESS="1",
                    STRESS_LOG_DIR=log_dir,
                    STRESS_HTTP_TARGET=http_target,
                    STRESS_HTTPS_TARGET=https_target,
                    STRESS_LARGE_TARGET=https_target,
                    STRESS_POST_TARGET=https_target,
                    STRESS_CURL_TOOL=str(curl_wrapper),
                    STRESS_ALLOW_TEST_TOOLS="1",
                    CURL_HOME=str(curl_home),
                    HTTP_PROXY="http://127.0.0.1:1",
                    HTTPS_PROXY="http://127.0.0.1:1",
                    ALL_PROXY="http://127.0.0.1:1",
                )
                result = subprocess.run(
                    ["bash", str(script)],
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=15,
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

    def test_dial9_evidence_requires_newer_hash_matched_sealed_pair(self):
        content = b"current trace"
        meta = {
            "dial9_baseline_ready": "1",
            "dial9_baseline_max_index": "7",
            "dial9_collection_ok": "1",
            "dial9_current_segment_count": "1",
            "dial9_required_pair_count": "1",
        }
        with tempfile.TemporaryDirectory() as trace_dir:
            path = Path(trace_dir) / "trace.8.bin"
            path.write_bytes(content)
            summary = {
                "schema_version": 1,
                "schema_complete": True,
                "baseline_max_index": 7,
                "current_segment_count": 1,
                "current_indices": [8],
                "required_pair_count": 1,
                "artifacts": [{
                    "name": path.name,
                    "index": 8,
                    "state": "sealed",
                    "encoding": "raw",
                    "size": len(content),
                    "sha256": hashlib.sha256(content).hexdigest(),
                }],
            }
            self.assertEqual(dial9_evidence_issues(meta, summary, trace_dir), [])

            stale = dict(meta, dial9_baseline_max_index="8")
            self.assertTrue(any(
                "not newer" in issue
                for issue in dial9_evidence_issues(stale, summary, trace_dir)
            ))
            active = json.loads(json.dumps(summary))
            active["artifacts"][0]["state"] = "active"
            self.assertTrue(any(
                "not declared sealed" in issue
                for issue in dial9_evidence_issues(meta, active, trace_dir)
            ))
            malformed = json.loads(json.dumps(summary))
            malformed["artifacts"][0]["name"] = 8
            self.assertTrue(any(
                "non-canonical artifact name" in issue
                for issue in dial9_evidence_issues(meta, malformed, trace_dir)
            ))
            path.write_bytes(b"tampered")
            self.assertTrue(any(
                "hash identity" in issue
                for issue in dial9_evidence_issues(meta, summary, trace_dir)
            ))

    def test_embedded_extractor_wires_provider_ceiling_and_leak_verdicts(self):
        script_dir = Path(__file__).parent
        shell = (script_dir / "soak_test.sh").read_text()
        marker = "<<'PYEOF'\n"
        extractor = shell.split(marker, 1)[1].split("\nPYEOF", 1)[0]
        gauge = (
            "live-flow counts tcp=0 udp=0 total=0 peak=0 softCap=0 hardCap=0 "
            "retiring=0 retirementOverlap=0 "
            "pressure[triggers=0 scans=0 skipped=0 selected=0 evicted=0 "
            "spared=0 canceled=0 expired=0 pending=0]"
        )
        with tempfile.TemporaryDirectory() as artifact_dir:
            out = Path(artifact_dir)
            source_contents = {
                "soak_test": b"fixture soak source\n",
                "stress_traffic": b"fixture stress source\n",
                "soak_pressure_log": b"fixture parser source\n",
                "signed_run_evidence": b"fixture signed helper source\n",
            }
            source_files = {
                "soak_test": "source-soak_test.sh",
                "stress_traffic": "source-stress_traffic.sh",
                "soak_pressure_log": "source-soak_pressure_log.py",
                "signed_run_evidence": "source-signed_run_evidence.py",
            }
            source_hashes = {
                key: hashlib.sha256(content).hexdigest()
                for key, content in source_contents.items()
            }
            for key, filename in source_files.items():
                (out / filename).write_bytes(source_contents[key])
            profile_lines = canonical_release_soak_profile_lines()
            (out / "release-soak-profile.tsv").write_text("".join(profile_lines))
            release_profile_hash = hashlib.sha256(
                "".join(profile_lines).encode()).hexdigest()

            def write_meta(
                leaks_rc,
                provider_end_pid="10",
                softcap="0",
                hardcap="0",
                baseline_registered="0",
                baseline_total="0",
                mode="find-ceiling",
                outage_start="101.110000",
                outage_end="101.410000",
            ):
                (out / "run-meta.tsv").write_text(
                    f"repo_head\t{'1' * 40}\nrepo_dirty\t0\n"
                    f"soak_script_sha256\t{source_hashes['soak_test']}\n"
                    f"stress_script_sha256\t{source_hashes['stress_traffic']}\n"
                    f"pressure_parser_sha256\t{source_hashes['soak_pressure_log']}\n"
                    f"signed_evidence_helper_sha256\t{source_hashes['signed_run_evidence']}\n"
                    f"release_profile_sha256\t{release_profile_hash}\n"
                    "release_profile_eligible\t0\n"
                    "configured_stress_seconds\t180\n"
                    "configured_stress_concurrency\t24\n"
                    "configured_fanout_target\t40\n"
                    "configured_fanout_hold_seconds\t90\n"
                    "configured_idle_target\t40\n"
                    "configured_idle_hold_seconds\t150\n"
                    "configured_idle_tail_seconds\t135\n"
                    "configured_max_safe_flows\t300\n"
                    "configured_file_descriptor_limit\t16384\n"
                    "configured_skip_stress\t0\n"
                    "configured_skip_fanout\t0\n"
                    "configured_skip_idle\t0\n"
                    "configured_skip_sleep\t0\n"
                    "configured_allow_unsafe_load\t0\n"
                    "configured_live_hard_cap_enabled\t0\n"
                    "configured_no_spin_quiescence_seconds\t60\n"
                    "log_stream_started\t1\n"
                    "log_stream_alive_end\t1\n"
                    "log_stream_child_rc\t143\nlog_stream_joined\t1\n"
                    "baseline_gauge_seen\t1\n"
                    "baseline_gauge_phase_local\t1\n"
                    "probe_monitor_alive_end\t1\n"
                    "probe_monitor_child_rc\t143\nprobe_monitor_joined\t1\n"
                    "provider_continuous\t1\n"
                    "holder_cleanup_ok\t1\n"
                    "provider_start_pid\t10\nprovider_start_time\tstart\n"
                    f"provider_start_identity\t{'4' * 64}\n"
                    f"common_provider_generation_identity\t{'4' * 64}\n"
                    f"provider_end_pid\t{provider_end_pid}\nprovider_end_time\tstart\n"
                    f"provider_end_identity\t{'4' * 64}\n"
                    "provider_bundle\torg.example.provider\n"
                    "provider_executable\t/Applications/Provider\n"
                    "provider_executable_name\tProvider\n"
                    "crash_process_name\tProvider\n"
                    f"provider_binary_sha256\t{'5' * 64}\n"
                    "provider_codesign_identifier\torg.example.provider\n"
                    "provider_codesign_cdhash\tabcdef\n"
                    "provider_codesign_team\tTEAM123\n"
                    "common_provider_captured\t1\n"
                    "log_stream_pid\t20\nprobe_monitor_pid\t30\n"
                    "provider_generation_monitor_pid\t40\n"
                    "provider_generation_initial_captured\t1\n"
                    "provider_generation_monitor_alive_end\t1\n"
                    "provider_generation_monitor_child_rc\t143\n"
                    "provider_generation_monitor_joined\t1\n"
                    "provider_generation_monitor_forced\t0\n"
                    "provider_generation_sample_after_crash_ok\t1\n"
                    "udp_workload_exercised\t0\n"
                    "dial9_claim\tunattributed-diagnostic\n"
                    "dial9_diagnostic_only\t1\n"
                    "dial9_coverage_claimed\t0\n"
                    "pressure_gauge_schema_version\t2\n"
                    "run_uuid\t11111111-2222-3333-8444-555555555555\n"
                    "run_start_epoch_ms\t80000\n"
                    "run_end_epoch_ms\t173000\n"
                    "final_provider_observation_epoch_ms\t173000\n"
                    "final_provider_observation_pid\t10\n"
                    f"final_provider_observation_identity\t{'4' * 64}\n"
                    "final_provider_observation_ok\t1\n"
                    "crash_snapshot_epoch_ms\t173500\n"
                    "post_snapshot_provider_observation_epoch_ms\t174000\n"
                    "post_snapshot_provider_observation_pid\t10\n"
                    f"post_snapshot_provider_observation_identity\t{'4' * 64}\n"
                    "post_snapshot_provider_observation_ok\t1\n"
                    "cpu_sample_command_rc\t0\n"
                    "cpu_sample_joined\t1\n"
                    "cpu_sample_forced\t0\n"
                    "cpu_sample_privilege\tsudo\n"
                    "cpu_sample_ownership_normalized\t1\n"
                    "baseline_mem_child_rc\t0\n"
                    "baseline_mem_joined\t1\n"
                    "baseline_mem_forced\t0\n"
                    "baseline_mem_privilege\tsudo\n"
                    "baseline_mem_sudo_rc\t0\n"
                    "baseline_mem_ps_rc\t0\n"
                    "baseline_mem_vmmap_rc\t0\n"
                    "baseline_mem_start_epoch_ms\t92000\n"
                    "baseline_mem_end_epoch_ms\t93000\n"
                    "baseline_mem_provider_pid\t10\n"
                    f"baseline_mem_identity_before\t{'4' * 64}\n"
                    f"baseline_mem_identity_after\t{'4' * 64}\n"
                    "final_mem_child_rc\t0\n"
                    "final_mem_joined\t1\n"
                    "final_mem_forced\t0\n"
                    "final_mem_privilege\tsudo\n"
                    "final_mem_sudo_rc\t0\n"
                    "final_mem_ps_rc\t0\n"
                    "final_mem_vmmap_rc\t0\n"
                    "final_mem_heap_rc\t0\n"
                    "final_mem_heap_filter_rc\t0\n"
                    "final_mem_start_epoch_ms\t173100\n"
                    "final_mem_end_epoch_ms\t173200\n"
                    "final_mem_provider_pid\t10\n"
                    f"final_mem_identity_before\t{'4' * 64}\n"
                    f"final_mem_identity_after\t{'4' * 64}\n"
                    "idle_cpu_required_samples\t10\n"
                    "idle_cpu_interval_seconds\t1\n"
                    "idle_cpu_hot_percent\t90.0\n"
                    "idle_cpu_hot_streak\t5\n"
                    "idle_cpu_warm_percent\t80.0\n"
                    "idle_cpu_max_warm_samples\t4\n"
                    "idle_cpu_regression_allowance_percent\t5.0\n"
                    "idle_cpu_absolute_mean_ceiling_percent\t10.0\n"
                    "idle_cpu_baseline_probe_monitor_active\t1\n"
                    "idle_cpu_post_probe_monitor_active\t1\n"
                    "idle_cpu_post_quiescence_seconds\t60\n"
                    "idle_cpu_baseline_top_command_rc\t0\n"
                    "idle_cpu_baseline_top_joined\t1\n"
                    "idle_cpu_baseline_top_forced\t0\n"
                    "idle_cpu_baseline_top_privilege\tsudo\n"
                    f"idle_cpu_baseline_identity_before\t{'4' * 64}\n"
                    f"idle_cpu_baseline_identity_after\t{'4' * 64}\n"
                    "idle_cpu_post_top_command_rc\t0\n"
                    "idle_cpu_post_top_joined\t1\n"
                    "idle_cpu_post_top_forced\t0\n"
                    "idle_cpu_post_top_privilege\tsudo\n"
                    f"idle_cpu_post_identity_before\t{'4' * 64}\n"
                    f"idle_cpu_post_identity_after\t{'4' * 64}\n"
                    f"leaks_command_rc\t{leaks_rc}\n"
                    "leaks_joined\t1\nleaks_forced\t0\nleaks_privilege\tsudo\n"
                    "leaks_start_epoch_ms\t173200\n"
                    "leaks_end_epoch_ms\t173300\n"
                    "leaks_provider_pid\t10\n"
                    f"leaks_identity_before\t{'4' * 64}\n"
                    f"leaks_identity_after\t{'4' * 64}\n"
                    f"mode\t{mode}\n"
                    f"softcap\t{softcap}\nhardcap\t{hardcap}\n"
                    f"baseline_registered\t{baseline_registered}\n"
                    f"baseline_total\t{baseline_total}\n"
                    "dial9_baseline_ready\t1\n"
                    "dial9_baseline_max_index\t8\n"
                    "dial9_collection_ok\t1\n"
                    "dial9_current_segment_count\t1\n"
                    "dial9_required_pair_count\t1\n"
                    "dial9_collection_attempted\t0\n"
                    "ceiling_found\t1\nceiling_recovered\t1\n"
                    f"ceiling_outage_start\t{outage_start}\n"
                    f"ceiling_outage_end\t{outage_end}\n"
                )

            write_meta(0)
            self.write_memory_diagnostic_artifacts(out, artifact_pid=10)
            (out / "phases.tsv").write_text(
                "idle-baseline\tstart\t80.000000\t1970-01-01T00:01:20Z\n"
                "idle-baseline\tend\t91.000000\t1970-01-01T00:01:31Z\n"
                "baseline\tstart\t100.000000\t1970-01-01T00:01:40Z\n"
                "baseline\tend\t101.000000\t1970-01-01T00:01:41Z\n"
                "ceiling\tstart\t101.000000\t1970-01-01T00:01:41Z\n"
                "ceiling\tend\t102.000000\t1970-01-01T00:01:42Z\n"
                "no-spin\tstart\t102.000000\t1970-01-01T00:01:42Z\n"
                "no-spin\tend\t173.000000\t1970-01-01T00:02:53Z\n"
            )
            rows = [
                {
                    "timestamp": "1970-01-01 00:01:40.200000+0000",
                    "processID": 10,
                    "subsystem": "org.example.provider",
                    "category": "lifecycle",
                    "eventMessage": gauge,
                    "messageType": "Debug",
                },
                {
                    "timestamp": "1970-01-01 00:01:41.050000+0000",
                    "processID": 10,
                    "subsystem": "org.example.provider",
                    "category": "lifecycle",
                    "eventMessage": gauge.replace(
                        "total=0 peak=0", "total=1 peak=1"
                    ).replace("tcp=0", "tcp=1", 1),
                    "messageType": "Debug",
                },
                {
                    "timestamp": "1970-01-01 00:01:41.150000+0000",
                    "processID": 10,
                    "subsystem": "org.example.provider",
                    "category": "lifecycle",
                    "eventMessage": "kernel flow allocation exhausted: resource=nexus",
                    "messageType": "Error",
                },
            ]
            (out / "provider-timeline.tsv").write_text(
                f"100.100000\t{'4' * 64}\n101.900000\t{'4' * 64}\n"
            )
            (out / "system.ndjson").write_text(
                "".join(json.dumps(row) + "\n" for row in rows)
            )
            (out / "probe-timeline.txt").write_text(
                "100.200000\t100.300000\t1970-01-01T00:01:40Z\t0\t200\n"
                "101.200000\t101.300000\t1970-01-01T00:01:41Z\t0\t200\n"
                "110.000000\t110.100000\t1970-01-01T00:01:50Z\t0\t200\n"
                "125.000000\t125.100000\t1970-01-01T00:02:05Z\t0\t200\n"
                "140.000000\t140.100000\t1970-01-01T00:02:20Z\t0\t200\n"
                "155.000000\t155.100000\t1970-01-01T00:02:35Z\t0\t200\n"
                "170.000000\t170.100000\t1970-01-01T00:02:50Z\t0\t200\n"
            )
            (out / "ceiling-probes.tsv").write_text(
                "101.100000\t101.110000\t28\t000\t1\t101.050000\n"
                "101.200000\t101.210000\t28\t000\t1\t101.050000\n"
                "101.400000\t101.410000\t0\t200\t0\t101.050000\n"
            )
            (out / "leaks.txt").write_text(
                "Process 10: 0 leaks for 0 total leaked bytes.\n"
            )
            (out / "idle-cpu-baseline.tsv").write_text("".join(
                f"{index}\t{80 + index:.6f}\t10\t{'4' * 64}\t1.0\n"
                for index in range(1, 11)
            ))
            (out / "idle-cpu-post.tsv").write_text("".join(
                f"{index}\t{162 + index:.6f}\t10\t{'4' * 64}\t1.0\n"
                for index in range(1, 11)
            ))
            (out / "workload-claims.tsv").write_text(
                "evidence_kind\tsoak\n"
                "run_uuid\t11111111-2222-3333-8444-555555555555\n"
                "dial9_claim\tunattributed-diagnostic\n"
                "dial9_diagnostic_only\t1\n"
                "dial9_workload_coverage\t0\n"
                "tcp_workload_exercised\t1\n"
                "udp_workload_exercised\t0\n"
                "schema_complete\t1\n"
            )
            (out / "provider-generation-samples.tsv").write_text(
                "fixture provider generation proof\n"
            )
            crash_snapshot = (
                "schema_version\t2\n"
                "run_uuid\t11111111-2222-3333-8444-555555555555\n"
                f"provider_generation_identity\t{'4' * 64}\n"
                "since_epoch_ms\t80000\n"
                "snapshot_epoch_ms\t{}\n"
                "process_names\tProvider\n"
                "crash_count\t0\n"
                f"crash_names_sha256\t{'a' * 64}\n"
                "schema_complete\t1\n"
            )
            (out / "crashes-before.tsv").write_text(crash_snapshot.format(80001))
            (out / "crashes").mkdir()
            (out / "crashes" / "crash-snapshot.tsv").write_text(
                crash_snapshot.format(173500)
            )
            trace_content = b"fixture-current-dial9-trace"
            (out / "dial9-traces").mkdir()
            (out / "dial9-traces" / "trace.9.bin").write_bytes(trace_content)
            (out / "dial9-evidence.json").write_text(json.dumps({
                "schema_version": 1,
                "baseline_max_index": 8,
                "current_segment_count": 1,
                "current_indices": [9],
                "artifacts": [{
                    "name": "trace.9.bin",
                    "index": 9,
                    "state": "sealed",
                    "encoding": "raw",
                    "size": len(trace_content),
                    "sha256": hashlib.sha256(trace_content).hexdigest(),
                }],
                "tproxy_open_count": 1,
                "tproxy_close_count": 1,
                "paired_flow_count": 1,
                "udp_paired_flow_count": 1,
                "required_pair_count": 1,
                "schema_complete": True,
            }))

            def run_extractor():
                result = subprocess.run(
                    ["python3", "-c", extractor, str(out), str(script_dir)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(result.returncode, 0, result.stdout)
                status = (out / "soak-verdict.tsv").read_text().splitlines(True)
                return parse_evidence_status_lines(status), result.stdout

            status, output = run_extractor()
            self.assertEqual(status, 0, output)

            summary_path = out / "dial9-evidence.json"
            summary = json.loads(summary_path.read_text())
            summary["future_field"] = {"nested": [1, True, None]}
            summary_path.write_text(json.dumps(summary, indent=2) + "\n")
            status, output = run_extractor()
            self.assertEqual(status, 0, output)
            encoded_summary = json.dumps(summary)
            for key, conflicting in (
                ("schema_complete", False), ("required_pair_count", 0),
                ("current_segment_count", None), ("artifacts", []),
            ):
                field = json.dumps(key) + ":" + json.dumps(conflicting)
                for text in (
                    "{" + field + "," + encoded_summary[1:],
                    encoded_summary[:-1] + "," + field + "}",
                ):
                    with self.subTest(duplicate_dial9_key=key, text=text):
                        summary_path.write_text(text + "\n")
                        status, output = run_extractor()
                        self.assertEqual(status, 2, output)
                        self.assertIn("dial9 evidence summary is missing or malformed", output)
            summary_path.write_text(encoded_summary.replace(
                '"state": "sealed"', '"state": "active", "state": "sealed"'
            ) + "\n")
            status, output = run_extractor()
            self.assertEqual(status, 2, output)
            self.assertIn("dial9 evidence summary is missing or malformed", output)
            summary_path.write_text(json.dumps(summary, indent=2) + "\n")

            for key, conflicting in (
                ("processID", 999), ("subsystem", "foreign"),
                ("timestamp", "1970-01-01 00:00:00+0000"),
                ("eventMessage", "unexpected provider failure"),
            ):
                encoded = json.dumps(rows[0])
                field = json.dumps(key) + ":" + json.dumps(conflicting)
                with self.subTest(duplicate_ndjson_key=key):
                    (out / "system.ndjson").write_text(
                        "{" + field + "," + encoded[1:] + "\n"
                        + "".join(json.dumps(row) + "\n" for row in rows[1:])
                    )
                    status, output = run_extractor()
                    self.assertEqual(status, 2, output)
                    self.assertIn("malformed NDJSON record at line 1", output)
            (out / "system.ndjson").write_text(
                "".join(json.dumps(row) + "\n" for row in rows)
            )

            (out / "fanout.txt").write_text(
                "fanout\t503\t0\t0.250000\tcurl_exit=22\n"
            )
            status, output = run_extractor()
            self.assertEqual(status, 1, output)
            self.assertIn("active fanout transfer failure", output)
            (out / "fanout.txt").write_text(
                "ceiling\t000\t0\t1.000000\tcurl_exit=28\n"
            )
            status, output = run_extractor()
            self.assertEqual(status, 0, output)
            (out / "fanout.txt").unlink()

            rows[2]["timestamp"] = "1970-01-01 00:01:40.900000+0000"
            (out / "system.ndjson").write_text(
                "".join(json.dumps(row) + "\n" for row in rows)
            )
            status, output = run_extractor()
            self.assertEqual(status, 2, output)
            self.assertIn("unclassified provider Error", output)
            rows[2]["timestamp"] = "1970-01-01 00:01:41.150000+0000"
            (out / "system.ndjson").write_text(
                "".join(json.dumps(row) + "\n" for row in rows)
            )

            malformed_episode = {
                "timestamp": "1970-01-01 00:01:41.300000+0000",
                "processID": 10,
                "subsystem": "org.example.provider",
                "category": "lifecycle",
                "eventMessage": (
                    "flow pressure episode ended: startEpochMs=101200 durationMs=10 "
                    "peakOccupancy=2 softCap=0 scans=1 skipped=0 selected=0 "
                    "evicted=1 spared=0 canceled=0 expired=0 startEpochUs=101200000"
                ),
                "messageType": "Default",
            }
            (out / "system.ndjson").write_text(
                "".join(json.dumps(row) + "\n" for row in rows + [malformed_episode])
            )
            status, output = run_extractor()
            self.assertEqual(status, 2, output)
            self.assertIn("pressure-episode sample is malformed", output)
            (out / "system.ndjson").write_text(
                "".join(json.dumps(row) + "\n" for row in rows)
            )

            unknown_error = {
                "timestamp": "1970-01-01 00:01:41.300000+0000",
                "processID": 10,
                "subsystem": "org.example.provider",
                "category": "tproxy",
                "eventMessage": "unexpected opaque provider failure",
                "messageType": "Error",
            }
            (out / "system.ndjson").write_text(
                "".join(json.dumps(row) + "\n" for row in rows + [unknown_error])
            )
            status, output = run_extractor()
            self.assertEqual(status, 1, output)
            self.assertIn("unclassified provider Error", output)
            (out / "system.ndjson").write_text(
                "".join(json.dumps(row) + "\n" for row in rows)
            )

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

            write_meta(0, softcap="1")
            rows[0]["eventMessage"] = gauge.replace("softCap=0", "softCap=1")
            rows[1]["eventMessage"] = rows[0]["eventMessage"]
            (out / "system.ndjson").write_text(
                "".join(json.dumps(row) + "\n" for row in rows)
            )
            status, output = run_extractor()
            self.assertEqual(status, 2, output)
            self.assertIn("flow-pressure soft cap is enabled (1)", output)

            write_meta(
                0,
                softcap="80",
                hardcap="80",
                baseline_registered="5",
                baseline_total="6",
                mode="cap-validate",
            )
            status, output = run_extractor()
            self.assertEqual(status, 2, output)
            self.assertIn(
                "cap-validation mode conflicts with effective live-flow hard-cap headroom",
                output,
            )

            rows[0]["eventMessage"] = gauge
            rows[1]["eventMessage"] = gauge.replace(
                "total=0 peak=0", "total=1 peak=1"
            ).replace("tcp=0", "tcp=1", 1)
            (out / "system.ndjson").write_text(
                "".join(json.dumps(row) + "\n" for row in rows)
            )
            for kwargs, expected in (
                ({"baseline_total": "00"}, "run metadata 'baseline_total'"),
                (
                    {"outage_start": "1.0111e2"},
                    "recorded ceiling outage window does not match direct probes",
                ),
                (
                    {"provider_end_pid": "010"},
                    "run metadata 'provider_end_pid' is not a positive integer",
                ),
            ):
                with self.subTest(kwargs=kwargs):
                    write_meta(0, **kwargs)
                    status, output = run_extractor()
                    self.assertEqual(status, 2, output)
                    self.assertIn(expected, output)

            write_meta(0)
            for artifact, contents, expected in (
                (
                    "pool-intervals.tsv",
                    "fanout\t1e2\t106.000000\n",
                    "invalid established-pool interval at line 1",
                ),
                (
                    "pool-brackets.tsv",
                    "fanout\t0100\t0\t0\t101\t0\t0\t102\t0\t0\t1\n",
                    "invalid provider flow-pool bracket at line 1",
                ),
            ):
                with self.subTest(artifact=artifact):
                    artifact_path = out / artifact
                    artifact_path.write_text(contents)
                    status, output = run_extractor()
                    self.assertEqual(status, 2, output)
                    self.assertIn(expected, output)
                    artifact_path.write_text("")

    def test_soak_exit_trap_seals_and_verifies_before_tar(self):
        shell = Path(__file__).with_name("soak_test.sh").read_text()
        finalizer = shell.split("finalize_and_exit() {", 1)[1].split(
            "\n}\n\n# shellcheck disable=SC2329  # invoked through trap", 1
        )[0]
        ordering = [
            finalizer.index("cleanup"),
            finalizer.index("capture_crashes_after"),
            finalizer.index('evidence_tool seal "$OUT"'),
            finalizer.index('evidence_tool verify "$OUT"'),
            finalizer.index("package_sealed_evidence"),
        ]
        self.assertEqual(ordering, sorted(ordering))
        package = shell.split("package_sealed_evidence() {", 1)[1].split(
            "\n}\n\n# shellcheck disable=SC2329  # reached through the EXIT finalizer",
            1,
        )[0]
        self.assertLess(package.index('/usr/bin/tar -czf "$temporary"'),
                        package.index('mv "$temporary" "$tarball"'))
        self.assertIn('[[ ! -e "$OUT.tgz" ]]', shell)
        self.assertIn(
            "sealed evidence packaging failed; no canonical tarball was published",
            finalizer,
        )
        failure = finalizer.index(
            "sealed evidence packaging failed; no canonical tarball was published")
        self.assertLess(failure, finalizer.index('write_common_status "$final_exit"', failure))
        self.assertLess(
            finalizer.index('write_common_status "$final_exit"', failure),
            finalizer.index(
                'evidence_tool seal "$OUT" --actual-exit-code "$final_exit"',
                failure,
            ),
        )
        self.assertIn("trap handle_exit EXIT", shell)
        self.assertIn('finalize_and_exit "$exit_code"', shell)
        self.assertNotIn('tar -czf "$TARBALL"', shell)

    def test_sealed_evidence_packaging_publishes_only_complete_archive(self):
        shell = Path(__file__).with_name("soak_test.sh").read_text()
        body = shell.split("package_sealed_evidence() {", 1)[1].split(
            "\n}\n\n# shellcheck disable=SC2329  # reached through the EXIT finalizer",
            1,
        )[0]
        function = "package_sealed_evidence() {" + body + "\n}\n"
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "evidence"
            out.mkdir()
            (out / "evidence-manifest.tsv").write_text("sealed\n")
            success = subprocess.run(
                [
                    "bash", "-c",
                    "set -e\nOUT=$1\n" + function
                    + "package_sealed_evidence\n"
                    + "test -f \"$OUT.tgz\"\n"
                    + "test -z \"$(find \"$(dirname \"$OUT\")\" -name "
                      "\"$(basename \"$OUT\").tgz.tmp.*\" -print -quit)\"\n",
                    "packaging-test", str(out),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            self.assertEqual(success.returncode, 0, success.stdout)

            (out.with_suffix(".tgz")).unlink()
            collision = subprocess.run(
                [
                    "bash", "-c",
                    "set -e\nOUT=$1\n" + function
                    + "touch \"$OUT.tgz.tmp.$$\"\n"
                    + "if package_sealed_evidence; then exit 9; fi\n"
                    + "test ! -e \"$OUT.tgz\"\n",
                    "packaging-test", str(out),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            self.assertEqual(collision.returncode, 0, collision.stdout)

    def test_provider_selection_rejects_multiple_exact_executables(self):
        shell = Path(__file__).with_name("soak_test.sh").read_text()
        body = shell.split("select_unique_provider_process() {", 1)[1].split(
            "\n}\n\ncapture_idle_cpu_series()", 1)[0]
        selector = "select_unique_provider_process() {" + body + "\n}\n"
        common = (
            "PROVIDER_BUNDLE=org.example.provider\n"
            "pgrep() { printf '11\\n12\\n'; }\n"
        )
        duplicate = subprocess.run(
            [
                "bash", "-c", common
                + "provider_executable_for_pid() { printf '/Library/SystemExtensions/%s/org.example.provider.systemextension/Contents/MacOS/Provider\\n' \"$1\"; }\n"
                + selector
                + "if select_unique_provider_process '/org.example.provider.systemextension/Contents/MacOS/Provider'; then exit 9; fi\n",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self.assertEqual(duplicate.returncode, 0, duplicate.stdout)

        unique = subprocess.run(
            [
                "bash", "-c", common
                + "provider_executable_for_pid() { if test \"$1\" = 11; then printf '/wrong/Provider\\n'; else printf '/Library/SystemExtensions/uuid/org.example.provider.systemextension/Contents/MacOS/Provider\\n'; fi; }\n"
                + selector
                + "test \"$(select_unique_provider_process '/org.example.provider.systemextension/Contents/MacOS/Provider')\" = $'12\\t/Library/SystemExtensions/uuid/org.example.provider.systemextension/Contents/MacOS/Provider'\n",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self.assertEqual(unique.returncode, 0, unique.stdout)
        provider_start = shell.split("# ── Liveness", 1)[1].split(
            "# ── Start live log capture", 1)[0]
        self.assertNotIn('PID="$(pgrep', provider_start)

    def test_provider_executable_lookup_uses_shared_kernel_probe_without_sudo(self):
        shell = Path(__file__).with_name("soak_test.sh").read_text()
        body = shell.split("provider_executable_for_pid() {", 1)[1].split("\n}\n", 1)[0]
        result = subprocess.run(
            ["bash", "-c", "evidence_tool() { test \"$*\" = 'process-executable --pid 42' || exit 9; "
             "printf '/kernel/provider\\n'; }\n"
             "sudo() { exit 8; }\n"
             "provider_executable_for_pid() {" + body + "\n}\n"
             "provider_executable_for_pid 42"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(result.stdout, "/kernel/provider\n")

    def exercise_incomplete_cleanup_finalizer(self, reaped):
        shell = Path(__file__).with_name("soak_test.sh").read_text()

        def extract(name, following):
            return name + "() {" + shell.split(name + "() {", 1)[1].split(
                following, 1)[0] + "\n}\n"

        write_status = extract(
            "write_incomplete_status", "\n}\n\n# Reject ambiguous")
        cleanup = extract(
            "cleanup", "\n}\n\n# Bash 3.2 on macOS has no timed `wait`")
        finalizer = extract(
            "finalize_and_exit",
            "\n}\n\n# shellcheck disable=SC2329  # invoked through trap",
        )
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "evidence"
            out.mkdir()
            (out / "soak-verdict.tsv").write_text(
                "complete\t1\npassed\t1\nexit_code\t0\nschema_complete\t1\n")
            harness = (
                "OUT=$1\nACTIVE_CHILD_PID=999\nACTIVE_CHILD_PRIVILEGE=direct\n"
                "PROBE_MON_PID=\nGENERATION_MON_PID=\nWAKE_DL_PID=\n"
                "CPU_SAMPLE_PID=\nCPU_SERIES_PID=\n"
                "SUDO_KEEPALIVE_PID=\nLOG_STREAM_PID=\nLOG_STREAM_STARTED=0\n"
                "CLEANUP_STARTED=0\nFINAL_CLEANUP_OK=1\n"
                "HOLDER_CLEANUP_LAST_UNREAPED=0\nARTIFACTS_INITIALIZED=1\n"
                "FINALIZATION_STARTED=0\n"
                f"bounded_stop_and_join() {{ BOUNDED_CHILD_REAPED={reaped}; BOUNDED_CHILD_OK=0; }}\n"
                "kill_holders() { HOLDER_CLEANUP_LAST_UNREAPED=0; }\n"
                "warn() { :; }\n"
                + write_status + cleanup + finalizer
                + "finalize_and_exit 0\n"
            )
            result = subprocess.run(
                ["bash", "-c", harness, "cleanup-test", str(out)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            self.assertEqual(result.returncode, 2, result.stdout)
            verdict = (out / "soak-verdict.tsv").read_text()
            self.assertIn("complete\t0\npassed\t0\nexit_code\t2\n", verdict)
            self.assertIn("cleanup did not prove complete artifact-writer shutdown", verdict)
            self.assertFalse((out / "evidence-manifest.tsv").exists())
            self.assertFalse(out.with_suffix(".tgz").exists())

    def test_unreaped_writer_leaves_truthful_unsealed_directory(self):
        self.exercise_incomplete_cleanup_finalizer(reaped=0)

    def test_forced_cleanup_cannot_reuse_a_passing_verdict(self):
        self.exercise_incomplete_cleanup_finalizer(reaped=1)

    def test_soak_shell_bounds_privileged_diagnostics_and_freezes_run_end(self):
        shell = Path(__file__).with_name("soak_test.sh").read_text()
        for source_name in (
            "source-soak_test.sh", "source-stress_traffic.sh",
            "source-soak_pressure_log.py", "source-signed_run_evidence.py",
        ):
            self.assertIn(source_name, shell)
        self.assertIn("signed_evidence_helper_sha256\\t%s", shell)
        self.assertIn('CRASH_PROCESS="$PROVIDER_EXECUTABLE_NAME"', shell)
        self.assertNotIn(
            'CRASH_PROCESS="RamaTransparentProxyExampleExtension"', shell
        )
        for line in canonical_release_soak_profile_lines():
            key, value = line.rstrip("\n").split("\t")
            self.assertIn(f"printf '{key}\\t{value}\\n'", shell)
        self.assertIn(
            'sudo -n /usr/bin/sample "$PID" 5 -file "$OUT/idle-cpu.sample.txt"',
            shell,
        )
        self.assertNotIn('ps -o pid= -o %cpu=', shell)
        self.assertIn(
            'sudo -n /usr/bin/top -l 11 -s 1 -pid "$PID" -stats pid,cpu -n 1',
            shell,
        )
        no_spin = shell.split("phase_mark no-spin start", 1)[1].split(
            "phase_mark no-spin end", 1)[0]
        self.assertLess(
            no_spin.index('sleep "$CEILING_NO_SPIN_QUIESCE_SECONDS"'),
            no_spin.index('capture_idle_cpu_series "$OUT/idle-cpu-post.tsv" post'),
        )
        self.assertIn('bounded_wait_and_join "$CPU_SAMPLE_PID" 8 sudo', shell)
        self.assertIn('cpu_sample_privilege\\t%s', shell)
        baseline_memory = shell.split(
            "printf '=== baseline provider pid=%s @ %s ===", 1
        )[1].split(
            "phase_mark baseline end", 1
        )[0]
        self.assertIn(
            'bounded_wait_and_join "$ACTIVE_CHILD_PID" 30 sudo', baseline_memory
        )
        self.assertIn('baseline_mem_forced\\t%s', baseline_memory)
        self.assertIn('baseline_mem_privilege\\t%s', baseline_memory)
        self.assertIn('baseline_mem_ps_rc\\t%s', baseline_memory)
        self.assertIn('baseline_mem_vmmap_rc\\t%s', baseline_memory)
        self.assertNotIn('vmmap --summary "$PID" 2>/dev/null ||', baseline_memory)
        self.assertIn(
            'if [[ "$BASELINE_MEM_JOINED" != 1 ]]', baseline_memory
        )
        final_memory = shell.split(
            'FINAL_MEM_STATUS="$OUT/final-mem-command-status.tsv"', 1
        )[1].split("# ── leaks pass", 1)[0]
        self.assertIn(
            'bounded_wait_and_join "$ACTIVE_CHILD_PID" 30 sudo', final_memory
        )
        self.assertIn('final_mem_forced\\t%s', final_memory)
        self.assertIn('final_mem_privilege\\t%s', final_memory)
        for command in ("ps", "vmmap", "heap", "heap_filter"):
            self.assertIn(f'final_mem_{command}_rc\\t%s', final_memory)
        self.assertNotIn(
            'vmmap --summary "$SNAP_PID" 2>/dev/null ||', final_memory
        )
        post_forensics = shell.split(
            "capture_post_boundary_forensics() {", 1
        )[1].split("\n}\nprintf 'holder_cleanup_ok", 1)[0]
        self.assertNotIn('pgrep -f "$PROVIDER_BUNDLE"', post_forensics)
        self.assertIn('SNAP_PID="$PID"', post_forensics)
        for key in (
            "final_mem_start_epoch_ms", "final_mem_end_epoch_ms",
            "final_mem_provider_pid", "final_mem_identity_before",
            "final_mem_identity_after", "leaks_start_epoch_ms",
            "leaks_end_epoch_ms", "leaks_provider_pid",
            "leaks_identity_before", "leaks_identity_after",
        ):
            self.assertIn(f"{key}\\t%s", post_forensics)
        dial9 = shell.split('sudo -n "$DIAL9_EVIDENCE_BIN" collect', 1)[1].split(
            "# ── Stop log capture", 1)[0]
        self.assertIn('bounded_wait_and_join "$ACTIVE_CHILD_PID" 145 sudo', dial9)
        self.assertIn('dial9_collect_forced\\t%s', dial9)
        self.assertLess(
            shell.index('bounded_wait_and_join "$ACTIVE_CHILD_PID" 145 sudo'),
            shell.index("phase_mark no-spin start"),
        )
        self.assertLess(
            shell.index("freeze_run_end_provider_observation", shell.index("phase_mark no-spin end")),
            shell.index("# ── Stop log capture"),
        )
        freeze_call = shell.index(
            "freeze_run_end_provider_observation", shell.index("phase_mark no-spin end")
        )
        monitor_join = shell.index(
            'if [[ "$PROBE_MONITOR_JOINED" != 1 || "$LOG_STREAM_JOINED" != 1 ]]'
        )
        forensic_call = shell.index("\ncapture_post_boundary_forensics\n", monitor_join)
        crash_call = shell.index("\ncapture_crashes_after\n", forensic_call)
        self.assertLess(freeze_call, monitor_join)
        self.assertLess(monitor_join, forensic_call)
        self.assertLess(forensic_call, crash_call)
        generation_output = shell.index(
            '--output "$OUT/provider-generation-samples.tsv"'
        )
        run_start = shell.index(
            'RUN_START_EPOCH_MS="$(epoch_ms_now)"', generation_output
        )
        generation_start = shell.index(
            "\nstart_provider_generation_monitor\n", run_start
        )
        crash_before = shell.index(
            'evidence_tool snapshot-crashes --since-epoch-ms "$RUN_START_EPOCH_MS"',
            generation_start,
        )
        self.assertLess(generation_output, run_start)
        self.assertLess(run_start, generation_start)
        self.assertLess(generation_start, crash_before)
        generation_stop = shell.index(
            'bounded_stop_and_join "$GENERATION_MON_PID" 5 direct', crash_call
        )
        self.assertLess(crash_call, generation_stop)
        crash = shell.split("capture_crashes_after() {", 1)[1].split(
            "\n}\n\n# ── Pretty output", 1)[0]
        self.assertIn(
            '--append "$OUT/provider-generation-samples.tsv"', crash
        )
        self.assertIn('--run-uuid "$RUN_UUID"', crash)
        self.assertIn(
            '--provider-generation-identity "$COMMON_PROVIDER_GENERATION_IDENTITY"',
            crash,
        )
        self.assertLess(
            crash.index('evidence_tool snapshot-crashes'),
            crash.index('--append "$OUT/provider-generation-samples.tsv"'),
        )
        generation_monitor = shell.split(
            "start_provider_generation_monitor() {", 1
        )[1].split("\n}\n\n# Count live", 1)[0]
        self.assertIn('--cadence-ms 2000 --max-gap-ms 5000', generation_monitor)
        self.assertIn('sleep 2', generation_monitor)
        stress = shell.split('bash "$STRESS_SH"', 1)[1].split(
            "if [[ \"$SKIP_FANOUT\"", 1)[0]
        self.assertIn(
            'bounded_wait_and_join "$ACTIVE_CHILD_PID" "$((STRESS_SECONDS + 120))" direct',
            stress,
        )
        self.assertNotIn('wait "$ACTIVE_CHILD_PID"', stress)
        self.assertIn('post_snapshot_provider_observation_identity\\t%s', crash)
        freeze = shell.split("freeze_run_end_provider_observation() {", 1)[1].split(
            "\n}\n\ncapture_crashes_after()", 1)[0]
        self.assertIn('RUN_END_EPOCH_MS="$observation_epoch"', freeze)
        self.assertLess(
            freeze.index('observation_epoch="$(epoch_ms_now)"'),
            freeze.index('process_identity "$observed_pid"'),
        )
        self.assertLess(
            crash.index("freeze_run_end_provider_observation"),
            crash.index("evidence_tool snapshot-crashes"),
        )
        status = shell.split("write_common_status() {", 1)[1].split(
            "\n}\n\n# shellcheck disable=SC2329  # reached through EXIT/INT/TERM handlers",
            1,
        )[0]
        self.assertNotIn("epoch_ms_now", status)


class SoakOwnedProcessCleanupTests(unittest.TestCase):
    @staticmethod
    def cleanup_helpers():
        source = Path(__file__).with_name("soak_test.sh").read_text()
        marker = "# Every owned background function"
        if marker not in source:
            marker = "child_job_is_active() {"
        return source[source.index(marker):source.index("\nsoak_verdict_exit_code() {")]

    @staticmethod
    def live_process(pid):
        result = subprocess.run(
            ["ps", "-o", "state=", "-p", str(pid)], capture_output=True, text=True,
        )
        state = result.stdout.strip()
        return bool(state) and not state.startswith("Z")

    def run_fixture(self, mode, join="stop", identity_mismatch=False, expire_discovery=False, producer_site=None):
        fixture = r"""
import os, signal, sys, time
from pathlib import Path
root = Path(sys.argv[1])
mode = sys.argv[2]
def record():
    with (root / "fixture.pids").open("a") as output:
        output.write(str(os.getpid()) + "\n")
def resistant():
    record()
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    (root / "ready").write_text("ready")
    if mode == "stopped":
        os.kill(os.getpid(), signal.SIGSTOP)
    while True:
        time.sleep(1)
record()
if mode in ("clean", "error", "guard_error"):
    (root / "ready").write_text("ready")
    sys.exit({"clean": 0, "error": 7, "guard_error": 125}[mode])
if mode == "term":
    (root / "ready").write_text("ready")
    while True:
        time.sleep(1)
child = os.fork()
if child == 0:
    if mode == "subgroup":
        os.setsid()
    if mode == "grandchild":
        grandchild = os.fork()
        if grandchild != 0:
            os._exit(0)
    resistant()
if mode == "grandchild":
    os.waitpid(child, 0)
while not (root / "ready").exists():
    time.sleep(0.01)
if mode in ("exit_first", "grandchild"):
    sys.exit(0)
while True:
    time.sleep(1)
"""
        helpers = self.cleanup_helpers()
        if expire_discovery:
            helpers = helpers.replace("soak_collect_tree() {", "real_soak_collect_tree() {", 1)
            helpers += '\nsoak_collect_tree() { real_soak_collect_tree "$1" "$2" "$3" "$SECONDS"; }\n'
        harness = helpers + r"""
PYTHON_BIN=$1
fixture_root=$2
fixture_mode=$3
fixture_output=/dev/stdout
if [[ "$5" == mismatch ]]; then fixture_output="$fixture_root/fixture.out"; fi
if declare -F owned_job >/dev/null; then
  owned_job "$PYTHON_BIN" "$fixture_root/fixture.py" "$fixture_root" "$fixture_mode" >"$fixture_output" 2>&1 &
else
  "$PYTHON_BIN" "$fixture_root/fixture.py" "$fixture_root" "$fixture_mode" >"$fixture_output" 2>&1 &
fi
root_pid=$!
printf '%s\n' "$root_pid" > "$fixture_root/root.pid"
if declare -F remember_owned_child >/dev/null; then remember_owned_child "$root_pid"; fi
ready_deadline=$((SECONDS + 3))
while [[ ! -e "$fixture_root/ready" ]] && (( SECONDS < ready_deadline )); do sleep 0.01; done
[[ -e "$fixture_root/ready" ]] || exit 91
if [[ "$fixture_mode" == exit_first || "$fixture_mode" == grandchild ]]; then sleep 0.2; fi
if [[ "$5" == mismatch ]]; then SOAK_CHILD_IDENTITIES[root_pid]=$(printf '%064d' 0); fi
bounded_${4}_and_join "$root_pid" 2 direct
printf 'status=%s,%s,%s,%s\n' "$BOUNDED_CHILD_RC" "$BOUNDED_CHILD_OK" "$BOUNDED_CHILD_REAPED" "$BOUNDED_CHILD_FORCED"
"""
        if producer_site is not None:
            source = Path(__file__).with_name("soak_test.sh").read_text()
            pid_variable = {
                "probe": "PROBE_MON_PID", "log": "LOG_STREAM_PID",
                "wake": "WAKE_DL_PID", "generation": "GENERATION_MON_PID",
            }[producer_site]
            if producer_site == "wake":
                start = source.rindex('  bounded_stop_and_join "$WAKE_DL_PID" 5 direct')
                terminal = '  (( BOUNDED_CHILD_REAPED )) && WAKE_DL_PID=""'
                end = source.index(terminal, start) + len(terminal)
            else:
                start = source.rindex(f'if [[ -n "${pid_variable}" ]]; then')
                end = source.index("\nfi\n", start) + len("\nfi\n")
            # Execute the real terminal producer call site, including clearing
            # its PID. No later cleanup can rediscover the discarded result.
            producer = (
                "FINAL_CLEANUP_OK=1\nwarn() { :; }\nsudo() { shift; \"$@\"; }\n"
                + f'{pid_variable}="$root_pid"\n'
                + source[start:end]
            )
            harness = harness.replace('bounded_${4}_and_join "$root_pid" 2 direct', producer)
            def function(name):
                return name + "() {" + source.split(name + "() {", 1)[1].split("\n}\n", 1)[0] + "\n}\n"
            # This is a producer/finalizer composition fixture, not a signed
            # envelope. Stub unrelated verification; reaching seal is a bug.
            harness += function("write_incomplete_status") + function("finalize_and_exit") + r"""
OUT="$fixture_root"
REPO="$fixture_root" REPO_HEAD=fixture REPO_DIRTY=0
FINALIZATION_STARTED=0 ARTIFACTS_INITIALIZED=1
cleanup() { :; }
capture_crashes_after() { :; }
soak_verdict_exit_code() { printf '0\n'; }
git() { if [[ "$*" == *"rev-parse HEAD" ]]; then printf 'fixture\n'; fi; return 0; }
write_common_status() { :; }
evidence_tool() { printf '%s\n' "$1" >> "$OUT/seal-attempts"; }
package_sealed_evidence() { :; }
hdr() { :; }
say() { :; }
finalize_and_exit 0
"""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "fixture.py").write_text(fixture)
            unrelated = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(60)"],
                start_new_session=True, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            process = subprocess.Popen(
                ["/bin/bash", "-c", harness, "soak-cleanup-fixture", sys.executable,
                 str(root), mode, join, "mismatch" if identity_mismatch else "match"],
                start_new_session=True, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True,
            )
            try:
                output, _ = process.communicate(timeout=20)
                incomplete_producer = producer_site is not None and mode == "subgroup"
                self.assertEqual(process.returncode, 2 if incomplete_producer else 0, output)
                statuses = re.findall(r"^status=(.*)$", output, re.MULTILINE)
                self.assertEqual(len(statuses), 1, output)
                pids = [int(pid) for pid in (root / "fixture.pids").read_text().split()]
                live = [pid for pid in pids if self.live_process(pid)]
                self.assertIsNone(unrelated.poll(), "cleanup touched an unrelated process")
                if incomplete_producer:
                    self.assertFalse((root / "seal-attempts").exists(), output)
                    verdict = (root / "soak-verdict.tsv").read_text()
                    self.assertIn("cleanup did not prove complete artifact-writer shutdown", verdict)
                elif producer_site is not None:
                    self.assertEqual((root / "seal-attempts").read_text().splitlines(), ["seal", "verify"])
                return statuses[0].split(","), live
            finally:
                # Fixture cleanup is separate from the behavior being asserted.
                # Never signal the runner's group or a PID outside this fixture.
                if (root / "root.pid").exists():
                    pid = int((root / "root.pid").read_text())
                    try:
                        if os.getpgid(pid) == pid:
                            os.killpg(pid, signal.SIGKILL)
                        else:
                            os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                if (root / "fixture.pids").exists():
                    for pid in map(int, (root / "fixture.pids").read_text().split()):
                        try:
                            os.kill(pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5)
                unrelated.terminate()
                unrelated.wait(timeout=5)

    def test_stop_reaps_term_resistant_and_stopped_descendants(self):
        for mode in ("resistant", "stopped"):
            with self.subTest(mode=mode):
                status, live = self.run_fixture(mode)
                self.assertEqual(live, [])
                self.assertEqual(status[1:], ["0", "1", "1"])

    def test_terminal_producer_cannot_discard_forced_descendant_cleanup(self):
        for producer_site in ("probe", "log", "wake", "generation"):
            with self.subTest(producer_site=producer_site):
                status, live = self.run_fixture("subgroup", producer_site=producer_site)
                self.assertEqual(live, [])
                self.assertEqual(status, ["143", "0", "1", "1"])

    def test_terminal_producer_accepts_normal_term_cleanup(self):
        for producer_site in ("probe", "log", "wake", "generation"):
            with self.subTest(producer_site=producer_site):
                status, live = self.run_fixture("term", producer_site=producer_site)
                self.assertEqual(live, [])
                self.assertEqual(status, ["143", "1", "1", "0"])

    def test_wait_reaps_orphans_and_stdout_holders_after_direct_command_exits(self):
        for mode in ("exit_first", "grandchild"):
            with self.subTest(mode=mode):
                status, live = self.run_fixture(mode, join="wait")
                self.assertEqual(live, [])
                self.assertEqual(status[1:], ["0", "1", "1"])

    def test_natural_completion_preserves_command_exit_status(self):
        for mode, expected in (("clean", ["0", "1", "1", "0"]),
                               ("error", ["7", "0", "1", "0"])):
            with self.subTest(mode=mode):
                status, live = self.run_fixture(mode, join="wait")
                self.assertEqual(live, [])
                self.assertEqual(status, expected)

    def test_normal_term_stop_is_complete_without_forcing(self):
        status, live = self.run_fixture("term")
        self.assertEqual(live, [])
        self.assertEqual(status, ["143", "1", "1", "0"])

    def test_guard_failure_status_cannot_claim_proven_cleanup(self):
        status, live = self.run_fixture("guard_error", join="wait")
        self.assertEqual(live, [])
        self.assertEqual(status, ["125", "0", "0", "0"])

    def test_expired_discovery_cleans_group_but_cannot_claim_complete_evidence(self):
        status, live = self.run_fixture("grandchild", join="wait", expire_discovery=True)
        self.assertEqual(live, [])
        self.assertEqual(status[1:], ["0", "0", "1"])

    def test_discovery_visits_each_owned_generation_once(self):
        from test_modern_udp_evidence import exercise_owned_chain_discovery
        helpers = self.cleanup_helpers() + r"""
soak_fixture_pid_identity() { soak_child_identity "$1"; }
soak_fixture_signal_owned_identity() { soak_signal_identity "$1" "$2" "$3" direct 1; }
soak_fixture_collect_owned_tree() {
  SOAK_COLLECT_SEEN=(); SOAK_COLLECT_COUNT=0
  soak_collect_tree "$1" "$2" direct "$3"
}
"""
        exercise_owned_chain_discovery(self, helpers, "soak_fixture_")

    def test_changed_generation_is_never_signalled_or_claimed_reaped(self):
        status, live = self.run_fixture("term", identity_mismatch=True)
        self.assertTrue(live)
        self.assertEqual(status[1:], ["0", "0", "1"])

    def test_unowned_pid_is_never_signalled_or_claimed_reaped(self):
        unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        try:
            result = subprocess.run(
                ["/bin/bash", "-c", self.cleanup_helpers() + r"""
bounded_stop_and_join "$1" 1 direct
printf '%s,%s,%s,%s\n' "$BOUNDED_CHILD_RC" "$BOUNDED_CHILD_OK" "$BOUNDED_CHILD_REAPED" "$BOUNDED_CHILD_FORCED"
""", "unowned-pid", str(unrelated.pid)],
                capture_output=True, text=True, timeout=3,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout.strip(), "127,0,0,0")
            self.assertIsNone(unrelated.poll())
        finally:
            unrelated.terminate()
            unrelated.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
