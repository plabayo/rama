#!/usr/bin/env python3
"""Behavioral regression tests for the pressure telemetry parser."""

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from pressure_log import (
    engine_lifecycle_event,
    filter_provider_ndjson_records,
    flow_gauge,
    flow_gauge_issue,
    main,
    lifecycle_category_issue,
    no_headroom_event,
    parse_epoch,
    parse_ndjson_lines,
    parse_oslog_timestamp,
    phase_for_epoch,
    pressure_counters,
    pressure_episode,
    pressure_telemetry_issue,
    selection_event,
    summarize_pressure_rows,
    summarize_udp_pressure_rows,
    summarize_writer_memory_pressure_rows,
    udp_pressure_event,
    writer_memory_pressure_event,
)


class PressureLogTests(unittest.TestCase):
    def test_cli_reports_writer_drops_and_rejects_malformed_records(self):
        record = {
            "processID": 123, "subsystem": "rama.test",
            "timestamp": "2026-09-06 10:00:00.000000+0200",
            "eventMessage": "UDP client writer dropped datagrams reason=aggregate_capacity "
                            "cumulative_dropped_items=8 cumulative_dropped_bytes=4096 "
                            "aggregate_dropped_items=4",
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "provider.ndjson"
            path.write_text(json.dumps(record) + "\n")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main([str(path), "--pid", "123", "--subsystem", "rama.test"])
            self.assertEqual(status, 0)
            summary = json.loads(output.getvalue())
            self.assertEqual(summary["udp_writer_drop_samples"][0]["dropped_items"], 8)
            self.assertEqual(summary["writer_pressure"]["status"], "NOT EXERCISED")
            record["eventMessage"] = record["eventMessage"].replace(
                "aggregate_dropped_items=4", "aggregate_dropped_items=9")
            path.write_text(json.dumps(record) + "\n{invalid}\n")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main([str(path), "--pid", "123", "--subsystem", "rama.test"])
            self.assertEqual(status, 1)
            self.assertTrue(json.loads(output.getvalue())["issues"])

    def test_current_selection_line(self):
        message = (
            "flow pressure: occupancy 460 over soft cap 450; selected 100 "
            "idle flow(s) toward low-water 350 (100 pending teardown)"
        )
        self.assertEqual(
            selection_event(message),
            {"occupancy": 460, "soft_cap": 450, "selected": 100},
        )

    def test_current_no_headroom_line(self):
        message = (
            "flow pressure: occupancy 451, soft cap 450, but no flow idle "
            "past 120000ms floor; admitting without reap"
        )
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

    def test_obsolete_messages_do_not_match(self):
        self.assertIsNone(
            selection_event(
                "flow pressure: occupancy 460 over soft cap 450; reaping 100 idle"
            )
        )
        self.assertFalse(
            no_headroom_event(
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

    def test_native_log_preamble_requires_exact_identity_and_first_position(self):
        record = '{"processID":10,"subsystem":"org.example.provider"}\n'
        preamble = ('Filtering the log data using "processIdentifier == 10 '
                    'AND subsystem == "org.example.provider""\n')
        for lines in ([record], [preamble, record]):
            decoded, issues = parse_ndjson_lines(
                lines, provider_pid="10", subsystem="org.example.provider")
            self.assertEqual(decoded, [json.loads(record)])
            self.assertEqual(issues, [])
        for lines, malformed_line in (
            ([preamble.replace("== 10", "== 11"), record], 1),
            ([preamble.replace("example.provider", "foreign.provider"), record], 1),
            ([preamble.rstrip()[:-1], record], 1),
            ([preamble, preamble, record], 2),
            ([record, preamble], 2),
            (["\n", preamble, record], 2),
            ([preamble, '{"key":1,"key":2}\n', record], 2),
        ):
            with self.subTest(lines=lines):
                decoded, issues = parse_ndjson_lines(
                    lines, provider_pid=10, subsystem="org.example.provider")
                self.assertEqual(decoded, [json.loads(record)])
                self.assertEqual(issues, [f"malformed NDJSON record at line {malformed_line}"])
        # Without an independently supplied capture identity, stay JSON-only.
        _, issues = parse_ndjson_lines([preamble, record])
        self.assertEqual(issues, ["malformed NDJSON record at line 1"])

    def test_native_log_footer_requires_exact_count_shape_and_final_position(self):
        record = {"processID": 10, "subsystem": "org.example.provider"}
        footer = {"count": 1, "finished": 1}
        decoded, issues = parse_ndjson_lines(
            [json.dumps(record), json.dumps(footer), "\n"])
        self.assertEqual(decoded, [record])
        self.assertEqual(issues, [])
        for invalid in (
            {**footer, "count": 0}, {**footer, "count": True},
            {**footer, "finished": True}, {**footer, "finished": 0},
            {**footer, "eventMessage": "unexpected event"},
        ):
            with self.subTest(footer=invalid):
                decoded, _ = parse_ndjson_lines(
                    [json.dumps(record), json.dumps(invalid)])
                _, issues = filter_provider_ndjson_records(
                    decoded, 10, "org.example.provider")
                self.assertTrue(issues)
        decoded, _ = parse_ndjson_lines(
            [json.dumps(footer), json.dumps(record)])
        _, issues = filter_provider_ndjson_records(decoded, 10, "org.example.provider")
        self.assertTrue(issues)

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



if __name__ == "__main__":
    unittest.main()
