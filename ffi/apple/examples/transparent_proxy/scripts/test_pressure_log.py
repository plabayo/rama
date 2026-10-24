#!/usr/bin/env python3
"""Behavioral regression tests for the pressure telemetry parser."""

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from pressure_log import (
    filter_provider_ndjson_records,
    flow_gauge,
    flow_gauge_issue,
    lifecycle_category_issue,
    main,
    parse_ndjson_lines,
    pressure_telemetry_issue,
    summarize_pressure_rows,
    summarize_udp_pressure_rows,
    summarize_writer_memory_pressure_rows,
)


class PressureLogTests(unittest.TestCase):
    udp_drop = (
        'UDP ingress pressure dropped datagram flow_id=42 pressure="global_bytes" '
        "cumulative_drops=2 global_retained_bytes=8192 "
        "global_max_retained_bytes=8192"
    )
    udp_resume = (
        'UDP ingress pressure resumed flow flow_id=42 pressure="global_bytes" '
        "cumulative_resumptions=1 global_retained_bytes=1024 "
        "global_max_retained_bytes=8192"
    )

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

    def test_writer_memory_pressure_fails_closed_and_never_counts_rows_as_recovery(self):
        entered = (
            'writer memory pressure entered protocol="tcp" '
            'reason="tcp_waiter_gate" retainedBytes=6 maxBytes=8 '
            'retainedItems=6 maxItems=8'
        )
        recovered = (
            'writer memory pressure recovered protocol="aggregate" '
            'reason="low_water" retainedBytes=4 maxBytes=8 '
            'retainedItems=2 maxItems=8'
        )
        result = summarize_writer_memory_pressure_rows([(100, entered), (101, recovered)])
        self.assertEqual(result["status"], "GOOD")
        for rows in (
            [(100, entered)],
            [(100, entered), (101, entered)],
            [(100, entered), (101, entered.replace("entered", "recovered"))],
        ):
            with self.subTest(rows=rows):
                result = summarize_writer_memory_pressure_rows(rows)
                self.assertNotEqual(result["status"], "GOOD")
                self.assertEqual(result["recovered_reasons"], [])

    def test_udp_pressure_ceiling_requires_later_recovery(self):
        drop, resume = self.udp_drop, self.udp_resume
        recovered = summarize_udp_pressure_rows(
            [(101, drop), (102, resume)], workload_exercised=True, mode="find-ceiling"
        )
        self.assertEqual(recovered["status"], "GOOD")
        for rows in ([(101, drop)], [(101, resume), (102, drop)]):
            with self.subTest(rows=rows):
                failed = summarize_udp_pressure_rows(
                    rows, workload_exercised=True, mode="find-ceiling"
                )
                self.assertEqual(failed["status"], "FAILED")
                self.assertEqual(failed["unrecovered"], ["global_bytes"])

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
        for rows, status in (
            ([(101, drop), (102, resume)], "GOOD"),
            ([(101, drop), (102, resume.replace("flow_id=77", "flow_id=78"))], "INCOMPLETE"),
            ([
                (101, drop.replace("flow_id=77", "flow_id=78")),
                (102, resume.replace("flow_id=77", "flow_id=78")),
            ], "INCOMPLETE"),
        ):
            with self.subTest(rows=rows):
                result = summarize_udp_pressure_rows(
                    rows, workload_exercised=True, mode="find-ceiling", required_flow_id=77,
                )
                self.assertEqual(result["status"], status)

    def test_swift_udp_staging_drop_is_always_unhealthy(self):
        staging = (
            'UDP Swift ingress staging dropped datagrams reason="generation_bytes" '
            "cumulative_drop_events=1 cumulative_dropped_items=3 "
            "cumulative_dropped_bytes_lower_bound=1200 "
            "generation_retained_items=8 generation_max_retained_items=8 "
            "generation_retained_bytes=8192 generation_max_retained_bytes=8192"
        )
        recovered = [(101, self.udp_drop), (102, self.udp_resume)]
        for rows, mode, status in (
            (recovered, "find-ceiling", "GOOD"),
            (recovered + [(103, staging)], "find-ceiling", "FAILED"),
            ([(101, staging)], "stress-only", "FAILED"),
        ):
            with self.subTest(rows=rows, mode=mode):
                result = summarize_udp_pressure_rows(
                    rows, workload_exercised=True, mode=mode
                )
                self.assertEqual(result["status"], status)

    def test_udp_pressure_counter_rollback_is_incomplete(self):
        staging = (
            'UDP Swift ingress staging dropped datagrams reason="flow_items" '
            "cumulative_drop_events=2 cumulative_dropped_items=4 "
            "cumulative_dropped_bytes_lower_bound=10 "
            "generation_retained_items=1 generation_max_retained_items=8192 "
            "generation_retained_bytes=1 generation_max_retained_bytes=8192"
        )
        drop, resume = self.udp_drop, self.udp_resume
        earlier = drop.replace("cumulative_drops=2", "cumulative_drops=1")
        for rows, status in (
            ([(101, earlier), (102, drop), (103, resume)], "GOOD"),
            ([(101, drop), (102, earlier), (103, resume)], "INCOMPLETE"),
            ([
                (101, staging),
                (102, staging.replace("cumulative_drop_events=2", "cumulative_drop_events=1")),
            ], "INCOMPLETE"),
        ):
            with self.subTest(rows=rows):
                result = summarize_udp_pressure_rows(
                    rows, workload_exercised=True, mode="find-ceiling"
                )
                self.assertEqual(result["status"], status)

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
        unbounded = summarize_pressure_rows(rows)
        self.assertEqual(unbounded["observed_peak"], 480)
        self.assertTrue(unbounded["eviction_observed"])
        evidence = summarize_pressure_rows(rows, baseline_end_epoch=100)
        self.assertEqual(evidence["observed_peak"], 25)
        self.assertFalse(evidence["eviction_observed"])


if __name__ == "__main__":
    unittest.main()
