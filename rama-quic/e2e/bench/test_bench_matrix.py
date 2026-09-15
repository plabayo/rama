"""The pure parts of the benchmark matrix: sizes, cell values, tables and the SVG heat-map."""
import unittest
import xml.etree.ElementTree as ET

import bench_matrix as bm


def sample(seconds, ok=True, size=0):
    return {"seconds": seconds, "ok": ok, "bytes": size, "exit": 0 if ok else 1}


class SizeTests(unittest.TestCase):
    def test_units(self):
        self.assertEqual(bm.parse_size("4G"), 4 << 30)
        self.assertEqual(bm.parse_size("8M"), 8 << 20)
        self.assertEqual(bm.parse_size("1K"), 1024)
        self.assertEqual(bm.parse_size("1"), 1)

    def test_invalid(self):
        with self.assertRaises(bm.BenchError):
            bm.parse_size("4GB")

    def test_file_names_and_requests(self):
        names = bm.file_names("small", 12)
        self.assertEqual(names[0], "small-00")
        self.assertEqual(names[-1], "small-11")
        self.assertEqual(bm.file_names("bulk", 1), ["bulk-0"])
        self.assertEqual(bm.requests_for(["a", "b"]), "https://server4:443/a https://server4:443/b")

    def test_overrides(self):
        lock = {"cases": {"bulk": {"files": 1, "size": "4G"}}}
        bm.apply_overrides(lock, ["bulk.size=64M", "bulk.files=2"])
        self.assertEqual(lock["cases"]["bulk"], {"files": 2, "size": "64M"})
        with self.assertRaises(bm.BenchError):
            bm.apply_overrides(lock, ["nope.size=1"])
        with self.assertRaises(bm.BenchError):
            bm.apply_overrides(lock, ["bulk.unit=x"])


class CellValueTests(unittest.TestCase):
    def test_goodput_excludes_process_start(self):
        case = {"unit": "MiB/s", "files": 1}
        samples = [sample(4.5, size=1 << 30), sample(4.0, size=1 << 30), sample(5.0, size=1 << 30)]
        value, low, high, short = bm.cell_value(case, samples, handshake_seconds=0.5)
        self.assertFalse(short)
        self.assertAlmostEqual(value, 1024 / 4.0)
        self.assertAlmostEqual(low, 1024 / 4.5)
        self.assertAlmostEqual(high, 1024 / 3.5)

    def test_requests_per_second(self):
        case = {"unit": "req/s", "files": 2000}
        value, _, _, short = bm.cell_value(case, [sample(2.5)], handshake_seconds=0.5)
        self.assertAlmostEqual(value, 1000.0)
        self.assertFalse(short, "2.5 s is five 0.5 s baselines")
        _, _, _, short = bm.cell_value(case, [sample(1.5)], handshake_seconds=0.5)
        self.assertTrue(short, "1.5 s is under four 0.5 s baselines")

    def test_handshake_in_milliseconds(self):
        case = {"unit": "ms", "files": 1}
        value, low, high, short = bm.cell_value(case, [sample(0.4), sample(0.6), sample(0.5)], None)
        self.assertEqual((value, low, high, short), (500.0, 400.0, 600.0, False))

    def test_failed_samples_do_not_score(self):
        case = {"unit": "MiB/s", "files": 1}
        self.assertEqual(bm.cell_value(case, [sample(1.0, ok=False)], 0.1), (None, None, None, False))
        value, _, _, _ = bm.cell_value(case, [sample(1.0, ok=False), sample(2.1, size=1 << 20)], 0.1)
        self.assertAlmostEqual(value, 0.5)


class TimestampTests(unittest.TestCase):
    def test_docker_timestamps(self):
        start = bm.parse_docker_time("2026-09-15T16:03:38.123456789Z")
        end = bm.parse_docker_time("2026-09-15T16:03:40.5Z")
        self.assertAlmostEqual(end - start, 2.376543211, places=6)
        with self.assertRaises(bm.BenchError):
            bm.parse_docker_time("yesterday")


class RenderTests(unittest.TestCase):
    def setUp(self):
        self.names = ["rama-boring", "quinn"]
        self.case = {"unit": "MiB/s", "files": 1, "size": "4G", "description": "one stream", "testcase": "transfer"}
        self.cells = {
            ("rama-boring", "rama-boring"): {"value": 812.0, "min": 800.0, "max": 830.0},
            ("rama-boring", "quinn"): {"value": 640.5, "min": 600.0, "max": 650.0, "short": True},
            ("quinn", "rama-boring"): {"value": None, "min": None, "max": None},
            ("quinn", "quinn"): {"value": 99.4, "min": 90.0, "max": 100.0},
        }
        self.meta = {"os": "Linux 6.1", "arch": "aarch64", "cpus": 16, "docker": "29.3.0",
                     "timestamp": "2026-09-15 16:00 UTC", "rama_commit": "149c6882c", "repeat": 3,
                     "emulated": ["quiche (amd64)"], "virtualized": True}

    def test_table(self):
        text = bm.table("bulk", "MiB/s", self.names, self.names, self.cells)
        self.assertIn("812", text)
        self.assertIn("n/a", text)
        self.assertIn("640*", text)
        self.assertIn("99.4", text)
        self.assertTrue(text.startswith("bulk [MiB/s]"))

    def test_svg_is_well_formed_and_labelled(self):
        svg = bm.heatmap_svg("bulk", self.case, self.names, self.names, self.cells, self.meta)
        root = ET.fromstring(svg)
        self.assertEqual(root.tag, "{http://www.w3.org/2000/svg}svg")
        texts = [t.text or "" for t in root.iter("{http://www.w3.org/2000/svg}text")]
        joined = "\n".join(texts)
        for expected in ("Linux 6.1", "149c6882c", "2026-09-15 16:00 UTC", "rama-boring", "quinn", "812", "640", "n/a",
                         "quiche (amd64)", "virtual machine", "4G", "640*", "start-up baselines"):
            self.assertIn(expected, joined)
        self.assertNotIn("<script", svg)
        self.assertNotIn("http://", svg.replace("http://www.w3.org/2000/svg", ""))

    def test_best_cell_is_darkest_and_unsupported_is_hatched(self):
        svg = bm.heatmap_svg("bulk", self.case, self.names, self.names, self.cells, self.meta)
        self.assertIn('fill="#1f4ef8"', svg)
        self.assertIn('fill="url(#na)"', svg)
        lower = bm.color_for(10.0, best=10.0, worst=100.0, higher_is_better=False)
        self.assertEqual(lower, "#1f4ef8")
        self.assertNotEqual(bm.color_for(100.0, best=10.0, worst=100.0, higher_is_better=False), "#1f4ef8")

    def test_svg_is_deterministic(self):
        first = bm.heatmap_svg("bulk", self.case, self.names, self.names, self.cells, self.meta)
        second = bm.heatmap_svg("bulk", self.case, self.names, self.names, self.cells, self.meta)
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
