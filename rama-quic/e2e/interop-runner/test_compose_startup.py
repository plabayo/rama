"""Check the merged startup graph with Compose, without a running Docker engine."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from run_interop import compose_override


@unittest.skipUnless(shutil.which("docker"), "Docker Compose is required")
class ComposeStartupTests(unittest.TestCase):
    def config(self, *selected):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            # The pinned upstream makes both endpoints depend on the simulator.
            upstream = {"services": {
                "sim": {"image": "sim"},
                "server": {"image": "server", "depends_on": ["sim"]},
                "client": {"image": "client", "depends_on": ["sim"]},
                "iperf_client": {"image": "iperf"},
                "iperf_server": {"image": "iperf"},
            }}
            base = root / "base.json"
            base.write_text(json.dumps(upstream))
            override = root / "override.json"
            override.write_text(json.dumps(compose_override("test-startup", "linux/amd64", "sim")))
            startup = Path(__file__).resolve().parent / "compose.startup.yaml"
            env = dict(os.environ)
            env.pop("COMPOSE_PROFILES", None)
            result = subprocess.run(
                ["docker", "compose", "--project-name", "test-startup",
                 "-f", str(base), "-f", str(override), "-f", str(startup),
                 "config", "--format", "json", *selected],
                env=env, capture_output=True, text=True, timeout=15, check=True,
            )
            return json.loads(result.stdout)["services"]

    def test_protocol_run_starts_server_before_simulator_before_client(self):
        services = self.config("sim", "client", "server")
        self.assertFalse(services["server"].get("depends_on"))
        self.assertEqual(services["sim"]["depends_on"]["server"]["condition"], "service_started")
        self.assertEqual(services["client"]["depends_on"]["sim"]["condition"], "service_started")

    def test_client_compliance_does_not_start_a_server(self):
        services = self.config("sim", "client")
        self.assertEqual(set(services), {"sim", "client"})
        self.assertFalse(services["sim"].get("depends_on"))

    def test_server_compliance_does_not_need_a_simulator(self):
        services = self.config("server")
        self.assertEqual(set(services), {"server"})
        self.assertFalse(services["server"].get("depends_on"))
