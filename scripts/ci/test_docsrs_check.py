"""The docs.rs tool's target probe must not alter actual compiler invocations."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("docsrs_check", Path(__file__).parents[1] / "docsrs_check.py")
docsrs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(docsrs)


class DocsrsProbeTests(unittest.TestCase):
    def test_only_the_exact_availability_probe_is_a_library(self):
        probe = ["-", "--target=aarch64-apple-ios", "-Zunpretty=expanded"]
        self.assertEqual(docsrs.compiler_arguments(probe), [*probe, "--crate-type=lib"])
        for arguments in (["-vV"], ["src/lib.rs", "--crate-type=lib"],
                          [*probe, "--cfg=docsrs"], ["-", "--target", "missing"]):
            self.assertEqual(docsrs.compiler_arguments(arguments), arguments)

    def test_compiler_failure_status_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            compiler = Path(directory) / "compiler.py"
            compiler.write_text("import sys; sys.exit(19)\n")
            result = subprocess.run([sys.executable, str(Path(docsrs.__file__)),
                                     "--rustc", sys.executable, str(compiler)])
        self.assertEqual(result.returncode, 19)
