"""Keep the expensive optional JS backend in one explicit Linux lane."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class InterpreterWorkflowTests(unittest.TestCase):
    def test_interpreter_lane_is_linux_only_and_uses_recipe(self):
        workflow = (ROOT / ".github/workflows/CI.yml").read_text()
        job = workflow.split("  test-js-interpreter:\n", 1)[1].split("\n  precheck-fmt:", 1)[0]
        self.assertIn("runs-on: ubuntu-latest", job)
        self.assertNotIn("matrix:", job)
        self.assertIn("run: just test-js-interpreter", job)
        self.assertIn("needs: [precheck-rust, precheck-docs, precheck-fmt, meta-lints]", job)
        gate = workflow.split("  ci-success:\n", 1)[1].split("\n  deploy-rama-cli-docker:", 1)[0]
        self.assertIn("      - test-js-interpreter\n", gate)
        recipe = (ROOT / "justfile").read_text().split("\ntest-js-interpreter:\n", 1)[1].split("\n\n", 1)[0]
        self.assertIn("RAMA_TEST_JS_INTERPRETER=1", recipe)
        self.assertIn("-p rama-js -p rama-pac --all-features", recipe)

    def test_backend_override_does_not_leak_into_other_ci_jobs(self):
        for path in (ROOT / ".github/workflows").glob("*.yml"):
            self.assertNotIn("RAMA_TEST_JS_INTERPRETER", path.read_text(), path.name)

    def test_production_rust_never_reads_test_override(self):
        for crate in ("rama-js", "rama-pac"):
            for path in (ROOT / crate / "src").rglob("*.rs"):
                self.assertNotIn('var("RAMA_TEST_JS_INTERPRETER")', path.read_text(), str(path))


if __name__ == "__main__":
    unittest.main()
