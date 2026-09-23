"""Exercise the signing boundary with fake platform tools and fake credentials."""

import base64
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from check_workflows import ROOT


class SigningIsolationTests(unittest.TestCase):
    def sign(self, fail=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tools = root / "tools"
            tools.mkdir()
            temporary = root / "temp"
            temporary.mkdir()
            binary = root / "target/aarch64-apple-darwin/release/rama"
            binary.parent.mkdir(parents=True)
            binary.write_text("#!/bin/sh\necho executed >> \"$TEST_LOG\"\nexit 99\n")
            binary.chmod(0o755)
            # The signing script must never invoke cargo or the candidate binary.
            for name in ("security", "codesign", "ditto", "xcrun", "xattr", "spctl", "cargo"):
                tool = tools / name
                tool.write_text("""#!/bin/sh
name=$(basename "$0")
printf '%s %s\\n' "$name" "$*" >> "$TEST_LOG"
if [ "$name" = cargo ]; then exit 99; fi
if [ "$name" = codesign ] && [ "$TEST_FAIL" = yes ]; then exit 42; fi
if [ "$name" = xcrun ]; then
  case "$2" in
    submit) echo 'id: 11111111-1111-1111-1111-111111111111' ;;
    log) echo '{"status": "Accepted"}' ;;
  esac
fi
exit 0
""")
                tool.chmod(0o755)
            log = root / "commands.log"
            env = {**os.environ, "PATH": str(tools) + os.pathsep + os.environ["PATH"],
                   "HOME": str(root), "RUNNER_TEMP": str(temporary), "TEST_LOG": str(log),
                   "TEST_FAIL": "yes" if fail else "no", "KEYCHAIN_NAME": "test.keychain-db",
                   "MACOS_CERT_P12": base64.b64encode(b"fake certificate").decode(),
                   "MACOS_CERT_PASSWORD": "fake password", "AC_API_KEY": "fake private key",
                   "AC_API_KEY_ID": "fake id", "AC_API_ISSUER_ID": "fake issuer"}
            result = subprocess.run(["bash", str(ROOT / "rama-cli/scripts/sign_macos.sh"),
                                     "aarch64-apple-darwin"], cwd=root, env=env,
                                    capture_output=True, text=True, timeout=10)
            commands = log.read_text()
            self.assertNotIn("cargo ", commands)
            self.assertNotIn("executed", commands)
            self.assertIn("security delete-keychain", commands)
            self.assertFalse((temporary / "rama-cert.p12").exists())
            self.assertFalse((temporary / "rama-key.p8").exists())
            self.assertEqual(result.returncode, 42 if fail else 0, result.stdout + result.stderr)

    def test_signing_never_executes_build_output(self):
        self.sign()

    def test_failure_cleans_up_credentials(self):
        self.sign(fail=True)
