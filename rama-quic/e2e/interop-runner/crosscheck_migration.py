"""Cross-check retained captures with only response-first path ordering relaxed.

This diagnostic is for the pinned NgTCP2 peer, in either Rama role. It preserves
upstream's other assertions and never changes its
checkout or the recorded test results. The regular gate uses check_migration.py.
"""
import argparse
import inspect
import json
import logging
from pathlib import Path
import subprocess
import sys
import textwrap
from types import SimpleNamespace

OLD_CHECK = '''            if hasattr(p["quic"], "path_challenge.data") is False:
                logging.info(
                    "First server packet on new path %s did not contain a PATH_CHALLENGE frame",
                    cur,
                )
                logging.info(p["quic"])
                return TestResult.FAILED
            else:
                challenges.add(getattr(p["quic"], "path_challenge.data"))'''
NEW_CHECK = '''            if hasattr(p["quic"], "path_challenge.data") is False:
                # Permit probing-only PATH_RESPONSE packets before our challenge.
                later = [q for q in tr_server if int(q.number) >= int(p.number) and self._path(q) == cur]
                found = False
                for q in later:
                    if hasattr(q["quic"], "path_challenge.data"):
                        challenges.add(getattr(q["quic"], "path_challenge.data"))
                        found = True
                        break
                    types = q["quic"].get_field("frame_type")
                    fields = types.all_fields if types is not None else []
                    if not fields or any(int(v.show, 0) not in (0, 0x1a, 0x1b, 0x18) for v in fields):
                        return TestResult.FAILED
                if not found:
                    return TestResult.FAILED
            else:
                challenges.add(getattr(p["quic"], "path_challenge.data"))'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifacts", type=Path)
    parser.add_argument("--role", choices=["client", "server"], required=True)
    args = parser.parse_args()
    upstream = args.artifacts / "upstream"
    lock = json.loads((args.artifacts / "runner.lock.json").read_text())
    revision = subprocess.check_output(
        ["git", "-C", str(upstream), "rev-parse", "HEAD"], text=True,
    ).strip()
    if revision != lock["revision"]:
        parser.error("upstream checkout does not match the retained run's lock")
    pair = "ngtcp2_rama" if args.role == "client" else "rama_ngtcp2"
    directory = args.artifacts / f"logs-rama-{args.role}" / pair / "connectionmigration"
    sys.path.insert(0, str(upstream))
    import testcases_quic as tc

    logging.basicConfig(level=logging.INFO)
    source = textwrap.dedent(inspect.getsource(tc.TestCasePortRebinding.check))
    if source.count(OLD_CHECK) != 1:
        parser.error("upstream checker changed; review the diagnostic before using it")
    source = source.replace(OLD_CHECK, NEW_CHECK)
    # A method compiled outside its class lacks the zero-argument super closure.
    source = source.replace("super().check()", "super(TestCasePortRebinding, self).check()")
    namespace = dict(tc.__dict__)
    exec(source, namespace)
    tc.TestCasePortRebinding.check = namespace["check"]
    case = tc.TestCaseConnectionMigration(
        SimpleNamespace(name=str(directory / "sim")),
        str(directory / "client/keys.log"), str(directory / "server/keys.log"),
    )
    case._server_www_dir = SimpleNamespace(name=str(directory / "server_www"))
    case._client_download_dir = SimpleNamespace(name=str(directory / "client_downloads"))
    case._files = [p.name for p in (directory / "server_www").iterdir() if p.is_file()]
    result = case.check()
    print("Upstream with only response-first rule relaxed:", result)
    return 0 if result == tc.TestResult.SUCCEEDED else 1


if __name__ == "__main__":
    raise SystemExit(main())
