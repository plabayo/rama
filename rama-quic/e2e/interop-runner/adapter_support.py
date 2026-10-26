"""Log retention with Docker-inspected exit provenance, including unsupported cases."""
import json
import logging
import shutil
import subprocess


def copy_logs(self, container, directory):
    # Compose resolves the service within this invocation's project. Upstream's
    # global `docker ps | awk` lookup would copy another run's named container.
    base = ["docker", "compose", "--env-file", "empty.env"]
    ids = subprocess.check_output(base + ["ps", "--all", "--quiet", container], text=True).split()
    if len(ids) != 1:
        raise RuntimeError(f"expected one {container} container, found {ids}")
    state = json.loads(subprocess.check_output(["docker", "inspect", ids[0]], text=True))[0]["State"]
    if state["Running"]:
        raise RuntimeError(f"{container} still running during result collection")
    evidence = getattr(self, "_rama_evidence", None)
    if evidence is not None:
        evidence[f"{container}_exit"] = state["ExitCode"]
    result = subprocess.run(
        ["docker", "compose", "--env-file", "empty.env", "cp",
         f"{container}:/logs/.", directory.name],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60,
    )
    if result.returncode:
        # Unsupported endpoints may exit before creating /logs. Only an actual
        # 127 permits that absence; a missing successful/failed run's logs is fatal.
        if state["ExitCode"] == 127 and b"Could not find the file /logs/." in result.stdout:
            return
        logging.error("Copying %s logs failed: %s", container,
                      result.stdout.decode(errors="replace"))
        raise RuntimeError(f"could not retain {container} logs")
    if evidence is not None and state["ExitCode"] == 127:
        shutil.copytree(directory.name,
                        self._rama_evidence_dir / evidence["case"] / container)
