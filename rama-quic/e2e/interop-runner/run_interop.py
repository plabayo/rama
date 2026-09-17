#!/usr/bin/env python3
"""Build Rama's endpoint and run the pinned independent QUIC interop matrix."""
import argparse
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import uuid

from check_results import InvalidResults, gate, load_report
from check_qlogs import gate_qlogs

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def execute(command, **kwargs):
    print("+ " + " ".join(map(str, command)), flush=True)
    return subprocess.run(list(map(str, command)), check=True, **kwargs)


def output(command, **kwargs):
    return subprocess.check_output(list(map(str, command)), text=True, **kwargs).strip()


def run_managed(command, timeout=30 * 60, **kwargs):
    """Stop the whole upstream process group before Compose resource cleanup."""
    process = subprocess.Popen(list(map(str, command)), start_new_session=True, **kwargs)
    try:
        return process.wait(timeout=timeout)
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass
        # Descendant shell/Compose processes can outlive their Python parent.
        # Kill the group even if that parent has already exited.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)
        raise


def snapshot_container_logs(checkout, env, artifacts, console):
    """Keep in-container evidence even when upstream is interrupted before copy."""
    base = ["docker", "compose", "--env-file", "empty.env"]
    errors = []
    try:
        running = subprocess.run(base + ["ps", "--all", "--quiet"], cwd=checkout, env=env,
                                 stdout=subprocess.PIPE, stderr=console, timeout=10, check=True)
        if not running.stdout.strip():
            return errors
    except (subprocess.SubprocessError, OSError) as error:
        errors.append(f"snapshot container discovery: {error}")
        # Discovery failure must not prevent trying to preserve each service.
    destination = artifacts / "last-containers"
    destination.mkdir(exist_ok=True)
    try:
        with (destination / "compose.log").open("w") as logs:
            subprocess.run(base + ["logs", "--no-color", "--timestamps"], cwd=checkout,
                           env=env, stdout=logs, stderr=console, timeout=10, check=True)
    except (subprocess.SubprocessError, OSError) as error:
        errors.append(f"snapshot console logs: {error}")
    for service in ("sim", "client", "server"):
        target = destination / service
        target.mkdir(exist_ok=True)
        try:
            subprocess.run(base + ["cp", f"{service}:/logs/.", str(target)], cwd=checkout,
                           env=env, stdout=console, stderr=console, timeout=10, check=True)
        except (subprocess.SubprocessError, OSError) as error:
            errors.append(f"snapshot {service} logs (service may not exist): {error}")
    for error in errors:
        print(error, file=console, flush=True)
    return errors


def compose_override(project, platform, simulator):
    services = {name: {"container_name": f"{project}-{name}", "platform": platform}
                for name in ("sim", "client", "server", "iperf_client", "iperf_server")}
    services["sim"].update({
        "image": simulator,
        "entrypoint": ["/bin/bash", "/rama-run-simulator.sh"],
        "volumes": [f"{HERE / 'run_simulator.sh'}:/rama-run-simulator.sh:ro"],
    })
    # Compose 5.1 abort-on-exit can kill immediately without service-level grace,
    # despite `up --timeout 10`; allow endpoints and packet capture processes to drain explicitly.
    for role in ("sim", "client", "server"):
        services[role]["stop_grace_period"] = "10s"
    return {"services": services}


def inspect_image(reference, platform):
    expected_os, expected_arch = platform.split("/")
    command = ["docker", "image", "inspect", reference]
    info = json.loads(output(command))[0]
    # A multi-platform local store can inspect the host variant by default.
    # Classic stores already return the variant selected by the preceding pull.
    if (info.get("Os"), info.get("Architecture")) != (expected_os, expected_arch):
        info = json.loads(output(command + ["--platform", platform]))[0]
    if (info.get("Os"), info.get("Architecture")) != (expected_os, expected_arch):
        raise RuntimeError(f"image {reference} does not provide requested platform {platform}")
    return info


def verify_image_backend(info, requested):
    selected = ((info.get("Config") or {}).get("Labels") or {}).get("org.ramaproxy.quic.tls-backend")
    if selected != requested:
        raise RuntimeError(f"Rama image backend {selected!r} does not match requested {requested!r}")


def preflight():
    if sys.version_info < (3, 10):
        raise RuntimeError("Python >=3.10 required by upstream; set PYTHON=/path/to/python3.12")
    for program in ("docker", "git", "tshark", "openssl", "bash"):
        if not shutil.which(program):
            raise RuntimeError(f"required executable missing: {program}")
    openssl = output(["openssl", "version"])
    version = re.match(r"OpenSSL (\d+)\.", openssl)
    if not version or int(version.group(1)) < 3:
        raise RuntimeError(
            f"OpenSSL >=3 required by upstream certificate generation; found {openssl}. "
            "On macOS, install openssl@3 and prepend $(brew --prefix openssl@3)/bin to PATH."
        )
    compose = output(["docker", "compose", "version", "--short"])
    version = re.search(r"(\d+)\.(\d+)", compose)
    if not version or tuple(map(int, version.groups())) < (2, 36):
        raise RuntimeError(f"Docker Compose >=2.36 required (interface_name); found {compose}")
    docker = json.loads(output(["docker", "version", "--format", "{{json .}}"]))
    engine = docker.get("Server", {}).get("Version", "unknown")
    version = re.match(r"(\d+)\.(\d+)", engine)
    if not version or tuple(map(int, version.groups())) < (28, 1):
        raise RuntimeError(f"Docker Engine >=28.1 required (interface_name); found {engine}")
    tshark = output(["tshark", "--version"]).splitlines()[0]
    version = re.search(r"(\d+)\.(\d+)", tshark)
    if not version or tuple(map(int, version.groups())) < (4, 5):
        raise RuntimeError(f"tshark >=4.5 required; found {tshark}")
    if output(["docker", "info", "--format", "{{.OSType}}"] ) != "linux":
        raise RuntimeError("Docker must run Linux containers")
    # The upstream simulator and trace parser require fixed subnets. Never tear
    # down someone else's networks to obtain them; fail before creating ours.
    network_ids = output(["docker", "network", "ls", "--quiet"]).split()
    if network_ids:
        networks = json.loads(output(["docker", "network", "inspect", *network_ids]))
        required = [ipaddress.ip_network(s) for s in (
            "193.167.0.0/24", "193.167.100.0/24",
            "fd00:cafe:cafe:0::/64", "fd00:cafe:cafe:100::/64")]
        for network in networks:
            for config in network.get("IPAM", {}).get("Config", []) or []:
                if not config.get("Subnet"):
                    continue
                existing = ipaddress.ip_network(config["Subnet"], strict=False)
                if any(existing.version == wanted.version and existing.overlaps(wanted)
                       for wanted in required):
                    raise RuntimeError(f"network {network['Name']} overlaps the runner's fixed subnets; stop its owner first")
    return {"compose": compose, "tshark": tshark, "openssl": openssl,
            "docker": docker,
            "python": sys.version}


def main():
    lock = json.loads((HERE / "runner.lock.json").read_text())
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", choices=["boring", "rustls-ring", "rustls-aws-lc"], default="rustls-ring")
    parser.add_argument("--image", default="glendc/rama-quic-interop:local")
    parser.add_argument("--skip-build", action="store_true", help="use an already built local image")
    parser.add_argument("--artifacts", type=Path, help="new directory for this run; must not exist")
    parser.add_argument("--tests", default=",".join(lock["cases"]),
                        help="comma-separated subset for diagnosis; default is the full required gate")
    parser.add_argument("--platform", choices=["linux/amd64", "linux/arm64"], default=lock["platform"])
    args = parser.parse_args()
    cases = args.tests.split(",")
    if not cases or len(set(cases)) != len(cases) or set(cases) - set(lock["cases"]):
        parser.error("--tests must select unique cases from runner.lock.json")
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._/@:-]*", args.image):
        parser.error("invalid image reference")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    project = "rama-quic-" + uuid.uuid4().hex[:12]
    artifacts = (args.artifacts or ROOT / "target/quic-interop" / f"{stamp}-{project}").resolve()
    artifacts.mkdir(parents=True, exist_ok=False)
    print(f"Retaining QUIC interop artifacts: {artifacts}", flush=True)
    shutil.copy2(HERE / "runner.lock.json", artifacts)
    shutil.copy2(HERE / "requirements.lock", artifacts)
    manifest = {"project": project, "cases": cases, "full_gate": cases == lock["cases"],
                "platform": args.platform, "image": args.image, "backend": args.backend, "roles": {}}
    env = os.environ.copy()
    env.update(COMPOSE_PROJECT_NAME=project, DOCKER_DEFAULT_PLATFORM=args.platform,
               RAMA_CLEANUP_IMAGE=lock["cleanup"], COMPOSE_ANSI="never")
    checkout = artifacts / "upstream"
    compose_ready = False

    def interrupted(signum, frame):
        raise KeyboardInterrupt(f"signal {signum}")

    signal.signal(signal.SIGTERM, interrupted)
    try:
        manifest["runtime"] = preflight()
        manifest["rama_revision"] = output(["git", "rev-parse", "HEAD"], cwd=ROOT)
        manifest["rama_status"] = output(["git", "status", "--short"], cwd=ROOT)
        if not args.skip_build:
            execute(["docker", "build", "--platform", args.platform, "--tag", args.image,
                     "--build-arg", f"TLS_BACKEND={args.backend}", "--file", HERE / "Dockerfile", ROOT])
        images = {"rama": args.image, "simulator": lock["simulator"],
                  "cleanup": lock["cleanup"], **lock["peers"]}
        manifest["images"] = {}
        for name, ref in images.items():
            if name != "rama":
                execute(["docker", "pull", "--platform", args.platform, ref])
            manifest["images"][name] = inspect_image(ref, args.platform)
            if name == "rama":
                verify_image_backend(manifest["images"][name], args.backend)
        execute(["git", "init", checkout])
        execute(["git", "-C", checkout, "remote", "add", "origin", lock["repository"]])
        execute(["git", "-C", checkout, "fetch", "--depth=1", "origin", lock["revision"]])
        execute(["git", "-C", checkout, "checkout", "--detach", "FETCH_HEAD"])
        if output(["git", "-C", checkout, "rev-parse", "HEAD"]) != lock["revision"]:
            raise RuntimeError("upstream revision mismatch")
        implementations = {name: {"image": ref, "url": "https://github.com/" + repo, "role": "both"}
                           for name, ref, repo in [
                               ("rama", args.image, "plabayo/rama"),
                               ("quic-go", lock["peers"]["quic-go"], "quic-go/quic-go"),
                               ("ngtcp2", lock["peers"]["ngtcp2"], "ngtcp2/ngtcp2")]}
        (checkout / "implementations_quic.json").write_text(json.dumps(implementations, indent=2) + "\n")
        override = compose_override(project, args.platform, lock["simulator"])
        compose_path = artifacts / "compose.override.json"
        compose_path.write_text(json.dumps(override, indent=2) + "\n")
        env["COMPOSE_FILE"] = os.pathsep.join(map(str, [checkout / "docker-compose.yml", compose_path]))
        # Avoid empty variables breaking Compose during final cleanup.
        for name in ("CLIENT_WWW", "CLIENT_DOWNLOADS", "SERVER_WWW", "SERVER_DOWNLOADS", "CERTS"):
            env[name] = str(artifacts)
        env.update(SERVER=args.image, CLIENT=args.image)
        compose_ready = True
        lock_hash = hashlib.sha256((HERE / "requirements.lock").read_bytes()).hexdigest()[:16]
        venv = ROOT / "target/quic-interop" / f"venv-{sys.version_info.major}.{sys.version_info.minor}-{lock_hash}"
        if not (venv / ".installed").exists():
            execute([sys.executable, "-m", "venv", venv])
            execute([venv / "bin/python", "-m", "pip", "install", "--disable-pip-version-check",
                     "--requirement", HERE / "requirements.lock"])
            (venv / ".installed").touch()
        manifest["python_dependencies"] = output([venv / "bin/python", "-m", "pip", "freeze"])
        failed = False
        for role in ("client", "server"):
            clients = ["rama"] if role == "client" else list(lock["peers"])
            servers = list(lock["peers"]) if role == "client" else ["rama"]
            # Offering a compatible version as a client needs a TLS backend that changes
            # version mid-handshake; the Rama client built on rustls reports v2 unsupported.
            role_cases = [case for case in cases
                          if not (case == "v2" and role == "client" and args.backend != "boring")]
            report = artifacts / f"rama-{role}.json"
            command = [venv / "bin/python", HERE / "upstream_adapter.py", checkout,
                       "-c", ",".join(clients), "-s", ",".join(servers), "-t", ",".join(role_cases),
                       "-n", "rama,quic-go,ngtcp2", "-j", report,
                       "-l", artifacts / f"logs-rama-{role}", "-f", "true", "-d"]
            print(f"Running Rama as {role}: {','.join(role_cases)} (console: {artifacts / f'rama-{role}.log'})", flush=True)
            with (artifacts / f"rama-{role}.log").open("w") as console:
                status = run_managed(command, cwd=checkout, env=env,
                                     stdout=console, stderr=subprocess.STDOUT)
            result = {"runner_exit": status}
            try:
                result["successful_outcomes"] = gate(load_report(report), clients=clients,
                                                     servers=servers, cases=role_cases)
                if status != 0:
                    raise InvalidResults(f"runner exited {status} despite report")
                result["qlogs"] = gate_qlogs(artifacts, role=role, peers=list(lock["peers"]), cases=role_cases)
                result["qlog_records"] = sum(trace["records"] for trace in result["qlogs"].values())
                print(f"PASS Rama {role}: {result['successful_outcomes']} outcomes", flush=True)
            except (InvalidResults, OSError, json.JSONDecodeError) as error:
                result["error"] = str(error)
                failed = True
                print(f"FAIL Rama {role}: {error}", flush=True)
            manifest["roles"][role] = result
        manifest["passed"] = not failed
        return 1 if failed else 0
    except (Exception, KeyboardInterrupt) as error:
        manifest["passed"] = False
        manifest["error"] = str(error)
        print(f"QUIC interop failed: {error}", file=sys.stderr)
        return 1
    finally:
        if compose_ready:
            with (artifacts / "cleanup.log").open("w") as cleanup:
                try:
                    manifest["snapshot_errors"] = snapshot_container_logs(checkout, env, artifacts, cleanup)
                except Exception as error:
                    manifest["snapshot_errors"] = [str(error)]
                    print(f"Unable to snapshot containers: {error}", file=cleanup, flush=True)
                try:
                    subprocess.run(["docker", "compose", "--env-file", "empty.env", "down",
                                    "--volumes", "--timeout", "5"], cwd=checkout, env=env,
                                   stdout=cleanup, stderr=subprocess.STDOUT, timeout=60, check=True)
                except (subprocess.SubprocessError, OSError) as error:
                    manifest["cleanup_error"] = str(error)
                    print(f"Project cleanup failed; inspect {artifacts / 'cleanup.log'}", file=sys.stderr)
        (artifacts / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        print(f"Artifacts retained: {artifacts}", flush=True)
        if "cleanup_error" in manifest:
            return 1


if __name__ == "__main__":
    sys.exit(main())
