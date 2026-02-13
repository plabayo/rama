#!/usr/bin/env python3
from __future__ import annotations

import argparse
import io
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile


def api_get(url: str, token: str):
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))


def api_request(url: str, token: str) -> urllib.request.Request:
    return urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "bench-baseline-downloader",
        },
    )


def download_artifact_zip(zip_api_url: str, token: str) -> bytes:
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    opener = urllib.request.build_opener(NoRedirect)

    req = urllib.request.Request(
        zip_api_url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "bench-baseline-downloader",
        },
    )

    try:
        with opener.open(req) as resp:
            # Some setups might actually return the bytes directly without redirect
            return resp.read()
    except urllib.error.HTTPError as e:
        # We expect a redirect. urllib raises HTTPError for 30x when redirects are disabled.
        if e.code not in (301, 302, 303, 307, 308):
            raise

        location = e.headers.get("Location") or e.headers.get("location")
        if not location:
            raise RuntimeError(f"Redirect without Location header, status={e.code}")

        print(f"Redirect location: {location}", file=sys.stderr)

        # Follow redirect manually without auth header
        req2 = urllib.request.Request(
            location,
            headers={"User-Agent": "bench-baseline-downloader"},
        )
        with urllib.request.urlopen(req2) as resp2:
            return resp2.read()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True, help="owner/repo")
    ap.add_argument(
        "--workflow", required=True, help="workflow file name, e.g. benchmarks.yml"
    )
    ap.add_argument(
        "--artifact", required=True, help="artifact name, e.g. benchmarks-baselines"
    )
    ap.add_argument("--out", required=True, help="output directory")
    ap.add_argument("--branch", default="main")
    args = ap.parse_args()

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        print("Missing GITHUB_TOKEN in environment", file=sys.stderr)
        return 2

    os.makedirs(args.out, exist_ok=True)

    runs_url = f"https://api.github.com/repos/{args.repo}/actions/workflows/{args.workflow}/runs?branch={args.branch}&status=success&per_page=20"
    runs = api_get(runs_url, token)
    workflow_runs = runs.get("workflow_runs", [])
    if not workflow_runs:
        print("No successful runs found", file=sys.stderr)
        return 0

    run_id = workflow_runs[0]["id"]

    arts_url = f"https://api.github.com/repos/{args.repo}/actions/runs/{run_id}/artifacts?per_page=100"
    artifacts = api_get(arts_url, token).get("artifacts", [])
    match = [a for a in artifacts if a.get("name") == args.artifact]

    if not match:
        print(
            f"No artifact named {args.artifact} found in run {run_id}", file=sys.stderr
        )
        return 0

    artifact_id = match[0]["id"]

    zip_url = (
        f"https://api.github.com/repos/{args.repo}/actions/artifacts/{artifact_id}/zip"
    )
    data = download_artifact_zip(zip_url, token)

    with zipfile.ZipFile(io.BytesIO(data)) as z:
        z.extractall(args.out)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
