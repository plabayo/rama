#!/usr/bin/env python3
"""Cancel obsolete PR work using trusted metadata only, including late reruns."""

import argparse
import json
import os
from pathlib import Path
from datetime import datetime, timedelta, timezone
import subprocess
import time
from urllib.parse import urlencode


ACTIVE = ("queued", "in_progress", "pending", "waiting", "requested")


def api(path, method="GET", paginate=False):
    command = ["gh", "api", "--method", method, path]
    if paginate:
        command += ["--paginate", "--slurp"]
    for attempt in range(3):
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            return json.loads(result.stdout) if result.stdout.strip() else None
        if attempt < 2:
            time.sleep(2 ** attempt)
    raise RuntimeError(f"gh {method} {path}: {result.stderr.strip()}")


class Reaper:
    def __init__(self, repo, default_branch, self_id, request=api, sleep=time.sleep):
        self.repo = repo
        self.default_branch = default_branch
        self.self_id = self_id
        self.request = request
        self.sleep = sleep
        self.pulls = {}
        self.branches = {}
        self.runs_url = f"repos/{repo}/actions/runs"

    def active_runs(self):
        runs = {}
        for status in ACTIVE:
            pages = self.request(f"{self.runs_url}?status={status}&per_page=100", paginate=True)
            for page in pages:
                for run in page["workflow_runs"]:
                    if run["id"] != self.self_id and run["status"] != "completed":
                        runs[run["id"]] = run
        return list(runs.values())

    def pull(self, number):
        if number not in self.pulls:
            self.pulls[number] = self.request(f"repos/{self.repo}/pulls/{number}")
        return self.pulls[number]

    def obsolete(self, run):
        if run["event"] not in ("pull_request", "workflow_dispatch"):
            return False
        if run["event"] == "workflow_dispatch" and run["head_branch"] == self.default_branch:
            return False
        head_repo = run.get("head_repository") or {}
        if not head_repo.get("id") or not head_repo.get("owner"):
            return False
        references = run.get("pull_requests") or []
        if references:
            candidates = [self.pull(pr["number"]) for pr in references]
        else:
            # GitHub returns [] here after merge. Branch names alone are unsafe:
            # use the source owner in the query and check the repository ID too.
            key = (head_repo["id"], run["head_branch"])
            if key not in self.branches:
                query = urlencode({"state": "all", "head": f"{head_repo['owner']['login']}:{run['head_branch']}",
                                   "per_page": 100})
                pages = self.request(f"repos/{self.repo}/pulls?{query}", paginate=True)
                self.branches[key] = [pr for page in pages for pr in page]
            candidates = self.branches[key]
        candidates = [pr for pr in candidates
                      if (pr["head"].get("repo") or {}).get("id") == head_repo["id"]
                      and pr["head"]["ref"] == run["head_branch"]
                      and pr["base"]["repo"]["full_name"] == self.repo]
        # A branch may be reused for a new PR. Never cancel its live work.
        if any(pr["state"] == "open" for pr in candidates):
            return False
        return any(pr.get("merged_at") and pr["created_at"] <= run["created_at"]
                   and (run["created_at"] <= pr["merged_at"]
                        or run["head_sha"] == pr["head"]["sha"])
                   for pr in candidates)

    def unfinished(self, ids):
        return {run_id for run_id in ids
                if self.request(f"{self.runs_url}/{run_id}")["status"] != "completed"}

    def stale_jobless_run(self, run_id, error):
        # GitHub can retain phantom queued runs indefinitely, rejecting both
        # cancellation endpoints. Never exempt real jobs or a fresh queue entry.
        if "(HTTP 409)" not in error or "Cannot cancel a workflow run that has not been queued yet" not in error:
            return False
        run = self.request(f"{self.runs_url}/{run_id}")
        if run["status"] != "queued":
            return False
        updated = datetime.fromisoformat(run["updated_at"].replace("Z", "+00:00"))
        if datetime.now(timezone.utc) - updated < timedelta(days=1):
            return False
        jobs = self.request(f"{self.runs_url}/{run_id}/jobs?per_page=1")
        if jobs["total_count"] != 0 or jobs["jobs"]:
            return False
        print(f"::warning::GitHub rejected cancellation of stale jobless run {run_id}; "
              "no runner jobs exist. A later sweep will retry.", flush=True)
        return True

    def cancel(self, ids):
        pending = set(ids)
        errors = []
        # Normal cancellation gives cleanup a short grace period. Force-cancel
        # bypasses always() jobs that otherwise keep scarce runner slots alive.
        for method, polls in (("cancel", 3), ("force-cancel", 12)):
            for run_id in sorted(pending):
                print(f"{method}: {run_id}", flush=True)
                try:
                    self.request(f"{self.runs_url}/{run_id}/{method}", method="POST")
                except RuntimeError as error:
                    # Completion can race a POST; poll authoritative state below.
                    errors.append(str(error))
                    if method == "force-cancel" and self.stale_jobless_run(run_id, str(error)):
                        pending.remove(run_id)
            for _ in range(polls):
                pending = self.unfinished(pending)
                if not pending:
                    return
                self.sleep(5)
        pending = self.unfinished(pending)
        if pending:
            raise RuntimeError(f"Runs still unfinished: {sorted(pending)}; API errors: {errors}")

    def sweep(self, dry_run=False):
        # Refresh PR state on each scan; a merge may race the first listing.
        self.pulls.clear()
        self.branches.clear()
        ids = [run["id"] for run in self.active_runs() if self.obsolete(run)]
        print(f"Merged PR runs{' (dry run)' if dry_run else ''}: {ids}", flush=True)
        if not dry_run:
            self.cancel(ids)
        return ids


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    reaper = Reaper(os.environ["GITHUB_REPOSITORY"], event["repository"]["default_branch"],
                    int(os.environ.get("GITHUB_RUN_ID", "0")))
    reaper.sweep(args.dry_run)
    if not args.dry_run:
        # Re-list after cancellation to catch queued -> running transitions and
        # runs that were not yet visible at merge time. The schedule is a backstop.
        reaper.sleep(10)
        reaper.sweep()


if __name__ == "__main__":
    main()
