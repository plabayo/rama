"""Merged-run cleanup must not cancel live PRs or trust an accepted POST."""

from copy import deepcopy
import unittest
from unittest.mock import Mock

from cancel_merged_pr_runs import ACTIVE, Reaper


REPO = "plabayo/rama"
SOURCE = {"id": 42, "owner": {"login": "plabayo"}}


def run(**changes):
    value = {"id": 7, "event": "pull_request", "status": "in_progress",
             "head_repository": SOURCE, "head_branch": "patch/ci", "head_sha": "abc",
             "created_at": "2026-10-22T10:00:00Z", "pull_requests": []}
    value.update(changes)
    return value


def pull(**changes):
    value = {"number": 70, "state": "closed", "merged_at": "2026-10-23T10:00:00Z",
             "created_at": "2026-10-21T10:00:00Z",
             "head": {"repo": SOURCE, "ref": "patch/ci", "sha": "abc"},
             "base": {"repo": {"full_name": REPO}}}
    value.update(changes)
    return value


class MatchingTests(unittest.TestCase):
    def reaper(self, candidates):
        def request(path, **kwargs):
            if "pulls?" in path:
                self.assertIn("head=plabayo%3Apatch%2Fci", path)
                self.assertTrue(kwargs["paginate"])
                return [[pr] for pr in candidates]
            return next(pr for pr in candidates if path.endswith(f"/{pr['number']}"))
        return Reaper(REPO, "main", 99, request=request, sleep=lambda _: None)

    def test_merged_pr_with_empty_run_association_and_older_head(self):
        self.assertTrue(self.reaper([pull()]).obsolete(run(head_sha="older")))

    def test_explicit_association_is_resolved(self):
        self.assertTrue(self.reaper([pull()]).obsolete(run(pull_requests=[{"number": 70}])))

    def test_manual_run_and_late_run_at_merged_head(self):
        reaper = self.reaper([pull()])
        self.assertTrue(reaper.obsolete(run(event="workflow_dispatch")))
        self.assertTrue(reaper.obsolete(run(created_at="2026-10-24T10:00:00Z")))

    def test_pr_source_branch_named_main_can_still_be_cancelled(self):
        pr = pull(head={"repo": SOURCE, "ref": "main", "sha": "abc"})
        self.assertTrue(self.reaper([pr]).obsolete(
            run(head_branch="main", pull_requests=[{"number": 70}])))

    def test_unrelated_and_live_work_is_preserved(self):
        cases = [
            (run(event="push"), [pull()]),
            (run(event="schedule"), [pull()]),
            (run(event="workflow_run"), [pull()]),
            (run(event="workflow_dispatch", head_branch="main"), [pull()]),
            (run(head_repository=None), [pull()]),
            (run(), [pull(state="open", merged_at=None)]),
            (run(), [pull(merged_at=None)]),
            (run(), []),
            (run(created_at="2026-10-20T10:00:00Z"), [pull()]),
            (run(created_at="2026-10-24T10:00:00Z", head_sha="new"), [pull()]),
            (run(), [pull(), pull(number=71, state="open", merged_at=None)]),
            (run(), [pull(head={"repo": {"id": 43}, "ref": "patch/ci", "sha": "abc"})]),
            (run(), [pull(head={"repo": None, "ref": "patch/ci", "sha": "abc"})]),
            (run(), [pull(base={"repo": {"full_name": "another/repo"}})]),
        ]
        for candidate, pulls in cases:
            with self.subTest(run=candidate, pulls=pulls):
                self.assertFalse(self.reaper(pulls).obsolete(candidate))

    def test_active_statuses_paginate_deduplicate_and_exclude_self(self):
        request = Mock(return_value=[{"workflow_runs": [run(), run(id=99)]},
                                     {"workflow_runs": [run(id=8), run(status="completed")]}])
        reaper = Reaper(REPO, "main", 99, request=request)
        self.assertEqual({item["id"] for item in reaper.active_runs()}, {7, 8})
        self.assertEqual(request.call_count, len(ACTIVE))
        self.assertTrue(all(call.kwargs["paginate"] for call in request.call_args_list))

    def test_dry_run_never_posts_and_next_sweep_refreshes_merge_state(self):
        pr = pull(state="open", merged_at=None)
        def request(path, method="GET", **_):
            self.assertEqual(method, "GET")
            return [[deepcopy(pr)]] if "pulls?" in path else [{"workflow_runs": [run()]}]
        reaper = Reaper(REPO, "main", 99, request=request)
        self.assertEqual(reaper.sweep(dry_run=True), [])
        pr.update(state="closed", merged_at="2026-10-23T10:00:00Z")
        self.assertEqual(reaper.sweep(dry_run=True), [7])


class CancellationTests(unittest.TestCase):
    def exercise(self, finish_after=None, reject=False):
        calls = []
        def request(path, method="GET", **_):
            if method == "POST":
                calls.append(path.rsplit("/", 1)[-1])
                if reject:
                    raise RuntimeError("409: completion raced cancellation")
                return None
            return {"status": "completed" if finish_after in calls else "in_progress"}
        return Reaper(REPO, "main", 99, request=request, sleep=lambda _: None), calls

    def test_normal_cancellation_is_verified(self):
        reaper, calls = self.exercise("cancel")
        reaper.cancel([7])
        self.assertEqual(calls, ["cancel"])

    def test_stuck_always_job_is_force_cancelled_and_verified(self):
        reaper, calls = self.exercise("force-cancel")
        reaper.cancel([7])
        self.assertEqual(calls, ["cancel", "force-cancel"])

    def test_completion_race_is_success(self):
        reaper, calls = self.exercise("cancel", reject=True)
        reaper.cancel([7])
        self.assertEqual(calls, ["cancel"])

    def test_accepted_but_ineffective_cancellation_fails(self):
        reaper, calls = self.exercise()
        with self.assertRaisesRegex(RuntimeError, "still unfinished"):
            reaper.cancel([7])
        self.assertEqual(calls, ["cancel", "force-cancel"])

    def test_post_failures_still_escalate_and_fail(self):
        reaper, calls = self.exercise(reject=True)
        with self.assertRaisesRegex(RuntimeError, "still unfinished"):
            reaper.cancel([7, 8])
        self.assertEqual(calls, ["cancel", "cancel", "force-cancel", "force-cancel"])


if __name__ == "__main__":
    unittest.main()
