"""Merged-run cleanup must not cancel live or unrelated work."""

import unittest

from cancel_merged_pr_runs import Reaper


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
                return [[pr] for pr in candidates]
            return next(pr for pr in candidates if path.endswith(f"/{pr['number']}"))
        return Reaper(REPO, "main", 99, request=request, sleep=lambda _: None)

    def test_merged_pr_run_is_obsolete(self):
        self.assertTrue(self.reaper([pull()]).obsolete(run()))

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
