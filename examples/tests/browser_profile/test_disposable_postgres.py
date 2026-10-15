import subprocess
import unittest
from unittest.mock import MagicMock, patch

from disposable_postgres import isolated_environment, run


class DatabaseTests(unittest.TestCase):
    def test_existing_database_and_cookie_are_never_inherited(self):
        parent = dict(PGHOST='production', PGPASSWORD='secret', PGSERVICE='production',
                      DATABASE_URL='production', RAMA_FP_DATABASE_URL='production',
                      RAMA_FP_STORAGE_COOKIE='existing', RAMA_FP_TEST_PG='production',
                      NO_PROXY='elsewhere', PATH='/bin')
        child = isolated_environment(parent, 'disposable', 'owned-container')
        self.assertFalse(any(key.startswith('PG') for key in child))
        self.assertNotIn('RAMA_FP_STORAGE_COOKIE', child)
        self.assertNotIn('RAMA_FP_TEST_PG', child)
        for key in ('DATABASE_URL', 'RAMA_FP_DATABASE_URL', 'PR10_CAPTURE_DATABASE_URL'):
            self.assertEqual(child[key], 'disposable')
        self.assertEqual(child['NO_PROXY'], '127.0.0.1,localhost')
        self.assertEqual(child['PATH'], '/bin')
        self.assertEqual(parent['DATABASE_URL'], 'production')

    def test_failed_child_still_removes_only_owned_container(self):
        child = MagicMock()
        child.wait.return_value = 3
        child.poll.return_value = 3
        with patch('disposable_postgres.subprocess.check_output',
                   side_effect=['sha256:local-image', '127.0.0.1:54321']), \
             patch('disposable_postgres.subprocess.run') as command, \
             patch('disposable_postgres.subprocess.Popen', return_value=child) as popen:
            command.return_value.returncode = 0
            self.assertEqual(run(['test-child'], environment={}), 3)
            calls = [call.args[0] for call in command.call_args_list]
            started = next(args for args in calls if args[:2] == ['docker', 'run'])
            owned = started[started.index('--name') + 1]
            self.assertEqual(calls[-1], ['docker', 'rm', '--force', owned])
            self.assertTrue(owned.startswith('rama-pr10-test-'))
            self.assertIn('--pull=never', started)
            self.assertIn('127.0.0.1::5432', started)
            child.wait.assert_called_once_with(timeout=300)
            self.assertEqual(popen.call_args.kwargs['env']['PR10_TEST_PG_CONTAINER'], owned)

    def test_timeout_terminates_child_before_removing_database(self):
        child = MagicMock(pid=123)
        child.wait.side_effect = [subprocess.TimeoutExpired('test-child', 300), 0]
        child.poll.return_value = None
        with patch('disposable_postgres.subprocess.check_output',
                   side_effect=['sha256:local-image', '127.0.0.1:54321']), \
             patch('disposable_postgres.subprocess.run') as command, \
             patch('disposable_postgres.subprocess.Popen', return_value=child), \
             patch('disposable_postgres.os.killpg') as kill:
            command.return_value.returncode = 0
            with self.assertRaises(subprocess.TimeoutExpired):
                run(['test-child'], environment={})
            kill.assert_called_once()
            self.assertEqual(command.call_args.args[0][:3], ['docker', 'rm', '--force'])


if __name__ == '__main__':
    unittest.main()
