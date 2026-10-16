import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from browser_h1 import main


class BrowserSelectionTests(unittest.TestCase):
    def test_explicit_browser_is_passed_to_isolated_capture(self):
        for browser in ('chrome', 'firefox'):
            with self.subTest(browser=browser), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                binary = root / 'binary'
                binary.touch()
                output = root / 'evidence'
                with patch('sys.argv', ['test', '--rama', str(binary),
                                       f'--{browser}', str(binary), '--output', str(output), '--flows', 'all']), \
                     patch('browser_h1.shutil.which', return_value='/test/tool'), \
                     patch('browser_h1.subprocess.run'), \
                     patch('browser_h1.run', return_value=0) as capture:
                    self.assertEqual(main(browser), 0)
                environment = capture.call_args.kwargs['environment']
                self.assertEqual(environment['RAMA_ROUNDTRIP_BROWSER'], browser)
                self.assertEqual(environment['RAMA_ROUNDTRIP_FLOWS'], 'all')
                self.assertEqual(environment['RAMA_ROUNDTRIP_BROWSER_BINARY'], str(binary.resolve()))
                self.assertEqual(environment['RAMA_ROUNDTRIP_BINARY'], str(binary.resolve()))
                self.assertEqual(output.stat().st_mode & 0o777, 0o700)
                self.assertEqual(capture.call_args.kwargs['image_name'], 'postgres:17-alpine')

    def test_existing_evidence_is_rejected_before_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / 'binary'
            binary.touch()
            with patch('sys.argv', ['test', '--rama', str(binary), '--firefox', str(binary),
                                   '--output', str(root)]), \
                 patch('browser_h1.shutil.which', return_value='/test/tool'), \
                 patch('browser_h1.subprocess.run'), patch('browser_h1.run') as capture:
                with self.assertRaises(FileExistsError):
                    main('firefox')
                capture.assert_not_called()


if __name__ == '__main__':
    unittest.main()
