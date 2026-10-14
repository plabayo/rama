import unittest
import urllib.error
from unittest.mock import patch, MagicMock

from apple_preview_runner import select_runner, fetch_catalog


class PreviewRunnerTests(unittest.TestCase):
    def test_new_major_rolls_forward_numerically(self):
        catalog = "\n".join([
            "| Xcode | arm64 | `xcode-9` | [software] |",
            "| Xcode preview | arm64 | `xcode-28` or `xcode-28-xlarge` | [software] |",
            "| Xcode | arm64 | `xcode-27` | [software] |",
            "| Xcode deprecated | arm64 | `xcode-99` | [software] |",
            "| Xcode | arm64 | `xcode-100-xlarge` | [software] |",
            "| unrelated | x64 | `xcode-101` | [software] |",
            "Elsewhere `xcode-102` is mentioned.",
        ])
        self.assertEqual(select_runner(catalog), "xcode-28")

    def test_missing_or_changed_catalog_fails_instead_of_falling_back(self):
        for catalog in ("", "| macOS | arm64 | `macos-latest` | [software] |",
                        "| Xcode | arm64 | `xcode-27;evil` | [software] |"):
            with self.subTest(catalog=catalog), self.assertRaises(ValueError):
                select_runner(catalog)


    def test_transient_fetch_retries_but_bad_catalog_does_not(self):
        response = MagicMock()
        response.__enter__.return_value.read.return_value = b"bad catalog"
        with patch("apple_preview_runner.urllib.request.urlopen", side_effect=[urllib.error.URLError("offline"), response]) as fetch, patch("apple_preview_runner.time.sleep"):
            with self.assertRaises(ValueError):
                select_runner(fetch_catalog())
        self.assertEqual(fetch.call_count, 2)

    def test_fetch_retry_budget_is_bounded(self):
        with patch("apple_preview_runner.urllib.request.urlopen", side_effect=TimeoutError()) as fetch, patch("apple_preview_runner.time.sleep"), self.assertRaises(TimeoutError):
            fetch_catalog()
        self.assertEqual(fetch.call_count, 3)
