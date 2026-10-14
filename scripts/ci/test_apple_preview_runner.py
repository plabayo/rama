import unittest

from apple_preview_runner import select_runner


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
