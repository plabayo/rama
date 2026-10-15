from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from check_private_api_trait import check, production_objects


class TraitObjectTests(unittest.TestCase):
    def test_native_and_xcode_layouts_include_only_release_production_objects(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            included = [
                "arm64-apple-macosx/release/RamaAppleNetworkExtension.build/TcpNwParameters.swift.o",
                "out/Intermediates.noindex/RamaAppleNetworkExtension.build/Release/RamaAppleNetworkExtension.build/Objects-normal/arm64/TcpNwParameters.o",
            ]
            excluded = [
                "arm64-apple-macosx/debug/RamaAppleNetworkExtension.build/TcpNwParameters.swift.o",
                "out/Intermediates.noindex/RamaAppleNetworkExtension.build/Release/RamaAppleNetworkExtensionTests.build/Objects-normal/arm64/TcpNwParameters.o",
                "release/RamaAppleXpcClient.build/Client.o",
            ]
            for name in included + excluded:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"object")
            self.assertEqual(set(production_objects(root)), {root / name for name in included})

    def test_no_objects_does_not_pass_as_a_public_build(self):
        with tempfile.TemporaryDirectory() as directory, patch("check_private_api_trait.subprocess.run"), self.assertRaisesRegex(RuntimeError, "No production objects"):
            check(Path(directory))
