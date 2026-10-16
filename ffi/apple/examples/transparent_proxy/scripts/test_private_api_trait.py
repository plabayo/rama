from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from check_private_api_trait import SYMBOL, check, production_objects


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
        with tempfile.TemporaryDirectory() as directory, patch("check_private_api_trait.subprocess.run"), patch("check_private_api_trait.subprocess.check_output", return_value=directory), self.assertRaisesRegex(RuntimeError, "No production objects"):
            check(Path(directory))

    def test_reported_product_outside_scratch_is_inspected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            product = root / "products" / "RamaAppleNetworkExtension.o"
            product.parent.mkdir()
            product.write_bytes(b"production object")
            # A sibling target must not influence this target's result.
            (product.parent / "RamaAppleNetworkExtensionTests.o").write_bytes(SYMBOL)
            self.assertEqual(production_objects(root / "scratch", product.parent), [product])

    def test_trait_symbol_is_required_only_in_opted_in_product(self):
        for public_symbol, private_symbol in [(False, True), (True, True), (False, False)]:
            with self.subTest(public_symbol=public_symbol, private_symbol=private_symbol), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                public = root / "public-products"
                private = root / "private-products"
                for path, present in [(public, public_symbol), (private, private_symbol)]:
                    path.mkdir()
                    (path / "RamaAppleNetworkExtension.o").write_bytes(SYMBOL if present else b"object")
                with patch("check_private_api_trait.subprocess.run"), patch(
                    "check_private_api_trait.subprocess.check_output",
                    side_effect=[str(public), str(private)],
                ):
                    if public_symbol or not private_symbol:
                        with self.assertRaisesRegex(RuntimeError, "Private symbol presence"):
                            check(root / "scratch")
                    else:
                        check(root / "scratch")
