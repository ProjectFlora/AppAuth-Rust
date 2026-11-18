"""Tests for scripts/normalize_xcframework_plist.py.

The canonicalizer rewrites an xcframework Info.plist into a deterministic
form after xcodebuild -create-xcframework has written it in a run-varying
slice order. Each test writes a throwaway plist and runs a copy of the
script on it; the package script's double create-xcframework self-test then
covers the xcodebuild side of the pair on a real machine.

Run with: python3 -m unittest discover -s scripts -p 'test_*.py'
"""
import os
import plistlib
import shutil
import subprocess
import tempfile
import unittest

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
NORMALIZER = os.path.join(SCRIPTS_DIR, "normalize_xcframework_plist.py")

# The slice set the release xcframework must contain.
SLICES = {
    "ios-arm64": {
        "BinaryPath": "libnative_oidc.a",
        "HeadersPath": "Headers",
        "LibraryIdentifier": "ios-arm64",
        "LibraryPath": "libnative_oidc.a",
        "SupportedArchitectures": ["arm64"],
        "SupportedPlatform": "ios",
    },
    "ios-arm64-simulator": {
        "BinaryPath": "libnative_oidc.a",
        "HeadersPath": "Headers",
        "LibraryIdentifier": "ios-arm64-simulator",
        "LibraryPath": "libnative_oidc.a",
        "SupportedArchitectures": ["arm64"],
        "SupportedPlatform": "ios",
        "SupportedPlatformVariant": "simulator",
    },
    "macos-arm64_x86_64": {
        "BinaryPath": "libnative_oidc_macos.a",
        "HeadersPath": "Headers",
        "LibraryIdentifier": "macos-arm64_x86_64",
        "LibraryPath": "libnative_oidc_macos.a",
        "SupportedArchitectures": ["x86_64", "arm64"],  # deliberately unsorted
        "SupportedPlatform": "macos",
    },
}


def _write_plist(path, order):
    """Write an Info.plist whose array order and arch order are scrambled,
    the way xcodebuild emits them from run to run."""
    libraries = []
    for identifier in order:
        library = {key: value for key, value in SLICES[identifier].items()}
        # A fresh list, reversed: the module-level fixture must not mutate.
        library["SupportedArchitectures"] = list(
            reversed(library["SupportedArchitectures"])
        )
        libraries.append(library)
    info = {
        "AvailableLibraries": libraries,
        "CFBundlePackageType": "XFWK",
        "XCFrameworkFormatVersion": "1.0",
    }
    with open(path, "wb") as handle:
        plistlib.dump(info, handle, fmt=plistlib.FMT_XML)


class NormalizeXcframeworkPlistTestCase(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="normalize-plist-test-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.plist = os.path.join(self.tmpdir, "Info.plist")
        _write_plist(self.plist, [
            "macos-arm64_x86_64", "ios-arm64", "ios-arm64-simulator"])

    def _run(self):
        return subprocess.run(
            ["python3", NORMALIZER, self.plist],
            capture_output=True, text=True)

    def _identifiers(self):
        with open(self.plist, "rb") as handle:
            return [library["LibraryIdentifier"]
                    for library in plistlib.load(handle)["AvailableLibraries"]]

    def _assert_refused(self, mutate, message):
        """Rewrite the plist with mutate, then require a clean rejection:
        nonzero exit, the named message on stderr, no traceback, and the
        file left untouched."""
        with open(self.plist, "rb") as handle:
            info = plistlib.load(handle)
        mutate(info)
        with open(self.plist, "wb") as handle:
            plistlib.dump(info, handle, fmt=plistlib.FMT_XML)
        with open(self.plist, "rb") as handle:
            before = handle.read()
        proc = self._run()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn(message, proc.stderr)
        self.assertNotIn("Traceback", proc.stderr)
        with open(self.plist, "rb") as handle:
            self.assertEqual(handle.read(), before)

    def test_scrambled_input_is_canonicalized(self):
        proc = self._run()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(
            self._identifiers(),
            ["ios-arm64", "ios-arm64-simulator", "macos-arm64_x86_64"])
        with open(self.plist, "rb") as handle:
            architectures = {
                library["LibraryIdentifier"]: library["SupportedArchitectures"]
                for library in plistlib.load(handle)["AvailableLibraries"]
            }
        self.assertEqual(architectures["macos-arm64_x86_64"],
                         ["arm64", "x86_64"])

    def test_normalized_output_is_idempotent(self):
        proc = self._run()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        with open(self.plist, "rb") as handle:
            first = handle.read()
        proc = self._run()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        with open(self.plist, "rb") as handle:
            self.assertEqual(handle.read(), first)

    def test_wrong_slice_set_is_refused(self):
        with open(self.plist, "rb") as handle:
            info = plistlib.load(handle)
        info["AvailableLibraries"] = [
            library for library in info["AvailableLibraries"]
            if library["LibraryIdentifier"] != "ios-arm64-simulator"
        ]
        with open(self.plist, "wb") as handle:
            plistlib.dump(info, handle, fmt=plistlib.FMT_XML)
        with open(self.plist, "rb") as handle:
            before = handle.read()
        proc = self._run()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("unexpected XCFramework slices", proc.stderr)
        self.assertNotIn("Traceback", proc.stderr)
        with open(self.plist, "rb") as handle:
            self.assertEqual(handle.read(), before)

    def test_missing_library_identifier_is_refused(self):
        # LibraryIdentifier is the sort key: without the key check this
        # slice would crash the sort with a KeyError traceback, and the
        # fallback names it by its position.
        self._assert_refused(
            lambda info: info["AvailableLibraries"][0].pop(
                "LibraryIdentifier"),
            "library 'libraries[0]' is missing key 'LibraryIdentifier'")

    def test_missing_supported_platform_is_refused(self):
        self._assert_refused(
            lambda info: info["AvailableLibraries"][1].pop(
                "SupportedPlatform"),
            "library 'ios-arm64' is missing key 'SupportedPlatform'")

    def test_missing_supported_architectures_is_refused(self):
        self._assert_refused(
            lambda info: info["AvailableLibraries"][2].pop(
                "SupportedArchitectures"),
            "library 'ios-arm64-simulator' is missing key "
            "'SupportedArchitectures'")

    def test_missing_available_libraries_is_refused(self):
        self._assert_refused(
            lambda info: info.pop("AvailableLibraries"),
            "missing key 'AvailableLibraries'")

    def test_rejection_names_the_plist(self):
        self._assert_refused(
            lambda info: info["AvailableLibraries"][1].pop(
                "SupportedPlatform"),
            "Info.plist: library 'ios-arm64' is missing key "
            "'SupportedPlatform'")


if __name__ == "__main__":
    unittest.main()
