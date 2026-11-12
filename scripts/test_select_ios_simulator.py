import unittest

from select_ios_simulator import select_device


def device(name, udid, state="Shutdown", available=True):
    return dict(name=name, udid=udid, state=state, isAvailable=available)


class SimulatorSelectionTests(unittest.TestCase):
    def test_booted_new_generation_does_not_override_requested_minimum(self):
        devices = {
            "com.apple.CoreSimulator.SimRuntime.iOS-26-0": [device("iPhone 17", "new", "Booted")],
            "com.apple.CoreSimulator.SimRuntime.iOS-18-5": [device("iPhone 16", "minimum")],
        }
        self.assertEqual(select_device(devices, "18")[0], "minimum")

    def test_oldest_available_runtime_and_booted_device_within_it(self):
        devices = {
            "com.apple.CoreSimulator.SimRuntime.iOS-18-10": [device("iPhone 16", "later", "Booted")],
            "com.apple.CoreSimulator.SimRuntime.iOS-18-5": [
                device("iPhone 15", "shutdown"), device("iPhone 16", "booted", "Booted")],
            "com.apple.CoreSimulator.SimRuntime.iOS-18-0": [
                device("iPhone 15", "unavailable", available=False)],
        }
        self.assertEqual(select_device(devices, "18")[0:2], ("booted", "Booted"))

    def test_missing_requested_generation_fails_instead_of_falling_back(self):
        with self.assertRaisesRegex(ValueError, "no available iPhone"):
            select_device({"com.apple.CoreSimulator.SimRuntime.iOS-26-0":
                           [device("iPhone 17", "new")]}, "18")

    def test_ipad_and_non_ios_devices_do_not_satisfy_iphone_requirement(self):
        with self.assertRaises(ValueError):
            select_device({
                "com.apple.CoreSimulator.SimRuntime.iOS-18-5": [device("iPad Pro", "ipad")],
                "com.apple.CoreSimulator.SimRuntime.tvOS-18-0": [device("iPhone fake", "tv")],
            }, "18")

    def test_unset_major_allows_local_use(self):
        self.assertEqual(select_device({"com.apple.CoreSimulator.SimRuntime.iOS-26-0":
                                        [device("iPhone 17", "local")]}, "")[0], "local")

    def test_latest_ignores_booted_older_runtime_and_unavailable_newer_runtime(self):
        devices = {
            "com.apple.CoreSimulator.SimRuntime.iOS-18-5": [device("iPhone 16", "old", "Booted")],
            "com.apple.CoreSimulator.SimRuntime.iOS-26-9": [device("iPhone 17", "older-patch", "Booted")],
            "com.apple.CoreSimulator.SimRuntime.iOS-26-10": [device("iPhone 17", "latest")],
            "com.apple.CoreSimulator.SimRuntime.iOS-27-0": [
                device("iPhone 18", "unavailable", available=False)],
        }
        self.assertEqual(select_device(devices, "latest")[0], "latest")

    def test_invalid_major_is_rejected(self):
        for major in ("0", "18.0", "-1", "newest"):
            with self.subTest(major=major), self.assertRaises(ValueError):
                select_device({}, major)


if __name__ == "__main__":
    unittest.main()
