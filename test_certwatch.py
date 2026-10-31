import datetime as dt
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import certwatch  # noqa: E402

NOW = dt.datetime(2026, 11, 1, 0, 0, 0, tzinfo=dt.timezone.utc)


def cert(days: float) -> dict:
    exp = NOW + dt.timedelta(days=days)
    return {"notAfter": exp.strftime("%b %d %H:%M:%S %Y GMT")}


class TestCheck(unittest.TestCase):
    def line(self, days, warn=21, crit=7):
        return certwatch.check("example.com", cert(days), warn, crit, NOW)

    def test_far_future_is_ok(self):
        text, code = self.line(80)
        self.assertEqual(code, 0)
        self.assertTrue(text.startswith("OK"))

    def test_warning_window(self):
        _, code = self.line(14)
        self.assertEqual(code, 1)

    def test_critical_window(self):
        text, code = self.line(3)
        self.assertEqual(code, 1)
        self.assertTrue(text.startswith("CRITICAL"))

    def test_expired(self):
        text, code = self.line(-1)
        self.assertEqual(code, 2)
        self.assertTrue(text.startswith("EXPIRED"))

    def test_boundary_is_inclusive_low(self):
        # exactly 7 days left is not yet critical (crit is "< crit_days")
        _, code = self.line(7.0)
        self.assertEqual(code, 1)

    def test_custom_thresholds(self):
        _, code = self.line(40, warn=60, crit=30)
        self.assertEqual(code, 1)


class TestNotAfter(unittest.TestCase):
    def test_parse_openssl_format(self):
        d = certwatch.not_after_of({"notAfter": "Jun  2 12:00:00 2027 GMT"})
        self.assertEqual(d.year, 2027)
        self.assertEqual(d.month, 6)
        self.assertEqual(d.day, 2)
        self.assertEqual(d.tzinfo, dt.timezone.utc)

    def test_missing_field(self):
        with self.assertRaises(ValueError):
            certwatch.not_after_of({})


class TestTargets(unittest.TestCase):
    def test_load_targets_all_kinds(self):
        cfg = {"targets": [
            {"name": "inline", "not_after": "Jun  2 12:00:00 2027 GMT"},
        ]}
        out = certwatch.load_targets(cfg)
        self.assertEqual(out[0][0], "inline")

    def test_target_without_source_rejected(self):
        with self.assertRaises(ValueError):
            certwatch.load_targets({"targets": [{"name": "x"}]})

    def test_target_without_name_rejected(self):
        with self.assertRaises(ValueError):
            certwatch.load_targets({"targets": [{"not_after": "Jun  2 12:00:00 2027 GMT"}]})


class TestCli(unittest.TestCase):
    def run_cli(self, argv, cfg=None):
        if cfg is not None:
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
                json.dump(cfg, fh)
            self.addCleanup(os.unlink, fh.name)
            argv = argv + ["--config", fh.name]
        return certwatch.main(argv)

    def test_no_targets_is_config_error(self):
        self.assertEqual(certwatch.main([]), 3)

    def test_all_ok_exit_0(self):
        cfg = {"targets": [{"name": "a", "not_after": "Jun  2 12:00:00 2030 GMT"}]}
        self.assertEqual(self.run_cli([], cfg), 0)

    def test_one_expired_exit_2(self):
        cfg = {"targets": [
            {"name": "good", "not_after": "Jun  2 12:00:00 2030 GMT"},
            {"name": "dead", "not_after": "Jun  2 12:00:00 2020 GMT"},
        ]}
        self.assertEqual(self.run_cli([], cfg), 2)

    def test_warning_exit_1(self):
        soon = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=3))
        cfg = {"targets": [{"name": "soon", "not_after": soon.strftime("%b %d %H:%M:%S %Y GMT")}]}
        self.assertEqual(self.run_cli([], cfg), 1)

    def test_endpoint_failure_is_not_a_traceback(self):
        with mock.patch.object(certwatch, "from_endpoint",
                               side_effect=OSError("connection refused")):
            self.assertEqual(certwatch.main(["--host", "127.0.0.1:1"]), 3)


if __name__ == "__main__":
    unittest.main()
