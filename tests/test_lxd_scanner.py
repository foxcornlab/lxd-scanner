import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from lxd_scanner import grade, parse_version, table  # noqa: E402

SCANNER = os.path.join(os.path.dirname(__file__), "..", "lxd_scanner.py")


def run_cli(*args):
    proc = subprocess.run([sys.executable, SCANNER, *args],
                          capture_output=True, text=True)
    return proc


class TestParse(unittest.TestCase):
    def test_plain_and_padded(self):
        self.assertEqual(parse_version("6.9"), (6, 9, 0))
        self.assertEqual(parse_version("6.10.1"), (6, 10, 1))
        self.assertEqual(parse_version("v5.21.8"), (5, 21, 8))

    def test_suffix_and_bad(self):
        self.assertEqual(parse_version("6.9-123"), (6, 9, 0))
        self.assertIsNone(parse_version("not-a-version"))
        self.assertIsNone(parse_version(""))


class TestLxdGrades(unittest.TestCase):
    def test_each_branch_vulnerable(self):
        for version in ("4.0.14", "5.0.10", "5.21.8", "6.9"):
            self.assertEqual(grade("lxd", parse_version(version))["verdict"],
                             "VULNERABLE", version)

    def test_each_branch_fixed(self):
        for version in ("4.0.15", "5.0.11", "5.21.9", "6.10.1"):
            self.assertEqual(grade("lxd", parse_version(version))["verdict"],
                             "FIXED", version)

    def test_610_trap_still_vulnerable(self):
        # 6.10 fixed the September flaws, not this CVE.
        self.assertEqual(grade("lxd", parse_version("6.10"))["verdict"],
                         "VULNERABLE")
        self.assertEqual(grade("lxd", parse_version("6.10.0"))["verdict"],
                         "VULNERABLE")

    def test_below_lower_bound_is_unknown_not_clean(self):
        for version in ("4.0.13", "5.0.9", "5.21.7", "6.8", "6.7"):
            self.assertEqual(grade("lxd", parse_version(version))["verdict"],
                             "UNKNOWN", version)

    def test_unlisted_branch_unknown(self):
        self.assertEqual(grade("lxd", parse_version("5.5"))["verdict"],
                         "UNKNOWN")
        self.assertEqual(grade("lxd", parse_version("7.0"))["verdict"],
                         "UNKNOWN")

    def test_unparseable(self):
        self.assertEqual(grade("lxd", None)["verdict"], "UNKNOWN")


class TestOtherProducts(unittest.TestCase):
    def test_microcloud(self):
        self.assertEqual(
            grade("microcloud", parse_version("2.1.4"))["verdict"],
            "VULNERABLE")
        self.assertEqual(
            grade("microcloud", parse_version("2.1.5"))["verdict"], "FIXED")
        self.assertEqual(
            grade("microcloud", parse_version("3.4.0"))["verdict"],
            "VULNERABLE")
        self.assertEqual(
            grade("microcloud", parse_version("3.4.1"))["verdict"], "FIXED")
        self.assertEqual(
            grade("microcloud", parse_version("4.0"))["verdict"], "UNKNOWN")

    def test_incus(self):
        self.assertEqual(grade("incus", parse_version("7.5"))["verdict"],
                         "VULNERABLE")
        self.assertEqual(grade("incus", parse_version("7.6.0"))["verdict"],
                         "FIXED")


class TestCli(unittest.TestCase):
    def test_vulnerable_exit_2_and_fixed_exit_0(self):
        self.assertEqual(run_cli("--version", "6.9").returncode, 2)
        self.assertEqual(run_cli("--version", "6.10.1").returncode, 0)
        self.assertEqual(run_cli("--version", "6.8").returncode, 0)

    def test_unknown_is_not_clean_text(self):
        proc = run_cli("--version", "6.8")
        self.assertIn("UNKNOWN", proc.stdout)

    def test_json_output(self):
        proc = run_cli("--version", "5.21.8", "--json")
        data = json.loads(proc.stdout)
        self.assertEqual(data["verdict"], "VULNERABLE")
        self.assertEqual(data["product"], "lxd")

    def test_network_api_note(self):
        proc = run_cli("--version", "6.9", "--network-api")
        self.assertIn("network HTTPS API is on", proc.stdout)

    def test_list_rows(self):
        proc = run_cli("--list")
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(len(table()), 6)
        self.assertIn("6.10.1", proc.stdout)

    def test_inventory_json(self):
        entries = [{"product": "lxd", "version": "5.21.8"},
                   {"product": "microcloud", "version": "3.4.1"}]
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                         delete=False) as handle:
            json.dump(entries, handle)
            path = handle.name
        try:
            proc = run_cli("--inventory-json", path)
            self.assertEqual(proc.returncode, 2)
            self.assertIn("5.21.8", proc.stdout)
            proc = run_cli("--product", "microcloud",
                           "--inventory-json", path)
            self.assertEqual(proc.returncode, 0)
        finally:
            os.unlink(path)

    def test_deb_position(self):
        proc = run_cli("--version", "6.9", "--package", "deb")
        self.assertIn("NOT_AFFECTED_PER_UBUNTU", proc.stdout)

    def test_no_input_errors(self):
        self.assertEqual(run_cli().returncode, 1)


if __name__ == "__main__":
    unittest.main()
