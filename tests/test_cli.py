import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path

from envdoctor.cli import main


def run(args):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(args)
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "app.py").write_text(
            "import os\nTOKEN = os.environ['API_TOKEN']\nDEBUG = os.getenv('DEBUG', '0')\n",
            encoding="utf-8")
        (self.root / ".env").write_text(
            "API_TOKEN=placeholder\nDEBUG=0\nLEGACY_URL=http://old.internal\n",
            encoding="utf-8")
        (self.root / ".env.example").write_text(
            "API_TOKEN=changeme\nDEBUG=0\nMISSING_ONE=\n", encoding="utf-8")

    def test_scan_finds_unused(self):
        code, out, _ = run(["scan", str(self.root)])
        self.assertEqual(code, 0)
        self.assertIn("LEGACY_URL", out)
        self.assertIn("unused", out)

    def test_scan_json_shape(self):
        code, out, _ = run(["scan", str(self.root), "--json"])
        payload = json.loads(out)
        self.assertGreaterEqual(payload["warnings"], 1)
        self.assertEqual(payload["usages"], 2)
        self.assertIn("by_rule", payload)

    def test_fail_on_warning(self):
        code, _, _ = run(["scan", str(self.root), "--fail-on", "warning"])
        self.assertEqual(code, 1)

    def test_fail_on_never(self):
        code, _, _ = run(["scan", str(self.root), "--fail-on", "never"])
        self.assertEqual(code, 0)

    def test_ignore_glob(self):
        code, out, _ = run(["scan", str(self.root), "--ignore", "LEGACY_*", "--json"])
        payload = json.loads(out)
        keys = {row["key"] for row in payload["findings"] if row["rule"] == "unused"}
        self.assertNotIn("LEGACY_URL", keys)

    def test_explicit_env_file(self):
        other = self.root / "custom.env"
        other.write_text("UNRELATED=1\n", encoding="utf-8")
        code, out, _ = run(["scan", str(self.root / "app.py"), "--env", str(other),
                            "--json"])
        payload = json.loads(out)
        self.assertEqual(payload["env_files"], [str(other)])
        self.assertIn("undeclared", payload["by_rule"])

    def test_no_info(self):
        code, out, _ = run(["scan", str(self.root), "--no-info", "--json"])
        payload = json.loads(out)
        self.assertEqual(payload["infos"], 0)

    def test_rules(self):
        code, out, _ = run(["rules"])
        self.assertEqual(code, 0)
        self.assertIn("unused", out)
        self.assertIn("fix:", out)

    def test_rules_json(self):
        code, out, _ = run(["rules", "--json"])
        self.assertEqual(json.loads(out)[0]["code"], "unused")

    def test_missing_env_file(self):
        with self.assertRaises(SystemExit):
            run(["scan", str(self.root), "--env", str(self.root / "absent.env")])

    def test_empty_directory_reports_zero(self):
        empty = self.root / "empty"
        empty.mkdir()
        code, out, _ = run(["scan", str(empty), "--env", str(self.root / ".env")])
        self.assertEqual(code, 0)
        self.assertIn("0 file(s) scanned", out)


if __name__ == "__main__":
    unittest.main()
