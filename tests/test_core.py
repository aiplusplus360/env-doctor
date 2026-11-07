import os
import tempfile
import unittest
from pathlib import Path

from envdoctor import (Usage, analyze, gate, parse_env, scan_paths, scan_text, summarise)


class ScanTests(unittest.TestCase):
    def test_index_access_is_required(self):
        usages, _ = scan_text('x = os.environ["API_KEY"]', "a.py")
        self.assertEqual([(u.name, u.mode) for u in usages], [("API_KEY", "required")])

    def test_get_without_default_is_required(self):
        usages, _ = scan_text('x = os.environ.get("A")', "a.py")
        self.assertEqual(usages[0].mode, "required")

    def test_get_with_default(self):
        usages, _ = scan_text('x = os.getenv("A", "fallback")', "a.py")
        self.assertEqual(usages[0].mode, "defaulted")

    def test_bare_getenv(self):
        usages, _ = scan_text('x = getenv("A")', "a.py")
        self.assertEqual(usages[0].name, "A")

    def test_bare_environ(self):
        usages, _ = scan_text('from os import environ\nx = environ["A"]', "a.py")
        self.assertEqual(usages[0].name, "A")

    def test_setdefault(self):
        usages, _ = scan_text('os.environ.setdefault("A", "1")', "a.py")
        self.assertEqual(usages[0].mode, "setdefault")

    def test_line_numbers(self):
        usages, _ = scan_text("a = 1\n\nb = os.environ['A']\n", "a.py")
        self.assertEqual(usages[0].line, 3)

    def test_commented_out_line_is_ignored(self):
        usages, _ = scan_text('# x = os.environ["A"]\n', "a.py")
        self.assertEqual(usages, [])

    def test_trailing_comment_is_ignored(self):
        usages, _ = scan_text('x = os.environ["A"]  # os.environ["B"]', "a.py")
        self.assertEqual([u.name for u in usages], ["A"])

    def test_dynamic_key_is_reported_separately(self):
        usages, dynamic = scan_text('x = os.environ[f"PREFIX_{name}"]', "a.py")
        self.assertEqual(usages, [])
        self.assertEqual(dynamic[0].mode, "dynamic")

    def test_dynamic_get_is_reported(self):
        _, dynamic = scan_text("x = os.environ.get(name)", "a.py")
        self.assertEqual(len(dynamic), 1)

    def test_dynamic_reported_once_per_line(self):
        _, dynamic = scan_text("x = os.environ[name] or os.environ[other]", "a.py")
        self.assertEqual(len(dynamic), 1)

    def test_javascript_access(self):
        usages, _ = scan_text('const x = process.env.API_KEY;', "a.js")
        self.assertEqual(usages, [])

    def test_shell_access(self):
        usages, _ = scan_text('echo "$API_KEY"', "run.sh")
        self.assertEqual(usages, [])


class EnvParseTests(unittest.TestCase):
    def test_simple_pairs(self):
        entries = parse_env("A=1\nB=two\n", ".env")
        self.assertEqual([(e.key, e.value) for e in entries], [("A", "1"), ("B", "two")])

    def test_export_prefix(self):
        entries = parse_env("export A=1\n", ".env")
        self.assertEqual(entries[0].key, "A")
        self.assertTrue(entries[0].exported)

    def test_comments_and_blanks(self):
        self.assertEqual(parse_env("# A=1\n\n  \nB=2\n", ".env")[0].key, "B")

    def test_hash_inside_quoted_value(self):
        entries = parse_env('URL="http://x/#frag"\n', ".env")
        self.assertEqual(entries[0].value, "http://x/#frag")

    def test_empty_value(self):
        entries = parse_env("A=\n", ".env")
        self.assertEqual(entries[0].value, "")

    def test_single_quotes(self):
        self.assertEqual(parse_env("A='one two'\n", ".env")[0].value, "one two")

    def test_invalid_lines_are_skipped(self):
        self.assertEqual(parse_env("not a pair\nA=1\n", ".env")[0].key, "A")

    def test_example_detection(self):
        self.assertTrue(parse_env("A=1", ".env.example")[0].is_example)
        self.assertTrue(parse_env("A=1", "config/.env.sample")[0].is_example)
        self.assertFalse(parse_env("A=1", ".env")[0].is_example)


class AnalyzeTests(unittest.TestCase):
    def test_unused_key(self):
        findings = analyze([], parse_env("OLD=1", ".env"))
        self.assertEqual([f.rule for f in findings], ["unused"])

    def test_used_key_is_not_reported(self):
        findings = analyze([Usage("A", "a.py", 1, "required")], parse_env("A=1", ".env"))
        self.assertEqual(findings, [])

    def test_undeclared_key(self):
        findings = analyze([Usage("A", "a.py", 4, "required")], parse_env("B=1", ".env"))
        rules = [f.rule for f in findings]
        self.assertIn("undeclared", rules)

    def test_no_declarations_means_no_undeclared(self):
        findings = analyze([Usage("A", "a.py", 1, "required")], [])
        self.assertEqual(findings, [])

    def test_case_mismatch(self):
        findings = analyze([Usage("API_KEY", "a.py", 1, "required")],
                           parse_env("api_key=1", ".env"))
        self.assertEqual([f.rule for f in findings], ["case-mismatch"])

    def test_duplicate_declaration(self):
        findings = analyze([Usage("A", "a.py", 1, "required")],
                           parse_env("A=1\nA=2\n", ".env"))
        self.assertEqual([f.rule for f in findings], ["duplicate-declaration"])

    def test_duplicate_across_files_is_allowed(self):
        entries = parse_env("A=1", ".env") + parse_env("A=placeholder", ".env.example")
        findings = [f for f in analyze([Usage("A", "a.py", 1, "required")], entries)
                    if f.rule == "duplicate-declaration"]
        self.assertEqual(findings, [])

    def test_empty_declaration(self):
        findings = analyze([], parse_env("A=", ".env"))
        self.assertIn("empty-declaration", [f.rule for f in findings])

    def test_ignore_glob(self):
        findings = analyze([], parse_env("CI_COMMIT_SHA=x\nLOCAL_ONLY=1", ".env"),
                           ignore=["CI_*"])
        self.assertEqual([f.key for f in findings], ["LOCAL_ONLY"])

    def test_dynamic_access_reported(self):
        findings = analyze([], [], [Usage("<dynamic>", "a.py", 2, "dynamic")])
        self.assertEqual([f.rule for f in findings], ["dynamic-access"])

    def test_secret_in_example(self):
        secret = "sk-" + "a1B2c3D4" * 5
        findings = analyze([], parse_env("API_KEY=%s" % secret, ".env.example"))
        self.assertIn("secret-in-example", [f.rule for f in findings])

    def test_placeholder_is_not_a_secret(self):
        findings = analyze([], parse_env("API_KEY=changeme", ".env.example"))
        self.assertNotIn("secret-in-example", [f.rule for f in findings])

    def test_short_secret_value_is_not_flagged(self):
        findings = analyze([], parse_env("API_KEY=abc", ".env.example"))
        self.assertNotIn("secret-in-example", [f.rule for f in findings])

    def test_real_env_file_is_not_scanned_for_secrets(self):
        findings = analyze([], parse_env("API_KEY=sk-" + "a1B2c3D4" * 5, ".env"))
        self.assertNotIn("secret-in-example", [f.rule for f in findings])

    def test_ordering_puts_errors_first(self):
        entries = parse_env("A=1\nA=2\nB=\n", ".env")
        findings = analyze([Usage("A", "a.py", 1, "required")], entries)
        self.assertEqual(findings[0].severity, "error")

    def test_findings_are_deterministic(self):
        first = analyze([], parse_env("A=1\nB=2\n", ".env"))
        second = analyze([], parse_env("A=1\nB=2\n", ".env"))
        self.assertEqual(first, second)


class ScanPathsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "app.py").write_text(
            "import os\nTOKEN = os.environ['API_TOKEN']\n", encoding="utf-8")
        nested = self.root / "pkg"
        nested.mkdir()
        (nested / "worker.py").write_text("DB = os.getenv('DB_URL', 'sqlite://')\n",
                                          encoding="utf-8")
        vendor = self.root / "node_modules"
        vendor.mkdir()
        (vendor / "index.js").write_text("process.env.IGNORED\n", encoding="utf-8")

    def test_scans_recursively(self):
        files, usages, _ = scan_paths([str(self.root)])
        names = {usage.name for usage in usages}
        self.assertEqual(names, {"API_TOKEN", "DB_URL"})
        self.assertTrue(all("node_modules" not in path for path in files))

    def test_single_file_root(self):
        files, usages, _ = scan_paths([str(self.root / "app.py")])
        self.assertEqual(len(files), 1)
        self.assertEqual(usages[0].name, "API_TOKEN")

    def test_env_files_are_not_scanned_as_source(self):
        (self.root / ".env").write_text("API_TOKEN=x\n", encoding="utf-8")
        files, _, _ = scan_paths([str(self.root)])
        self.assertFalse(any(os.path.basename(path) == ".env" for path in files))


class ReportTests(unittest.TestCase):
    def test_summarise(self):
        findings = analyze([], parse_env("OLD=1", ".env"))
        summary = summarise(findings)
        self.assertGreaterEqual(summary["warnings"], 1)
        self.assertFalse(summary["clean"])

    def test_gate(self):
        findings = analyze([], parse_env("A=1\nA=2", ".env"))
        self.assertTrue(gate(findings, "error"))
        self.assertFalse(gate(findings, "never"))

    def test_gate_rejects_unknown(self):
        with self.assertRaises(ValueError):
            gate([], "critical")


if __name__ == "__main__":
    unittest.main()
