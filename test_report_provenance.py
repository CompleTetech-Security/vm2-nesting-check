"""Detached report provenance with synthetic inputs and a fixed UTC clock."""
import contextlib
import csv
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import vm2_nesting_check as c

STAMP = "2026-10-25T20:55:49+00:00"


class ReportProvenanceTests(unittest.TestCase):
    def csv_rows(self, rows, **options):
        stream = io.StringIO(newline="")
        c.write_report(stream, rows, format="csv", generated_at=STAMP, **options)
        return list(csv.DictReader(io.StringIO(stream.getvalue(), newline="")))

    def assert_metadata(self, row):
        self.assertEqual(STAMP, row["generated_at"])
        self.assertEqual(c.TOOL_NAME, row["tool"])
        self.assertEqual(c.TOOL_VERSION, row["tool_version"])
        self.assertEqual(c.RULES_DATE, row["rules_as_of"])
        self.assertEqual(c.REPORT_SCHEMA_VERSION, row["report_schema_version"])

    def test_all_formats_agree_for_multiple_rows_with_fixed_clock(self):
        rows = [c.assess_entry("sample", "version", version)
                for version in ("3.11.6", "3.11.7")]
        csv_rows = self.csv_rows(rows)
        for row in csv_rows:
            self.assert_metadata(row)
            self.assertEqual("result", row["record_type"])
            self.assertEqual("not_tested", row["exploitability"])
        report = json.loads(c.render_report(rows, format="json", generated_at=STAMP))
        self.assert_metadata(report)
        rendered = c.render_report(rows, format="html", generated_at=STAMP).decode()
        for value in (STAMP, c.TOOL_NAME, c.TOOL_VERSION, c.RULES_DATE):
            self.assertIn(value, rendered)
        self.assertNotEqual(STAMP, c.RULES_DATE)

    def test_empty_complete_and_incomplete_summaries_keep_provenance(self):
        for complete in (True, False):
            with self.subTest(complete=complete):
                row, = self.csv_rows([], complete=complete)
                self.assert_metadata(row)
                self.assertEqual("summary", row["record_type"])
                self.assertEqual(str(complete).lower(), row["report_complete"])
                self.assertEqual("not_tested", row["exploitability"])
                self.assertEqual("", row["package_version"])

    def test_interruption_retains_run_clock_and_atomic_partial_evidence(self):
        real_assess = c.assess_entry
        for fmt in ("csv", "json", "html"):
            for completed in (0, 1):
                with self.subTest(fmt=fmt, completed=completed), tempfile.TemporaryDirectory() as directory:
                    target = Path(directory) / ("partial." + fmt)
                    calls = []
                    def interrupt(*args, **kwargs):
                        if len(calls) == completed:
                            raise KeyboardInterrupt
                        calls.append(True)
                        return real_assess(*args, **kwargs)
                    with mock.patch.object(c, "utc_now", return_value=STAMP) as clock, \
                            mock.patch.object(c, "assess_entry", side_effect=interrupt), \
                            contextlib.redirect_stderr(io.StringIO()):
                        code = c.main(["--version", "3.11.6", "--version", "3.11.7",
                                       "--format", fmt, "--output", str(target)])
                    self.assertEqual(130, code)
                    clock.assert_called_once_with()
                    text = target.read_text(encoding="utf-8")
                    self.assertIn(STAMP, text)
                    if fmt == "csv":
                        rows = list(csv.DictReader(io.StringIO(text)))
                        self.assertEqual(1, len(rows))
                        self.assert_metadata(rows[0])
                        self.assertEqual("false", rows[0]["report_complete"])
                        self.assertEqual("result" if completed else "summary", rows[0]["record_type"])
                    elif fmt == "json":
                        report = json.loads(text)
                        self.assert_metadata(report)
                        self.assertFalse(report["complete"])
                        self.assertEqual(completed, len(report["results"]))
                    else:
                        self.assertIn("Interrupted run", text)
                    self.assertEqual([target.name], [p.name for p in Path(directory).iterdir()])

    def test_render_retry_after_interrupt_keeps_original_run_clock(self):
        original = c.save_report
        calls = []
        def interrupt_once(*args, **kwargs):
            calls.append(kwargs["generated_at"])
            if len(calls) == 1:
                raise KeyboardInterrupt
            return original(*args, **kwargs)
        with mock.patch.object(c, "utc_now", side_effect=[STAMP, "2099-01-01T00:00:00+00:00"]) as clock, \
                mock.patch.object(c, "save_report", side_effect=interrupt_once), \
                contextlib.redirect_stdout(io.StringIO()) as output, \
                contextlib.redirect_stderr(io.StringIO()):
            code = c.main(["--version", "3.11.6", "--format", "json"])
        self.assertEqual(130, code)
        clock.assert_called_once_with()
        self.assertEqual([STAMP, STAMP], calls)
        report = json.loads(output.getvalue())
        self.assert_metadata(report)
        self.assertFalse(report["complete"])

    def test_csv_envelope_overrides_row_metadata_without_weakening_escaping(self):
        row = c.assess_entry(" \t=1+1", "inventory", "3.11.7")
        row.update(tool="=spoof", tool_version="=spoof", generated_at="=spoof")
        exported, = self.csv_rows([row])
        self.assert_metadata(exported)
        self.assertEqual("' \t=1+1", exported["input_label"])
        self.assertEqual("fixed_version_reported", exported["status"])
        self.assertEqual("not_tested", exported["exploitability"])


if __name__ == "__main__":
    unittest.main()
