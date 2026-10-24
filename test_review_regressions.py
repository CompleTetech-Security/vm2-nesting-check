"""Synthetic regressions from independent report review."""
import contextlib
import csv
import io
import unittest
from unittest import mock
import vm2_nesting_check as checker


class EmptyCsvInterruptionTests(unittest.TestCase):
    def test_first_assessment_interrupt_preserves_summary_without_asset_finding(self):
        output, error = io.StringIO(), io.StringIO()
        with mock.patch.object(checker, "assess_entry", side_effect=KeyboardInterrupt), contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            code = checker.main(["--version", ".".join(str(x) for x in checker.FIXED), "--format", "csv"])
        rows = list(csv.DictReader(io.StringIO(output.getvalue(), newline="")))
        self.assertEqual(130, code)
        self.assertEqual(1, len(rows))
        self.assertEqual("summary", rows[0]["record_type"])
        self.assertEqual("false", rows[0]["report_complete"])
        self.assertEqual(checker.CVE_ID, rows[0]["cve"])
        self.assertEqual("not_tested", rows[0]["exploitability"])
        self.assertEqual("", rows[0]["status"])
        self.assertEqual("", rows[0]["input_label"])
