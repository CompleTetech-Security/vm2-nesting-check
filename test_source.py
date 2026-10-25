"""Synthetic source review cases; never execute JavaScript or contact targets."""
import contextlib
import csv
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import vm2_nesting_check as c


class SourceTests(unittest.TestCase):
    def scan(self, code):
        return c.scan_source_text(code, "src/service.ts")

    def cli(self, *args):
        with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
            code = c.main(list(args))
        return code, out.getvalue(), err.getvalue()

    def test_import_bound_aliases_and_namespace_imports(self):
        for binding, constructor in [
            ("const {NodeVM} = require('vm2');", "NodeVM"),
            ("const {NodeVM: N} = require('vm2');", "N"),
            ("const N = require('vm2').NodeVM;", "N"),
            ("const vm = require('vm2');", "vm.NodeVM"),
            ("import { NodeVM as N } from 'vm2';", "N"),
            ("import { NodeVM as N, } from 'vm2';", "N"),
            ("import * as vm from 'vm2';", "vm.NodeVM"),
        ]:
            with self.subTest(binding=binding):
                rows = self.scan(binding + "\nconst sandbox = new " + constructor + "({nesting:true, require:[]});")
                self.assertEqual(1, len(rows))
                row = rows[0]
                self.assertEqual("lexical_source_candidate", row["evidence_type"])
                self.assertEqual(("literal_true", "array_candidate"), (row["source_nesting"], row["source_require"]))
                self.assertEqual(2, row["source_line"])
                self.assertEqual("unknown", row["status"])
                self.assertEqual("not_reported", row["precondition_nodevm_nesting_enabled"])
                self.assertEqual("not_tested", row["exploitability"])

    def test_off_defaults_require_shapes_and_dynamic_configuration(self):
        cases = [
            ("", "not_specified", "not_specified"),
            ("{}", "not_specified", "not_specified"),
            ("{nesting:false, require:{builtin:[]}}", "literal_false", "object_candidate"),
            ("{nesting:true, require:true}", "literal_true", "literal_true"),
            ("{nesting:true, require:false}", "literal_true", "literal_false"),
            ("{nesting:true, require:null}", "literal_true", "literal_null"),
            ("{nesting:config.nesting, require:options}", "unknown", "unknown"),
            ("{nesting:true, ...options, require:[]}", "unknown", "unknown"),
            ("{nesting:true, nesting:false, require:[]}", "unknown", "unknown"),
            ("{nesting:true, ['require']:[]}", "unknown", "unknown"),
            ("options", "unknown", "unknown"),
            ("{nesting:true, require:[] || []}", "literal_true", "unknown"),
            ("{nesting:true, require:[]}, anotherOption", "unknown", "unknown"),
        ]
        for options, nesting, require in cases:
            with self.subTest(options=options):
                row = self.scan("import {NodeVM} from 'vm2'; new NodeVM(" + options + ");")[0]
                self.assertEqual((nesting, require), (row["source_nesting"], row["source_require"]))
                self.assertEqual("unknown", row["status"])

    def test_comments_strings_templates_regex_and_unrelated_constructors(self):
        code = r'''
        import {NodeVM} from 'other';
        // new NodeVM({nesting:true, require:[]});
        /* const {NodeVM} = require('vm2'); new NodeVM({}); */
        const text = "const {NodeVM} = require('vm2'); new NodeVM({});";
        const template = `new NodeVM({nesting:true, require:[]})`;
        const regex = /new NodeVM\(\{nesting:true, require:\[\]\}\)/;
        new NodeVM({nesting:true, require:[]});
        '''
        rows = self.scan(code)
        self.assertEqual(["source_coverage"], [r["evidence_type"] for r in rows])
        self.assertEqual("unknown", rows[0]["source_nesting"])
        # A genuine import does not turn text inside comments/strings into code.
        self.assertEqual("source_coverage", self.scan("import {NodeVM} from 'vm2'; const s='new NodeVM({})';")[0]["evidence_type"])

    def test_run_argument_shape_is_never_trust_or_taint(self):
        prefix = "const {NodeVM} = require('vm2'); const sandbox = new NodeVM({nesting:true, require:[]});"
        for expression, expected in [("'static text'", "literal_string"), ("'vm2'", "literal_string"), ("'nesting'", "literal_string"), ("'require'", "literal_string"), ("'prefix' + request.body.code", "dynamic_or_unsupported"), ("'literal', 'filename'", "literal_string"), ("request.body.code", "dynamic_or_unsupported"), ("trustedCode", "dynamic_or_unsupported"), ("`template`", "dynamic_or_unsupported")]:
            row = self.scan(prefix + "sandbox.run(" + expression + ");")[0]
            self.assertEqual(expected, row["source_run_argument"])
            self.assertEqual("not_reported", row["precondition_attacker_supplied_javascript_executed"])
        row = self.scan(prefix + "other.run(request.body.code);")[0]
        self.assertEqual("not_observed", row["source_run_argument"])

    def test_scopes_reassignment_and_same_name_remain_low_confidence_candidates(self):
        row = self.scan("import {NodeVM} from 'vm2'; function f(NodeVM) { new NodeVM({nesting:true, require:[]}); }")[0]
        self.assertEqual("unknown", row["status"])
        self.assertEqual("insufficient", row["evidence_confidence"])
        self.assertIn("shadowing", " ".join(row["notes"]))

    def test_malformed_and_token_limited_inputs_fail_closed(self):
        for text in ["/* open", "'open", "`open", "({]", "const r=/open", "{"]:
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.scan(text)
        with self.assertRaises(ValueError):
            self.scan(";" * 200001)
        row = self.scan("import {NodeVM} from 'vm2'; new NodeVM({nesting:true, require:[" + "0," * 3000 + "]});")[0]
        self.assertEqual(("unknown", "unknown"), (row["source_nesting"], row["source_require"]))

    def test_cli_relative_paths_separate_versions_and_output_parity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "service.ts"
            path.write_text("import {NodeVM} from 'vm2'; new NodeVM({nesting:true, require:[]});", encoding="utf-8")
            args = ["--version", "3.11.7", "--source", str(path), "--source-root", str(root)]
            code, out, err = self.cli(*args, "--format", "json", "--fail-on-finding")
            self.assertEqual((0, ""), (code, err))
            rows = json.loads(out)["results"]
            self.assertEqual(["fixed_version_reported", "unknown"], [r["status"] for r in rows])
            self.assertEqual("service.ts", rows[1]["source_path"])
            self.assertNotIn(str(root), out)
            code, out, _ = self.cli(*args, "--format", "csv")
            csv_rows = list(csv.DictReader(io.StringIO(out)))
            self.assertEqual(rows[1]["source_require"], csv_rows[1]["source_require"])
            code, out, _ = self.cli(*args, "--format", "html")
            self.assertIn("service.ts:1", out)
            self.assertIn("array_candidate", out)
            self.assertNotIn(str(root), out)

    def test_source_input_cannot_be_overwritten_even_with_force(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.js"
            original = "const x=1;"
            path.write_text(original, encoding="utf-8")
            args = ["--source", str(path), "--source-root", directory]
            self.assertEqual(2, self.cli(*args, "--output", str(path), "--force")[0])
            self.assertEqual(original, path.read_text(encoding="utf-8"))
            if hasattr(os, "link"):
                alias = Path(directory) / "alias.js"
                os.link(path, alias)
                self.assertEqual(2, self.cli(*args, "--output", str(alias), "--force")[0])

    def test_source_root_bounds_file_bounds_and_no_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "input.js"
            path.write_text("process.exit(99);", encoding="utf-8")
            with mock.patch.object(subprocess, "run", side_effect=AssertionError("must not execute")):
                self.assertEqual(0, self.cli("--source", str(path), "--source-root", directory)[0])
            self.assertEqual(2, self.cli("--source", str(path))[0])
            child = root / "child"
            child.mkdir()
            self.assertEqual(2, self.cli("--source", str(path), "--source-root", str(child))[0])
            path.write_bytes(b" " * (c.MAX_INPUT_BYTES + 1))
            self.assertEqual(2, self.cli("--source", str(path), "--source-root", directory)[0])

    def test_standalone_copy_retains_source_inspection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checker = root / "checker.py"
            checker.write_bytes(Path(c.__file__).read_bytes())
            source = root / "source.js"
            source.write_text("import {NodeVM} from 'vm2'; new NodeVM({nesting:true,require:[]});", encoding="utf-8")
            result = subprocess.run([sys.executable, str(checker), "--source", str(source), "--source-root", str(root), "--format", "json"], capture_output=True, text=True, check=True)
            self.assertEqual("array_candidate", json.loads(result.stdout)["results"][0]["source_require"])


if __name__ == "__main__":
    unittest.main()
