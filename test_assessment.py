"""Independent advisory golden cases and hostile-input/publication behavior."""
import contextlib
import csv
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import vm2_nesting_check as c
CASES = [('3.11.3', 'unknown'), ('3.11.4', 'potentially_affected'), ('3.11.6', 'potentially_affected'), ('3.11.7', 'fixed_version_reported'), ('3.11.8', 'fixed_version_reported'), ('3.12.0', 'unknown'), ('4.0.0', 'unknown')]
FIXED = '3.11.7'

class AssessmentTests(unittest.TestCase):
    def run_cli(self,*args):
        with contextlib.redirect_stdout(io.StringIO()) as out,contextlib.redirect_stderr(io.StringIO()) as err:
            try: code=c.main(list(args))
            except SystemExit as exc: code=exc.code
        return code,out.getvalue(),err.getvalue()
    def test_primary_source_boundary_cases(self):
        for version,status in CASES:
            with self.subTest(version=version): self.assertEqual(status,c.assess_version(version)['status'])
    def test_version_conflicts_qualifiers_and_custom_provenance(self):
        for version in ['', 'latest', '1', '1.2', '01.2.3', '１.2.3', FIXED+'-rc.1', FIXED+'+vendor', '\u00a0'+FIXED, True, None]:
            self.assertEqual('unknown',c.assess_version(version)['status'])
        self.assertEqual('unknown',c.assess_version(FIXED,version_candidates=['0.0.1'])['status'])
        for version,_ in CASES:
            self.assertEqual('unknown',c.assess_version(version,build_source='custom')['status'])
    def test_observations_never_change_patch_or_exploitability(self):
        for flag in [True,False,None]:
            r=c.assess_entry('example','inventory',FIXED,observations={k:flag for k in c.PRECONDITION_KEYS})
            self.assertEqual('fixed_version_reported',r['status']);self.assertEqual('not_tested',r['exploitability'])
    def test_inventory_schema_types_and_duplicate_keys(self):
        good={'schema_version':1,'package_version':FIXED,'package':'vm2'}
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'input.json'
            for data in [{},[],{**good,'extra':1},{**good,'schema_version':True},{**good,c.PRECONDITION_KEYS[0]:'true'},{**good,'package':'different-package'},{**good,'package_version':4}]:
                p.write_text(json.dumps(data));self.assertEqual(2,self.run_cli('--inventory',str(p))[0])
            p.write_text('{"sensitive-key":1,"sensitive-key":2}')
            code,out,err=self.run_cli('--inventory',str(p));self.assertEqual((2,''),(code,out));self.assertNotIn('sensitive-key',err)
            p.write_text(json.dumps(good));code,out,_=self.run_cli('--inventory',str(p),'--format','json')
            self.assertEqual(0,code);self.assertEqual('fixed_version_reported',json.loads(out)['results'][0]['status'])
    def test_input_budgets_and_special_files(self):
        self.assertEqual(2,self.run_cli('--version','v'*513)[0])
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'large.json';p.write_bytes(b' '*(c.MAX_INPUT_BYTES+1));self.assertEqual(2,self.run_cli('--inventory',str(p))[0])
            if hasattr(os,'mkfifo'):
                q=Path(d)/'pipe';os.mkfifo(q)
                with mock.patch.object(Path,'open',side_effect=AssertionError('must not open pipe')):
                    self.assertEqual(2,self.run_cli('--inventory',str(q))[0])
            with mock.patch.object(c,'MAX_ENTRIES',2):
                self.assertEqual(2,self.run_cli('--version',FIXED,'--version',FIXED,'--version',FIXED)[0])
    def test_csv_roundtrips_controls_and_neutralizes_mixed_whitespace(self):
        labels=['alpha\r=1+1',' \t=1+1',' \r=1+1','\v=1+1','\f@x','\u00a0=1+1','=1+1']
        out=io.StringIO();c.write_report(out,[c.assess_entry(x,'inventory',FIXED) for x in labels],format='csv')
        rows=list(csv.DictReader(io.StringIO(out.getvalue(),newline='')))
        self.assertEqual(len(labels),len(rows));self.assertEqual(labels[0],rows[0]['input_label'])
        for original,row in zip(labels[1:],rows[1:]): self.assertEqual("'"+original,row['input_label'])
    def test_html_is_escaped_and_script_free(self):
        text=c.render_html([c.assess_entry('<script>bad</script>','inventory',FIXED)])
        self.assertNotIn('<script',text.lower());self.assertIn('&lt;script&gt;',text)
    def test_json_csv_and_html_are_same_assessment(self):
        for fmt in ['json','csv','html']:
            code,out,_=self.run_cli('--version',FIXED,'--format',fmt)
            self.assertEqual(0,code);self.assertIn('fixed_version_reported',out);self.assertIn('not_tested',out)
    def test_output_protects_inputs_and_existing_reports(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'input.json';data=json.dumps({'schema_version':1,'package_version':FIXED});p.write_text(data)
            self.assertEqual(2,self.run_cli('--inventory',str(p),'--output',str(p),'--force')[0]);self.assertEqual(data,p.read_text())
            q=Path(d)/'out.json';q.write_text('keep');self.assertEqual(2,self.run_cli('--version',FIXED,'--output',str(q))[0]);self.assertEqual('keep',q.read_text())
    def test_interruption_retains_completed_results(self):
        real=c.assess_entry;calls=0
        def interrupt(*args,**kwargs):
            nonlocal calls
            calls+=1
            if calls==2: raise KeyboardInterrupt
            return real(*args,**kwargs)
        with mock.patch.object(c,'assess_entry',interrupt):
            code,out,_=self.run_cli('--version',FIXED,'--version',FIXED,'--format','json')
        self.assertEqual(130,code);report=json.loads(out);self.assertFalse(report['complete']);self.assertEqual(1,len(report['results']))
    def test_interrupted_stdout_is_never_retried(self):
        class Sink:
            calls=0
            def write(self,data): self.calls+=1;raise KeyboardInterrupt
        sink=Sink()
        with contextlib.redirect_stdout(sink),contextlib.redirect_stderr(io.StringIO()): code=c.main(['--version',FIXED,'--format','json'])
        self.assertEqual(130,code);self.assertEqual(1,sink.calls)
    def test_finding_gate_help_and_standalone_copy(self):
        affected=next(v for v,s in CASES if s=='potentially_affected')
        self.assertEqual(1,self.run_cli('--version',affected,'--fail-on-finding')[0])
        self.assertEqual(0,self.run_cli('--version','unknown','--fail-on-finding')[0])
        self.assertEqual(0,self.run_cli('--help')[0])
        import subprocess,sys
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'checker.py';p.write_bytes(Path(c.__file__).read_bytes())
            r=subprocess.run([sys.executable,str(p),'--version',FIXED,'--format','json'],capture_output=True,text=True,timeout=10)
            self.assertEqual(0,r.returncode);self.assertEqual('fixed_version_reported',json.loads(r.stdout)['results'][0]['status'])
if __name__=='__main__': unittest.main()
