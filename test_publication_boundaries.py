"""Synthetic publication-boundary and portable CSV regressions."""
import contextlib
import inspect
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import vm2_nesting_check as c
VERSION_FIELD = 'package_version'
FIXED = '3.11.7'

class PublicationBoundaryTests(unittest.TestCase):
    def run_cli(self,*args):
        with contextlib.redirect_stdout(io.StringIO()) as out,contextlib.redirect_stderr(io.StringIO()) as err:
            code=c.main(list(args))
        return code,out.getvalue(),err.getvalue()
    def test_completed_atomic_operation_then_interrupt_is_never_repeated(self):
        for force,attribute in [(False,'link'),(True,'replace')]:
            with self.subTest(force=force),tempfile.TemporaryDirectory() as directory:
                target=Path(directory)/'report.json'
                if force:target.write_text('old')
                original=getattr(c.os,attribute);calls=[]
                def publish_then_interrupt(src,dst):
                    calls.append((src,dst));original(src,dst);raise KeyboardInterrupt
                with mock.patch.object(c.os,attribute,publish_then_interrupt):
                    code,_,_=self.run_cli('--version',FIXED,'--format','json','--output',str(target),*(['--force'] if force else []))
                self.assertEqual(130,code);self.assertEqual(1,len(calls))
                self.assertTrue(json.loads(target.read_text())['complete'])
                self.assertEqual(['report.json'],sorted(p.name for p in Path(directory).iterdir()))
    def test_interrupt_at_success_flag_assignment_is_guarded(self):
        lines,start=inspect.getsourcelines(c.save_report)
        atomic=max(i for i,line in enumerate(lines) if 'os.link(' in line or 'os.replace(' in line)
        flag=start+next(i for i in range(atomic+1,len(lines)) if 'state["published"] = True' in lines[i])
        for force in [False,True]:
            with self.subTest(force=force),tempfile.TemporaryDirectory() as directory:
                target=Path(directory)/'report.json';seen=[]
                if force:target.write_text('old')
                def trace(frame,event,arg):
                    if frame.f_code is c.save_report.__code__ and event=='line' and frame.f_lineno==flag and not seen:
                        seen.append(True);sys.settrace(None);raise KeyboardInterrupt
                    return trace
                try:
                    sys.settrace(trace)
                    code,_,_=self.run_cli('--version',FIXED,'--format','json','--output',str(target),*(['--force'] if force else []))
                finally:sys.settrace(None)
                self.assertTrue(seen);self.assertEqual(130,code)
                self.assertTrue(json.loads(target.read_text())['complete'])
    def test_competing_identical_bytes_are_not_our_staged_inode(self):
        for force,attribute in [(False,'link'),(True,'replace')]:
            with self.subTest(force=force),tempfile.TemporaryDirectory() as directory:
                target=Path(directory)/'report.json';calls=[];original=getattr(c.os,attribute)
                def competitor(src,dst):
                    calls.append(True)
                    if len(calls)==1:
                        Path(dst).write_bytes(Path(src).read_bytes());raise KeyboardInterrupt
                    return original(src,dst)
                with mock.patch.object(c.os,attribute,competitor):
                    code,_,_=self.run_cli('--version',FIXED,'--format','json','--output',str(target),*(['--force'] if force else []))
                self.assertEqual(2,len(calls))
                self.assertEqual(130 if force else 2,code)
                self.assertEqual(not force,json.loads(target.read_text())['complete'])
    def test_nul_csv_fails_before_stdout_new_or_forced_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory=Path(directory)/'input.json';inventory.write_text(json.dumps({'schema_version':1,VERSION_FIELD:FIXED,'label':'example\x00asset'}))
            for mode in ['stdout','new','force']:
                with self.subTest(mode=mode):
                    target=Path(directory)/(mode+'.csv');args=[]
                    if mode!='stdout':args=['--output',str(target)]
                    if mode=='force':target.write_text('KEEP');args+=['--force']
                    code,out,err=self.run_cli('--inventory',str(inventory),'--format','csv',*args)
                    self.assertEqual((2,''),(code,out));self.assertNotIn('Traceback',err)
                    if mode=='force':self.assertEqual('KEEP',target.read_text())
                    else:self.assertFalse(target.exists())
            code,out,_=self.run_cli('--inventory',str(inventory),'--format','json')
            self.assertEqual(0,code);self.assertEqual('example\x00asset',json.loads(out)['results'][0]['input_label'])
if __name__=='__main__':unittest.main()
