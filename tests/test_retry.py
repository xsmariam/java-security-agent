import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from run_analysis import sources, run_verified_audit, AuditError, digests

ROOT = Path(__file__).resolve().parents[1]

class RetryTests(unittest.TestCase):
    def payload(self):
        fs = sources(ROOT/'vulnshop')
        path = 'src/main/java/com/vulnshop/web/DiagnosticsHandler.java'
        line = next(i for i, x in enumerate(fs[path].read_text().splitlines(), 1) if '/bin/sh' in x)
        finding = dict(id='F001', title='OS command injection', severity='Critical', cwe='CWE-78',
                       file=path, line_start=line, line_end=line, evidence='/bin/sh',
                       explanation='User input reaches the operating system shell.',
                       remediation='Avoid shells; pass fixed arguments.', confidence='high',
                       verification_status='source-supported',
                       risk={'exposure':3,'exploitability':3,'impact':3,
                             'rationale':'Unauthenticated controllable command execution.', 'assumptions':''})
        return fs, dict(repository='vulnshop',scan_mode='ai-only',files_reviewed=list(fs),
                        unreviewed_files=[],registration_review={'file':'src/main/java/com/vulnshop/web/RegistrationHandler.java','username':{'status':'uncertain','reason':'Not assessed by the test fixture.'},'email':{'status':'uncertain','reason':'Not assessed by the test fixture.'},'password':{'status':'uncertain','reason':'Not assessed by the test fixture.'}},findings=[finding])

    def test_invalid_first_attempt_then_valid(self):
        fs, good = self.payload()
        bad = copy.deepcopy(good)
        bad['findings'][0]['evidence'] = 'fabricated code evidence'
        responses = [type('R', (), {'returncode':0,'stdout':json.dumps(x),'stderr':''}) for x in (bad,good)]
        before=digests(fs)
        with patch('run_analysis.subprocess.run',side_effect=responses) as mocked:
            data, tries = run_verified_audit('copilot', ROOT, fs)
        self.assertEqual(tries,2)
        self.assertEqual(data,good)
        self.assertEqual(mocked.call_count,2)
        self.assertEqual(before,digests(fs))
        for call in mocked.call_args_list:
            cmd=call.args[0]
            self.assertIn('--deny-tool=write,shell',cmd)
            self.assertNotIn('--allow-all',cmd)
        self.assertIn('PREVIOUS RESPONSE FAILED LOCAL VALIDATION',mocked.call_args_list[1].args[0][2])

    def test_all_attempts_invalid(self):
        fs, bad = self.payload()
        bad['findings'][0]['evidence']='fabricated'
        response=type('R', (), {'returncode':0,'stdout':json.dumps(bad),'stderr':''})
        with patch('run_analysis.subprocess.run',return_value=response) as mocked:
            with self.assertRaisesRegex(AuditError,'after 3 attempts'):
                run_verified_audit('copilot',ROOT,fs)
        self.assertEqual(mocked.call_count,3)

if __name__=='__main__': unittest.main()
