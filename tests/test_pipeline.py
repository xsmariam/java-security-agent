import tempfile
import unittest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from run_analysis import sources, digests, build_snapshot, validate, AuditError
from phase_a.risk_policy import assess_finding
from phase_b.report_generator import summary, html_preview
ROOT = Path(__file__).resolve().parents[1]
class GuardrailTests(unittest.TestCase):
    def fixture(self):
        files = sources(ROOT / 'vulnshop')
        key = 'src/main/java/com/vulnshop/web/DiagnosticsHandler.java'
        line = next(i for i,s in enumerate(files[key].read_text().splitlines(),1) if '/bin/sh' in s)
        obj = {'repository':'vulnshop','scan_mode':'ai-only','files_reviewed':list(files),'unreviewed_files':[], 'registration_review':{'file':'src/main/java/com/vulnshop/web/RegistrationHandler.java','username':{'status':'uncertain','reason':'Not assessed by the test fixture.'},'email':{'status':'uncertain','reason':'Not assessed by the test fixture.'},'password':{'status':'uncertain','reason':'Not assessed by the test fixture.'}}, 'findings':[{'id':'F001','title':'Command injection','severity':'Critical','cwe':'CWE-78','file':key,'line_start':line,'line_end':line,'evidence':'/bin/sh','explanation':'Shell receives unsafe input.','remediation':'Avoid shell execution.','confidence':'high','verification_status':'source-supported','risk':{'exposure':3,'exploitability':3,'impact':3,'rationale':'Unauthenticated shell invocation with high impact.','assumptions':''}}]}
        return files,obj
    def test_source_snapshot_untouched(self):
        files,_=self.fixture(); old=digests(files)
        self.assertEqual(len(files),19)
        with tempfile.TemporaryDirectory() as temp:
            build_snapshot(files,Path(temp))
            self.assertEqual(old,digests({k:Path(temp)/k for k in files}))
            self.assertFalse((Path(temp)/'vulnshop-eval').exists())
        self.assertEqual(old,digests(files))
    def test_valid_output(self):
        files,obj=self.fixture()
        validate(obj,files)
        self.assertIn('Command injection',summary(obj))
        self.assertIn('Documentation and team action items',html_preview(obj))
    def test_invented_line_rejected(self):
        files,obj=self.fixture(); obj['findings'][0].update(line_start=9999,line_end=9999)
        with self.assertRaises(AuditError):validate(obj,files)
    def test_invented_evidence_rejected(self):
        files,obj=self.fixture(); obj['findings'][0]['evidence']='fabricated attack path'
        with self.assertRaises(AuditError):validate(obj,files)
    def test_coverage_gap_rejected(self):
        files,obj=self.fixture(); obj['files_reviewed'].pop()
        with self.assertRaises(AuditError):validate(obj,files)
    def test_risk_rubric_enforced(self):
        files,obj=self.fixture()
        obj['findings'][0]['severity']='Medium'
        with self.assertRaises(AuditError):validate(obj,files)
    def test_risk_score_boundaries(self):
        _,obj=self.fixture(); f=obj['findings'][0]
        self.assertEqual(assess_finding(f)['severity'],'Critical')
        f['verification_status']='conditional'; f['risk']['assumptions']='Network perimeter not confirmed'
        self.assertEqual(assess_finding(f)['severity'],'High')
        f['verification_status']='requires-review'
        self.assertEqual(assess_finding(f)['severity'],'Medium')
    def test_secret_merging_rejected(self):
        files,obj=self.fixture()
        path='src/main/java/com/vulnshop/config/AppConfig.java'
        obj['findings'][0].update(file=path,line_start=8,line_end=11,cwe='CWE-798',evidence='DB_PASSWORD',title='Grouped hardcoded secrets')
        with self.assertRaisesRegex(AuditError, 'combined hardcoded secrets'):
            validate(obj,files)
    def test_html_escaping(self):
        _,obj=self.fixture(); obj['findings'][0]['title']='<script>bad</script>'
        self.assertNotIn('<script>bad</script>',html_preview(obj))
        self.assertIn('&lt;script&gt;',html_preview(obj))
if __name__=='__main__':unittest.main()
