import copy
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from run_analysis import validate, sources, AuditError
from phase_a.risk_policy import assess_finding
ROOT = Path(__file__).resolve().parents[1]

def risk(status='source-supported', exposure=3, exploitability=3, impact=2):
    return dict(verification_status=status,cwe='CWE-79',risk=dict(exposure=exposure,exploitability=exploitability,impact=impact,rationale='Review of controlled input and reachable output context.',assumptions='Deployment prerequisites remain to be verified.' if status != 'source-supported' else ''))

class FinalCalibrationTests(unittest.TestCase):
    def fixture(self):
        files=sources(ROOT/'vulnshop')
        regpath='src/main/java/com/vulnshop/web/RegistrationHandler.java'
        return files, {'repository':'vulnshop','scan_mode':'ai-only','files_reviewed':list(files),'unreviewed_files':[], 'registration_review':{'file':regpath,'username':{'status':'uncertain','reason':'Need an independent source review.'},'email':{'status':'uncertain','reason':'Need an independent source review.'},'password':{'status':'uncertain','reason':'Need an independent source review.'}},'findings':[]}
    def test_reflected_xss_and_file_read_cap_at_high(self):
        f=risk()
        self.assertEqual(assess_finding(f)['severity'],'High')
        f['cwe']='CWE-22'
        self.assertEqual(assess_finding(f)['severity'],'High')
        f['cwe']='CWE-78'
        self.assertEqual(assess_finding(f)['severity'],'Critical')
    def test_active_fast_hash_minimum_high(self):
        f=risk(exposure=1,exploitability=2,impact=2)
        f['cwe']='CWE-916'
        self.assertEqual(assess_finding(f)['severity'],'High')
        f['verification_status']='requires-review'
        f['risk']['assumptions']='Not used in reviewed code'
        self.assertEqual(assess_finding(f)['severity'],'Medium')
    def test_registration_review_required_and_missing_fields_need_finding(self):
        files,obj=self.fixture()
        del obj['registration_review']
        with self.assertRaisesRegex(AuditError,'registration'):validate(obj,files)
        _,obj=self.fixture()
        obj['registration_review']['email']['status']='missing'
        with self.assertRaisesRegex(AuditError,'CWE-20'):validate(obj,files)
    def test_normalizes_legacy_key_once(self):
        files,obj=self.fixture()
        path='src/main/java/com/vulnshop/util/CryptoUtil.java'
        lines=files[path].read_text().splitlines()
        key=next(i for i,l in enumerate(lines,1) if 'LEGACY_KEY =' in l)
        des=next(i for i,l in enumerate(lines,1) if 'Cipher.getInstance("DES/ECB' in l)
        def finding(id,cwe,line,evidence,title):
            return dict(id=id,title=title,severity='Medium',cwe=cwe,file=path,line_start=line,line_end=line,evidence=evidence,explanation='Unverified cryptographic helper with security weaknesses.',remediation='Use AES-GCM instead of the legacy cipher.',confidence='medium',verification_status='requires-review',risk=dict(exposure=1,exploitability=1,impact=2,rationale='Legacy helper appears unused within the reviewed repository.',assumptions='Assumes other code calls the helper'))
        obj['findings']=[finding('F001','CWE-798',key,'LEGACY_KEY =','Hardcoded legacy key'),finding('F002','CWE-327',des,'DES/ECB/PKCS5Padding','Legacy DES encryption')]
        result=validate(obj,files)
        self.assertEqual(len(result['findings']),1)
        self.assertEqual(result['findings'][0]['id'],'F001')
        self.assertEqual(result['findings'][0]['related_locations'][0]['line'],key)

if __name__=='__main__':unittest.main()
