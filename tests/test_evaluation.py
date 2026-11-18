import sys, unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from evaluate_baseline import compare
class EvaluationTests(unittest.TestCase):
    def test_combined_findings_are_not_double_counted(self):
        expected=[{'id':'A','name':'one','file':'f.java','cwe':'CWE-798','line_start':2,'line_end':2},{'id':'B','name':'two','file':'f.java','cwe':'CWE-798','line_start':4,'line_end':4}]
        findings=[{'id':'F1','title':'secrets','file':'f.java','cwe':'CWE-798','line_start':2,'line_end':4,'severity':'High'}]
        for e in expected:e['severity']='High'
        result=compare(expected,findings)
        self.assertEqual(result['matched_distinct_expected'],1)
        self.assertEqual(result['recall'],0.5)
    def test_synonymous_cwe_matches(self):
        expected=[{'id':'A','name':'weak hash','file':'f.java','cwe':'CWE-328','line_start':20,'line_end':20,'severity':'High'}]
        findings=[{'id':'F1','title':'weak hash','file':'f.java','cwe':'CWE-916','line_start':20,'line_end':20,'severity':'High'}]
        self.assertEqual(compare(expected,findings)['recall'],1)
if __name__=='__main__':unittest.main()
