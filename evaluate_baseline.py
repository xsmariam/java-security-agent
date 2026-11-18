#!/usr/bin/env python3
"""Local, post-scan comparison against an external answer key. Never sent to AI."""
import argparse, csv, json
from pathlib import Path

# Alternative CWEs for semantically equivalent planted weaknesses.
ALIASES = [ {'CWE-328','CWE-916'}, {'CWE-20','CWE-521'} ]
def compatible(a, b):
    return a == b or any({a,b} <= group for group in ALIASES)
def overlaps(a,b):
    return max(int(a['line_start']),int(b['line_start'])) <= min(int(a['line_end']),int(b['line_end']))
def compare(key, findings):
    # Bipartite edges: one reported finding matches at most one planted issue.
    edges = [[j for j, f in enumerate(findings) if f['file']==g['file'] and compatible(f['cwe'],g['cwe']) and overlaps(f,g)] for g in key]
    matching = {}
    def augment(i, seen):
        for j in edges[i]:
            if j in seen: continue
            seen.add(j)
            if j not in matching or augment(matching[j],seen):
                matching[j]=i
                return True
        return False
    for i in range(len(key)): augment(i,set())
    matched_expected = set(matching.values())
    return {
        'expected_count':len(key), 'reported_count':len(findings),
        'matched_distinct_expected':len(matched_expected),
        'recall':len(matched_expected)/len(key) if key else None,
        'unmatched_expected':[{'id':k['id'],'name':k['name']} for i,k in enumerate(key) if i not in matched_expected],
        'unmatched_findings':[{'id':f['id'],'title':f['title'],'file':f['file']} for j,f in enumerate(findings) if j not in matching],
        'matched_severity_agreement':sum(findings[j]['severity']==key[i]['severity'] for j,i in matching.items()),
        'matched_count':len(matching),
        'severity_agreement_rate':(sum(findings[j]['severity']==key[i]['severity'] for j,i in matching.items())/len(matching)) if matching else None,
        'note':'Unmatched findings are NOT automatically false positives; manual adjudication required. Grouped findings lower one-to-one match counts.'
    }
def main():
    ap=argparse.ArgumentParser(description='Compare a completed audit to a separately held planted-vulnerability key')
    ap.add_argument('--key',type=Path,required=True,help='Path OUTSIDE project to original answer_key.csv')
    ap.add_argument('--findings',type=Path,default=Path(__file__).parent/'output'/'findings.json')
    args=ap.parse_args()
    project=Path(__file__).resolve().parent
    key_path=args.key.resolve()
    if key_path==project or project in key_path.parents:
        ap.error('The answer key must remain outside the project directory to keep it away from agent inputs')
    with key_path.open(newline='',encoding='utf-8-sig') as handle: key=list(csv.DictReader(handle))
    data=json.loads(args.findings.read_text())
    print(json.dumps(compare(key,data['findings']),indent=2))
if __name__=='__main__':main()
