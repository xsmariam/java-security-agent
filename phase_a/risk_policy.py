"""Transparent qualitative risk model. Not a CVSS implementation."""
from __future__ import annotations
import re

class RiskPolicyError(ValueError):
    pass

# Each dimension: 0 (lowest) to 3 (highest). All must be supported by reasoning.
# Total 0-2 Low, 3-5 Medium, 6-7 High, 8-9 Critical.
# Unverified runtime reachability caps severity to Medium; conditional assumptions cap at High.
VALID_STATUS = {"source-supported", "conditional", "requires-review"}

def assess_finding(f: dict) -> dict:
    risk = f.get("risk")
    if not isinstance(risk, dict):
        raise RiskPolicyError('missing risk assessment')
    for name in ('exposure', 'exploitability', 'impact'):
        if type(risk.get(name)) is not int or risk[name] not in (0,1,2,3):
            raise RiskPolicyError(f'{name} must be an integer between 0 and 3')
    if not isinstance(risk.get('rationale'), str) or not 15 <= len(risk['rationale']) <= 350:
        raise RiskPolicyError('risk rationale is missing or too long')
    if f.get('verification_status') not in VALID_STATUS:
        raise RiskPolicyError('invalid verification_status')
    if f['verification_status'] != 'source-supported' and not (isinstance(risk.get('assumptions'), str) and risk['assumptions'].strip()):
        raise RiskPolicyError('conditional findings require explicit assumptions')
    if not isinstance(risk.get('assumptions', ''), str) or len(risk.get('assumptions', '')) > 300:
        raise RiskPolicyError('invalid assumptions')
    score = sum(risk[k] for k in ('exposure','exploitability','impact'))
    severity = ('Low' if score <= 2 else 'Medium' if score <= 5 else 'High' if score <= 7 else 'Critical')
    if f['verification_status'] == 'conditional' and severity == 'Critical': severity = 'High'
    if f['verification_status'] == 'requires-review' and severity in ('Critical','High'): severity = 'Medium'
    # Calibrated, conservative impact ceilings for the *identified* weakness.
    # A reflected script or a file-read traversal alone is not proof of server
    # execution, administrative compromise, or catastrophic data disclosure.
    # Such distinct consequences must have separate, independently supported evidence.
    if f.get('cwe') in {'CWE-79', 'CWE-22'} and severity == 'Critical':
        severity = 'High'
    # An actively used, source-supported fast password hash is a high-priority
    # authentication storage weakness even though the offline attack requires
    # obtaining hashes. An unused/unverified helper is not covered by this rule.
    if f.get('cwe') in {'CWE-916', 'CWE-328'} and f['verification_status'] == 'source-supported' and severity in {'Low', 'Medium'}:
        severity = 'High'
    return {'score':score,'severity':severity}


# Conservative detection of source-literal credential assignments; used only to
# reject aggregated hardcoded-secret findings, not to assert vulnerability existence.
DECLARATION = re.compile(r'\b([A-Za-z_$][\w$]*(?:PASSWORD|SECRET|API_KEY|TOKEN)[\w$]*)\s*=\s*"[^"\n]+"', re.I)

def secret_declaration_lines(lines: list[str], start: int, end: int) -> list[tuple[int,str]]:
    return [(i, m.group(1)) for i in range(start,end+1) for m in DECLARATION.finditer(lines[i-1])]
