# Risk assessment policy — transparent, qualitative (not CVSS)

For every finding, provide `risk.exposure`, `risk.exploitability`, and `risk.impact` as integer scores from 0 to 3, supported by a short `risk.rationale` and any `risk.assumptions`.

- **Exposure:** 0 unreachable/unused, 1 limited trusted usage, 2 authenticated/limited external access, 3 externally reachable or unauthenticated entry point supported by source.
- **Exploitability:** 0 purely theoretical, 1 significant prerequisites, 2 moderate constraints, 3 straightforward malicious input or misuse path.
- **Impact:** 0 negligible, 1 limited integrity or disclosure, 2 meaningful account/data/service compromise, 3 server code execution, broad privileged account compromise, or severe sensitive-data exposure.

**Deterministic scoring:** sum all three dimensions (0–9). 0–2 Low, 3–5 Medium, 6–7 High, 8–9 Critical. When deployment assumptions are necessary (`conditional`), cap at High. When source alone does not establish runtime reachability (`requires-review`), cap at Medium. The program rejects any model-supplied severity that disagrees with the rubric. Do not manipulate scores to hit a desired severity or match an answer key.

`verification_status` choices:
- `source-supported`: clear vulnerable source-flow demonstrated; still not exploited or dynamically verified.
- `conditional`: vulnerability depends on deployment conditions or external guardrails; state assumptions.
- `requires-review`: uncertain reachability, security impact, or third-party/environment behavior; state assumptions.

**Important:** source excerpt validation proves that a quoted string exists at the cited location, NOT that the vulnerability is real. Human review remains necessary. Never report qualitative risk numbers as CVSS scores.

## Calibrated risk interpretation (Phase A final)

The local validator additionally applies published conservative rules after the 0–9 base calculation:

- Reflected XSS (CWE-79) and read-only path traversal (CWE-22) are capped at **High**. An independently demonstrated, more destructive outcome must be represented and evidenced as its own weakness, not assumed from the CWE.
- Active, source-supported fast password hashing (CWE-916 or CWE-328) has a **High** minimum because it affects persistent authentication credentials. This does **not** override `requires-review` for an uncalled helper.
- A fixed key and legacy cipher belonging to the *same* helper constitute one actionable encryption defect; different database/payment credentials remain separate.

These are conservative internal prioritization rules, **not CVSS or an external severity standard**. The question is whether the risk claim is defensible, not whether it agrees with the planted-vulnerability answer key.
