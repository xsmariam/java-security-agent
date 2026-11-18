# Phase A: evidence-first review

Inspect **every** Java file in the provided source snapshot. If one cannot be reviewed, list it in `unreviewed_files`. Focus on vulnerable flows (source -> validation/authorization -> sensitive sink), not keyword matching. Find as many independently defensible defects as evidence supports; never force a target number. Distinguish secure lookalikes. Especially examine registration validation.

Respond with ONLY one valid JSON object (no markdown fences or commentary):
{
  "repository": "vulnshop",
  "scan_mode": "ai-only",
  "files_reviewed": ["src/main/java/..."],
  "unreviewed_files": [],
  "registration_review": {
    "file": "src/main/java/com/vulnshop/web/RegistrationHandler.java",
    "username": {"status": "missing", "reason": "State whether required, blank, length and allowable characters are checked."},
    "email": {"status": "missing", "reason": "State whether required, blank, syntax and length are checked."},
    "password": {"status": "missing", "reason": "State whether required, blank, length and password policy are checked."}
  },
  "findings": [
    {
      "id": "F001",
      "title": "Short vulnerability name",
      "severity": "High",
      "cwe": "CWE-89",
      "file": "src/main/java/.../Example.java",
      "line_start": 13,
      "line_end": 14,
      "evidence": "EXACT short substring copied from the cited source lines, with any secrets redacted",
      "explanation": "One sentence with source/sink and security impact; state assumptions",
      "remediation": "One concrete defensive change",
      "confidence": "high",
      "verification_status": "source-supported",
      "risk": {"exposure": 3, "exploitability": 3, "impact": 3, "rationale": "Explain how the path supports each score.", "assumptions": ""}
    }
  ]
}

If source evidence itself contains a secret, select a nearby short non-secret exact excerpt; never quote the secret. Do not make up a path or line number. Limit findings to 100. Use relative source paths and each reviewed file once. Do not include raw source dumps, exploit payloads, or evaluation metrics.

## Independent reporting rules

- Treat each unique hardcoded credential/API key assignment as an independent finding and line location even if both share CWE-798. Do not merge findings to shorten the output. Group only in the *email summary* later.
- Independently score each finding using `risk_rubric.md`. Do not force the model to match an answer key. Mention uncertain reachability in `verification_status` and `risk.assumptions`.
- A secure comparator must not be flagged solely for containing a risk-related keyword.
- Source-supported means code evidence exists; it does *not* claim successful exploitation or an independently verified true positive.

## Strict local evidence matching

The Python validator accepts `evidence` only when it is a **literal, contiguous, character-for-character substring** of the indicated lines. Do not combine two distant lines into a single excerpt, change indentation, add ellipses, or normalize quotes/whitespace. Prefer a short distinctive expression on a single line. Cite that line for both `line_start` and `line_end` where possible. Never return secret values. Invalid output is rejected and may trigger a limited, read-only retry.

## Registration review completeness

If a `RegistrationHandler.java` file exists, include `registration_review` exactly as illustrated, with one short, source-grounded assessment for each of username, email and password. Statuses: `present`, `missing`, `uncertain`. Check required/null, blank, bounds, malformed inputs; email syntax; and password length/policy. Trace validation in called helpers before saying it is absent. If username or email validation is missing, include a dedicated registration CWE-20 finding (one combined finding is acceptable when both stem from the same missing validation). If password validation is missing, include a CWE-521 or CWE-20 finding. Do not presume validation just because database constraints might exist. No invented validations.

## Overlap and severity calibration

- Report fixed-key DES/ECB as ONE underlying legacy encryption defect, referencing both the key and algorithm in its explanation/remediation. Do not create a separate CWE-798 issue for the same DES key. Database password and payment API key are independently managed secrets and require separate findings.
- Report Critical only where source-supported scope and impact justify it. Reflected XSS (CWE-79) and read-only file traversal (CWE-22) are normally at most High without independent evidence of a more catastrophic impact; do not claim command execution simply from file read.
- An actively used fast unsalted password hash is High at minimum; an unused cryptographic helper with uncertain reachability belongs in requires-review and is capped at Medium.
- Risk score must reflect the actual source path and prerequisites; the deterministic policy applies conservative caps/floors after scoring. Don't attempt to match a known answer key.
