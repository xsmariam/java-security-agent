# Java security review checklist
Guidance is defensive; it is not a substitute for official OWASP/NIST/CISA documentation.

1. **Injection (CWE-89, CWE-78, CWE-79)**: trace user input to JDBC SQL strings, operating-system commands, and HTML output. Parameterize SQL, avoid shells, and encode output for context. Note whether sanitization already exists.
2. **Broken access control (CWE-862, CWE-639, CWE-22)**: verify identity and role checks at every sensitive endpoint; check object ownership; normalize file paths and enforce a trusted root.
3. **Authentication (CWE-328, CWE-916, CWE-330)**: check password storage and token entropy. Prefer slow, salted password hashes and `SecureRandom`.
4. **Hardcoded secrets (CWE-798)**: flag secret literals, not environment-based secret retrieval. Never echo credential values.
5. **Input validation (CWE-20)**: inspect registration and all request-handling boundaries for required-field, size, format and type constraints. Missing checks are only security findings with a specific plausible impact.
6. **Data protection (CWE-532, CWE-327)**: no password/PII logging; prefer authenticated encryption and managed keys; qualify unused insecure helpers as potential.
7. **XML parsing (CWE-611)**: disable unsafe DTD/external entity support for untrusted XML.
8. **Resilience (CWE-400)**: verify request sizes/resources are bounded.

Review secure comparators too: properly bound PreparedStatements, SecureRandom, validated download paths, encrypted AES-GCM, env-sourced secrets. Never flag by keyword alone.

Severity (Critical/High/Medium/Low) is a qualitative estimate, not a CVSS score. Explicitly qualify environmental assumptions and unverified reachability.
