# VulnShop – Intentionally Vulnerable Java Test Repository

**WARNING: This code is deliberately insecure. Never deploy it or reuse any of it.**

A small Java web app (JDK only: `com.sun.net.httpserver`, JDBC, JCE; no external
dependencies) used as the scan target for the AI-Powered Secure Software Development
Agent project. It compiles with Java 17+.

## Structure
- `config/` application configuration
- `model/` User model
- `db/` data access (JDBC)
- `auth/` login, hashing, sessions
- `web/` HTTP handlers (login, register, profile, admin, files, search, comment, ping, import)
- `util/` HTTP and crypto helpers

## Notes for evaluators
- The code contains planted vulnerabilities **and** secure look-alike code, so false
  positives can be measured.
- The code has no hint comments. Do **not** put the answer key inside this repo or
  workspace when running the agent, or the agent can read it.
- The answer key lives in the sibling `vulnshop-eval/` folder.

## Build check
    javac -d out $(find src -name '*.java')
