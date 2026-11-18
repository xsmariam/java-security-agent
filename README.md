# Java Security Auditor — Phase A

A new terminal-driven Java security agent inspired by your previous two-phase hackathon workflow. The original hackathon scripts are not required. This package includes your existing VulnShop Java test application and a Python orchestrator that calls the **real GitHub Copilot CLI** in a restricted, read-only environment. It does not simulate findings.

## Requirements

- macOS with VS Code, Python 3.10+, GitHub Copilot CLI installed and authenticated.
- GitHub Copilot entitlement that supports CLI use (VS Code chat access does not necessarily mean the CLI is installed).
- To install/sign in to the Copilot CLI, follow [GitHub's setup instructions](https://docs.github.com/en/copilot/how-tos/copilot-cli/set-up-copilot-cli).

## Use in VS Code Terminal

1. Unzip and open **java-security-agent-phase-a** in VS Code.
2. Run `python3 --version` and `copilot --help`. If Copilot is missing, install it using GitHub's official instructions.
3. Run `python3 run_analysis.py --check` (no AI call).
4. Run `python3 run_analysis.py` and type **ANALYZE** when prompted. This approves sharing the selected Java source with GitHub Copilot, not modifications, emails, or additional actions.
5. Review `output/audit_summary.txt`, `output/findings.json`, and `output/audit_preview.html` (open HTML in a browser).

Optional: `python3 run_analysis.py --repo /path/to/your/java/repo` to scan another Java repo; `--yes` only skips the initial approval prompt for the model scan and never permits edits or email.

## How it works

**Phase A:** Python copies *only `.java` files* to a disposable workspace. The answer key and evaluation data stay outside it. The CLI custom agent is limited to file viewing/search (`view,grep,glob`), with shell and write tools denied. Prompts contain Java security checklists and instructions to ignore prompt injection inside source files. Copilot returns full JSON for validation.

**Validation:** Every claimed file must exist, coverage must exactly partition the Java source list, and each finding must cite a valid line interval and an exact piece of source code. Duplicated IDs or possible leaked credentials cause a hard failure. These checks **reduce hallucination risk, but cannot prove an interpretation is right or ensure every issue is found**. An engineer must verify security conclusions and environmental assumptions.

**Phase B preview:** Python creates a short terminal summary, all findings in structured JSON, and a professional HTML audit with a compact vulnerability table and documentation/team action items. **It is not yet an actual Outlook draft; no Outlook integration or transmission is included.** Outlook can be added later behind a separate approval gate and minimum required permissions.

## Security properties

- Source is read, never executed or edited; no compiling, tests, commits, PRs, email sends, deployments, MCP tools, or cloud uploads other than the explicitly approved Copilot code review request.
- Copilot receives the isolated snapshot rather than the original repo. Original source hashes are checked before and after.
- Output is outside the repository and POSIX file permissions restrict new output files to the current user. `.gitignore` excludes them.
- The model is not granted general shell or write permissions; **do not remove those tool limits**.
- Real Java source is transmitted to GitHub Copilot for AI review. Use only with authorization to share that code; for corporate repos, follow your organization's data-handling rules.
- Source files larger than 2 MB, more than 250 Java files, or malformed/unsupported response formats fail closed.
- The deliberately vulnerable VulnShop application must not be deployed on a public network.

## Test

`python3 -m unittest discover -s tests -v`

Tests run offline and do not call the AI. For research evaluation, keep the provided `answer_key.csv` outside the source repo and outside Phase A's AI workspace. Compare against it only after collecting an independent scan report.

## Limitations

This is source-only AI analysis, not dynamic proof of exploitability, not a full independent security audit, and not the old hackathon code. CLI availability and exact flags depend on your installed Copilot CLI version. If they differ, check [official programmatic CLI docs](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-programmatic-reference) and [tool permission docs](https://docs.github.com/en/copilot/how-tos/copilot-cli/use-copilot-cli/allowing-tools) rather than disabling protections.


## Phase A v2: risk calibration and evaluation

- Each finding now requires **exposure**, **exploitability**, and **impact** scores (0–3), a rationale, a source-evidence verification status, and explicit assumptions where relevant. The Python validator independently derives severity from these values and rejects conflicting labels. See `phase_a/risk_rubric.md`. The numeric sum is a *custom qualitative rubric*, not CVSS; it cannot validate model reasoning by itself.
- Distinct hardcoded-secret assignments must be listed as separate findings. Attempts to merge multiple source-literal secrets into one CWE-798 finding are rejected.
- The concise terminal report still shows just five prioritized items, while retaining all findings in JSON. Uncertain/conditional findings are counted for human review.
- To compare after scanning, **keep `answer_key.csv` outside this project** and run `python3 evaluate_baseline.py --key /absolute/path/to/answer_key.csv`. The evaluator never sends the key to Copilot, and does not automatically label extra findings as false positives.
- Run local tests: `python3 -m unittest discover -s tests -v`. If Copilot fails to produce a valid structured response, the scan fails closed without generating a new audit report; review the error rather than granting broad permissions.
- The scan is AI-only and requires service consent. Do not use `--allow-all`, and do not place actual secrets in the repo. The source snapshot prevents source edits by the agent, but it is not a formally verified OS sandbox or a guarantee that the AI cannot err.

## Phase A v2.1: validation-retry fix

If Copilot supplies an evidence excerpt that does not exactly occur on the cited lines (or any other field fails validation), the application discards that output and requests a **complete fresh scan** with feedback. It makes at most **three read-only Copilot calls total** per approved run, and never disables evidence checks or edits Java files. Rejected responses are not saved as valid reports. The terminal reports the reason and retry count. If every attempt fails, no new audit is generated (older files in `output/` may still exist; their timestamps should not be mistaken for this run). The approval message now states that up to two additional model calls may occur. These retries may consume additional Copilot quota.

## Phase A final: calibrated triage and complete registration review

- Severity has documented conservative calibration for reflected XSS, file-read traversal, and active weak password storage. The rubric is qualitative, not CVSS, and still requires engineering judgment.
- A required `registration_review` section checks username, email, and password validation independently; when missing controls are claimed, linked CWE-20/CWE-521 findings must appear.
- The final verified JSON normalizes the hardcoded DES key with its DES/ECB helper as one underlying cryptographic issue, retaining the related source location. It **never** merges database-password and payment API-key findings.
- `output/findings.json` remains machine-readable and `audit_summary.txt` concise. Existing `vulnshop` Java files are unchanged. No Outlook action happens in Phase A.
- Compared with the previous version, schema and validation are stricter: a CLI model response that omits `registration_review` may be retried, not silently accepted.
