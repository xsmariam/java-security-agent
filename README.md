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

**Validation:** Every claimed file must exist, coverage must exactly partition the Java source list, and each finding must cite a valid line interval and an exact piece of source code. Duplicated IDs or possible leaked credentials cause a hard failure. These checks reduce hallucination risk, but cannot prove an interpretation is right or ensure every issue is found. An engineer must verify security conclusions and environmental assumptions.

**Phase B preview:** Python creates a short terminal summary, all findings in structured JSON, and a professional HTML audit with a compact vulnerability table and documentation/team action items. **It is not yet an actual Outlook draft; no Outlook integration or transmission is included.** Outlook will be added later behind a separate approval gate and minimum required permissions.

## Security properties

- Source is read, never executed or edited; no compiling, tests, commits, PRs, email sends, deployments, MCP tools, or cloud uploads other than the explicitly approved Copilot code review request.
- Copilot receives the isolated snapshot rather than the original repo. Original source hashes are checked before and after.
- Output is outside the repository and POSIX file permissions restrict new output files to the current user. `.gitignore` excludes them.
- The model is not granted general shell or write permissions; 
- Real Java source is transmitted to GitHub Copilot for AI review.
