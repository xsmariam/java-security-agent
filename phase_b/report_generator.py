"""Generate concise redacted local reports from validated Phase A JSON."""
from __future__ import annotations
import html
from pathlib import Path

ORDER = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}


def summary(data: dict) -> str:
    fs = sorted(data['findings'], key=lambda x: (ORDER[x['severity']], x['file'], x['line_start']))
    counts = {k: sum(f['severity'] == k for f in fs) for k in ORDER}
    lines = [f"Security audit: {data['repository']} | {len(data['files_reviewed'])}/{len(data['files_reviewed'])+len(data['unreviewed_files'])} Java files | {len(fs)} findings",
             'Severity: ' + ', '.join(f'{v} {k}' for k,v in counts.items()), 'Top priorities:']
    lines.extend(f"- {f['severity']}: {f['title']} ({f['cwe']}) — {Path(f['file']).name}:{f['line_start']} — {f['remediation']}" for f in fs[:5])
    if len(fs) > 5:
        lines.append(f"+ {len(fs)-5} additional findings in findings.json")
    if data['unreviewed_files']:
        lines.append(f"Coverage gap: {len(data['unreviewed_files'])} Java files not reviewed")
    lines.append('Next: assign remediation owners, document risks in a shared register, then rescan after fixes.')
    pending = sum(f.get('verification_status') != 'source-supported' for f in fs)
    lines.append(f'Human review: {pending} conditional/uncertain findings. Evidence excerpts are checked; exploitability is not proven.')
    lines.append('AI-only static review; no source files changed.')
    return '\n'.join(lines)


def html_preview(data: dict) -> str:
    fs = sorted(data['findings'], key=lambda x: (ORDER[x['severity']], x['file'], x['line_start']))
    esc = lambda s: html.escape(str(s), quote=True)
    rows = '\n'.join('<tr>' + ''.join(f'<td>{esc(v)}</td>' for v in [f['severity'], f['title']+' ('+f['cwe']+')', Path(f['file']).name+':'+str(f['line_start']), f['remediation']]) + '</tr>' for f in fs[:8])
    total = len(data['files_reviewed']) + len(data['unreviewed_files'])
    body = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Security Risk Audit — {esc(data['repository'])}</title>
<style>body{{font:14px -apple-system,BlinkMacSystemFont,Segoe UI,Arial,sans-serif;color:#202936;max-width:920px;margin:35px auto;padding:0 18px;line-height:1.5}}
h1{{font-size:23px}}.muted{{color:#606b78}}table{{border-collapse:collapse;width:100%;font-size:13px}}th,td{{padding:9px 10px;border:1px solid #d9dfe5;text-align:left;vertical-align:top}}th{{background:#f0f3f6}}li{{margin:4px 0}}</style></head><body>
<h1>Security Risk Audit — {esc(data['repository'])}</h1><p><strong>Scope:</strong> {len(data['files_reviewed'])}/{total} Java files reviewed<br><strong>Scan:</strong> AI-only, read-only<br><strong>Findings:</strong> {len(fs)} (Critical {sum(f['severity']=='Critical' for f in fs)}, High {sum(f['severity']=='High' for f in fs)}, Medium {sum(f['severity']=='Medium' for f in fs)}, Low {sum(f['severity']=='Low' for f in fs)})</p>
<h2>Prioritized findings</h2><table><tr><th>Severity</th><th>Vulnerability</th><th>Location</th><th>Recommended action</th></tr>{rows}</table>
<p class="muted">Showing up to 8 priorities. Full verified findings are stored locally in findings.json.</p>
<h2>Documentation and team action items</h2><ol><li>Log validated findings with CWE, affected file and accountable engineering owner.</li><li>Prioritize remediation of Critical and High items; record exceptions and approval decisions.</li><li>Update Java secure coding guidance and unit tests for recurring root causes.</li><li>Arrange independent validation and rescan after changes.</li></ol>
<p class="muted">AI-only source review; risk scoring is qualitative, and no dynamic verification was performed. This is a local HTML preview, not an Outlook draft, and nothing was emailed.</p></body></html>'''
    return body
