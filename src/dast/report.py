import html
import json
from pathlib import Path


def write_report(report: dict, directory: str):
    out = Path(directory)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    esc = lambda value: html.escape(str(value), quote=True)
    rows = "".join(
        "<tr><td>" + "</td><td>".join(esc(f[k]) for k in
            ("severity", "rule", "role", "url", "evidence", "remediation")) + "</td></tr>"
        for f in report["findings"])
    document = (
        '<!doctype html><html lang="en"><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<title>DAST report</title><body><h1>DAST assessment</h1>'
        f'<p>Target: {esc(report["target"])}</p>'
        f'<p>Requests: {report["requests"]}; stop: {esc(report["stop_reason"])}</p>'
        '<p>These findings describe observed configuration, not proven exploitation.</p>'
        '<table border="1"><thead><tr><th>Severity</th><th>Rule</th><th>Role</th>'
        '<th>URL</th><th>Evidence</th><th>Remediation</th></tr></thead>'
        f'<tbody>{rows}</tbody></table><h2>Coverage</h2><pre>{esc(json.dumps(report["pages"], indent=2))}</pre>'
        f'<h2>Errors</h2><pre>{esc(json.dumps(report["errors"], indent=2))}</pre>'
        '<h2>Limitations</h2><ul>' +
        "".join(f"<li>{esc(v)}</li>" for v in report["limitations"]) +
        '</ul></body></html>')
    (out / "report.html").write_text(document, encoding="utf-8")
