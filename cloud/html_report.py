"""Render findings as a self-contained HTML dashboard report."""
from __future__ import annotations

from collections import Counter
from typing import TextIO

from cloud.core import Finding, Status

_TEMPLATE = """\
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Automation Hardening Report</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:system-ui,-apple-system,sans-serif;background:#f8f9fa;color:#1a1a2e;padding:2rem}}
h1{{margin-bottom:.5rem}}
.meta{{color:#666;margin-bottom:2rem}}
.stats{{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:2rem}}
.stat{{background:#fff;border-radius:8px;padding:1rem 1.5rem;box-shadow:0 1px 3px rgba(0,0,0,.1)}}
.stat strong{{display:block;font-size:2rem}}
.stat.pass strong{{color:#16a34a}}
.stat.fail strong{{color:#dc2626}}
.stat.error strong{{color:#ea580c}}
.stat.skip strong{{color:#6b7280}}
table{{width:100%;border-collapse:collapse;background:#fff;
  border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.1)}}
th,td{{padding:.75rem 1rem;text-align:left;border-bottom:1px solid #e5e7eb}}
th{{background:#f3f4f6;font-weight:600}}
.badge{{display:inline-block;padding:.2rem .6rem;border-radius:4px;
  font-size:.75rem;font-weight:600;text-transform:uppercase}}
.badge-pass{{background:#dcfce7;color:#166534}}
.badge-fail{{background:#fee2e2;color:#991b1b}}
.badge-error{{background:#ffedd5;color:#9a3412}}
.badge-skip{{background:#f3f4f6;color:#374151}}
.badge-manual{{background:#fef9c3;color:#854d0e}}
</style>
</head>
<body>
<h1>Automation Hardening Report</h1>
<p class="meta">{meta}</p>
<div class="stats">
<div class="stat pass"><strong>{pass_count}</strong><span>Pass</span></div>
<div class="stat fail"><strong>{fail_count}</strong><span>Fail</span></div>
<div class="stat error"><strong>{error_count}</strong><span>Error</span></div>
<div class="stat skip"><strong>{skip_count}</strong><span>Skip/Manual</span></div>
</div>
<table>
<thead><tr><th>Status</th><th>Control</th><th>Resource</th><th>Evidence</th><th>Remediation</th></tr></thead>
<tbody>
{rows}
</tbody>
</table>
</body>
</html>
"""


def _badge(status: Status) -> str:
    return f'<span class="badge badge-{status.value}">{status.value}</span>'


def _esc(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def render_html(findings: list[Finding], stream: TextIO) -> None:
    """Render findings as a self-contained HTML dashboard."""
    counts = Counter(f.status for f in findings)
    rows = []
    for f in findings:
        rows.append(
            f"<tr><td>{_badge(f.status)}</td>"
            f"<td>{_esc(f.control_id)}</td>"
            f"<td>{_esc(f.resource)}</td>"
            f"<td>{_esc(f.evidence[:120])}</td>"
            f"<td>{_esc(f.remediation[:120])}</td></tr>"
        )
    html = _TEMPLATE.format(
        meta=f"{len(findings)} findings across {len(set(f.control_id for f in findings))} controls",
        pass_count=counts.get(Status.PASS, 0),
        fail_count=counts.get(Status.FAIL, 0),
        error_count=counts.get(Status.ERROR, 0),
        skip_count=counts.get(Status.SKIP, 0) + counts.get(Status.MANUAL, 0),
        rows="\n".join(rows),
    )
    stream.write(html)
