from __future__ import annotations

from pathlib import Path

CSS = """
body { font-family: system-ui, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
nav { background: #1a1a2e; padding: 12px 20px; margin: -20px -20px 20px; }
nav a { color: #e0e0e0; margin-right: 16px; text-decoration: none; }
nav a:hover { color: #fff; }
.card { background: #fff; border-radius: 8px; padding: 16px; margin-bottom: 12px;
         box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; }
.badge-fail { background: #fee; color: #c00; }
.badge-pass { background: #efe; color: #060; }
h1 { color: #1a1a2e; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 8px; border-bottom: 1px solid #eee; }
"""

NAV = """<nav>
<a href="index.html">Overview</a>
<a href="controls.html">Controls</a>
<a href="providers.html">Providers</a>
</nav>"""


def _wrap(title: str, body: str) -> str:
    return (
        f"<!DOCTYPE html><html><head><meta charset='utf-8'>"
        f"<title>{title}</title><style>{CSS}</style></head>"
        f"<body>{NAV}{body}</body></html>"
    )


def _gen_index(findings: list[dict]) -> str:
    total = len(findings)
    fails = sum(1 for f in findings if f.get("status") == "FAIL")
    passes = total - fails
    body = (
        f"<h1>Automation Hardening Dashboard</h1>"
        f"<div class='card'><h2>Summary</h2>"
        f"<p>Total: {total} | "
        f"<span class='badge badge-pass'>PASS: {passes}</span> | "
        f"<span class='badge badge-fail'>FAIL: {fails}</span></p></div>"
    )
    return _wrap("Dashboard", body)


def _gen_controls(findings: list[dict]) -> str:
    rows = ""
    for f in findings:
        status = f.get("status", "UNKNOWN")
        cls = "badge-fail" if status == "FAIL" else "badge-pass"
        rows += (
            f"<tr><td>{f.get('control', '')}</td>"
            f"<td><span class='badge {cls}'>{status}</span></td>"
            f"<td>{f.get('message', '')}</td></tr>"
        )
    body = (
        f"<h1>Controls</h1><div class='card'><table>"
        f"<tr><th>Control</th><th>Status</th><th>Message</th></tr>"
        f"{rows}</table></div>"
    )
    return _wrap("Controls", body)


def _gen_providers(findings: list[dict]) -> str:
    providers: dict[str, list[dict]] = {}
    for f in findings:
        p = f.get("provider", "unknown")
        providers.setdefault(p, []).append(f)

    body = "<h1>Providers</h1>"
    for name, items in sorted(providers.items()):
        fails = sum(1 for i in items if i.get("status") == "FAIL")
        body += (
            f"<div class='card'><h2>{name}</h2>"
            f"<p>Checks: {len(items)} | "
            f"<span class='badge badge-fail'>FAIL: {fails}</span></p></div>"
        )
    return _wrap("Providers", body)


def generate_dashboard(findings, output_dir) -> None:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "index.html").write_text(_gen_index(findings))
    (out / "controls.html").write_text(_gen_controls(findings))
    (out / "providers.html").write_text(_gen_providers(findings))
