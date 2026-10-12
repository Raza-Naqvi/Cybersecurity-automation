"""Turn a check's findings into a JSON + HTML report under reports/."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Template

REPORTS_DIR = Path(__file__).resolve().parents[3] / "reports"

_HTML_TEMPLATE = Template(
    """<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>{{ title }}</title>
  <style>
    body { font-family: -apple-system, sans-serif; margin: 2rem; color: #1a1a1a; }
    h1 { font-size: 1.4rem; }
    .meta { color: #666; margin-bottom: 1.5rem; }
    section { margin-bottom: 1.5rem; }
    .flag { color: #b00020; font-weight: 600; }
    .ok { color: #1a7f37; }
    pre { background: #f6f6f6; padding: 0.75rem; overflow-x: auto; }
  </style>
</head>
<body>
  <h1>{{ title }}</h1>
  <div class="meta">Target: {{ target }} &middot; Generated: {{ generated_at }}</div>
  {% for section in sections %}
  <section>
    <h2 class="{{ 'flag' if section.flagged else 'ok' }}">{{ section.name }}</h2>
    <pre>{{ section.detail }}</pre>
  </section>
  {% endfor %}
</body>
</html>
"""
)


@dataclass(frozen=True)
class Finding:
    name: str
    flagged: bool
    detail: str


@dataclass(frozen=True)
class Report:
    title: str
    target: str
    generated_at: str
    findings: tuple[Finding, ...]

    @property
    def has_flags(self) -> bool:
        return any(finding.flagged for finding in self.findings)


def build_report(title: str, target: str, findings: list[Finding]) -> Report:
    return Report(
        title=title,
        target=target,
        generated_at=datetime.now(timezone.utc).isoformat(),
        findings=tuple(findings),
    )


def _slug(value: str) -> str:
    return "".join(ch if ch.isalnum() else "-" for ch in value.lower()).strip("-")


def write_report(report: Report, output_dir: Path | None = None) -> tuple[Path, Path]:
    """Write the report as both JSON and HTML. Returns (json_path, html_path)."""
    out_dir = output_dir or REPORTS_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base_name = f"{_slug(report.title)}_{_slug(report.target)}_{stamp}"

    json_path = out_dir / f"{base_name}.json"
    json_path.write_text(
        json.dumps(
            {
                "title": report.title,
                "target": report.target,
                "generated_at": report.generated_at,
                "findings": [finding.__dict__ for finding in report.findings],
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    html_path = out_dir / f"{base_name}.html"
    html_path.write_text(
        _HTML_TEMPLATE.render(
            title=report.title,
            target=report.target,
            generated_at=report.generated_at,
            sections=[finding.__dict__ for finding in report.findings],
        ),
        encoding="utf-8",
    )
    return json_path, html_path
