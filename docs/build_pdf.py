#!/usr/bin/env python3
"""Regenerate docs/UniPE_Team_Guide.pdf from docs/TEAM_GUIDE.md.

Requires: pip install markdown weasyprint  (unipe-ai/.venv already has them if used before)
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MD = ROOT / "docs" / "TEAM_GUIDE.md"
PDF = ROOT / "docs" / "UniPE_Team_Guide.pdf"


def main() -> int:
    try:
        import markdown
        from weasyprint import CSS, HTML
    except ImportError:
        print("Install deps: pip install markdown weasyprint", file=sys.stderr)
        return 1

    md = MD.read_text(encoding="utf-8")
    body = markdown.markdown(
        md,
        extensions=[
            "markdown.extensions.tables",
            "markdown.extensions.fenced_code",
            "markdown.extensions.toc",
            "markdown.extensions.sane_lists",
            "markdown.extensions.nl2br",
        ],
    )
    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/>
<title>UniPE — Comprehensive Team Technical Guide</title></head><body>
<section class="title-page">
  <p class="eyebrow">Team technical documentation</p>
  <h1 class="doc-title">UniPE</h1>
  <p class="subtitle">AI-Based Detection of Cyber Threats<br/>in Unidirectional IP Traffic</p>
  <p class="meta">Comprehensive technical guide for teammates</p>
  <p class="meta-small">Source: <code>docs/TEAM_GUIDE.md</code></p>
</section>
{body}
</body></html>"""
    css_path = Path(__file__).with_name("team_guide.css")
    styles = [CSS(filename=str(css_path))] if css_path.exists() else []
    if not styles:
        # fallback minimal if css file missing
        styles = [CSS(string="@page { size: A4; margin: 2cm; @bottom-center { content: counter(page); } }")]
    HTML(string=html, base_url=str(MD.parent)).write_pdf(PDF, stylesheets=styles)
    print(f"wrote {PDF} ({PDF.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
