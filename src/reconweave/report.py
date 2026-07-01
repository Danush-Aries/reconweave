"""Self-contained offline HTML report.

Renders a force-directed graph as INLINE SVG (layout computed with
networkx spring_layout, deterministic seed), a risk panel, and a findings
list. No CDN, no external assets — the file opens offline in any browser.
"""

from __future__ import annotations

import html
import json
from typing import Any, Dict, List, Tuple

import networkx as nx

from .engine import ScanResult
from .entities import NodeType

_TYPE_COLORS = {
    NodeType.DOMAIN.value: "#4f8cff",
    NodeType.SUBDOMAIN.value: "#7aa8ff",
    NodeType.IP.value: "#00c2a8",
    NodeType.CIDR.value: "#3ad0c0",
    NodeType.EMAIL.value: "#ff8a3d",
    NodeType.USERNAME.value: "#ffcf3d",
    NodeType.PERSON.value: "#e15bff",
    NodeType.ORG.value: "#ff5b7f",
    NodeType.PHONE.value: "#9d7bff",
    NodeType.ASN.value: "#6bd968",
    NodeType.CRYPTO_WALLET.value: "#f2c14e",
    NodeType.SOCIAL_PROFILE.value: "#4de1ff",
}
_BAND_COLORS = {
    "critical": "#ff3b57", "high": "#ff7a3d", "medium": "#ffcf3d",
    "low": "#6bd968", "minimal": "#4de1ff",
}
_W, _H = 900, 560


def _layout(g: nx.MultiDiGraph) -> Dict[str, Tuple[float, float]]:
    if g.number_of_nodes() == 0:
        return {}
    simple = nx.Graph()
    simple.add_nodes_from(g.nodes())
    simple.add_edges_from((u, v) for u, v, _ in g.edges(keys=True))
    try:
        pos = nx.spring_layout(simple, seed=42, k=1.4, iterations=80)
    except Exception:  # pragma: no cover
        pos = {n: (0.0, 0.0) for n in simple.nodes()}
    xs = [p[0] for p in pos.values()] or [0]
    ys = [p[1] for p in pos.values()] or [0]
    minx, maxx = min(xs), max(xs)
    miny, maxy = min(ys), max(ys)
    pad = 60
    scaled = {}
    for n, (x, y) in pos.items():
        sx = pad + (x - minx) / (maxx - minx + 1e-9) * (_W - 2 * pad)
        sy = pad + (y - miny) / (maxy - miny + 1e-9) * (_H - 2 * pad)
        scaled[n] = (sx, sy)
    return scaled


def _svg(result: ScanResult) -> str:
    g = result.graph.to_networkx()
    pos = _layout(g)
    parts = [f'<svg viewBox="0 0 {_W} {_H}" xmlns="http://www.w3.org/2000/svg" '
             f'class="graph" role="img" aria-label="entity graph">']
    # edges
    for u, v, _ in g.edges(keys=True):
        if u not in pos or v not in pos:
            continue
        x1, y1 = pos[u]
        x2, y2 = pos[v]
        parts.append(f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" '
                     f'stroke="#2b3a5a" stroke-width="1" opacity="0.7"/>')
    # nodes
    for nid, data in g.nodes(data=True):
        if nid not in pos:
            continue
        x, y = pos[nid]
        color = _TYPE_COLORS.get(data.get("type"), "#9aa4bf")
        conf = float(data.get("confidence", 0.5))
        r = 6 + conf * 8
        seed_flag = data.get("attributes", {}).get("is_seed")
        stroke = "#ffffff" if seed_flag else "#0b1120"
        sw = 3 if seed_flag else 1
        label = html.escape(str(data.get("value", ""))[:28])
        title = html.escape(f"{data.get('type')}: {data.get('value')} "
                            f"(conf {conf:.2f})")
        parts.append(
            f'<g><circle cx="{x:.1f}" cy="{y:.1f}" r="{r:.1f}" fill="{color}" '
            f'stroke="{stroke}" stroke-width="{sw}"><title>{title}</title></circle>'
            f'<text x="{x:.1f}" y="{y - r - 3:.1f}" font-size="9" fill="#c9d4ee" '
            f'text-anchor="middle">{label}</text></g>')
    parts.append("</svg>")
    return "".join(parts)


def _legend() -> str:
    items = []
    for t, c in _TYPE_COLORS.items():
        items.append(f'<span class="chip"><span class="dot" style="background:{c}">'
                     f'</span>{html.escape(t)}</span>')
    return '<div class="legend">' + "".join(items) + "</div>"


def _risk_panel(result: ScanResult) -> str:
    risk = result.risk
    color = _BAND_COLORS.get(risk.band, "#9aa4bf")
    rows = []
    for f in risk.factors:
        pct = min(100, int(f.points))
        rows.append(
            f'<div class="factor"><div class="factor-h"><span>{html.escape(f.name)}</span>'
            f'<span class="pts">+{f.points:.0f}</span></div>'
            f'<div class="bar"><div class="bar-fill" style="width:{pct}%;'
            f'background:{color}"></div></div>'
            f'<div class="detail">{html.escape(f.detail)}</div></div>')
    if not rows:
        rows.append('<div class="detail">No exposure factors detected.</div>')
    return (
        f'<div class="panel"><h2>Exposure Risk</h2>'
        f'<div class="score" style="color:{color}">{risk.score}<span>/100</span></div>'
        f'<div class="band" style="background:{color}">{html.escape(risk.band.upper())}</div>'
        + "".join(rows) + "</div>")


def _findings(result: ScanResult) -> str:
    lines: List[str] = []
    stats = result.graph.stats()
    for t, n in sorted(stats["nodes_by_type"].items()):
        lines.append(f"{n} × {html.escape(t)}")
    corr = result.correlations[:20]
    corr_html = "".join(
        f'<li><b>{html.escape(c.kind)}</b>: {html.escape(c.rationale)} '
        f'<span class="conf">({c.confidence:.2f})</span></li>' for c in corr)
    if not corr_html:
        corr_html = "<li>No cross-source correlations.</li>"
    return (
        f'<div class="panel"><h2>Findings</h2>'
        f'<p class="muted">{html.escape(", ".join(lines))}</p>'
        f'<h3>Correlations ({len(result.correlations)})</h3>'
        f'<ul class="findings">{corr_html}</ul></div>')


_CSS = """
*{box-sizing:border-box} body{margin:0;background:#0b1120;color:#e6ecff;
font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
header{padding:20px 28px;border-bottom:1px solid #1c2740;
background:linear-gradient(90deg,#111a30,#0b1120)}
header h1{margin:0;font-size:22px;letter-spacing:.5px}
header .sub{color:#8ea0c9;font-size:13px;margin-top:4px}
.wrap{display:grid;grid-template-columns:2fr 1fr;gap:18px;padding:22px 28px}
.card{background:#0f1830;border:1px solid #1c2740;border-radius:12px;padding:16px}
.graph{width:100%;height:auto;background:#0a1022;border-radius:10px}
.panel{background:#0f1830;border:1px solid #1c2740;border-radius:12px;
padding:16px;margin-bottom:18px}
.panel h2{margin:0 0 12px;font-size:16px;color:#cdd8f5}
.score{font-size:52px;font-weight:800;line-height:1}
.score span{font-size:18px;color:#6b7ba3;font-weight:500}
.band{display:inline-block;margin:8px 0 14px;padding:3px 10px;border-radius:20px;
color:#0b1120;font-weight:700;font-size:12px}
.factor{margin-bottom:12px}
.factor-h{display:flex;justify-content:space-between;font-size:13px;margin-bottom:4px}
.pts{color:#ff9a6b;font-weight:700}
.bar{height:7px;background:#182238;border-radius:6px;overflow:hidden}
.bar-fill{height:100%}
.detail{font-size:11px;color:#8ea0c9;margin-top:3px}
.legend{display:flex;flex-wrap:wrap;gap:10px;margin-top:12px}
.chip{font-size:11px;color:#b9c6e8;display:flex;align-items:center;gap:5px}
.dot{width:10px;height:10px;border-radius:50%;display:inline-block}
.findings{margin:6px 0 0;padding-left:18px;font-size:13px;line-height:1.6}
.conf{color:#6b7ba3}
.muted{color:#8ea0c9;font-size:13px}
footer{padding:14px 28px;color:#5f6f95;font-size:12px;border-top:1px solid #1c2740}
@media(max-width:820px){.wrap{grid-template-columns:1fr}}
"""


def render_html(result: ScanResult) -> str:
    seed = result.seed
    meta = (f"seed: {html.escape(seed.value)} · type: {seed.type.value} · "
            f"{result.graph.node_count} nodes / {result.graph.edge_count} edges · "
            f"{len(result.collectors_run)} collectors · "
            f"{'LIVE' if result.live else 'OFFLINE (mock)'}")
    body = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>reconweave report — {html.escape(seed.value)}</title>
<style>{_CSS}</style></head>
<body>
<header>
  <h1>reconweave &middot; OSINT correlation report</h1>
  <div class="sub">{meta}</div>
</header>
<div class="wrap">
  <div>
    <div class="card">{_svg(result)}{_legend()}</div>
  </div>
  <div>
    {_risk_panel(result)}
    {_findings(result)}
  </div>
</div>
<footer>Generated by reconweave — offline synthetic data (deterministic).
All entities are mock unless run with --live. Passive OSINT only.</footer>
</body></html>"""
    return body


def write_report(result: ScanResult, path: str) -> str:
    html_str = render_html(result)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html_str)
    return path


__all__ = ["render_html", "write_report"]
