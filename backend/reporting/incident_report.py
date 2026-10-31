"""
incident_report.py — ChainSight AI
Produces an analyst-readable HTML report and a structured JSON payload.
The HTML is print/PDF-optimised using inline CSS and @media print rules.
This system is RULE-BASED — no AI or ML inference is made.
"""

from __future__ import annotations

import json
from html import escape
from datetime import datetime, timezone
from typing import Any


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SEV_COLORS = {
    "critical": ("#c0392b", "#fdf0ee"),
    "high":     ("#d35400", "#fef3ec"),
    "medium":   ("#b7860b", "#fefbe6"),
    "low":      ("#27ae60", "#edfaf2"),
}

def _sev_badge(sev: str) -> str:
    fg, bg = _SEV_COLORS.get(sev.lower(), ("#555", "#f5f5f5"))
    label = escape(sev.upper())
    return (
        f'<span style="display:inline-block;padding:2px 9px;border-radius:999px;'
        f'font-size:11px;font-weight:700;letter-spacing:.5px;'
        f'background:{bg};color:{fg};border:1px solid {fg}40">{label}</span>'
    )


def _fmt_ts(ts: Any) -> str:
    """Return a human-readable timestamp from ISO string, epoch float, or None."""
    if not ts:
        return "—"
    try:
        if isinstance(ts, (int, float)):
            dt = datetime.fromtimestamp(float(ts), tz=timezone.utc)
        else:
            dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(ts)


def _esc(val: Any) -> str:
    return escape(str(val)) if val is not None else "—"


def _evidence_table(ev: dict) -> str:
    if not ev:
        return "<em>No evidence fields</em>"
    rows = ""
    for k, v in ev.items():
        rows += (
            f'<tr><td style="color:#6b7a8d;padding:4px 10px 4px 0;'
            f'white-space:nowrap;font-weight:500">{_esc(k)}</td>'
            f'<td style="color:#2c3e50;padding:4px 0;word-break:break-all">'
            f'{_esc(v)}</td></tr>'
        )
    return f'<table style="font-size:12px;border-collapse:collapse;width:100%">{rows}</table>'


def _inline_css() -> str:
    return """
<style>
  *{box-sizing:border-box}
  body{font-family:'Segoe UI',Arial,sans-serif;font-size:14px;color:#1a2d4a;
       background:#f7f9fc;margin:0;padding:0}
  .page{max-width:960px;margin:0 auto;padding:40px 48px 64px}
  h1{font-size:24px;color:#0d2540;margin:0 0 4px}
  h2{font-size:15px;color:#1a2d4a;margin:32px 0 10px;padding-bottom:6px;
     border-bottom:2px solid #d0dde8}
  h3{font-size:13px;color:#2d4a6a;margin:14px 0 6px}
  .header-block{background:#0d2540;color:#e8f4fb;padding:28px 32px;
                border-radius:10px;margin-bottom:28px}
  .header-block h1{color:#fff;font-size:22px}
  .header-block p{color:#a8d0e8;margin:6px 0 0;font-size:13px}
  .meta{display:flex;flex-wrap:wrap;gap:18px;margin-top:16px}
  .meta-item{background:rgba(255,255,255,.08);border-radius:7px;
             padding:10px 16px;min-width:150px}
  .meta-item label{display:block;font-size:10px;color:#7fb8d8;
                   letter-spacing:.8px;text-transform:uppercase;margin-bottom:4px}
  .meta-item span{font-size:16px;font-weight:700;color:#e0f3ff}
  .story{background:#fff;border-left:4px solid #2980b9;border-radius:0 8px 8px 0;
         padding:16px 20px;margin:0 0 8px;color:#1a2d4a;line-height:1.7;
         font-size:13.5px}
  .card{background:#fff;border:1px solid #dde5ef;border-radius:8px;
        padding:16px 18px;margin-bottom:12px}
  .card-header{display:flex;align-items:center;gap:10px;margin-bottom:10px}
  .card-title{font-weight:700;color:#1a2d4a;font-size:13px}
  .card-sub{font-size:11px;color:#6b7a8d}
  .ev-row{font-size:12px;color:#2c3e50}
  table.tl{width:100%;border-collapse:collapse;font-size:12px}
  table.tl th{text-align:left;color:#6b7a8d;font-weight:600;
              padding:8px 10px;border-bottom:2px solid #e0e8f0;
              background:#f2f6fa}
  table.tl td{padding:8px 10px;border-bottom:1px solid #edf1f7;
              vertical-align:top}
  table.tl tr:hover td{background:#f8fbff}
  .mitre-id{font-family:monospace;background:#eef2ff;color:#2c49a6;
            padding:2px 6px;border-radius:4px;font-size:11px}
  .pill{display:inline-block;padding:2px 9px;border-radius:999px;
        font-size:10px;font-weight:700;letter-spacing:.5px;
        text-transform:uppercase}
  .c-critical{background:#fdf0ee;color:#c0392b;border:1px solid #c0392b40}
  .c-high{background:#fef3ec;color:#d35400;border:1px solid #d3540040}
  .c-medium{background:#fefbe6;color:#b7860b;border:1px solid #b7860b40}
  .c-low{background:#edfaf2;color:#27ae60;border:1px solid #27ae6040}
  .reach-item{background:#fffdf0;border:1px solid #f0e68c;border-radius:6px;
              padding:10px 14px;margin-bottom:8px;font-size:12px}
  .action-item{display:flex;gap:10px;align-items:flex-start;
               padding:8px 0;border-bottom:1px solid #edf1f7;font-size:13px}
  .action-num{background:#0d2540;color:#fff;border-radius:50%;
              min-width:22px;height:22px;display:flex;align-items:center;
              justify-content:center;font-size:11px;font-weight:700;
              flex-shrink:0;margin-top:1px}
  .disclaimer{background:#fff8e6;border:1px solid #f0c040;border-radius:6px;
              padding:10px 14px;font-size:12px;color:#7a5c00;margin-top:24px}
  .no-print{margin-top:28px}
  .btn{display:inline-block;padding:9px 18px;background:#0d2540;color:#fff;
       border-radius:7px;font-size:13px;text-decoration:none;margin-right:8px;
       cursor:pointer;border:0}
  @media print{
    body{background:#fff}
    .no-print{display:none!important}
    .page{padding:20px 28px}
    .header-block{-webkit-print-color-adjust:exact;print-color-adjust:exact;
                  background:#0d2540!important;color:#fff!important}
    .meta-item{-webkit-print-color-adjust:exact;print-color-adjust:exact}
    .pill,.c-critical,.c-high,.c-medium,.c-low{
      -webkit-print-color-adjust:exact;print-color-adjust:exact}
    .mitre-id{-webkit-print-color-adjust:exact;print-color-adjust:exact}
  }
</style>
"""


# ---------------------------------------------------------------------------
# Narrative / story builder
# ---------------------------------------------------------------------------

def _build_story(incident: Any, events: list, detections: list) -> str:
    inc = incident.model_dump(mode="json")
    hosts = inc.get("hosts") or []
    users = inc.get("users") or []
    techniques = inc.get("techniques") or []
    tactics = sorted({d.get("tactic", "") for d in [dd.model_dump() for dd in detections] if d.get("tactic")})
    first_ts = _fmt_ts(inc.get("first_observed"))
    last_ts = _fmt_ts(inc.get("last_observed"))
    n_det = len(detections)
    n_ev = len(events)
    risk_label = inc.get("risk_label", "unknown").upper()
    risk_score = inc.get("risk_score", 0)

    host_str = ", ".join(_esc(h) for h in hosts[:4]) or "unknown hosts"
    if len(hosts) > 4:
        host_str += f" and {len(hosts)-4} more"
    user_str = ", ".join(_esc(u) for u in users[:3]) or "unknown users"
    tactic_str = ", ".join(_esc(t) for t in tactics) if tactics else "unknown tactics"
    tech_str = ", ".join(_esc(t) for t in techniques[:5]) if techniques else "none mapped"

    para1 = (
        f"Between <strong>{_esc(first_ts)}</strong> and <strong>{_esc(last_ts)}</strong>, "
        f"ChainSight's rule-based detection engine recorded <strong>{n_det} suspicious detection(s)</strong> "
        f"across <strong>{n_ev} event(s)</strong> on {host_str}. "
        f"Activity was attributed to account(s): <strong>{user_str}</strong>."
    )
    para2 = (
        f"Evidence indicates tactics consistent with <strong>{tactic_str}</strong>. "
        f"MITRE ATT&amp;CK techniques observed include: "
        f"<code style='font-size:12px'>{tech_str}</code>. "
        f"This investigation carries a <strong style='color:{'#c0392b' if risk_label=='CRITICAL' else '#d35400' if risk_label=='HIGH' else '#b7860b'}'>"
        f"{_esc(risk_label)} risk score of {risk_score}/100</strong>."
    )
    para3 = (
        "<em style='color:#6b7a8d'>Note: This report documents potential attack-chain indicators "
        "reconstructed from rule-based detection. Evidence must be validated against source telemetry "
        "before any containment action is taken. Inferred paths are investigative leads, not confirmed compromises.</em>"
    )
    return f'<div class="story"><p>{para1}</p><p>{para2}</p><p style="margin-top:10px">{para3}</p></div>'


# ---------------------------------------------------------------------------
# Main report() function
# ---------------------------------------------------------------------------

def report(incident, events, detections, reachability):
    """
    Returns (payload: dict, html: str).
    payload — structured JSON-serialisable data (format=json endpoint).
    html    — self-contained analyst HTML report (format=html endpoint).
    """

    # --- JSON payload (unchanged contract) ---
    payload = {
        "incident": incident.model_dump(mode="json"),
        "timeline": [e.model_dump(mode="json", exclude={"raw_event"}) for e in events],
        "detections": [d.model_dump() for d in detections],
        "potential_reachability": reachability,
        "recommended_steps": [
            "Validate evidence against source telemetry and asset context.",
            "Contain only after analyst review and according to incident response policy.",
            "Review related authentication, process, and network activity in the stated time window.",
            "Check for lateral movement from identified source IPs to other internal hosts.",
            "Audit privileged account activity in the observation window.",
        ],
    }

    # --- HTML report ---
    inc = incident.model_dump(mode="json")
    incident_id = inc.get("incident_id", "unknown")
    risk_label = inc.get("risk_label", "unknown")
    risk_score = inc.get("risk_score", 0)
    first_ts = _fmt_ts(inc.get("first_observed"))
    last_ts = _fmt_ts(inc.get("last_observed"))
    generated_at = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    hosts = inc.get("hosts") or []
    users = inc.get("users") or []

    risk_col = _SEV_COLORS.get(risk_label.lower(), ("#555", "#eee"))[0]

    # Risk badge in header
    header_badge = (
        f'<span style="display:inline-block;padding:4px 14px;border-radius:999px;'
        f'font-size:13px;font-weight:800;letter-spacing:.5px;'
        f'background:rgba(255,255,255,.12);color:#fff;border:1px solid rgba(255,255,255,.3)">'
        f'{_esc(risk_label.upper())} &nbsp;{risk_score}/100</span>'
    )

    # Meta cards
    meta_cards = "".join([
        f'<div class="meta-item"><label>First observed</label><span style="font-size:12px;font-weight:400">{_esc(first_ts)}</span></div>',
        f'<div class="meta-item"><label>Last observed</label><span style="font-size:12px;font-weight:400">{_esc(last_ts)}</span></div>',
        f'<div class="meta-item"><label>Detections</label><span>{len(detections)}</span></div>',
        f'<div class="meta-item"><label>Events</label><span>{len(events)}</span></div>',
        f'<div class="meta-item"><label>Hosts</label><span>{len(hosts)}</span></div>',
        f'<div class="meta-item"><label>Confidence</label><span>{round(inc.get("confidence", 0)*100)}%</span></div>',
    ])

    # ---- Executive Summary ----
    story_html = _build_story(incident, events, detections)

    # ---- Correlation reasons ----
    corr_reasons = inc.get("correlation_reasons") or []
    risk_reasons = inc.get("risk_reasons") or []
    grouping_html = ""
    if corr_reasons:
        items = "".join(f'<li style="margin-bottom:5px">{_esc(r)}</li>' for r in corr_reasons)
        grouping_html += f'<h3 style="margin-top:16px;color:#2d4a6a">Why events were grouped</h3><ul style="margin:0;padding-left:18px;font-size:13px;color:#2c3e50">{items}</ul>'
    if risk_reasons:
        items = "".join(f'<li style="margin-bottom:5px">{_esc(r)}</li>' for r in risk_reasons)
        grouping_html += f'<h3 style="margin-top:14px;color:#2d4a6a">Risk scoring factors</h3><ul style="margin:0;padding-left:18px;font-size:13px;color:#2c3e50">{items}</ul>'

    # ---- Chronological timeline ----
    tl_rows = ""
    for ev in events:
        ed = ev.model_dump(mode="json", exclude={"raw_event"})
        sev = (ed.get("severity") or "low").lower()
        badge_cls = f"pill c-{sev}"
        tech_id = _esc(ed.get("technique_id") or "")
        tech_name = _esc(ed.get("technique_name") or "")
        mitre_cell = f'<span class="mitre-id">{tech_id}</span> {tech_name}' if tech_id and tech_id != "—" else "—"
        tl_rows += (
            f'<tr>'
            f'<td style="white-space:nowrap;color:#4a5a6a">{_esc(_fmt_ts(ed.get("timestamp")))}</td>'
            f'<td><span class="{badge_cls}">{_esc(sev)}</span></td>'
            f'<td><strong style="color:#1a2d4a">{_esc(ed.get("action") or "")}</strong></td>'
            f'<td style="color:#4a5a6a">{_esc(ed.get("host") or "—")}</td>'
            f'<td style="color:#4a5a6a">{_esc(ed.get("user") or "—")}</td>'
            f'<td style="font-family:monospace;font-size:11px;color:#5a6a7a">{_esc(ed.get("process_name") or "—")}</td>'
            f'<td>{mitre_cell}</td>'
            f'</tr>'
        )
    timeline_section = (
        '<table class="tl"><thead><tr>'
        '<th>Timestamp</th><th>Severity</th><th>Action</th>'
        '<th>Host</th><th>User</th><th>Process</th><th>MITRE Technique</th>'
        '</tr></thead><tbody>'
        + (tl_rows or '<tr><td colspan="7" style="color:#999;text-align:center">No timeline events</td></tr>')
        + '</tbody></table>'
    )

    # ---- Detection evidence cards ----
    det_cards = ""
    for d in detections:
        dd = d.model_dump()
        sev = (dd.get("severity") or "low").lower()
        ev_dict = dd.get("evidence") or {}
        # Convert evidence to dict if it's a string
        if isinstance(ev_dict, str):
            try:
                ev_dict = json.loads(ev_dict)
            except Exception:
                ev_dict = {"raw": ev_dict}
        confidence_pct = round((dd.get("confidence") or 0) * 100)
        tech_id = dd.get("technique_id") or ""
        det_cards += f"""
<div class="card">
  <div class="card-header">
    <span class="pill c-{sev}">{_esc(sev)}</span>
    <div>
      <div class="card-title">{_esc(dd.get('rule_name') or dd.get('rule_id') or 'Unknown rule')}</div>
      <div class="card-sub">Rule ID: {_esc(dd.get('rule_id') or '—')} &nbsp;·&nbsp;
        Tactic: {_esc(dd.get('tactic') or '—')} &nbsp;·&nbsp;
        Confidence: <strong style="color:#1a2d4a">{confidence_pct}%</strong>
        {f'&nbsp;·&nbsp; <span class="mitre-id">{_esc(tech_id)}</span> {_esc(dd.get("technique_name") or "")}' if tech_id else ''}
      </div>
    </div>
  </div>
  <h3 style="font-size:11px;color:#6b7a8d;text-transform:uppercase;letter-spacing:.5px;margin:0 0 6px">Evidence</h3>
  {_evidence_table(ev_dict)}
</div>"""

    if not det_cards:
        det_cards = '<p style="color:#999">No detection details available.</p>'

    # ---- MITRE ATT&CK coverage ----
    mitre_map: dict[str, dict] = {}
    for d in detections:
        dd = d.model_dump()
        tid = dd.get("technique_id") or ""
        if not tid:
            continue
        if tid not in mitre_map:
            mitre_map[tid] = {
                "technique_id": tid,
                "technique_name": dd.get("technique_name") or "",
                "tactic": dd.get("tactic") or "",
                "count": 0,
            }
        mitre_map[tid]["count"] += 1

    mitre_rows = ""
    for m in sorted(mitre_map.values(), key=lambda x: x["technique_id"]):
        mitre_rows += (
            f'<tr>'
            f'<td><span class="mitre-id">{_esc(m["technique_id"])}</span></td>'
            f'<td style="color:#2c3e50">{_esc(m["technique_name"])}</td>'
            f'<td style="color:#4a5a6a">{_esc(m["tactic"])}</td>'
            f'<td style="text-align:center;font-weight:700;color:#1a2d4a">{m["count"]}</td>'
            f'</tr>'
        )
    if not mitre_rows:
        mitre_rows = '<tr><td colspan="4" style="color:#999;text-align:center">No MITRE techniques mapped</td></tr>'

    mitre_section = (
        '<table class="tl"><thead><tr>'
        '<th>Technique ID</th><th>Name</th><th>Tactic</th><th>Detections</th>'
        '</tr></thead><tbody>' + mitre_rows + '</tbody></table>'
    )

    # ---- Potential reachability ----
    reach_html = ""
    if reachability:
        for r in reachability[:10]:
            path_nodes = " → ".join(_esc(str(p)) for p in (r.get("path") or []))
            score_str = f'{round(r.get("score", 0) * 100)}%' if r.get("score") is not None else ""
            score_suffix = (
                f' &nbsp;<span style="color:#7a5c00">({score_str} reachability)</span>'
                if score_str else ""
            )
            reach_html += (
                f'<div class="reach-item">'
                f'<strong style="color:#7a5c00">Potential path:</strong> {path_nodes}'
                f'{score_suffix}'
                f'</div>'
            )

    reach_section = reach_html or '<p style="color:#999">No potential reachability paths computed.</p>'

    # ---- Recommended actions ----
    steps = payload["recommended_steps"]
    actions_html = "".join(
        f'<div class="action-item">'
        f'<div class="action-num">{i+1}</div>'
        f'<div>{_esc(s)}</div>'
        f'</div>'
        for i, s in enumerate(steps)
    )

    # ---- Assemble full HTML ----
    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ChainSight — Incident Report {_esc(incident_id)}</title>
{_inline_css()}
</head>
<body>
<div class="page">

  <!-- Header block -->
  <div class="header-block">
    <p style="font-size:11px;color:#7fb8d8;letter-spacing:1px;text-transform:uppercase;margin:0 0 6px">
      ChainSight AI &nbsp;·&nbsp; Rule-Based Security Investigation Report
    </p>
    <h1>Incident {_esc(incident_id)}</h1>
    <p style="margin:8px 0 16px">{header_badge}</p>
    <div class="meta">{meta_cards}</div>
    <p style="margin:14px 0 0;font-size:11px;color:#7fb8d8">
      Generated: {_esc(generated_at)} &nbsp;·&nbsp;
      Hosts: {_esc(', '.join(hosts[:3]) + (f' +{len(hosts)-3} more' if len(hosts)>3 else '') or '—')} &nbsp;·&nbsp;
      Accounts: {_esc(', '.join(users[:3]) + (f' +{len(users)-3} more' if len(users)>3 else '') or '—')}
    </p>
  </div>

  <!-- Executive Summary -->
  <h2>Executive Summary</h2>
  {story_html}
  {grouping_html}

  <!-- Attack Timeline -->
  <h2>Attack Timeline — Chronological Evidence</h2>
  {timeline_section}

  <!-- Detection Evidence -->
  <h2>Detection Evidence</h2>
  <p style="font-size:12px;color:#6b7a8d;margin-bottom:14px">
    Each card below corresponds to one triggered detection rule. Evidence fields are the
    raw values from the source event that caused the rule to fire.
  </p>
  {det_cards}

  <!-- MITRE ATT&CK -->
  <h2>MITRE ATT&amp;CK Coverage</h2>
  {mitre_section}

  <!-- Potential Reachability -->
  <h2>Potential Reachability (Investigative Leads)</h2>
  <p style="font-size:12px;color:#6b7a8d;margin-bottom:10px">
    These paths represent inferred investigative leads derived from graph traversal of
    observed relationships. They are <strong>not</strong> confirmation of successful lateral movement.
  </p>
  {reach_section}

  <!-- Recommended Actions -->
  <h2>Recommended Analyst Actions</h2>
  {actions_html}

  <!-- Disclaimer -->
  <div class="disclaimer">
    ⚠️ <strong>Rule-based detection only.</strong> ChainSight AI uses deterministic rule evaluation and
    evidence-based correlation. It does not use machine learning or AI inference. All findings represent
    potential indicators requiring human analyst validation before any response action.
  </div>

  <!-- Print / Download buttons -->
  <div class="no-print" style="margin-top:28px">
    <button class="btn" onclick="window.print()">🖨️ Print / Save as PDF</button>
    <a class="btn" style="background:#14526a" href="?format=json" target="_blank">JSON payload</a>
  </div>

</div>
</body>
</html>"""

    return payload, html
