"""HTML report generator for X-POSURE.

Generates a self-contained HTML report with interactive findings table,
executive summary, severity breakdown, and remediation checklist.
"""

import json
from datetime import datetime, timezone
from typing import List, Optional

from ..core.models import Finding, FindingTier, VerificationStatus, Severity, ScanStats


def _severity_color(severity) -> str:
    """Get color for severity level."""
    colors = {
        'critical': '#dc2626',
        'high': '#ea580c',
        'medium': '#ca8a04',
        'low': '#2563eb',
        'info': '#6b7280',
    }
    val = severity.value if hasattr(severity, 'value') else str(severity)
    return colors.get(val, '#6b7280')


def _tier_color(tier) -> str:
    """Get color for finding tier."""
    colors = {
        'critical': '#dc2626',
        'confirmed': '#ea580c',
        'likely': '#ca8a04',
        'possible': '#2563eb',
        'info': '#6b7280',
    }
    val = tier.value if hasattr(tier, 'value') else str(tier)
    return colors.get(val, '#6b7280')


def _mask_value(value: str) -> str:
    """Mask a credential value for display."""
    if len(value) <= 8:
        return '****'
    return value[:4] + '*' * (len(value) - 8) + value[-4:]


def generate_html_report(
    findings: List[Finding],
    stats: Optional[ScanStats] = None,
    target: str = "unknown",
) -> str:
    """
    Generate a self-contained HTML report.

    Args:
        findings: List of findings
        stats: Scan statistics
        target: Scan target

    Returns:
        HTML string
    """
    # Count by tier
    tier_counts = {}
    for tier in FindingTier:
        tier_counts[tier.value] = 0
    for f in findings:
        tier_val = f.tier.value if hasattr(f.tier, 'value') else str(f.tier)
        tier_counts[tier_val] = tier_counts.get(tier_val, 0) + 1

    # Count by severity
    sev_counts = {}
    for sev in Severity:
        sev_counts[sev.value] = 0
    for f in findings:
        if f.severity:
            sv = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
            sev_counts[sv] = sev_counts.get(sv, 0) + 1

    # Count verified
    verified_count = sum(1 for f in findings if f.status == VerificationStatus.VERIFIED)

    # Risk score (simple heuristic)
    risk_score = min(100, (
        tier_counts.get('critical', 0) * 25 +
        tier_counts.get('confirmed', 0) * 15 +
        tier_counts.get('likely', 0) * 8 +
        tier_counts.get('possible', 0) * 3
    ))

    # Build findings table rows
    findings_rows = ""
    for f in sorted(findings, key=lambda x: (
        ['critical', 'confirmed', 'likely', 'possible', 'info'].index(
            x.tier.value if hasattr(x.tier, 'value') else 'info'
        )
    )):
        tier_val = f.tier.value if hasattr(f.tier, 'value') else 'info'
        sev_val = f.severity.value if f.severity and hasattr(f.severity, 'value') else 'medium'
        status_val = f.status.value if hasattr(f.status, 'value') else str(f.status)
        sources_str = ', '.join(s.type for s in f.sources[:3])
        if len(f.sources) > 3:
            sources_str += f' (+{len(f.sources) - 3})'

        findings_rows += f"""
        <tr>
          <td><span class="badge" style="background:{_tier_color(f.tier)}">{tier_val.upper()}</span></td>
          <td>{f.credential_type}</td>
          <td><code>{f.masked_value}</code></td>
          <td><span class="badge" style="background:{_severity_color(f.severity or Severity.MEDIUM)}">{sev_val}</span></td>
          <td>{status_val}</td>
          <td>{f.identity or '-'}</td>
          <td>{sources_str}</td>
          <td>{f.confidence:.0%}</td>
        </tr>"""

    # Stats section
    stats_html = ""
    if stats:
        duration = ""
        if stats.end_time and stats.start_time:
            dur_s = (stats.end_time - stats.start_time).total_seconds()
            duration = f"{dur_s:.1f}s"

        stats_html = f"""
        <div class="stats-grid">
          <div class="stat-card">
            <div class="stat-value">{stats.subdomains_found}</div>
            <div class="stat-label">Subdomains</div>
          </div>
          <div class="stat-card">
            <div class="stat-value">{stats.js_files_found}</div>
            <div class="stat-label">JS Files</div>
          </div>
          <div class="stat-card">
            <div class="stat-value">{stats.candidates_found}</div>
            <div class="stat-label">Candidates</div>
          </div>
          <div class="stat-card">
            <div class="stat-value">{stats.verified_findings}</div>
            <div class="stat-label">Verified</div>
          </div>
          <div class="stat-card">
            <div class="stat-value">{duration}</div>
            <div class="stat-label">Duration</div>
          </div>
        </div>"""

    now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>X-POSURE Report — {target}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace; background: #0a0a0a; color: #e5e5e5; }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
  h1 {{ color: #22c55e; font-size: 2em; margin-bottom: 5px; }}
  h2 {{ color: #a3e635; font-size: 1.3em; margin: 30px 0 15px; border-bottom: 1px solid #333; padding-bottom: 8px; }}
  .subtitle {{ color: #888; font-size: 0.9em; margin-bottom: 20px; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }}
  .summary-card {{ background: #1a1a1a; border: 1px solid #333; border-radius: 8px; padding: 20px; text-align: center; }}
  .summary-card .value {{ font-size: 2em; font-weight: bold; }}
  .summary-card .label {{ color: #888; font-size: 0.85em; margin-top: 5px; }}
  .risk-score {{ font-size: 2.5em; font-weight: bold; color: {'#dc2626' if risk_score >= 75 else '#ea580c' if risk_score >= 50 else '#ca8a04' if risk_score >= 25 else '#22c55e'}; }}
  .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 10px; margin: 15px 0; }}
  .stat-card {{ background: #1a1a1a; border: 1px solid #333; border-radius: 6px; padding: 15px; text-align: center; }}
  .stat-value {{ font-size: 1.5em; font-weight: bold; color: #22c55e; }}
  .stat-label {{ color: #888; font-size: 0.8em; }}
  table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
  th {{ background: #1a1a1a; color: #a3e635; padding: 12px 8px; text-align: left; font-size: 0.85em; cursor: pointer; }}
  th:hover {{ background: #252525; }}
  td {{ padding: 10px 8px; border-bottom: 1px solid #222; font-size: 0.85em; }}
  tr:hover {{ background: #1a1a1a; }}
  code {{ background: #1a1a1a; padding: 2px 6px; border-radius: 3px; font-size: 0.85em; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; color: white; font-size: 0.75em; font-weight: bold; text-transform: uppercase; }}
  .filter-bar {{ margin: 15px 0; }}
  .filter-bar input {{ background: #1a1a1a; border: 1px solid #333; color: #e5e5e5; padding: 8px 12px; border-radius: 6px; width: 300px; }}
  .footer {{ color: #555; font-size: 0.8em; margin-top: 40px; padding-top: 20px; border-top: 1px solid #222; text-align: center; }}
</style>
</head>
<body>
<div class="container">

<h1>X-POSURE</h1>
<div class="subtitle">Attack Surface Report for <strong>{target}</strong> &mdash; {now}</div>

<h2>Executive Summary</h2>
<div class="summary-grid">
  <div class="summary-card">
    <div class="risk-score">{risk_score}</div>
    <div class="label">Risk Score</div>
  </div>
  <div class="summary-card">
    <div class="value">{len(findings)}</div>
    <div class="label">Total Findings</div>
  </div>
  <div class="summary-card">
    <div class="value" style="color:#dc2626">{tier_counts.get('critical', 0)}</div>
    <div class="label">Critical</div>
  </div>
  <div class="summary-card">
    <div class="value" style="color:#ea580c">{tier_counts.get('confirmed', 0)}</div>
    <div class="label">Confirmed</div>
  </div>
  <div class="summary-card">
    <div class="value" style="color:#ca8a04">{tier_counts.get('likely', 0)}</div>
    <div class="label">Likely</div>
  </div>
  <div class="summary-card">
    <div class="value">{verified_count}</div>
    <div class="label">Verified Active</div>
  </div>
</div>

{stats_html}

<h2>Findings</h2>
<div class="filter-bar">
  <input type="text" id="searchInput" placeholder="Filter findings..." onkeyup="filterTable()">
</div>
<table id="findingsTable">
  <thead>
    <tr>
      <th onclick="sortTable(0)">Tier</th>
      <th onclick="sortTable(1)">Type</th>
      <th onclick="sortTable(2)">Value</th>
      <th onclick="sortTable(3)">Severity</th>
      <th onclick="sortTable(4)">Status</th>
      <th onclick="sortTable(5)">Identity</th>
      <th onclick="sortTable(6)">Sources</th>
      <th onclick="sortTable(7)">Confidence</th>
    </tr>
  </thead>
  <tbody>
    {findings_rows}
  </tbody>
</table>

<h2>Remediation Checklist</h2>
<ul style="list-style: none; padding: 0;">
{''.join(f'<li style="padding:6px 0;">&#9744; Rotate <strong>{f.credential_type}</strong> ({f.masked_value}) — {f.tier.value if hasattr(f.tier, "value") else f.tier}</li>' for f in findings if f.tier in (FindingTier.CRITICAL, FindingTier.CONFIRMED))}
</ul>

<div class="footer">
  Generated by X-POSURE v5.0 &mdash; {now}
</div>

</div>

<script>
function filterTable() {{
  var input = document.getElementById('searchInput').value.toLowerCase();
  var rows = document.getElementById('findingsTable').getElementsByTagName('tr');
  for (var i = 1; i < rows.length; i++) {{
    var text = rows[i].textContent.toLowerCase();
    rows[i].style.display = text.includes(input) ? '' : 'none';
  }}
}}
function sortTable(col) {{
  var table = document.getElementById('findingsTable');
  var rows = Array.from(table.rows).slice(1);
  var asc = table.getAttribute('data-sort-asc') !== 'true';
  rows.sort(function(a, b) {{
    var at = a.cells[col].textContent.trim();
    var bt = b.cells[col].textContent.trim();
    return asc ? at.localeCompare(bt) : bt.localeCompare(at);
  }});
  rows.forEach(function(row) {{ table.tBodies[0].appendChild(row); }});
  table.setAttribute('data-sort-asc', asc);
}}
</script>
</body>
</html>"""
    return html


def write_html_report(
    findings: List[Finding],
    stats: Optional[ScanStats] = None,
    output_path: str = "xposure-report.html",
    target: str = "unknown",
):
    """
    Write findings to HTML report file.

    Args:
        findings: List of findings
        stats: Scan statistics
        output_path: Output file path
        target: Scan target
    """
    html = generate_html_report(findings, stats, target)
    with open(output_path, 'w') as f:
        f.write(html)
