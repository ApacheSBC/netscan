"""Reporting utilities for enriched network scan results."""

from __future__ import annotations

import json
from datetime import datetime
from html import escape
from pathlib import Path
from typing import Any, Dict, List


def _get_risk_color(risk_level: str) -> str:
    """Return a readable background color for each risk level."""
    color_map = {
        "Critical": "#f8d7da",  # red-ish
        "High": "#ffe5d0",  # orange-ish
        "Medium": "#fff3cd",  # yellow-ish
        "Low": "#d1e7dd",  # green-ish
    }
    return color_map.get(risk_level, "#f8f9fa")


def _extract_cve_ids(cves: Any) -> str:
    """Convert CVE list into a compact comma-separated string."""
    if not isinstance(cves, list) or not cves:
        return "-"

    cve_ids = []
    for item in cves:
        if isinstance(item, dict):
            cve_id = item.get("cve_id")
            if cve_id:
                cve_ids.append(str(cve_id))

    return ", ".join(cve_ids) if cve_ids else "-"


def save_json(results: List[Dict[str, Any]], output_path: str) -> None:
    """
    Save full enriched scan results as pretty-printed JSON.

    Any write/serialization errors are caught and printed.
    """
    try:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with path.open("w", encoding="utf-8") as file_obj:
            json.dump(results, file_obj, indent=2, ensure_ascii=False)

        print(f"JSON report saved: {path}")
    except OSError as err:
        print(f"[Report error] Could not write JSON report to {output_path}: {err}")
    except TypeError as err:
        print(f"[Report error] Could not serialize JSON report data: {err}")


def save_html(
    results: List[Dict[str, Any]], summary: Dict[str, Any], target: str, output_path: str
) -> None:
    """
    Generate and save a clean HTML security report.

    Report sections:
    - Header with target and timestamp
    - Summary counters
    - Color-coded findings table
    - Authorized-use disclaimer footer
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    counts = summary.get("counts", {})

    # Build table rows with risk color coding and escaped content.
    rows_html: List[str] = []
    for item in results:
        risk_level = str(item.get("risk_level", "Low"))
        row_color = _get_risk_color(risk_level)
        rows_html.append(
            (
                "<tr style='background-color: {bg};'>"
                "<td>{host}</td>"
                "<td>{port}</td>"
                "<td>{protocol}</td>"
                "<td>{service}</td>"
                "<td>{product_version}</td>"
                "<td><strong>{risk_level}</strong></td>"
                "<td>{risk_reason}</td>"
                "<td>{cve_ids}</td>"
                "</tr>"
            ).format(
                bg=escape(row_color),
                host=escape(str(item.get("host", "-"))),
                port=escape(str(item.get("port", "-"))),
                protocol=escape(str(item.get("protocol", "-"))),
                service=escape(str(item.get("service", "-"))),
                product_version=escape(str(item.get("product_version", "-"))),
                risk_level=escape(risk_level),
                risk_reason=escape(str(item.get("risk_reason", "-"))),
                cve_ids=escape(_extract_cve_ids(item.get("cves", []))),
            )
        )

    if not rows_html:
        rows_html.append(
            "<tr><td colspan='8' style='text-align:center;'>No findings available.</td></tr>"
        )

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>NetScan Security Report</title>
  <style>
    body {{
      font-family: Arial, sans-serif;
      margin: 0;
      background: #f4f6f8;
      color: #1f2937;
    }}
    .container {{
      max-width: 1200px;
      margin: 30px auto;
      background: #ffffff;
      border-radius: 10px;
      box-shadow: 0 4px 16px rgba(0, 0, 0, 0.08);
      overflow: hidden;
    }}
    .header {{
      padding: 24px 30px;
      background: #0f172a;
      color: #ffffff;
    }}
    .header h1 {{
      margin: 0 0 8px 0;
      font-size: 26px;
    }}
    .header p {{
      margin: 4px 0;
      opacity: 0.92;
    }}
    .section {{
      padding: 20px 30px;
    }}
    .summary-grid {{
      display: grid;
      grid-template-columns: repeat(4, minmax(120px, 1fr));
      gap: 12px;
    }}
    .summary-card {{
      border-radius: 8px;
      padding: 14px;
      text-align: center;
      font-weight: bold;
    }}
    .critical {{ background: #f8d7da; }}
    .high {{ background: #ffe5d0; }}
    .medium {{ background: #fff3cd; }}
    .low {{ background: #d1e7dd; }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 14px;
    }}
    th, td {{
      border: 1px solid #d1d5db;
      padding: 10px;
      text-align: left;
      vertical-align: top;
    }}
    th {{
      background: #e5e7eb;
      font-weight: 600;
    }}
    .footer {{
      padding: 16px 30px 24px;
      color: #6b7280;
      font-size: 13px;
      border-top: 1px solid #e5e7eb;
      background: #fafafa;
    }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Network Security Scan Report</h1>
      <p><strong>Target:</strong> {escape(target)}</p>
      <p><strong>Generated:</strong> {escape(timestamp)}</p>
    </div>

    <div class="section">
      <h2>Risk Summary</h2>
      <div class="summary-grid">
        <div class="summary-card critical">Critical: {escape(str(counts.get("Critical", 0)))}</div>
        <div class="summary-card high">High: {escape(str(counts.get("High", 0)))}</div>
        <div class="summary-card medium">Medium: {escape(str(counts.get("Medium", 0)))}</div>
        <div class="summary-card low">Low: {escape(str(counts.get("Low", 0)))}</div>
      </div>
    </div>

    <div class="section">
      <h2>Detailed Findings</h2>
      <table>
        <thead>
          <tr>
            <th>Host</th>
            <th>Port</th>
            <th>Protocol</th>
            <th>Service</th>
            <th>Product/Version</th>
            <th>Risk Level</th>
            <th>Risk Reason</th>
            <th>CVE IDs</th>
          </tr>
        </thead>
        <tbody>
          {"".join(rows_html)}
        </tbody>
      </table>
    </div>

    <div class="footer">
      Disclaimer: This tool is intended for defensive security testing on authorized systems only.
      Unauthorized scanning may violate policy and law.
    </div>
  </div>
</body>
</html>
"""

    try:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with path.open("w", encoding="utf-8") as file_obj:
            file_obj.write(html_content)

        print(f"HTML report saved: {path}")
    except OSError as err:
        print(f"[Report error] Could not write HTML report to {output_path}: {err}")


def generate_reports(
    enriched_results: List[Dict[str, Any]],
    summary: Dict[str, Any],
    target: str,
    output_dir: str,
) -> Dict[str, str]:
    """
    Generate timestamped JSON + HTML reports in the specified output directory.

    Returns a dictionary with the generated report paths.
    """
    timestamp_slug = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_dir = Path(output_dir)
    json_path = base_dir / f"scan_report_{timestamp_slug}.json"
    html_path = base_dir / f"scan_report_{timestamp_slug}.html"

    save_json(enriched_results, str(json_path))
    save_html(enriched_results, summary, target, str(html_path))

    print(f"Report generation complete. JSON: {json_path}")
    print(f"Report generation complete. HTML: {html_path}")

    return {"json": str(json_path), "html": str(html_path)}
