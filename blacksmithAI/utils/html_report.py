"""
HTML Report Generator - Beautiful interactive HTML penetration test report.
"""
import os
import json
from datetime import datetime
from typing import List, Dict, Any
from utils.audit_logger import audit_logger
from utils.attack_chain import chain_manager


class HTMLReportGenerator:
    """Generate beautiful HTML penetration test reports."""

    HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Penetration Test Report - {target}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f8fafc; color: #1e293b; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 40px 20px; }}
        .header {{ background: linear-gradient(135deg, #1e3a8a, #3b82f6); color: white; padding: 40px; border-radius: 12px; margin-bottom: 30px; }}
        .header h1 {{ font-size: 32px; margin-bottom: 10px; }}
        .header .meta {{ opacity: 0.9; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 16px; margin-bottom: 30px; }}
        .stat-card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); text-align: center; }}
        .stat-value {{ font-size: 28px; font-weight: bold; color: #1e3a8a; }}
        .stat-label {{ color: #64748b; font-size: 14px; margin-top: 4px; }}
        .section {{ background: white; padding: 30px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 20px; }}
        .section h2 {{ color: #1e3a8a; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 2px solid #e2e8f0; }}
        .finding {{ border-left: 4px solid #e2e8f0; padding: 16px; margin-bottom: 16px; background: #f8fafc; border-radius: 0 8px 8px 0; }}
        .finding.critical {{ border-left-color: #dc2626; }}
        .finding.high {{ border-left-color: #ea580c; }}
        .finding.medium {{ border-left-color: #ca8a04; }}
        .finding.low {{ border-left-color: #16a34a; }}
        .finding.info {{ border-left-color: #2563eb; }}
        .finding-title {{ font-weight: 600; font-size: 18px; margin-bottom: 8px; }}
        .badge {{ display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: 600; text-transform: uppercase; }}
        .badge.critical {{ background: #fef2f2; color: #dc2626; }}
        .badge.high {{ background: #fff7ed; color: #ea580c; }}
        .badge.medium {{ background: #fefce8; color: #ca8a04; }}
        .badge.low {{ background: #f0fdf4; color: #16a34a; }}
        .badge.info {{ background: #eff6ff; color: #2563eb; }}
        .evidence {{ background: #1e293b; color: #e2e8f0; padding: 12px; border-radius: 6px; font-family: monospace; font-size: 13px; overflow-x: auto; margin: 10px 0; }}
        .remediation {{ background: #f0fdf4; padding: 12px; border-radius: 6px; margin-top: 10px; }}
        .chain-vis {{ background: #1e293b; color: #e2e8f0; padding: 20px; border-radius: 8px; font-family: monospace; white-space: pre; }}
        .footer {{ text-align: center; color: #64748b; margin-top: 40px; padding-top: 20px; border-top: 1px solid #e2e8f0; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔨 Penetration Test Report</h1>
            <div class="meta">
                <p>Target: {target}</p>
                <p>Date: {date}</p>
                <p>Duration: {duration:.1f} minutes</p>
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{total_findings}</div>
                <div class="stat-label">Total Findings</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #dc2626;">{critical_count}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #ea580c;">{high_count}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #ca8a04;">{medium_count}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #16a34a;">{low_count}</div>
                <div class="stat-label">Low</div>
            </div>
        </div>

        <div class="section">
            <h2>Executive Summary</h2>
            <p>This report presents the results of a penetration test conducted against <strong>{target}</strong>.
            The assessment followed a structured methodology including reconnaissance, scanning, vulnerability mapping,
            exploitation, and post-exploitation activities.</p>
            <br>
            <p><strong>Key Findings:</strong> {key_findings_summary}</p>
        </div>

        <div class="section">
            <h2>Detailed Findings</h2>
            {findings_html}
        </div>

        <div class="section">
            <h2>Attack Chain Visualization</h2>
            <div class="chain-vis">{chain_vis}</div>
        </div>

        <div class="section">
            <h2>Methodology</h2>
            <ol>
                <li><strong>Reconnaissance</strong> - Passive and active information gathering</li>
                <li><strong>Scanning & Enumeration</strong> - Deep inspection of discovered services</li>
                <li><strong>Vulnerability Mapping</strong> - Identification of potential vulnerabilities</li>
                <li><strong>Exploitation</strong> - Controlled verification of vulnerabilities</li>
                <li><strong>Post-Exploitation</strong> - Impact assessment and lateral movement analysis</li>
            </ol>
        </div>

        <div class="footer">
            <p>Generated by BlacksmithAI Enhanced Reporting System</p>
            <p>{date}</p>
        </div>
    </div>
</body>
</html>"""

    def generate_html_report(
        self,
        target: str,
        findings: List[Dict[str, Any]],
        output_path: str,
        duration_minutes: float = 0,
    ):
        """Generate a beautiful HTML report."""

        # Count by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        # Generate findings HTML
        findings_html = ""
        for f in findings:
            sev = f.get("severity", "info").lower()
            findings_html += f"""
            <div class="finding {sev}">
                <div class="finding-title">{f.get('title', 'Unknown')}</div>
                <span class="badge {sev}">{sev.upper()}</span>
                <p style="margin-top: 10px;">{f.get('description', '')}</p>
                {f'<div class="evidence"><strong>Evidence:</strong><br>{f.get("evidence", "")[:500]}</div>' if f.get('evidence') else ''}
                {f'<div class="remediation"><strong>Remediation:</strong> {f.get("remediation", "")}</div>' if f.get('remediation') else ''}
            </div>
            """

        # Key findings summary
        key_findings = []
        if severity_counts["critical"] > 0:
            key_findings.append(f"{severity_counts['critical']} critical vulnerabilities")
        if severity_counts["high"] > 0:
            key_findings.append(f"{severity_counts['high']} high severity issues")
        key_findings_str = ", ".join(key_findings) if key_findings else "No critical or high severity findings identified."

        # Attack chain visualization
        chain_vis = "No attack chain data available."
        for chain_id, chain in chain_manager.chains.items():
            if chain.target == target:
                chain_vis = chain_manager.generate_visualization(chain_id)
                break

        html = self.HTML_TEMPLATE.format(
            target=target,
            date=datetime.now().strftime("%Y-%m-%d %H:%M"),
            duration=duration_minutes,
            total_findings=len(findings),
            critical_count=severity_counts["critical"],
            high_count=severity_counts["high"],
            medium_count=severity_counts["medium"],
            low_count=severity_counts["low"],
            key_findings_summary=key_findings_str,
            findings_html=findings_html,
            chain_vis=chain_vis,
        )

        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

        return output_path


# Global instance
html_report_generator = HTMLReportGenerator()
