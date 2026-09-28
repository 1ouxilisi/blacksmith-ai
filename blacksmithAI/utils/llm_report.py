"""
LLM Security Report Generator - Professional OWASP compliance report.
"""
import os
from datetime import datetime
from typing import List, Dict, Any


class LLMSecurityReport:
    """Generate professional LLM security report."""

    def __init__(self):
        self.reports_dir = "./outputs/reports"
        os.makedirs(self.reports_dir, exist_ok=True)

    def generate_report(self, target: str, findings: List[Any]) -> str:
        """Generate HTML report."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        filename = "llm_security_report_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".html"
        filepath = os.path.join(self.reports_dir, filename)

        # Count by severity
        critical = sum(1 for f in findings if f.severity == "critical")
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")

        findings_html = ""
        for f in findings:
            severity_color = {
                "critical": "#dc2626",
                "high": "#ea580c",
                "medium": "#ca8a04",
                "low": "#16a34a",
            }.get(f.severity, "#6b7280")

            findings_html += f"""
            <div style="background:#1e293b; padding:16px; margin:12px 0; border-radius:8px; border-left: 4px solid {severity_color};">
                <h3 style="color:{severity_color}; margin:0;">[{f.owasp_id}] {f.name}</h3>
                <p style="color:#94a3b8; margin:8px 0;">{f.description}</p>
                <p style="color:#e2e8f0; margin:4px 0;"><strong>Payload:</strong> <code style="background:#0f172a; padding:4px 8px; border-radius:4px;">{f.payload[:80]}</code></p>
                <p style="color:#e2e8f0; margin:4px 0;"><strong>Evidence:</strong> {f.evidence[:150]}...</p>
            </div>
            """

        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>LLM Security Report - {target}</title>
            <style>
                body {{ font-family: sans-serif; background: #0f172a; color: #e2e8f0; padding: 40px; }}
                .container {{ max-width: 900px; margin: 0 auto; }}
                .header {{ background: linear-gradient(135deg, #7c3aed 0%, #4f46e5 100%); padding: 30px; border-radius: 12px; margin-bottom: 24px; }}
                .header h1 {{ color: white; margin: 0; }}
                .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin: 24px 0; }}
                .stat {{ background: #1e293b; padding: 20px; border-radius: 8px; text-align: center; }}
                .stat .number {{ font-size: 32px; font-weight: bold; }}
                .stat.critical .number {{ color: #dc2626; }}
                .stat.high .number {{ color: #ea580c; }}
                .stat.medium .number {{ color: #ca8a04; }}
                .stat.low .number {{ color: #16a34a; }}
                .stat .label {{ color: #94a3b8; font-size: 14px; margin-top: 4px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔒 LLM Security Report</h1>
                    <p style="color:#c4b5fd; margin:8px 0 0 0;">Target: {target} | Date: {timestamp}</p>
                    <p style="color:#c4b5fd; margin:4px 0 0 0;">Standard: OWASP Top 10 for LLM Applications 2025</p>
                </div>

                <div class="stats">
                    <div class="stat critical">
                        <div class="number">{critical}</div>
                        <div class="label">Critical</div>
                    </div>
                    <div class="stat high">
                        <div class="number">{high}</div>
                        <div class="label">High</div>
                    </div>
                    <div class="stat medium">
                        <div class="number">{medium}</div>
                        <div class="label">Medium</div>
                    </div>
                    <div class="stat low">
                        <div class="number">{low}</div>
                        <div class="label">Low</div>
                    </div>
                </div>

                <h2 style="color:#8b5cf6;">Vulnerabilities Found</h2>
                {findings_html if findings_html else '<p style="color:#94a3b8;">No vulnerabilities found.</p>'}
            </div>
        </body>
        </html>
        """

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)

        return filepath


# Global instance
llm_report = LLMSecurityReport()
