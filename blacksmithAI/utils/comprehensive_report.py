"""
Comprehensive LLM Security Report - Combined LLM + Agentic report.
"""
import os
from datetime import datetime
from typing import List, Dict, Any


class ComprehensiveReport:
    """Generate combined LLM + Agentic security report."""

    def __init__(self):
        self.reports_dir = "./outputs/reports"
        os.makedirs(self.reports_dir, exist_ok=True)

    def generate_report(
        self,
        target: str,
        llm_findings: List[Any],
        agentic_findings: List[Any],
        attack_chain_results: List[Dict[str, Any]]
    ) -> str:
        """Generate comprehensive report."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        filename = "comprehensive_llm_security_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".html"
        filepath = os.path.join(self.reports_dir, filename)

        # Count by severity
        all_findings = []
        for f in llm_findings:
            all_findings.append({"source": "OWASP LLM Top 10", "id": f.owasp_id, "name": f.name, "severity": f.severity})
        for f in agentic_findings:
            all_findings.append({"source": "OWASP Agentic Top 10", "id": f["owasp_id"], "name": f["name"], "severity": f["severity"]})

        critical = sum(1 for f in all_findings if f["severity"] == "critical")
        high = sum(1 for f in all_findings if f["severity"] == "high")
        medium = sum(1 for f in all_findings if f["severity"] == "medium")
        low = sum(1 for f in all_findings if f["severity"] == "low")

        # Risk score
        risk_score = critical * 10 + high * 5 + medium * 2 + low * 1
        if risk_score >= 20:
            risk_level = "CRITICAL"
            risk_color = "#dc2626"
        elif risk_score >= 10:
            risk_level = "HIGH"
            risk_color = "#ea580c"
        elif risk_score >= 5:
            risk_level = "MEDIUM"
            risk_color = "#ca8a04"
        else:
            risk_level = "LOW"
            risk_color = "#16a34a"

        findings_html = ""
        for f in all_findings:
            sev_color = {
                "critical": "#dc2626",
                "high": "#ea580c",
                "medium": "#ca8a04",
                "low": "#16a34a",
            }.get(f["severity"], "#6b7280")

            findings_html += f"""
            <div style="background:#1e293b; padding:16px; margin:12px 0; border-radius:8px; border-left: 4px solid {sev_color};">
                <h3 style="color:{sev_color}; margin:0;">[{f['id']}] {f['name']}</h3>
                <p style="color:#94a3b8; margin:4px 0;">Source: {f['source']}</p>
            </div>
            """

        attack_chains_html = ""
        for chain in attack_chain_results:
            status = "🔴 VULNERABLE" if chain.get("success") else "✅ SECURE"
            attack_chains_html += f"""
            <div style="background:#1e293b; padding:12px; margin:8px 0; border-radius:6px;">
                <p style="margin:0;"><strong>{chain['chain_name']}:</strong> {status}</p>
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
                .risk-banner {{ background: {risk_color}; padding: 20px; border-radius: 8px; text-align: center; margin: 20px 0; }}
                .risk-banner .level {{ font-size: 32px; font-weight: bold; color: white; }}
                .stats {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin: 24px 0; }}
                .stat {{ background: #1e293b; padding: 16px; border-radius: 8px; text-align: center; }}
                .stat .number {{ font-size: 28px; font-weight: bold; }}
                .stat.critical .number {{ color: #dc2626; }}
                .stat.high .number {{ color: #ea580c; }}
                .stat.medium .number {{ color: #ca8a04; }}
                .stat.low .number {{ color: #16a34a; }}
                .stat.score .number {{ color: #7c3aed; }}
                .stat .label {{ color: #94a3b8; font-size: 12px; margin-top: 4px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔒 Comprehensive LLM Security Report</h1>
                    <p style="color:#c4b5fd; margin:8px 0 0 0;">Target: {target}</p>
                    <p style="color:#c4b5fd; margin:4px 0 0 0;">Date: {timestamp}</p>
                </div>

                <div class="risk-banner">
                    <div class="level">{risk_level} RISK</div>
                    <p style="color:white; margin:8px 0 0 0;">Overall Security Posture</p>
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
                    <div class="stat score">
                        <div class="number">{risk_score}</div>
                        <div class="label">Risk Score</div>
                    </div>
                </div>

                <h2 style="color:#8b5cf6;">Standards Tested</h2>
                <p style="color:#94a3b8;">✅ OWASP Top 10 for LLM Applications (2025)</p>
                <p style="color:#94a3b8;">✅ OWASP Top 10 for Agentic Applications (2026)</p>
                <p style="color:#94a3b8;">✅ Multi-Turn Attack Chains</p>

                <h2 style="color:#8b5cf6; margin-top: 24px;">Vulnerabilities Found</h2>
                {findings_html if findings_html else '<p style="color:#94a3b8;">No vulnerabilities found. Great!</p>'}

                <h2 style="color:#8b5cf6; margin-top: 24px;">Attack Chain Results</h2>
                {attack_chains_html if attack_chains_html else '<p style="color:#94a3b8;">No attack chains run.</p>'}
            </div>
        </body>
        </html>
        """

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)

        return filepath


# Global instance
comprehensive_report = ComprehensiveReport()
