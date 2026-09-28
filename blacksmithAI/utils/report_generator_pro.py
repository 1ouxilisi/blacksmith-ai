"""
Professional Report Generator
"""
import os
from datetime import datetime
from typing import List, Dict, Any
from utils.database import db


class ReportGenerator:
    def __init__(self):
        self.reports_dir = "./outputs/reports"
        os.makedirs(self.reports_dir, exist_ok=True)

    def generate_report(self, target, findings=None):
        if findings is None:
            findings = db.get_findings(limit=200)

        total = len(findings)
        critical = sum(1 for f in findings if f["severity"] == "critical")
        high = sum(1 for f in findings if f["severity"] == "high")
        medium = sum(1 for f in findings if f["severity"] == "medium")
        low = sum(1 for f in findings if f["severity"] == "low")
        risk_score = critical * 10 + high * 5 + medium * 2 + low * 1

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        filename = "report_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".html"
        filepath = os.path.join(self.reports_dir, filename)

        findings_html = ""
        for f in findings:
            sev = f["severity"]
            conf = round(f["confidence"] * 100)
            desc = f["description"][:300]
            findings_html += '<div class="finding ' + sev + '">'
            findings_html += '<div class="finding-title">'
            findings_html += '<span class="badge ' + sev + '">' + sev.upper() + '</span>'
            findings_html += f["title"]
            findings_html += '</div>'
            findings_html += '<div class="finding-meta">'
            findings_html += 'Type: ' + f["vuln_type"] + ' | Confidence: ' + str(conf) + '% | Status: ' + f["status"]
            findings_html += '</div>'
            findings_html += '<p>' + desc + '</p>'
            findings_html += '</div>'

        css = """
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { font-family: sans-serif; background: #f8fafc; color: #1e293b; padding: 40px; }
            .container { max-width: 1000px; margin: 0 auto; }
            .header { background: #1e293b; color: white; padding: 40px; border-radius: 12px; margin-bottom: 30px; }
            .header h1 { font-size: 28px; margin-bottom: 8px; }
            .header .target { color: #38bdf8; font-size: 18px; }
            .risk-score { background: #ef4444; color: white; padding: 8px 20px; border-radius: 20px; font-weight: bold; display: inline-block; margin-top: 16px; }
            .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 16px; margin-bottom: 30px; }
            .stat { background: white; padding: 20px; border-radius: 8px; text-align: center; }
            .stat-value { font-size: 32px; font-weight: bold; }
            .section { background: white; padding: 30px; border-radius: 8px; margin-bottom: 20px; }
            .finding { border-left: 4px solid #38bdf8; padding: 16px; margin: 12px 0; background: #f8fafc; }
            .finding.critical { border-left-color: #ef4444; }
            .finding.high { border-left-color: #f97316; }
            .finding.medium { border-left-color: #eab308; }
            .finding.low { border-left-color: #22c55e; }
            .badge { padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; margin-right: 8px; background: #fef2f2; color: #ef4444; }
        </style>
        """

        html = "<!DOCTYPE html><html><head><meta charset='UTF-8'>"
        html += "<title>Report - " + target + "</title>"
        html += css
        html += "</head><body><div class='container'>"
        html += "<div class='header'><h1>Security Assessment Report</h1>"
        html += "<div class='target'>Target: " + target + "</div>"
        html += "<div>Risk Score: <span class='risk-score'>" + str(risk_score) + "/100</span></div>"
        html += "</div>"
        html += "<div class='summary'>"
        html += "<div class='stat'><div class='stat-value'>" + str(total) + "</div><div>Total</div></div>"
        html += "<div class='stat'><div class='stat-value' style='color:#ef4444'>" + str(critical) + "</div><div>Critical</div></div>"
        html += "<div class='stat'><div class='stat-value' style='color:#f97316'>" + str(high) + "</div><div>High</div></div>"
        html += "<div class='stat'><div class='stat-value' style='color:#eab308'>" + str(medium) + "</div><div>Medium</div></div>"
        html += "<div class='stat'><div class='stat-value' style='color:#22c55e'>" + str(low) + "</div><div>Low</div></div>"
        html += "</div>"
        html += "<div class='section'><h2>Detailed Findings</h2>"
        html += findings_html
        html += "</div>"
        html += "</div></body></html>"

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)

        return filepath


report_generator_pro = ReportGenerator()
