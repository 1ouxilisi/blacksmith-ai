"""
Enhanced Report Generator - Generates professional penetration test reports
with attack chain visualization, findings, and remediation guidance.
"""
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from utils.audit_logger import audit_logger
from utils.attack_chain import chain_manager, ChainPhase, ChainStatus, AttackNode


class ReportGenerator:
    """Generates comprehensive penetration test reports."""

    def __init__(self):
        self.findings: List[Dict[str, Any]] = []
        self.target: str = ""
        self.start_time = datetime.now()

    def set_target(self, target: str):
        self.target = target

    def add_finding(
        self,
        title: str,
        severity: str,
        description: str,
        evidence: Optional[str] = None,
        remediation: Optional[str] = None,
        cve: Optional[str] = None,
        affected_component: Optional[str] = None,
    ):
        finding = {
            "id": f"F{len(self.findings)+1:03d}",
            "title": title,
            "severity": severity,
            "description": description,
            "evidence": evidence,
            "remediation": remediation,
            "cve": cve,
            "affected_component": affected_component,
            "timestamp": datetime.now().isoformat(),
        }
        self.findings.append(finding)
        audit_logger.log_finding(
            agent="ReportGenerator",
            title=title,
            severity=severity,
            description=description,
            evidence=evidence,
            cve=cve,
            affected_target=self.target,
        )

    def generate_markdown_report(self, output_path: Optional[str] = None) -> str:
        """Generate a full markdown penetration test report."""
        end_time = datetime.now()
        duration = (end_time - self.start_time).total_seconds() / 60

        # Count findings by severity
        severity_counts = {}
        for f in self.findings:
            sev = f["severity"].lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        report = f"""# Penetration Test Report

## Executive Summary

**Target:** {self.target}
**Date:** {self.start_time.strftime("%Y-%m-%d")}
**Duration:** {duration:.1f} minutes
**Total Findings:** {len(self.findings)}

### Findings Summary
| Severity | Count |
|----------|-------|
| Critical | {severity_counts.get('critical', 0)} |
| High | {severity_counts.get('high', 0)} |
| Medium | {severity_counts.get('medium', 0)} |
| Low | {severity_counts.get('low', 0)} |
| Info | {severity_counts.get('info', 0)} |

---

## Methodology

This engagement followed a structured penetration testing methodology:

1. **Reconnaissance** - Passive and active information gathering
2. **Scanning & Enumeration** - Deep inspection of discovered services
3. **Vulnerability Mapping** - Identification of potential vulnerabilities
4. **Exploitation** - Controlled verification of vulnerabilities
5. **Post-Exploitation** - Impact assessment and lateral movement analysis

---

## Detailed Findings

"""

        # Group findings by severity
        severity_order = ["critical", "high", "medium", "low", "info"]
        for sev in severity_order:
            sev_findings = [f for f in self.findings if f["severity"].lower() == sev]
            if not sev_findings:
                continue

            report += f"### {sev.upper()} Severity Findings\n\n"

            for finding in sev_findings:
                report += f"#### {finding['id']}: {finding['title']}\n\n"
                report += f"**Severity:** {finding['severity'].upper()}\n\n"
                if finding.get("cve"):
                    report += f"**CVE:** {finding['cve']}\n\n"
                if finding.get("affected_component"):
                    report += f"**Affected Component:** {finding['affected_component']}\n\n"
                report += f"**Description:**\n\n{finding['description']}\n\n"
                if finding.get("evidence"):
                    report += f"**Evidence:**\n\n```\n{finding['evidence'][:500]}\n```\n\n"
                if finding.get("remediation"):
                    report += f"**Remediation:**\n\n{finding['remediation']}\n\n"
                report += "---\n\n"

        # Add attack chain visualization
        report += "## Attack Chain Visualization\n\n"
        for chain_id, chain in chain_manager.chains.items():
            if chain.target == self.target:
                report += "```\n"
                report += chain_manager.generate_visualization(chain_id)
                report += "\n```\n\n"

        # Add audit summary
        report += "## Audit Log Summary\n\n"
        summary = audit_logger.get_session_summary()
        report += f"- Total events recorded: {summary['total_events']}\n"
        report += f"- Commands executed: {summary['total_commands']}\n"
        report += f"- Decisions made: {summary['total_decisions']}\n"
        report += f"- Approvals processed: {summary['total_approvals']}\n\n"

        report += "---\n\n*Report generated by BlacksmithAI Enhanced Reporting Module*\n"

        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(report)

        return report

    def generate_json_report(self, output_path: Optional[str] = None) -> Dict[str, Any]:
        """Generate a structured JSON report."""
        report = {
            "report_metadata": {
                "target": self.target,
                "start_time": self.start_time.isoformat(),
                "end_time": datetime.now().isoformat(),
                "tool": "BlacksmithAI",
            },
            "findings": self.findings,
            "attack_chains": [
                {
                    "chain_id": c.chain_id,
                    "target": c.target,
                    "success": c.success,
                    "nodes": [
                        {
                            "node_id": n.node_id,
                            "phase": n.phase.value,
                            "title": n.title,
                            "status": n.status.value,
                            "severity": n.severity,
                        }
                        for n in c.nodes
                    ],
                }
                for c in chain_manager.chains.values()
                if c.target == self.target
            ],
            "audit_summary": audit_logger.get_session_summary(),
        }

        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)

        return report


# Global instance
report_generator = ReportGenerator()
