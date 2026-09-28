"""
AI Remediation Advisor - LLM-powered fix recommendations.
"""
from typing import Dict, List, Any
from utils.llm_analyzer import llm_analyzer


class RemediationAdvisor:
    """Generate AI-powered fix recommendations for vulnerabilities."""

    def get_fix_recommendation(self, finding: Dict) -> Dict[str, Any]:
        """Generate a detailed fix recommendation for a finding."""
        if not llm_analyzer.available:
            return {
                "finding_id": finding.get("id"),
                "title": finding.get("title"),
                "recommendation": "LLM not available. Manual remediation required.",
                "priority": finding.get("severity", "medium"),
            }

        prompt = f"""You are a senior security engineer. Provide a detailed fix recommendation for this vulnerability:

Title: {finding.get('title')}
Type: {finding.get('vuln_type')}
Severity: {finding.get('severity')}
Target: {finding.get('target_url')}

Provide:
1. Why this is a problem
2. Step-by-step fix instructions
3. Code example showing the fix
4. How to verify the fix works

Keep it practical and actionable.
"""
        recommendation = llm_analyzer._chat(prompt)

        return {
            "finding_id": finding.get("id"),
            "title": finding.get("title"),
            "severity": finding.get("severity"),
            "recommendation": recommendation,
        }

    def get_fix_plan(self, findings: List[Dict]) -> Dict[str, Any]:
        """Generate a prioritized fix plan."""
        if not findings:
            return {"plan": "No findings to fix.", "total_issues": 0}

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_findings = sorted(
            findings,
            key=lambda f: severity_order.get(f.get("severity", "low"), 3)
        )

        plan = []
        for f in sorted_findings:
            plan.append({
                "title": f.get("title"),
                "severity": f.get("severity"),
                "target": f.get("target_url"),
                "order": len(plan) + 1,
            })

        return {
            "total_issues": len(findings),
            "critical": sum(1 for f in findings if f.get("severity") == "critical"),
            "high": sum(1 for f in findings if f.get("severity") == "high"),
            "fix_order": plan,
        }


remediation_advisor = RemediationAdvisor()
