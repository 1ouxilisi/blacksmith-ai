"""
LLM Analyzer - Use local Ollama models to analyze scan results.
Models: mistral-nemo:12b-pentest, qwen3:8b-pentest (purpose-built for security)
"""
import os
import json
import requests
from typing import List, Dict, Any, Optional
from utils.database import db
from utils.run_history import budget_guard


class LLMAnalyzer:
    """Use local LLM models to analyze findings and generate insights."""

    def __init__(self):
        # Use localhost directly - OLLAMA_HOST env var may be set to bind address (0.0.0.0)
        # which is not usable as a client address
        self.host = "http://localhost:11434"
        self.default_model = os.getenv("PENTEST_MODEL", "mistral-nemo:12b-pentest")
        self.available = self._check_connection()

    def _check_connection(self) -> bool:
        """Check if Ollama is running."""
        try:
            resp = requests.get(f"{self.host}/api/tags", timeout=5)
            return resp.status_code == 200
        except Exception:
            return False

    def _chat(self, prompt: str, model: str = None) -> str:
        """Send a prompt to the local LLM."""
        if not self.available:
            return "Ollama not available"

        if not budget_guard.can_spend(0.001):
            return "Budget limit reached"

        model = model or self.default_model
        try:
            resp = requests.post(
                f"{self.host}/api/generate",
                json={
                    "model": model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 0.1},
                },
                timeout=120,
            )
            if resp.status_code == 200:
                result = resp.json().get("response", "")
                budget_guard.record_spend(tokens=0, cost_usd=0.001)
                return result
            return f"Error: {resp.status_code}"
        except Exception as e:
            return f"Request failed: {e}"

    def analyze_finding(self, finding: Dict) -> Dict[str, Any]:
        """Use LLM to analyze a single finding: is it real? What's the impact?"""
        prompt = f"""You are a penetration testing expert. Analyze this vulnerability finding:

Title: {finding.get('title')}
Type: {finding.get('vuln_type')}
Severity: {finding.get('severity')}
Target: {finding.get('target_url')}
Description: {finding.get('description', '')}

Answer in JSON format:
{{
  "is_real_vulnerability": true/false,
  "confidence": 0.0-1.0,
  "exploitation_difficulty": "easy/medium/hard",
  "business_impact": "low/medium/high/critical",
  "false_positive_reason": "if false positive, why",
  "recommendation": "how to fix"
}}
"""
        result = self._chat(prompt)
        try:
            # Try to extract JSON from response
            start = result.find("{")
            end = result.rfind("}") + 1
            if start >= 0 and end > start:
                return json.loads(result[start:end])
        except json.JSONDecodeError:
            pass

        return {"raw_analysis": result}

    def correlate_findings(self, findings: List[Dict]) -> Dict[str, Any]:
        """Use LLM to correlate multiple findings into attack chains."""
        findings_summary = "\n".join([
            f"- {f['title']} ({f['severity']}) at {f['target_url']}"
            for f in findings[:10]  # Limit to 10 findings
        ])

        prompt = f"""You are a penetration testing expert. Given these vulnerabilities, identify possible attack chains:

{findings_summary}

Answer in JSON format:
{{
  "attack_chains": [
    {{
      "name": "Chain name",
      "steps": ["step 1", "step 2"],
      "final_impact": "what an attacker could achieve",
      "likelihood": "low/medium/high"
    }}
  ],
  "overall_risk": "low/medium/high/critical"
}}
"""
        result = self._chat(prompt)
        try:
            start = result.find("{")
            end = result.rfind("}") + 1
            if start >= 0 and end > start:
                return json.loads(result[start:end])
        except json.JSONDecodeError:
            pass

        return {"raw_analysis": result}

    def generate_report_summary(self, target: str, findings: List[Dict]) -> str:
        """Use LLM to generate an executive summary for the report."""
        findings_list = "\n".join([
            f"- {f['title']} ({f['severity']})"
            for f in findings
        ])

        prompt = f"""You are a security consultant. Write a 2-paragraph executive summary for a penetration test report on {target}.

Findings:
{findings_list}

Write in professional business language, focus on business risk, not technical details. Keep it under 200 words.
"""
        return self._chat(prompt)

    def get_status(self) -> Dict[str, Any]:
        """Get LLM analyzer status."""
        return {
            "ollama_available": self.available,
            "default_model": self.default_model,
            "budget_status": budget_guard.get_status(),
        }


# Global instance
llm_analyzer = LLMAnalyzer()
