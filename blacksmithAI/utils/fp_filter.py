"""
False Positive Filter - LLM-powered triage to filter out false positives
and low-quality findings before human review.
"""
import json
import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum
from agents.base import init_model
from langchain_core.messages import HumanMessage, SystemMessage


class FindingType(Enum):
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    SSRF = "ssrf"
    RCE = "rce"
    FILE_UPLOAD = "file_upload"
    LFI = "lfi"
    RFI = "rfi"
    DIRECTORY_TRAVERSAL = "directory_traversal"
    EXPOSED_PANEL = "exposed_panel"
    DEFAULT_CREDENTIALS = "default_credentials"
    INFO_DISCLOSURE = "info_disclosure"
    UNKNOWN = "unknown"


class TriageDecision(Enum):
    CONFIRMED = "confirmed"  # Likely real vulnerability
    LIKELY = "likely"        # Probably real, needs verification
    FALSE_POSITIVE = "false_positive"  # Likely false alarm
    LOW_VALUE = "low_value"   # Real but low impact


@dataclass
class RawFinding:
    """A raw finding from automated scanning."""
    target: str
    vuln_type: str
    title: str
    description: str
    evidence: str
    scanner: str = "nuclei"
    severity: str = "medium"
    cvss: float = 0.0


@dataclass
class TriageResult:
    """Result of LLM triage."""
    raw_finding: RawFinding
    decision: TriageDecision
    confidence: float  # 0-1
    reasoning: str
    suggested_severity: str
    notes: str = ""


class FalsePositiveFilter:
    """LLM-based false positive filter for automated scan results."""

    SYSTEM_PROMPT = """You are a senior penetration tester reviewing automated vulnerability scan results.
Your job is to filter out false positives and low-quality findings before human review.

For each finding, evaluate:
1. Is this a real vulnerability or a false positive?
2. What's the actual severity?
3. Is the evidence credible?

Be strict - many automated scans produce false positives.
Only mark as CONFIRMED if the evidence clearly shows a real vulnerability.

Output your analysis as JSON:
{
    "decision": "confirmed|likely|false_positive|low_value",
    "confidence": 0.0-1.0,
    "reasoning": "brief explanation",
    "suggested_severity": "critical|high|medium|low|info",
    "notes": "any additional notes"
}"""

    def __init__(self):
        self.llm = init_model().get_model()
        self.results: List[TriageResult] = []

    def triage_finding(self, finding: RawFinding) -> TriageResult:
        """Run LLM triage on a single finding."""
        user_prompt = f"""Review this scan finding:

Target: {finding.target}
Type: {finding.vuln_type}
Title: {finding.title}
Scanner: {finding.scanner}
Claimed Severity: {finding.severity}
Description: {finding.description}
Evidence:
```
{finding.evidence[:1000]}
```

Is this a real vulnerability? What's the actual severity?"""

        try:
            response = self.llm.invoke([
                SystemMessage(content=self.SYSTEM_PROMPT),
                HumanMessage(content=user_prompt),
            ])

            # Extract JSON from response
            content = response.content if hasattr(response, 'content') else str(response)
            json_match = re.search(r'\{[^}]+\}', content, re.DOTALL)

            if json_match:
                data = json.loads(json_match.group())
                result = TriageResult(
                    raw_finding=finding,
                    decision=TriageDecision(data.get("decision", "likely")),
                    confidence=float(data.get("confidence", 0.5)),
                    reasoning=data.get("reasoning", ""),
                    suggested_severity=data.get("suggested_severity", finding.severity),
                    notes=data.get("notes", ""),
                )
            else:
                result = TriageResult(
                    raw_finding=finding,
                    decision=TriageDecision.LIKELY,
                    confidence=0.5,
                    reasoning=content[:200],
                    suggested_severity=finding.severity,
                )

        except Exception as e:
            result = TriageResult(
                raw_finding=finding,
                decision=TriageDecision.LIKELY,
                confidence=0.3,
                reasoning=f"Triage failed: {e}",
                suggested_severity=finding.severity,
            )

        self.results.append(result)
        return result

    def triage_batch(self, findings: List[RawFinding]) -> List[TriageResult]:
        """Triage multiple findings."""
        results = []
        for f in findings:
            result = self.triage_finding(f)
            results.append(result)
        return results

    def get_review_queue(self) -> List[TriageResult]:
        """Get findings that need human review (not clearly false positive)."""
        return [
            r for r in self.results
            if r.decision in [TriageDecision.CONFIRMED, TriageDecision.LIKELY]
        ]

    def get_false_positives(self) -> List[TriageResult]:
        """Get findings filtered as false positives."""
        return [
            r for r in self.results
            if r.decision == TriageDecision.FALSE_POSITIVE
        ]

    def get_stats(self) -> Dict[str, int]:
        """Get triage statistics."""
        stats = {"total": len(self.results)}
        for decision in TriageDecision:
            stats[decision.value] = sum(
                1 for r in self.results if r.decision == decision
            )
        return stats

    def export_review_list(self, output_path: str):
        """Export findings ready for human review."""
        review_queue = self.get_review_queue()
        data = {
            "stats": self.get_stats(),
            "review_queue": [
                {
                    "target": r.raw_finding.target,
                    "type": r.raw_finding.vuln_type,
                    "title": r.raw_finding.title,
                    "scanner": r.raw_finding.scanner,
                    "claimed_severity": r.raw_finding.severity,
                    "suggested_severity": r.suggested_severity,
                    "confidence": r.confidence,
                    "reasoning": r.reasoning,
                    "evidence": r.raw_finding.evidence[:500],
                    "notes": r.notes,
                }
                for r in review_queue
            ],
            "filtered_false_positives": [
                {
                    "target": r.raw_finding.target,
                    "title": r.raw_finding.title,
                    "reasoning": r.reasoning,
                }
                for r in self.get_false_positives()
            ],
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)


# Global instance
fp_filter = FalsePositiveFilter()
