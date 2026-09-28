"""
Attack Chain Analyzer - Correlate findings into exploit chains.
Based on Strix's "chain findings together" design.
A weak JWT + an IDOR = full account takeover, not two separate bugs.
"""
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
from utils.database import db


@dataclass
class AttackChain:
    """A chain of vulnerabilities leading to a goal."""
    chain_id: str
    title: str
    description: str
    steps: List[Dict[str, Any]] = field(default_factory=list)
    impact: str = "medium"  # low, medium, high, critical
    total_severity: float = 0.0


class AttackChainAnalyzer:
    """Analyze and correlate findings into attack chains."""

    # Chain templates: (vuln_types_needed, chain_title, impact)
    CHAIN_TEMPLATES = [
        (
            ["information_disclosure", "sql_injection"],
            "Database Exfiltration Chain",
            "high",
            "Information disclosure exposes sensitive data, SQLi allows direct database access",
        ),
        (
            ["weak_authentication", "idor"],
            "Account Takeover Chain",
            "critical",
            "Weak auth + IDOR = unauthorized access to other users' accounts",
        ),
        (
            ["xss", "csrf"],
            "Session Hijack Chain",
            "high",
            "XSS steals session cookies, CSRF performs actions on behalf of victim",
        ),
        (
            ["ssrf", "information_disclosure"],
            "Internal Network Access Chain",
            "critical",
            "SSRF allows reaching internal services, info disclosure reveals infrastructure",
        ),
        (
            ["file_upload", "rce"],
            "Remote Code Execution Chain",
            "critical",
            "Unrestricted file upload leads to webshell deployment and RCE",
        ),
        (
            ["directory_traversal", "information_disclosure"],
            "Sensitive File Disclosure Chain",
            "medium",
            "Path traversal reads config files, exposing credentials and secrets",
        ),
    ]

    def analyze(self) -> List[AttackChain]:
        """Analyze all findings and identify attack chains."""
        findings = db.get_findings(limit=200)
        
        # Group findings by type
        by_type = defaultdict(list)
        for f in findings:
            vuln_type = f["vuln_type"].lower()
            by_type[vuln_type].append(f)
        
        chains = []
        chain_count = 0
        
        # Check each chain template
        for needed_types, title, impact, description in self.CHAIN_TEMPLATES:
            # Find matching findings
            matching = []
            all_found = True
            for vuln_type in needed_types:
                found = by_type.get(vuln_type, [])
                if found:
                    matching.extend(found)
                else:
                    all_found = False
                    break
            
            if all_found and matching:
                chain_count += 1
                # Calculate total severity
                total_sev = sum(
                    {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(f["severity"], 1)
                    for f in matching
                )
                
                chains.append(AttackChain(
                    chain_id=f"chain_{chain_count:03d}",
                    title=title,
                    description=description,
                    steps=[{
                        "finding_id": f["id"],
                        "title": f["title"],
                        "severity": f["severity"],
                        "target": f["target_url"],
                    } for f in matching],
                    impact=impact,
                    total_severity=total_sev,
                ))
        
        return chains

    def get_chain_summary(self) -> Dict[str, Any]:
        """Get a summary of identified attack chains."""
        chains = self.analyze()
        return {
            "total_chains": len(chains),
            "critical_chains": sum(1 for c in chains if c.impact == "critical"),
            "high_chains": sum(1 for c in chains if c.impact == "high"),
            "chains": [
                {
                    "id": c.chain_id,
                    "title": c.title,
                    "impact": c.impact,
                    "steps": len(c.steps),
                    "description": c.description,
                }
                for c in chains
            ],
        }


# Global instance
attack_chain_analyzer = AttackChainAnalyzer()
