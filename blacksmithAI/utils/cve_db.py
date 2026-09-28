"""
CVE/EXP Database - Search CVE details and find public exploits.
Integrates with NVD, Exploit-DB, and GitHub for vulnerability intelligence.
"""
import os
import json
import requests
from typing import List, Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class CVEInfo:
    """CVE vulnerability information."""
    cve_id: str
    description: str = ""
    severity: str = "unknown"
    cvss_score: float = 0.0
    published: str = ""
    references: List[str] = None
    exploits: List[Dict[str, str]] = None

    def __post_init__(self):
        if self.references is None:
            self.references = []
        if self.exploits is None:
            self.exploits = []


class CVEDatabase:
    """CVE and exploit database lookup."""

    NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    EXPLOIT_DB_API = "https://www.exploit-db.com/api"
    GITHUB_EXPLOIT_SEARCH = "https://api.github.com/search/repositories"

    def __init__(self):
        self.github_token = os.getenv("GITHUB_TOKEN", "")

    def lookup_cve(self, cve_id: str) -> Optional[CVEInfo]:
        """Look up CVE details from NVD."""
        try:
            resp = requests.get(
                self.NVD_API,
                params={"cveId": cve_id},
                timeout=30,
            )
            data = resp.json()
            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                return None

            cve_data = vulnerabilities[0].get("cve", {})
            descriptions = cve_data.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d["lang"] == "en"),
                ""
            )

            # Get CVSS score
            metrics = cve_data.get("metrics", {})
            cvss_score = 0.0
            severity = "unknown"
            if "cvssMetricV31" in metrics:
                cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                severity = cvss_data.get("baseSeverity", "unknown")
            elif "cvssMetricV2" in metrics:
                cvss_data = metrics["cvssMetricV2"][0]
                cvss_score = cvss_data.get("baseScore", 0.0)
                severity = cvss_data.get("baseSeverity", "unknown")

            # References
            references = [
                ref.get("url", "")
                for ref in cve_data.get("references", [])
            ]

            return CVEInfo(
                cve_id=cve_id,
                description=description,
                severity=severity.lower(),
                cvss_score=cvss_score,
                published=cve_data.get("published", ""),
                references=references,
            )

        except Exception as e:
            print(f"[CVE] Lookup failed: {e}")
            return None

    def search_exploits(self, cve_id: str) -> List[Dict[str, str]]:
        """Search for public exploits for a CVE."""
        exploits = []

        # Search GitHub
        try:
            headers = {}
            if self.github_token:
                headers["Authorization"] = f"token {self.github_token}"

            resp = requests.get(
                self.GITHUB_EXPLOIT_SEARCH,
                params={"q": cve_id, "sort": "stars", "per_page": 5},
                headers=headers,
                timeout=30,
            )
            data = resp.json()
            for item in data.get("items", []):
                exploits.append({
                    "source": "github",
                    "title": item.get("full_name", ""),
                    "url": item.get("html_url", ""),
                    "stars": item.get("stargazers_count", 0),
                    "description": item.get("description", ""),
                })
        except Exception as e:
            print(f"[CVE] GitHub exploit search failed: {e}")

        return exploits

    def get_full_info(self, cve_id: str) -> Optional[CVEInfo]:
        """Get full CVE info including exploits."""
        cve = self.lookup_cve(cve_id)
        if cve:
            cve.exploits = self.search_exploits(cve_id)
        return cve

    def search_by_keyword(self, keyword: str, limit: int = 10) -> List[CVEInfo]:
        """Search CVEs by keyword."""
        try:
            resp = requests.get(
                self.NVD_API,
                params={"keywordSearch": keyword, "resultsPerPage": limit},
                timeout=30,
            )
            data = resp.json()
            results = []
            for vuln in data.get("vulnerabilities", []):
                cve_data = vuln.get("cve", {})
                cve_id = cve_data.get("id", "")
                descriptions = cve_data.get("descriptions", [])
                description = next(
                    (d["value"] for d in descriptions if d["lang"] == "en"),
                    ""
                )
                results.append(CVEInfo(
                    cve_id=cve_id,
                    description=description[:200],
                ))
            return results
        except Exception as e:
            print(f"[CVE] Keyword search failed: {e}")
            return []


# Global instance
cve_db = CVEDatabase()
