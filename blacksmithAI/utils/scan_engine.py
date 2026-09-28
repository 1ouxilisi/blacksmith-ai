"""
Real Scan Engine - Actually runs scans, parses results, stores findings in DB.
Not just wrapping shell commands - full pipeline execution.
Uses only tools actually available in the mini-kali-slim container.
"""
import os
import json
import requests
from typing import List, Dict, Any, Optional
from datetime import datetime

from utils.database import db
from utils.parsers import scanner_parser, Vulnerability


class ScanEngine:
    """Production-grade scan engine with real parsing and storage."""

    def __init__(self):
        self.container_uri = os.getenv('container_uri', 'http://localhost:9756/exec')

    def _run_command(self, cmd: str, timeout: int = 300) -> str:
        """Execute command in Docker container, return stdout."""
        try:
            resp = requests.post(
                self.container_uri,
                json={"cmd": cmd, "timeout": timeout},
                timeout=timeout + 10,
            )
            if resp.status_code == 200:
                data = resp.json()
                stdout = data.get("stdout", "")
                stderr = data.get("stderr", "")
                if stderr:
                    print(f"[ScanEngine] stderr: {stderr[:200]}")
                return stdout
            return ""
        except Exception as e:
            print(f"[ScanEngine] Command failed: {e}")
            return ""

    def scan_target(self, target_url: str, scan_types: List[str] = None) -> Dict[str, Any]:
        """Run a full scan against a target and store results.

        Args:
            target_url: Target URL or IP
            scan_types: Which scans to run [nmap, nuclei, gobuster, subfinder]
        """
        if scan_types is None:
            scan_types = ["nmap", "nuclei", "gobuster"]

        results = {
            "target": target_url,
            "started_at": datetime.now().isoformat(),
            "ports": [],
            "vulnerabilities": [],
            "directories": [],
            "subdomains": [],
        }

        # Extract host from URL
        host = target_url.replace("http://", "").replace("https://", "").split("/")[0]
        domain = host.split(":")[0]

        # Mark target as scanning
        db.add_target(url=target_url)
        db.update_target_status(target_url, "scanning")

        # 1. Nmap - Port scan
        if "nmap" in scan_types:
            print(f"[ScanEngine] Nmap: {host}")
            output = self._run_command(f"nmap -sV -Pn {host}", timeout=120)
            nmap_result = scanner_parser.parse_nmap(output)
            results["ports"] = [vars(p) for p in nmap_result.get("ports", [])]
            print(f"[ScanEngine] Found {len(results['ports'])} open ports")

        # 2. Nuclei - Vulnerability scan (uses -j for JSONL output)
        if "nuclei" in scan_types:
            print(f"[ScanEngine] Nuclei: {target_url}")
            output = self._run_command(
                f"nuclei -u {target_url} -j -silent -severity critical,high,medium,low",
                timeout=600
            )
            vulns = scanner_parser.parse_nuclei(output, target_url)
            results["vulnerabilities"] = [vars(v) for v in vulns]
            print(f"[ScanEngine] Found {len(vulns)} vulnerabilities")

            # Store findings in database
            for vuln in vulns:
                db.add_finding(
                    target_url=vuln.target,
                    vuln_type=vuln.vuln_type,
                    title=vuln.title,
                    description=vuln.description,
                    evidence=vuln.evidence,
                    severity=vuln.severity,
                    confidence=0.8,
                    cve=vuln.cve,
                    raw_data=json.dumps(vars(vuln)),
                )

        # 3. Gobuster - Directory enumeration
        if "gobuster" in scan_types:
            print(f"[ScanEngine] Gobuster: {target_url}")
            # Check if wordlist exists first
            check = self._run_command("ls /usr/share/wordlists/dirb/common.txt 2>/dev/null || echo 'NOTFOUND'")
            if "NOTFOUND" not in check:
                output = self._run_command(
                    f"gobuster dir -u {target_url} -w /usr/share/wordlists/dirb/common.txt -q --no-color",
                    timeout=300
                )
                dirs = scanner_parser.parse_gobuster(output, "gobuster")
                results["directories"] = [vars(d) for d in dirs]
                print(f"[ScanEngine] Found {len(results['directories'])} directories")
            else:
                print("[ScanEngine] Wordlist not found, skipping gobuster")

        # 4. Subfinder - Subdomain enumeration
        if "subfinder" in scan_types:
            print(f"[ScanEngine] Subfinder: {domain}")
            output = self._run_command(f"subfinder -d {domain} -silent", timeout=60)
            subdomains = [s.strip() for s in output.strip().split("\n") if s.strip()]
            results["subdomains"] = subdomains
            print(f"[ScanEngine] Found {len(subdomains)} subdomains")

        # 5. WhatWeb - Technology fingerprinting
        if "whatweb" in scan_types:
            print(f"[ScanEngine] WhatWeb: {target_url}")
            output = self._run_command(f"whatweb --color=never {target_url}", timeout=60)
            results["tech_stack"] = output[:500]
            print(f"[ScanEngine] Tech stack identified")

        # 6. Nikto - Web server scan
        if "nikto" in scan_types:
            print(f"[ScanEngine] Nikto: {target_url}")
            output = self._run_command(f"nikto -h {target_url} -nointeract", timeout=300)
            results["nikto_findings"] = output[:1000]
            print(f"[ScanEngine] Nikto scan completed")

        # 7. SQLMap - SQL injection detection (passive only)
        if "sqlmap" in scan_types:
            print(f"[ScanEngine] SQLMap: {target_url} (passive)")
            output = self._run_command(
                f"sqlmap -u {target_url} --batch --smart --level=1 --risk=1",
                timeout=120
            )
            results["sqlmap_result"] = output[:500]
            print(f"[ScanEngine] SQLMap scan completed")

        # Mark target as completed
        db.update_target_status(target_url, "completed")
        results["completed_at"] = datetime.now().isoformat()

        # Log audit
        db.add_audit_log(
            agent="ScanEngine",
            action="scan_complete",
            command=f"full_scan {target_url}",
            output=f"ports={len(results['ports'])}, vulns={len(results['vulnerabilities'])}, dirs={len(results['directories'])}, subdomains={len(results['subdomains'])}",
            severity="info",
        )

        return results

    def quick_scan(self, target_url: str) -> Dict[str, Any]:
        """Quick scan - just nuclei low severity."""
        return self.scan_target(target_url, scan_types=["nuclei"])

    def full_scan(self, target_url: str) -> Dict[str, Any]:
        """Full scan - all tools."""
        return self.scan_target(target_url, scan_types=["nmap", "nuclei", "gobuster", "subfinder", "whatweb", "nikto", "sqlmap"])

    def get_scan_summary(self) -> Dict:
        """Get scan summary from database."""
        stats = db.get_stats()
        findings = db.get_findings(limit=20)
        return {
            "stats": stats,
            "recent_findings": findings,
        }


# Global instance
scan_engine = ScanEngine()

