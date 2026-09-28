"""
Enhanced Scanner - Multi-tool automated scanning pipeline.
Runs nmap, nuclei, directory enumeration, and web fingerprinting in sequence.
"""
import os
import json
import requests
import time
from typing import Dict, List, Any, Optional
from utils.fp_filter import RawFinding
from utils.notifier import notifier
from utils.audit_logger import audit_logger


class EnhancedScanner:
    """Multi-tool scanner for batch vulnerability hunting."""

    def __init__(self):
        self.container_uri = os.getenv('container_uri', 'http://localhost:9756/exec')

    def _run_command(self, cmd: str, timeout: int = 300) -> Dict[str, Any]:
        """Execute command in the Docker container."""
        try:
            resp = requests.post(
                self.container_uri,
                json={"cmd": cmd, "timeout": timeout},
                timeout=timeout + 10,
            )
            if resp.status_code == 200:
                return resp.json()
            return {"error": f"Status {resp.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def scan_nmap(self, target: str) -> Dict[str, Any]:
        """Run nmap service detection."""
        # Extract IP from target if it's a URL
        import re
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', target)
        if not ip_match:
            return {"skipped": "No IP address found"}

        ip = ip_match.group(1)
        cmd = f"nmap -sV -Pn -T4 --top-ports 100 {ip}"
        print(f"[Scanner] nmap: {ip}")
        result = self._run_command(cmd, timeout=180)
        audit_logger.log_command("EnhancedScanner", cmd, severity="info")
        return result

    def scan_nuclei(self, target: str) -> List[RawFinding]:
        """Run nuclei vulnerability scanner."""
        if not target.startswith("http"):
            target = f"http://{target}"

        cmd = f"nuclei -u {target} -silent -json -timeout 30 -severity medium,high,critical"
        print(f"[Scanner] nuclei: {target}")
        result = self._run_command(cmd, timeout=300)
        audit_logger.log_command("EnhancedScanner", cmd, severity="info")

        findings = []
        output = result.get("output", "") if isinstance(result, dict) else str(result)

        for line in output.split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                finding = RawFinding(
                    target=target,
                    vuln_type=data.get("template-id", "unknown"),
                    title=data.get("info", {}).get("name", "Unknown"),
                    description=data.get("info", {}).get("description", ""),
                    evidence=line[:500],
                    scanner="nuclei",
                    severity=data.get("info", {}).get("severity", "unknown"),
                )
                findings.append(finding)
                # Notify on high/critical
                notifier.notify_finding_simple(finding)
            except json.JSONDecodeError:
                continue

        return findings

    def scan_directory_enum(self, target: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt") -> Dict[str, Any]:
        """Run directory bruteforcing."""
        if not target.startswith("http"):
            target = f"http://{target}"

        cmd = f"gobuster dir -u {target} -w {wordlist} -q --timeout 10s"
        print(f"[Scanner] gobuster: {target}")
        result = self._run_command(cmd, timeout=300)
        audit_logger.log_command("EnhancedScanner", cmd, severity="info")
        return result

    def scan_web_fingerprint(self, target: str) -> Dict[str, Any]:
        """Fingerprint web technologies."""
        if not target.startswith("http"):
            target = f"http://{target}"

        cmd = f"whatweb {target} --log-json=-"
        print(f"[Scanner] whatweb: {target}")
        result = self._run_command(cmd, timeout=60)
        return result

    def scan_ssl(self, target: str) -> Dict[str, Any]:
        """Check SSL/TLS configuration."""
        cmd = f"sslscan --no-failed {target}"
        print(f"[Scanner] sslscan: {target}")
        result = self._run_command(cmd, timeout=60)
        return result

    def full_scan(self, target: str, enable_dir_enum: bool = False) -> Dict[str, Any]:
        """Run a full scan pipeline on a single target."""
        results = {
            "target": target,
            "nmap": None,
            "nuclei_findings": [],
            "directory_enum": None,
            "web_fingerprint": None,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

        # 1. Web fingerprint (fast)
        results["web_fingerprint"] = self.scan_web_fingerprint(target)

        # 2. Nuclei (main vulnerability scanner)
        results["nuclei_findings"] = self.scan_nuclei(target)

        # 3. Nmap (if IP available)
        results["nmap"] = self.scan_nmap(target)

        # 4. Directory enum (optional, slower)
        if enable_dir_enum:
            results["directory_enum"] = self.scan_directory_enum(target)

        return results


# Global instance
enhanced_scanner = EnhancedScanner()
