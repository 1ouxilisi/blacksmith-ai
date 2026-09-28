"""
Additional Scanners - More specialized scanning tools.
WPScan, Nikto, ZAP, Dirsearch, and more.
"""
import os
import requests
from typing import Dict, List, Any, Optional
from utils.audit_logger import audit_logger


class AdditionalScanners:
    """Additional specialized scanning tools."""

    def __init__(self):
        self.container_uri = os.getenv('container_uri', 'http://localhost:9756/exec')

    def _run_command(self, cmd: str, timeout: int = 300) -> Dict[str, Any]:
        """Execute command in Docker container."""
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

    def scan_wordpress(self, url: str) -> Dict[str, Any]:
        """Run WPScan against WordPress sites."""
        cmd = f"wpscan --url {url} --no-banner --format json"
        print(f"[Scanner] wpscan: {url}")
        result = self._run_command(cmd, timeout=300)
        audit_logger.log_command("AdditionalScanners", cmd, severity="info")
        return result

    def scan_nikto(self, url: str) -> Dict[str, Any]:
        """Run Nikto web server scanner."""
        cmd = f"nikto -h {url} -Format json -output -"
        print(f"[Scanner] nikto: {url}")
        result = self._run_command(cmd, timeout=600)
        audit_logger.log_command("AdditionalScanners", cmd, severity="info")
        return result

    def scan_directory_search(self, url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt") -> Dict[str, Any]:
        """Run dirsearch for directory enumeration."""
        cmd = f"dirsearch -u {url} -w {wordlist} --format json -q"
        print(f"[Scanner] dirsearch: {url}")
        result = self._run_command(cmd, timeout=300)
        return result

    def scan_ssl(self, target: str) -> Dict[str, Any]:
        """Check SSL/TLS configuration."""
        cmd = f"sslscan --no-failed {target}"
        print(f"[Scanner] sslscan: {target}")
        result = self._run_command(cmd, timeout=60)
        return result

    def scan_subdomain(self, domain: str) -> Dict[str, Any]:
        """Enumerate subdomains."""
        cmd = f"subfinder -d {domain} -silent"
        print(f"[Scanner] subfinder: {domain}")
        result = self._run_command(cmd, timeout=120)
        return result

    def scan_whois(self, domain: str) -> Dict[str, Any]:
        """WHOIS lookup."""
        cmd = f"whois {domain}"
        result = self._run_command(cmd, timeout=30)
        return result

    def scan_dns(self, domain: str) -> Dict[str, Any]:
        """DNS enumeration."""
        cmd = f"dig {domain} ANY +short"
        result = self._run_command(cmd, timeout=30)
        return result

    def full_web_scan(self, url: str) -> Dict[str, Any]:
        """Run a comprehensive web scan."""
        results = {
            "target": url,
            "wpscan": None,
            "nikto": None,
            "ssl": None,
            "timestamp": "",
        }

        # Check if WordPress
        results["wpscan"] = self.scan_wordpress(url)

        # Nikto
        results["nikto"] = self.scan_nikto(url)

        # SSL check
        if "https" in url:
            results["ssl"] = self.scan_ssl(url)

        return results


# Global instance
additional_scanners = AdditionalScanners()
