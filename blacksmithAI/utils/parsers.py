"""
Scanner Result Parsers - Parse actual tool output into structured findings.
Not just running commands and returning strings - real parsing of nmap, nuclei, gobuster output.
"""
import json
import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict


@dataclass
class PortInfo:
    port: int
    protocol: str
    state: str
    service: str
    version: str = ""
    product: str = ""


@dataclass
class Vulnerability:
    target: str
    vuln_type: str
    title: str
    severity: str
    description: str = ""
    evidence: str = ""
    cve: str = ""
    cvss: float = 0.0


@dataclass
class DirectoryEntry:
    path: str
    status_code: int
    size: int = 0
    redirect: str = ""


class NmapParser:
    """Parse nmap output (JSON format)."""

    def parse(self, output: str) -> Dict[str, Any]:
        """Parse nmap -oX output or try to parse text output."""
        result = {
            "ports": [],
            "hostnames": [],
            "os": "",
        }

        # Try JSON first (nmap -oX -)
        try:
            data = json.loads(output)
            return self._parse_json(data)
        except json.JSONDecodeError:
            pass

        # Fall back to text parsing
        return self._parse_text(output)

    def _parse_json(self, data: Dict) -> Dict:
        """Parse nmap XML->JSON output."""
        result = {"ports": [], "hostnames": []}
        for host in data.get("hosts", []):
            for port in host.get("ports", []):
                if port.get("state", {}).get("state") == "open":
                    service = port.get("service", {})
                    result["ports"].append(PortInfo(
                        port=port.get("portid", 0),
                        protocol=port.get("protocol", "tcp"),
                        state="open",
                        service=service.get("name", ""),
                        version=service.get("version", ""),
                        product=service.get("product", ""),
                    ))
        return result

    def _parse_text(self, output: str) -> Dict:
        """Parse nmap text output."""
        result = {"ports": []}
        lines = output.split("\n")
        for line in lines:
            # Match patterns like "22/tcp open  ssh"
            match = re.match(r"(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)(?:\s+(.*))?", line)
            if match:
                port = int(match.group(1))
                proto = match.group(2)
                state = match.group(3)
                service = match.group(4)
                version = match.group(5) or ""
                result["ports"].append(PortInfo(
                    port=port, protocol=proto, state=state,
                    service=service, version=version
                ))
        return result


class NucleiParser:
    """Parse nuclei JSONL output into structured vulnerabilities."""

    def parse(self, output: str, target: str = "") -> List[Vulnerability]:
        """Parse nuclei -json output (one JSON object per line)."""
        vulns = []
        for line in output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                info = data.get("info", {})
                vulns.append(Vulnerability(
                    target=data.get("host", target),
                    vuln_type=data.get("template-id", "unknown"),
                    title=info.get("name", data.get("template-id", "")),
                    severity=info.get("severity", "unknown"),
                    description=info.get("description", ""),
                    evidence=data.get("matched-at", ""),
                    cve=self._extract_cve(info),
                    cvss=info.get("classification", {}).get("cvss-score", 0.0),
                ))
            except json.JSONDecodeError:
                continue
        return vulns

    def _extract_cve(self, info: Dict) -> str:
        """Extract CVE ID from nuclei info."""
        classification = info.get("classification", {})
        cve_ids = classification.get("cve-id", [])
        if isinstance(cve_ids, list) and cve_ids:
            return cve_ids[0]
        return ""


class GobusterParser:
    """Parse gobuster/dirsearch output."""

    def parse(self, output: str, tool: str = "gobuster") -> List[DirectoryEntry]:
        """Parse directory brute force output."""
        entries = []
        lines = output.strip().split("\n")

        if tool == "gobuster":
            # gobuster output: /admin (Status: 200) [Size: 1234]
            for line in lines:
                match = re.match(r"(/\S+)\s+\(Status:\s+(\d+)\)\s+\[Size:\s+(\d+)\]", line)
                if match:
                    entries.append(DirectoryEntry(
                        path=match.group(1),
                        status_code=int(match.group(2)),
                        size=int(match.group(3)),
                    ))
        elif tool == "dirsearch":
            # dirsearch JSON output
            try:
                data = json.loads(output)
                for item in data.get("results", []):
                    entries.append(DirectoryEntry(
                        path=item.get("path", ""),
                        status_code=item.get("status", 0),
                        size=item.get("content-length", 0),
                    ))
            except json.JSONDecodeError:
                pass

        return entries


class WhatWebParser:
    """Parse whatweb output."""

    def parse(self, output: str) -> Dict[str, Any]:
        """Parse whatweb tech detection output."""
        result = {
            "technologies": [],
            "server": "",
            "title": "",
        }

        # whatweb output format:
        # http://example.com [200 OK] Apache[2.4.41], WordPress[5.8], ...
        match = re.search(r"\[(.*?)\]\s*(.*)", output)
        if match:
            result["title"] = match.group(1)
            techs = match.group(2).split(", ")
            result["technologies"] = [t.strip() for t in techs if t.strip()]

        return result


class ScannerParser:
    """Unified parser for all scanner outputs."""

    def __init__(self):
        self.nmap = NmapParser()
        self.nuclei = NucleiParser()
        self.gobuster = GobusterParser()
        self.whatweb = WhatWebParser()

    def parse_nmap(self, output: str) -> Dict:
        return self.nmap.parse(output)

    def parse_nuclei(self, output: str, target: str = "") -> List[Vulnerability]:
        return self.nuclei.parse(output, target)

    def parse_gobuster(self, output: str, tool: str = "gobuster") -> List[DirectoryEntry]:
        return self.gobuster.parse(output, tool)

    def parse_whatweb(self, output: str) -> Dict:
        return self.whatweb.parse(output)


# Global instance
scanner_parser = ScannerParser()
