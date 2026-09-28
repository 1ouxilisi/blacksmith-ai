"""
Multi-Agent Orchestrator - Specialized agents working together.
Based on PentAGI's multi-agent architecture (23K stars).
Each agent has a specific role: Recon, Exploitation, Coordinator.
"""
import os
import json
import time
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass, field
from utils.database import db


@dataclass
class AgentMessage:
    """Message passed between agents."""
    from_agent: str
    to_agent: str
    message_type: str  # finding, request, result, status
    content: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""

    def __post_init__(self):
        from datetime import datetime
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


class BaseAgent:
    """Base class for all agents."""

    def __init__(self, name: str, role: str):
        self.name = name
        self.role = role
        self.findings: List[Dict] = []
        self.messages: List[AgentMessage] = []
        self.busy = False

    def send_message(self, to_agent: str, msg_type: str, content: Dict):
        """Send a message to another agent."""
        msg = AgentMessage(
            from_agent=self.name,
            to_agent=to_agent,
            message_type=msg_type,
            content=content,
        )
        self.messages.append(msg)
        return msg

    def receive_message(self, msg: AgentMessage):
        """Receive a message from another agent."""
        self.messages.append(msg)
        self._handle_message(msg)

    def _handle_message(self, msg: AgentMessage):
        """Override this to handle incoming messages."""
        pass

    def run(self, target: str) -> List[Dict]:
        """Run the agent's task. Override in subclasses."""
        raise NotImplementedError


class ReconAgent(BaseAgent):
    """Reconnaissance Agent - Maps the attack surface."""

    def __init__(self):
        super().__init__(name="recon", role="reconnaissance")

    def run(self, target: str) -> List[Dict]:
        """Map the attack surface: subdomains, ports, services, tech stack."""
        self.busy = True
        findings = []

        # Subdomain enumeration
        try:
            import requests
            container_uri = os.getenv('container_uri', 'http://localhost:9756/exec')
            
            # Subfinder
            resp = requests.post(container_uri, json={
                "cmd": f"subfinder -d {target.replace('https://', '').replace('http://', '').split('/')[0]} -silent",
                "timeout": 30,
            }, timeout=35)
            if resp.status_code == 200:
                subs = resp.json().get("stdout", "").strip().split("\n")
                subs = [s for s in subs if s]
                for sub in subs[:20]:  # Limit to 20
                    findings.append({
                        "type": "subdomain",
                        "value": sub,
                        "confidence": 0.9,
                    })
        except Exception:
            pass

        # Port scanning summary (quick)
        try:
            import requests
            container_uri = os.getenv('container_uri', 'http://localhost:9756/exec')
            domain = target.replace('https://', '').replace('http://', '').split('/')[0]
            
            resp = requests.post(container_uri, json={
                "cmd": f"nmap -sT -Pn --top-ports 100 {domain} -oG -",
                "timeout": 60,
            }, timeout=65)
            if resp.status_code == 200:
                output = resp.json().get("stdout", "")
                # Parse open ports
                for line in output.split("\n"):
                    if "Ports:" in line and "open" in line:
                        findings.append({
                            "type": "open_ports",
                            "value": line.strip()[:200],
                            "confidence": 0.8,
                        })
                        break
        except Exception:
            pass

        self.findings = findings
        self.busy = False
        return findings


class ExploitationAgent(BaseAgent):
    """Exploitation Agent - Probes for specific vulnerability classes."""

    def __init__(self):
        super().__init__(name="exploit", role="exploitation")

    def run(self, target: str) -> List[Dict]:
        """Probe for vulnerabilities using nuclei."""
        self.busy = True
        findings = []

        try:
            import requests
            container_uri = os.getenv('container_uri', 'http://localhost:9756/exec')
            
            # Nuclei scan
            resp = requests.post(container_uri, json={
                "cmd": f"nuclei -u {target} -j -silent -rate-limit 50",
                "timeout": 120,
            }, timeout=125)
            if resp.status_code == 200:
                output = resp.json().get("stdout", "")
                # Parse JSONL findings
                for line in output.split("\n"):
                    line = line.strip()
                    if line:
                        try:
                            data = json.loads(line)
                            findings.append({
                                "type": "vulnerability",
                                "template": data.get("templateID", ""),
                                "severity": data.get("info", {}).get("severity", "unknown"),
                                "name": data.get("info", {}).get("name", "Unknown"),
                                "host": data.get("host", target),
                                "confidence": 0.7,
                            })
                        except json.JSONDecodeError:
                            pass
        except Exception:
            pass

        self.findings = findings
        self.busy = False
        return findings


class CoordinatorAgent(BaseAgent):
    """Coordinator Agent - Orchestrates other agents and correlates findings."""

    def __init__(self):
        super().__init__(name="coordinator", role="coordination")
        self.recon_agent = ReconAgent()
        self.exploit_agent = ExploitationAgent()
        self.all_findings: List[Dict] = []

    def run_full_assessment(self, target: str) -> Dict[str, Any]:
        """Run a full assessment: recon first, then exploitation."""
        self.busy = True
        result = {
            "target": target,
            "recon_findings": [],
            "exploit_findings": [],
            "correlated_chains": [],
            "started_at": time.time(),
        }

        # Step 1: Recon
        self.send_message("recon", "task", {"action": "recon", "target": target})
        recon_findings = self.recon_agent.run(target)
        result["recon_findings"] = recon_findings

        # Step 2: Exploitation
        self.send_message("exploit", "task", {"action": "exploit", "target": target})
        exploit_findings = self.exploit_agent.run(target)
        result["exploit_findings"] = exploit_findings

        # Step 3: Correlate findings
        self.all_findings = recon_findings + exploit_findings
        result["correlated_chains"] = self._correlate_findings()

        result["completed_at"] = time.time()
        result["duration"] = result["completed_at"] - result["started_at"]
        self.busy = False

        return result

    def _correlate_findings(self) -> List[Dict]:
        """Correlate findings into attack chains."""
        chains = []
        vuln_types = [f.get("type") for f in self.all_findings]
        severities = [f.get("severity", "unknown") for f in self.all_findings]

        # Simple correlation rules
        if "open_ports" in vuln_types and "vulnerability" in vuln_types:
            chains.append({
                "name": "Exposed Service + Known Vulnerability",
                "impact": "high",
                "description": "Open ports detected alongside known vulnerabilities",
            })

        if "subdomain" in vuln_types and "vulnerability" in vuln_types:
            chains.append({
                "name": "Subdomain Takeover Potential",
                "impact": "medium",
                "description": "Multiple subdomains found, one or more may have vulnerabilities",
            })

        return chains


# Global instance
orchestrator = CoordinatorAgent()
