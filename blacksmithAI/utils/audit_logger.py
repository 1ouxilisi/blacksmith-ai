"""
Audit Logger - Complete audit trail for penetration testing operations.
Records every action, command output, timestamps, and evidence for post-engagement review.
"""
import json
import os
from datetime import datetime
from typing import Optional, Dict, Any, List
from pathlib import Path


class AuditLogger:
    """Singleton audit logger that records all pentest operations."""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_dir = Path("./outputs/audit")
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.events: List[Dict[str, Any]] = []
        self.evidence_dir = self.log_dir / self.session_id / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.log_dir / self.session_id / "audit.jsonl"
        self._write_session_start()

    def _write_session_start(self):
        event = {
            "timestamp": datetime.now().isoformat(),
            "type": "session_start",
            "session_id": self.session_id,
            "event": "Penetration testing session initialized",
        }
        self._append_event(event)

    def _append_event(self, event: Dict[str, Any]):
        self.events.append(event)
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")

    def log_command(
        self,
        agent: str,
        command: str,
        output: Optional[str] = None,
        exit_code: Optional[int] = None,
        duration_ms: Optional[int] = None,
        severity: str = "info",
    ) -> str:
        """Log a shell command execution."""
        event_id = f"cmd_{len(self.events):06d}"
        event = {
            "id": event_id,
            "timestamp": datetime.now().isoformat(),
            "type": "command",
            "agent": agent,
            "command": command,
            "output_preview": (output[:500] if output else None),
            "output_length": len(output) if output else 0,
            "exit_code": exit_code,
            "duration_ms": duration_ms,
            "severity": severity,
        }
        # Save full output as evidence file
        if output:
            evidence_file = self.evidence_dir / f"{event_id}.txt"
            with open(evidence_file, "w", encoding="utf-8") as f:
                f.write(output)
            event["evidence_file"] = str(evidence_file)
        self._append_event(event)
        return event_id

    def log_finding(
        self,
        agent: str,
        title: str,
        severity: str,
        description: str,
        evidence: Optional[str] = None,
        cve: Optional[str] = None,
        affected_target: Optional[str] = None,
    ) -> str:
        """Log a security finding."""
        event_id = f"finding_{len(self.events):06d}"
        event = {
            "id": event_id,
            "timestamp": datetime.now().isoformat(),
            "type": "finding",
            "agent": agent,
            "title": title,
            "severity": severity,
            "description": description,
            "cve": cve,
            "affected_target": affected_target,
        }
        if evidence:
            evidence_file = self.evidence_dir / f"{event_id}_evidence.txt"
            with open(evidence_file, "w", encoding="utf-8") as f:
                f.write(evidence)
            event["evidence_file"] = str(evidence_file)
        self._append_event(event)
        return event_id

    def log_decision(
        self,
        agent: str,
        decision: str,
        rationale: str,
        next_action: Optional[str] = None,
    ) -> str:
        """Log an agent decision point."""
        event_id = f"decision_{len(self.events):06d}"
        event = {
            "id": event_id,
            "timestamp": datetime.now().isoformat(),
            "type": "decision",
            "agent": agent,
            "decision": decision,
            "rationale": rationale,
            "next_action": next_action,
        }
        self._append_event(event)
        return event_id

    def log_approval(
        self,
        agent: str,
        action: str,
        approved: bool,
        approver: str = "human",
        notes: Optional[str] = None,
    ) -> str:
        """Log a human approval/rejection of an action."""
        event_id = f"approval_{len(self.events):06d}"
        event = {
            "id": event_id,
            "timestamp": datetime.now().isoformat(),
            "type": "approval",
            "agent": agent,
            "action": action,
            "approved": approved,
            "approver": approver,
            "notes": notes,
        }
        self._append_event(event)
        return event_id

    def log_agent_message(
        self,
        agent: str,
        message: str,
        direction: str = "outbound",
    ) -> str:
        """Log agent communication."""
        event_id = f"msg_{len(self.events):06d}"
        event = {
            "id": event_id,
            "timestamp": datetime.now().isoformat(),
            "type": "agent_message",
            "agent": agent,
            "message": message[:1000],
            "direction": direction,
        }
        self._append_event(event)
        return event_id

    def get_session_summary(self) -> Dict[str, Any]:
        """Generate a summary of the current session."""
        commands = [e for e in self.events if e["type"] == "command"]
        findings = [e for e in self.events if e["type"] == "finding"]
        decisions = [e for e in self.events if e["type"] == "decision"]
        approvals = [e for e in self.events if e["type"] == "approval"]

        severity_counts = {}
        for f in findings:
            sev = f.get("severity", "unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            "session_id": self.session_id,
            "total_events": len(self.events),
            "total_commands": len(commands),
            "total_findings": len(findings),
            "total_decisions": len(decisions),
            "total_approvals": len(approvals),
            "findings_by_severity": severity_counts,
            "session_duration": (
                datetime.now() - datetime.fromisoformat(self.events[0]["timestamp"])
            ).total_seconds() if self.events else 0,
        }

    def export_report(self, output_path: Optional[str] = None) -> str:
        """Export the full audit log as a JSON report."""
        if output_path is None:
            output_path = str(self.log_dir / self.session_id / "session_report.json")

        report = {
            "session_summary": self.get_session_summary(),
            "events": self.events,
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        return output_path


# Global instance
audit_logger = AuditLogger()
