"""
Human-in-the-Loop Approval System.
Implements approval gates for high-risk operations before they execute.
"""
from enum import Enum
from typing import Optional, Dict, Any, Callable
from utils.audit_logger import audit_logger


class RiskLevel(Enum):
    LOW = "low"          # Safe to auto-execute (recon, non-intrusive scan)
    MEDIUM = "medium"    # Default to auto, but log (port scan, enum)
    HIGH = "high"        # Requires approval (active exploitation, brute force)
    CRITICAL = "critical"  # Always requires approval (destructive ops, DoS, data exfil)


class ApprovalDecision(Enum):
    APPROVED = "approved"
    REJECTED = "rejected"
    SKIPPED = "skipped"


# Default risk levels for common operations
RISK_PRESETS = {
    # Recon - low risk
    "nmap -sV": RiskLevel.MEDIUM,
    "nmap -Pn": RiskLevel.MEDIUM,
    "whois": RiskLevel.LOW,
    "dig": RiskLevel.LOW,
    "subfinder": RiskLevel.LOW,
    "assetfinder": RiskLevel.LOW,

    # Scanning - medium risk
    "gobuster": RiskLevel.MEDIUM,
    "feroxbuster": RiskLevel.MEDIUM,
    "wpscan": RiskLevel.MEDIUM,
    "nuclei": RiskLevel.MEDIUM,

    # Exploitation - high risk
    "sqlmap": RiskLevel.HIGH,
    "hydra": RiskLevel.HIGH,
    "medusa": RiskLevel.HIGH,
    "ncrack": RiskLevel.HIGH,
    "metasploit": RiskLevel.HIGH,
    "msfconsole": RiskLevel.HIGH,
    "searchsploit": RiskLevel.MEDIUM,

    # Post-exploitation - critical
    "impacket": RiskLevel.HIGH,
    "secretsdump": RiskLevel.CRITICAL,
    "psexec": RiskLevel.CRITICAL,
    "mimikatz": RiskLevel.CRITICAL,
    "rm -rf": RiskLevel.CRITICAL,
    "dd": RiskLevel.CRITICAL,
    "shutdown": RiskLevel.CRITICAL,
}


class ApprovalGate:
    """Manages approval workflow for high-risk operations."""

    def __init__(self, auto_approve_below: RiskLevel = RiskLevel.MEDIUM):
        self.auto_approve_below = auto_approve_below
        self.pending_approvals: Dict[str, Dict[str, Any]] = {}
        self.approval_history: list = []
        self._approval_callback: Optional[Callable] = None

    def set_approval_callback(self, callback: Callable[[str, str, str], ApprovalDecision]):
        """Set the function called when approval is needed.
        Callback should take (action_description, risk_level, command) and return ApprovalDecision.
        """
        self._approval_callback = callback

    def assess_risk(self, command: str) -> RiskLevel:
        """Assess risk level of a command based on presets."""
        command_lower = command.lower().strip()

        # Check for critical patterns first
        critical_patterns = ["rm -rf", "mkfs", "dd if=", "shutdown", "reboot", "format"]
        for pattern in critical_patterns:
            if pattern in command_lower:
                return RiskLevel.CRITICAL

        # Check against presets
        for preset_cmd, risk in RISK_PRESETS.items():
            if preset_cmd.lower() in command_lower:
                return risk

        # Default to medium for unknown commands
        return RiskLevel.MEDIUM

    def request_approval(
        self,
        agent: str,
        command: str,
        reason: str,
        risk_level: Optional[RiskLevel] = None,
    ) -> ApprovalDecision:
        """Request approval for a potentially dangerous operation."""
        if risk_level is None:
            risk_level = self.assess_risk(command)

        # Auto-approve low/medium risk based on threshold
        if risk_level.value <= self.auto_approve_below.value:
            audit_logger.log_approval(
                agent=agent,
                action=command,
                approved=True,
                approver="auto",
                notes=f"Auto-approved (risk: {risk_level.value})",
            )
            return ApprovalDecision.APPROVED

        # Need human approval
        approval_id = f"approval_{len(self.approval_history):06d}"
        self.pending_approvals[approval_id] = {
            "agent": agent,
            "command": command,
            "reason": reason,
            "risk_level": risk_level.value,
        }

        print(f"\n{'='*60}")
        print(f"[APPROVAL REQUIRED] Risk: {risk_level.value.upper()}")
        print(f"Agent: {agent}")
        print(f"Command: {command}")
        print(f"Reason: {reason}")
        print(f"{'='*60}")

        if self._approval_callback:
            decision = self._approval_callback(command, risk_level.value, reason)
        else:
            # Default: prompt user (CLI mode)
            user_input = input("Approve this action? (y/n/s=skip): ").strip().lower()
            if user_input == "y":
                decision = ApprovalDecision.APPROVED
            elif user_input == "s":
                decision = ApprovalDecision.SKIPPED
            else:
                decision = ApprovalDecision.REJECTED

        # Log the decision
        audit_logger.log_approval(
            agent=agent,
            action=command,
            approved=(decision == ApprovalDecision.APPROVED),
            approver="human" if not self._approval_callback else "callback",
            notes=f"Risk level: {risk_level.value}",
        )

        self.approval_history.append({
            "id": approval_id,
            "command": command,
            "risk_level": risk_level.value,
            "decision": decision.value,
        })

        if approval_id in self.pending_approvals:
            del self.pending_approvals[approval_id]

        return decision

    def get_pending_count(self) -> int:
        return len(self.pending_approvals)

    def get_approval_stats(self) -> Dict[str, int]:
        approved = sum(1 for a in self.approval_history if a["decision"] == "approved")
        rejected = sum(1 for a in self.approval_history if a["decision"] == "rejected")
        skipped = sum(1 for a in self.approval_history if a["decision"] == "skipped")
        return {
            "total": len(self.approval_history),
            "approved": approved,
            "rejected": rejected,
            "skipped": skipped,
        }


# Global instance
approval_gate = ApprovalGate()
