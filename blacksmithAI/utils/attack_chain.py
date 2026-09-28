"""
Attack Chain Analyzer - Maps and visualizes the attack chain from recon to post-exploitation.
Builds a dependency graph showing how findings lead to exploitation paths.
"""
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from enum import Enum
import json
from utils.audit_logger import audit_logger


class ChainPhase(Enum):
    RECON = "reconnaissance"
    SCAN = "scanning_enumeration"
    VULN = "vulnerability_mapping"
    EXPLOIT = "exploitation"
    POST_EXPLOIT = "post_exploitation"


class ChainStatus(Enum):
    DISCOVERED = "discovered"
    CONFIRMED = "confirmed"
    EXPLOITED = "exploited"
    BLOCKED = "blocked"


@dataclass
class AttackNode:
    """A single node in the attack chain."""
    node_id: str
    phase: ChainPhase
    title: str
    description: str
    status: ChainStatus = ChainStatus.DISCOVERED
    severity: str = "info"
    parent_ids: List[str] = field(default_factory=list)
    evidence: Optional[str] = None
    timestamp: str = field(default_factory=lambda: __import__('datetime').datetime.now().isoformat())


@dataclass
class AttackChain:
    """A complete attack chain from initial access to objective."""
    chain_id: str
    target: str
    nodes: List[AttackNode] = field(default_factory=list)
    success: bool = False
    notes: str = ""

    def add_node(self, node: AttackNode):
        self.nodes.append(node)
        audit_logger.log_decision(
            agent="AttackChain",
            decision=f"Added node: {node.title}",
            rationale=f"Phase: {node.phase.value}, Status: {node.status.value}",
        )

    def get_nodes_by_phase(self, phase: ChainPhase) -> List[AttackNode]:
        return [n for n in self.nodes if n.phase == phase]

    def get_attack_paths(self) -> List[List[AttackNode]]:
        """Find all paths from recon to post-exploitation."""
        paths = []
        start_nodes = [n for n in self.nodes if not n.parent_ids]

        def dfs(node: AttackNode, path: List[AttackNode]):
            path.append(node)
            children = [n for n in self.nodes if node.node_id in n.parent_ids]
            if not children:
                paths.append(path.copy())
            for child in children:
                dfs(child, path)
            path.pop()

        for start in start_nodes:
            dfs(start, [])
        return paths

    def get_critical_path(self) -> Optional[List[AttackNode]]:
        """Get the most successful attack path (with exploited nodes)."""
        paths = self.get_attack_paths()
        if not paths:
            return None

        def path_score(path):
            score = 0
            for node in path:
                if node.status == ChainStatus.EXPLOITED:
                    score += 10
                elif node.status == ChainStatus.CONFIRMED:
                    score += 5
                severity_scores = {"critical": 10, "high": 7, "medium": 4, "low": 2}
                score += severity_scores.get(node.severity, 1)
            return score

        return max(paths, key=path_score)


class AttackChainManager:
    """Manages multiple attack chains for a pentest engagement."""

    def __init__(self):
        self.chains: Dict[str, AttackChain] = {}

    def create_chain(self, target: str) -> AttackChain:
        chain_id = f"chain_{len(self.chains) + 1}"
        chain = AttackChain(chain_id=chain_id, target=target)
        self.chains[chain_id] = chain
        audit_logger.log_decision(
            agent="AttackChainManager",
            decision=f"Created attack chain for target: {target}",
            rationale="New engagement started",
        )
        return chain

    def get_chain(self, chain_id: str) -> Optional[AttackChain]:
        return self.chains.get(chain_id)

    def generate_visualization(self, chain_id: str) -> str:
        """Generate a text-based visualization of the attack chain."""
        chain = self.get_chain(chain_id)
        if not chain:
            return "Chain not found"

        viz_lines = []
        viz_lines.append(f"=== Attack Chain: {chain.target} ===")
        viz_lines.append(f"Chain ID: {chain.chain_id}")
        viz_lines.append(f"Nodes: {len(chain.nodes)}")
        viz_lines.append(f"Successful: {'Yes' if chain.success else 'No'}")
        viz_lines.append("")

        phases = [
            (ChainPhase.RECON, "RECON"),
            (ChainPhase.SCAN, "SCAN/ENUM"),
            (ChainPhase.VULN, "VULN MAP"),
            (ChainPhase.EXPLOIT, "EXPLOIT"),
            (ChainPhase.POST_EXPLOIT, "POST-EXPLOIT"),
        ]

        for phase, label in phases:
            nodes = chain.get_nodes_by_phase(phase)
            viz_lines.append(f"[{label}]")
            if not nodes:
                viz_lines.append("  (empty)")
            for node in nodes:
                status_icon = {
                    ChainStatus.DISCOVERED: "[?]",
                    ChainStatus.CONFIRMED: "[+]",
                    ChainStatus.EXPLOITED: "[!]",
                    ChainStatus.BLOCKED: "[X]",
                }.get(node.status, "[ ]")
                sev_tag = f"({node.severity.upper()})" if node.severity != "info" else ""
                viz_lines.append(f"  {status_icon} {node.title} {sev_tag}")
                if node.description:
                    viz_lines.append(f"      {node.description[:80]}")
            viz_lines.append("")

        # Show critical path
        critical = chain.get_critical_path()
        if critical:
            viz_lines.append("=== Critical Path ===")
            viz_lines.append(" -> ".join([n.title for n in critical]))

        return "\n".join(viz_lines)

    def export_chains_json(self, output_path: str):
        """Export all chains as JSON."""
        data = {
            "chains": [
                {
                    "chain_id": c.chain_id,
                    "target": c.target,
                    "success": c.success,
                    "notes": c.notes,
                    "nodes": [
                        {
                            "node_id": n.node_id,
                            "phase": n.phase.value,
                            "title": n.title,
                            "description": n.description,
                            "status": n.status.value,
                            "severity": n.severity,
                            "parent_ids": n.parent_ids,
                            "timestamp": n.timestamp,
                        }
                        for n in c.nodes
                    ],
                }
                for c in self.chains.values()
            ]
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)


# Global instance
chain_manager = AttackChainManager()
