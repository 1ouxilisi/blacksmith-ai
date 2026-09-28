"""
Agent Memory / Knowledge Graph - Persistent memory for agents.
Based on PentAGI's knowledge graph memory system.
Agents remember what they've found before, so they don't re-scan the same stuff.
"""
import os
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from utils.database import db


class AgentMemory:
    """Persistent memory for AI agents.
    Stores: past findings, target profiles, learned attack patterns.
    """

    def __init__(self):
        self.memory_dir = "./outputs/memory"
        os.makedirs(self.memory_dir, exist_ok=True)
        self.target_profiles: Dict[str, Dict] = {}
        self._load_target_profiles()

    def _load_target_profiles(self):
        """Load all target profiles from disk."""
        if os.path.exists(self.memory_dir):
            for filename in os.listdir(self.memory_dir):
                if filename.endswith(".json"):
                    path = os.path.join(self.memory_dir, filename)
                    with open(path, "r", encoding="utf-8") as f:
                        profile = json.load(f)
                        self.target_profiles[profile["domain"]] = profile

    def remember_target(self, domain: str, data: Dict[str, Any]):
        """Save what we learned about a target."""
        profile = {
            "domain": domain,
            "last_scanned": datetime.now().isoformat(),
            "history": self.target_profiles.get(domain, {}).get("history", []),
            **data,
        }
        # Add to scan history
        profile["history"].append({
            "timestamp": datetime.now().isoformat(),
            "findings_count": len(data.get("findings", [])),
        })
        # Keep only last 10 scans
        profile["history"] = profile["history"][-10:]

        self.target_profiles[domain] = profile

        # Save to disk
        path = os.path.join(self.memory_dir, f"{domain.replace('.', '_')}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(profile, f, indent=2, ensure_ascii=False)

    def recall_target(self, domain: str) -> Optional[Dict]:
        """Recall what we know about a target."""
        return self.target_profiles.get(domain)

    def should_skip(self, domain: str, days_threshold: int = 7) -> bool:
        """Check if we already scanned this target recently."""
        profile = self.recall_target(domain)
        if not profile:
            return False

        last_scanned = profile.get("last_scanned")
        if not last_scanned:
            return False

        try:
            last_time = datetime.fromisoformat(last_scanned)
            days_ago = (datetime.now() - last_time).days
            return days_ago < days_threshold
        except (ValueError, TypeError):
            return False

    def get_learned_patterns(self) -> List[Dict]:
        """Get attack patterns learned from past scans."""
        patterns = []
        for domain, profile in self.target_profiles.items():
            findings = profile.get("findings", [])
            for f in findings:
                patterns.append({
                    "domain": domain,
                    "vuln_type": f.get("vuln_type"),
                    "severity": f.get("severity"),
                    "learned_at": profile.get("last_scanned"),
                })
        return patterns

    def get_memory_summary(self) -> Dict[str, Any]:
        """Get summary of what the agent remembers."""
        total_targets = len(self.target_profiles)
        total_findings = sum(
            len(p.get("findings", [])) for p in self.target_profiles.values()
        )
        return {
            "total_targets_remembered": total_targets,
            "total_findings_remembered": total_findings,
            "targets": list(self.target_profiles.keys()),
        }


# Global instance
agent_memory = AgentMemory()
