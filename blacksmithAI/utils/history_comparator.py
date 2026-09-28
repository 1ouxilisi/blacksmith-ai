"""
History Comparator - Compare scan results over time to find new vulnerabilities.
"""
import os
import json
from typing import List, Dict, Any, Optional
from datetime import datetime
from dataclasses import dataclass, field


@dataclass
class DiffResult:
    """Result of comparing two scan results."""
    new_findings: List[Dict[str, Any]] = field(default_factory=list)
    resolved_findings: List[Dict[str, Any]] = field(default_factory=list)
    unchanged_findings: List[Dict[str, Any]] = field(default_factory=list)
    new_targets: List[str] = field(default_factory=list)
    offline_targets: List[str] = field(default_factory=list)


class HistoryComparator:
    """Compare historical scan results to identify changes."""

    def __init__(self, history_dir: str = "./outputs/history"):
        self.history_dir = history_dir
        os.makedirs(history_dir, exist_ok=True)

    def save_snapshot(self, name: str, data: Dict[str, Any]):
        """Save a scan snapshot for future comparison."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{name}_{timestamp}.json"
        filepath = os.path.join(self.history_dir, filename)

        snapshot = {
            "timestamp": datetime.now().isoformat(),
            "name": name,
            "data": data,
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=2, ensure_ascii=False)

        return filepath

    def load_snapshots(self, name: str) -> List[Dict[str, Any]]:
        """Load all snapshots for a given name."""
        snapshots = []
        for filename in sorted(os.listdir(self.history_dir)):
            if filename.startswith(name) and filename.endswith(".json"):
                filepath = os.path.join(self.history_dir, filename)
                with open(filepath, "r", encoding="utf-8") as f:
                    snapshots.append(json.load(f))
        return snapshots

    def compare(self, previous: Dict[str, Any], current: Dict[str, Any]) -> DiffResult:
        """Compare two scan results."""
        result = DiffResult()

        # Compare findings
        prev_findings = {f.get("title", ""): f for f in previous.get("findings", [])}
        curr_findings = {f.get("title", ""): f for f in current.get("findings", [])}

        # New findings
        for title, finding in curr_findings.items():
            if title not in prev_findings:
                result.new_findings.append(finding)

        # Resolved findings
        for title, finding in prev_findings.items():
            if title not in curr_findings:
                result.resolved_findings.append(finding)

        # Unchanged findings
        for title in curr_findings:
            if title in prev_findings:
                result.unchanged_findings.append(curr_findings[title])

        # Compare targets
        prev_targets = set(previous.get("targets", []))
        curr_targets = set(current.get("targets", []))
        result.new_targets = list(curr_targets - prev_targets)
        result.offline_targets = list(prev_targets - curr_targets)

        return result

    def get_latest_two(self, name: str) -> Optional[tuple]:
        """Get the two most recent snapshots for comparison."""
        snapshots = self.load_snapshots(name)
        if len(snapshots) < 2:
            return None
        return snapshots[-2], snapshots[-1]

    def compare_latest(self, name: str) -> Optional[DiffResult]:
        """Compare the two most recent scans."""
        pair = self.get_latest_two(name)
        if not pair:
            return None
        prev, curr = pair
        return self.compare(prev.get("data", {}), curr.get("data", {}))


# Global instance
history_comparator = HistoryComparator()
