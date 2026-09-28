"""
Run History & Budget Control - Track scan runs, LLM token usage, and enforce spend limits.
Based on Strix's "set a hard spend limit before first run" lesson.
"""
import os
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from utils.database import db


class RunHistory:
    """Track all scan runs with metadata and cost."""

    def __init__(self):
        self.runs_dir = "./outputs/runs"
        os.makedirs(self.runs_dir, exist_ok=True)

    def start_run(self, target: str, scan_type: str = "quick") -> str:
        """Start a new scan run, return run ID."""
        run_id = f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        run_data = {
            "run_id": run_id,
            "target": target,
            "scan_type": scan_type,
            "started_at": datetime.now().isoformat(),
            "status": "running",
            "findings_count": 0,
            "ports_found": 0,
            "llm_tokens_used": 0,
            "llm_cost_usd": 0.0,
        }
        self._save_run(run_id, run_data)
        return run_id

    def complete_run(self, run_id: str, stats: Dict[str, Any]):
        """Mark a run as completed."""
        run_data = self._load_run(run_id)
        if run_data:
            run_data.update({
                "status": "completed",
                "completed_at": datetime.now().isoformat(),
                **stats,
            })
            self._save_run(run_id, run_data)

    def _save_run(self, run_id: str, data: Dict):
        """Save run data to disk."""
        path = os.path.join(self.runs_dir, f"{run_id}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def _load_run(self, run_id: str) -> Optional[Dict]:
        """Load run data from disk."""
        path = os.path.join(self.runs_dir, f"{run_id}.json")
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        return None

    def list_runs(self, limit: int = 20) -> List[Dict]:
        """List all previous runs."""
        runs = []
        for filename in sorted(os.listdir(self.runs_dir), reverse=True):
            if filename.endswith(".json"):
                path = os.path.join(self.runs_dir, filename)
                with open(path, "r", encoding="utf-8") as f:
                    run = json.load(f)
                    runs.append(run)
                    if len(runs) >= limit:
                        break
        return runs

    def get_cost_summary(self) -> Dict[str, Any]:
        """Get cost summary across all runs."""
        runs = self.list_runs(limit=100)
        total_cost = sum(r.get("llm_cost_usd", 0) for r in runs)
        total_tokens = sum(r.get("llm_tokens_used", 0) for r in runs)
        completed = sum(1 for r in runs if r["status"] == "completed")
        
        return {
            "total_runs": len(runs),
            "completed_runs": completed,
            "total_tokens": total_tokens,
            "total_cost_usd": round(total_cost, 2),
            "avg_cost_per_run": round(total_cost / completed, 2) if completed else 0,
        }


class BudgetGuard:
    """Enforce LLM spend limits to prevent surprise bills."""

    def __init__(self):
        self.daily_limit_usd = float(os.getenv("DAILY_BUDGET_USD", "5.0"))
        self.run_limit_usd = float(os.getenv("RUN_BUDGET_USD", "1.0"))
        self.current_run_cost = 0.0
        self.daily_cost = self._load_daily_cost()

    def _load_daily_cost(self) -> float:
        """Load today's accumulated cost."""
        # In production, this would come from the database
        # For now, track in memory
        return 0.0

    def can_spend(self, estimated_cost: float = 0.01) -> bool:
        """Check if we can spend more on LLM calls."""
        if self.current_run_cost + estimated_cost > self.run_limit_usd:
            return False
        if self.daily_cost + estimated_cost > self.daily_limit_usd:
            return False
        return True

    def record_spend(self, tokens: int, cost_usd: float):
        """Record LLM usage."""
        self.current_run_cost += cost_usd
        self.daily_cost += cost_usd

    def get_status(self) -> Dict[str, Any]:
        """Get budget status."""
        return {
            "daily_limit_usd": self.daily_limit_usd,
            "daily_used_usd": round(self.daily_cost, 2),
            "daily_remaining_usd": round(self.daily_limit_usd - self.daily_cost, 2),
            "run_limit_usd": self.run_limit_usd,
            "run_used_usd": round(self.current_run_cost, 2),
            "run_remaining_usd": round(self.run_limit_usd - self.current_run_cost, 2),
        }


# Global instances
run_history = RunHistory()
budget_guard = BudgetGuard()
