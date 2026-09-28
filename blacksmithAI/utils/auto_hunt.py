"""
Auto Hunt Pipeline - End-to-end automated vulnerability hunting pipeline.
Collects targets -> queues them -> runs automated scans -> filters false positives -> produces review list.
"""
import os
import json
import time
from typing import List, Dict, Any, Optional
from datetime import datetime
from utils.asset_collector import asset_collector, Target
from utils.task_queue import task_queue, TaskStatus
from utils.fp_filter import fp_filter, RawFinding, TriageDecision
from utils.audit_logger import audit_logger


class AutoHuntPipeline:
    """Automated vulnerability hunting pipeline."""

    def __init__(self):
        self.running = False
        self.start_time: Optional[datetime] = None

    def collect_targets(self, source: str, query: str, size: int = 100) -> int:
        """Step 1: Collect targets from asset search engine."""
        targets = asset_collector.collect(source, query, size=size)
        print(f"[AutoHunt] Collected {len(targets)} targets from {source}")
        audit_logger.log_decision(
            agent="AutoHuntPipeline",
            decision=f"Collected {len(targets)} targets from {source}",
            rationale=f"Query: {query[:100]}",
        )
        return len(targets)

    def probe_targets(self) -> int:
        """Step 2: Probe which targets are alive."""
        alive = asset_collector.probe_all_alive()
        print(f"[AutoHunt] {alive} targets alive")
        return alive

    def build_queue(self, top_n: int = 50):
        """Step 3: Build task queue from top scored targets."""
        top_targets = asset_collector.get_top_targets(top_n)
        task_queue.add_targets(top_targets)
        stats = task_queue.get_stats()
        print(f"[AutoHunt] Queue built: {stats}")
        return stats

    def run_automated_scan(self, target_url: str) -> Dict[str, Any]:
        """
        Step 4: Run automated scan on a single target using enhanced scanner.
        Executes web fingerprinting + nuclei + nmap via the Docker shell.
        """
        from utils.enhanced_scanner import enhanced_scanner

        results = enhanced_scanner.full_scan(target_url)
        return results

    def run_batch(self, max_targets: int = 20):
        """Run the full batch pipeline."""
        self.running = True
        self.start_time = datetime.now()
        print(f"[AutoHunt] Starting batch hunt on {max_targets} targets...")

        tasks_processed = 0
        while self.running and tasks_processed < max_targets:
            task = task_queue.get_next_task()
            if not task:
                print("[AutoHunt] No more tasks in queue")
                break

            print(f"[AutoHunt] Scanning: {task.target.url} (score: {task.target.score})")
            audit_logger.log_command(
                agent="AutoHuntWorker",
                command=f"auto-scan {task.target.url}",
                severity="info",
            )

            try:
                results = self.run_automated_scan(task.target.url)
                task_queue.complete_task(task, results)
                tasks_processed += 1

                # Triage nuclei findings directly (enhanced scanner returns RawFinding list)
                findings = results.get("nuclei_findings", [])
                if findings:
                    print(f"[AutoHunt] Found {len(findings)} raw findings, running triage...")
                    fp_filter.triage_batch(findings)

            except Exception as e:
                task_queue.fail_task(task, str(e))

        self.running = False
        duration = (datetime.now() - self.start_time).total_seconds()
        print(f"[AutoHunt] Batch complete in {duration:.1f}s")
        print(f"[AutoHunt] Stats: {task_queue.get_stats()}")
        print(f"[AutoHunt] Triage: {fp_filter.get_stats()}")

    def _parse_nuclei_results(self, target: str, nuclei_output: Any) -> List[RawFinding]:
        """Parse nuclei JSON output into RawFinding objects."""
        findings = []
        # Nuclei output parsing depends on format
        if isinstance(nuclei_output, dict):
            output_text = nuclei_output.get("output", "") or nuclei_output.get("stdout", "")
        else:
            output_text = str(nuclei_output)

        for line in output_text.split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                finding = RawFinding(
                    target=target,
                    vuln_type=data.get("template-id", "unknown"),
                    title=data.get("info", {}).get("name", "Unknown"),
                    description=data.get("info", {}).get("description", ""),
                    evidence=line[:500],
                    scanner="nuclei",
                    severity=data.get("info", {}).get("severity", "unknown"),
                )
                findings.append(finding)
            except json.JSONDecodeError:
                continue

        return findings

    def generate_review_report(self, output_dir: str = "./outputs/autohunt"):
        """Generate final review report after batch hunting."""
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Export task results
        task_queue.export_results(f"{output_dir}/tasks_{timestamp}.json")

        # Export triage results (review list)
        fp_filter.export_review_list(f"{output_dir}/review_{timestamp}.json")

        # Generate summary
        summary = {
            "timestamp": datetime.now().isoformat(),
            "duration_seconds": (datetime.now() - self.start_time).total_seconds() if self.start_time else 0,
            "targets_collected": len(asset_collector.targets),
            "tasks": task_queue.get_stats(),
            "triage": fp_filter.get_stats(),
            "review_queue_size": len(fp_filter.get_review_queue()),
        }

        with open(f"{output_dir}/summary_{timestamp}.json", "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)

        print(f"[AutoHunt] Reports exported to {output_dir}/")
        return summary

    def stop(self):
        """Stop the running pipeline."""
        self.running = False
        print("[AutoHunt] Pipeline stopping...")


# Global instance
auto_hunt = AutoHuntPipeline()
