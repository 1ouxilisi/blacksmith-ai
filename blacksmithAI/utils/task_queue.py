"""
Task Queue - Job queue for batch scanning operations.
Manages target queue, concurrency, retries, and status tracking.
"""
import json
import os
import time
from enum import Enum
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
from utils.asset_collector import Target


class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class TaskPriority(Enum):
    HIGH = 3
    MEDIUM = 2
    LOW = 1


@dataclass
class ScanTask:
    """A single scanning task for one target."""
    task_id: str
    target: Target
    status: TaskStatus = TaskStatus.PENDING
    priority: TaskPriority = TaskPriority.MEDIUM
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    results: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    retries: int = 0
    max_retries: int = 2

    def start(self):
        self.status = TaskStatus.RUNNING
        self.started_at = datetime.now().isoformat()

    def complete(self, results: Dict[str, Any]):
        self.status = TaskStatus.COMPLETED
        self.completed_at = datetime.now().isoformat()
        self.results = results

    def fail(self, error: str):
        self.retries += 1
        if self.retries >= self.max_retries:
            self.status = TaskStatus.FAILED
            self.completed_at = datetime.now().isoformat()
            self.error = error
        else:
            self.status = TaskStatus.PENDING

    def skip(self, reason: str = ""):
        self.status = TaskStatus.SKIPPED
        self.completed_at = datetime.now().isoformat()
        self.error = reason


class TaskQueue:
    """Priority-based task queue for batch scanning."""

    def __init__(self, max_concurrent: int = 3):
        self.queue: List[ScanTask] = []
        self.completed: List[ScanTask] = []
        self.failed: List[ScanTask] = []
        self.max_concurrent = max_concurrent
        self.running: List[ScanTask] = []

    def add_task(self, target: Target, priority: TaskPriority = TaskPriority.MEDIUM) -> ScanTask:
        """Add a new scan task."""
        task_id = f"task_{len(self.queue) + len(self.completed) + len(self.failed) + 1:06d}"
        task = ScanTask(
            task_id=task_id,
            target=target,
            priority=priority,
        )
        # Insert by priority (high first)
        inserted = False
        for i, existing in enumerate(self.queue):
            if task.priority.value > existing.priority.value:
                self.queue.insert(i, task)
                inserted = True
                break
        if not inserted:
            self.queue.append(task)
        return task

    def add_targets(self, targets: List[Target]):
        """Add multiple targets as tasks, prioritized by score."""
        for t in targets:
            if t.score >= 70:
                priority = TaskPriority.HIGH
            elif t.score >= 40:
                priority = TaskPriority.MEDIUM
            else:
                priority = TaskPriority.LOW
            self.add_task(t, priority)

    def get_next_task(self) -> Optional[ScanTask]:
        """Get the next pending task."""
        if len(self.running) >= self.max_concurrent:
            return None

        for i, task in enumerate(self.queue):
            if task.status == TaskStatus.PENDING:
                task.start()
                self.running.append(task)
                self.queue.pop(i)
                return task
        return None

    def complete_task(self, task: ScanTask, results: Dict[str, Any]):
        """Mark a task as completed."""
        task.complete(results)
        if task in self.running:
            self.running.remove(task)
        self.completed.append(task)

    def fail_task(self, task: ScanTask, error: str):
        """Mark a task as failed."""
        task.fail(error)
        if task in self.running:
            self.running.remove(task)

        if task.status == TaskStatus.FAILED:
            self.failed.append(task)
        else:
            # Re-queue for retry
            self.queue.insert(0, task)

    def get_stats(self) -> Dict[str, Any]:
        """Get queue statistics."""
        return {
            "pending": len([t for t in self.queue if t.status == TaskStatus.PENDING]),
            "running": len(self.running),
            "completed": len(self.completed),
            "failed": len(self.failed),
            "skipped": len([t for t in self.completed if t.status == TaskStatus.SKIPPED]),
            "total": len(self.queue) + len(self.running) + len(self.completed) + len(self.failed),
        }

    def get_results(self) -> List[Dict[str, Any]]:
        """Get all completed task results."""
        return [
            {
                "task_id": t.task_id,
                "target": t.target.url,
                "ip": t.target.ip,
                "port": t.target.port,
                "title": t.target.title,
                "score": t.target.score,
                "results": t.results,
            }
            for t in self.completed
        ]

    def export_results(self, output_path: str):
        """Export all results to JSON."""
        data = {
            "stats": self.get_stats(),
            "results": self.get_results(),
            "failed": [
                {"task_id": t.task_id, "target": t.target.url, "error": t.error}
                for t in self.failed
            ],
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def clear(self):
        """Clear all tasks."""
        self.queue.clear()
        self.completed.clear()
        self.failed.clear()
        self.running.clear()


# Global instance
task_queue = TaskQueue()
