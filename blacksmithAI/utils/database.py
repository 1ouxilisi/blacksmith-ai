"""
Database Layer - SQLite persistent storage.
All targets, findings, tasks, and audit logs persist across restarts.
"""
import os
import json
import sqlite3
from datetime import datetime
from typing import List, Dict, Any, Optional
from contextlib import contextmanager


DB_PATH = "./store/blacksmith.db"


def init_db():
    """Initialize database schema."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Targets table
    c.execute("""
        CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT UNIQUE,
            ip TEXT,
            port INTEGER,
            title TEXT,
            status TEXT DEFAULT 'pending',
            score REAL DEFAULT 0,
            source TEXT,
            collected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_scanned_at TIMESTAMP
        )
    """)

    # Findings table
    c.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_url TEXT,
            vuln_type TEXT,
            title TEXT,
            description TEXT,
            evidence TEXT,
            severity TEXT DEFAULT 'medium',
            confidence REAL DEFAULT 0.5,
            status TEXT DEFAULT 'pending_review',
            cve TEXT,
            raw_data TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            reviewed_at TIMESTAMP,
            reviewed_by TEXT
        )
    """)

    # Scan tasks table
    c.execute("""
        CREATE TABLE IF NOT EXISTS scan_tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_url TEXT,
            task_type TEXT,
            status TEXT DEFAULT 'pending',
            priority INTEGER DEFAULT 5,
            command TEXT,
            result TEXT,
            started_at TIMESTAMP,
            completed_at TIMESTAMP,
            error TEXT
        )
    """)

    # Audit log table
    c.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent TEXT,
            action TEXT,
            command TEXT,
            output TEXT,
            severity TEXT DEFAULT 'info',
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Scan history table
    c.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_name TEXT,
            snapshot_name TEXT,
            targets_count INTEGER,
            findings_count INTEGER,
            snapshot_data TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Create indexes
    c.execute("CREATE INDEX IF NOT EXISTS idx_targets_status ON targets(status)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_tasks_status ON scan_tasks(status)")

    conn.commit()
    conn.close()
    print(f"[DB] Initialized at {DB_PATH}")


@contextmanager
def get_db():
    """Get database connection context manager."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


class Database:
    """Database operations for BlacksmithAI."""

    # === Targets ===
    def add_target(self, url: str, ip: str = "", port: int = 0,
                   title: str = "", source: str = "", score: float = 0) -> int:
        """Add a target, return ID."""
        with get_db() as conn:
            c = conn.cursor()
            try:
                c.execute("""
                    INSERT INTO targets (url, ip, port, title, source, score)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (url, ip, port, title, source, score))
                return c.lastrowid
            except sqlite3.IntegrityError:
                # Already exists, update score
                c.execute("UPDATE targets SET score = ? WHERE url = ?", (score, url))
                return c.lastrowid

    def get_targets(self, status: str = None, limit: int = 100) -> List[Dict]:
        """Get all targets."""
        with get_db() as conn:
            c = conn.cursor()
            if status:
                c.execute("SELECT * FROM targets WHERE status = ? ORDER BY score DESC LIMIT ?",
                         (status, limit))
            else:
                c.execute("SELECT * FROM targets ORDER BY score DESC LIMIT ?", (limit,))
            return [dict(row) for row in c.fetchall()]

    def update_target_status(self, url: str, status: str):
        """Update target scan status."""
        with get_db() as conn:
            conn.execute("UPDATE targets SET status = ?, last_scanned_at = CURRENT_TIMESTAMP WHERE url = ?",
                        (status, url))

    # === Findings ===
    def add_finding(self, target_url: str, vuln_type: str, title: str,
                    description: str = "", evidence: str = "", severity: str = "medium",
                    confidence: float = 0.5, cve: str = "", raw_data: str = "") -> int:
        """Add a finding, return ID."""
        with get_db() as conn:
            c = conn.cursor()
            c.execute("""
                INSERT INTO findings (target_url, vuln_type, title, description,
                                      evidence, severity, confidence, cve, raw_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (target_url, vuln_type, title, description, evidence,
                  severity, confidence, cve, raw_data))
            return c.lastrowid

    def get_findings(self, status: str = None, severity: str = None,
                     limit: int = 100) -> List[Dict]:
        """Get findings."""
        with get_db() as conn:
            c = conn.cursor()
            query = "SELECT * FROM findings WHERE 1=1"
            params = []
            if status:
                query += " AND status = ?"
                params.append(status)
            if severity:
                query += " AND severity = ?"
                params.append(severity)
            query += " ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END LIMIT ?"
            params.append(limit)
            c.execute(query, params)
            return [dict(row) for row in c.fetchall()]

    def update_finding_status(self, finding_id: int, status: str, reviewed_by: str = "user"):
        """Mark a finding as reviewed/confirmed/false_positive."""
        with get_db() as conn:
            conn.execute("""
                UPDATE findings SET status = ?, reviewed_at = CURRENT_TIMESTAMP, reviewed_by = ?
                WHERE id = ?
            """, (status, reviewed_by, finding_id))

    # === Tasks ===
    def add_task(self, target_url: str, task_type: str, command: str,
                 priority: int = 5) -> int:
        """Add a scan task, return ID."""
        with get_db() as conn:
            c = conn.cursor()
            c.execute("""
                INSERT INTO scan_tasks (target_url, task_type, command, priority)
                VALUES (?, ?, ?, ?)
            """, (target_url, task_type, command, priority))
            return c.lastrowid

    def get_pending_tasks(self, limit: int = 10) -> List[Dict]:
        """Get pending tasks by priority."""
        with get_db() as conn:
            c = conn.cursor()
            c.execute("""
                SELECT * FROM scan_tasks
                WHERE status = 'pending'
                ORDER BY priority ASC
                LIMIT ?
            """, (limit,))
            return [dict(row) for row in c.fetchall()]

    def update_task_status(self, task_id: int, status: str, result: str = "", error: str = ""):
        """Update task status."""
        with get_db() as conn:
            if status == "running":
                conn.execute("UPDATE scan_tasks SET status = ?, started_at = CURRENT_TIMESTAMP WHERE id = ?",
                            (status, task_id))
            elif status in ("completed", "failed"):
                conn.execute("""
                    UPDATE scan_tasks SET status = ?, result = ?, error = ?, completed_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, (status, result, error, task_id))
            else:
                conn.execute("UPDATE scan_tasks SET status = ? WHERE id = ?", (status, task_id))

    # === Audit ===
    def add_audit_log(self, agent: str, action: str, command: str = "",
                      output: str = "", severity: str = "info"):
        """Add audit log entry."""
        with get_db() as conn:
            conn.execute("""
                INSERT INTO audit_logs (agent, action, command, output, severity)
                VALUES (?, ?, ?, ?, ?)
            """, (agent, action, command, output[:5000], severity))

    def get_audit_logs(self, limit: int = 100) -> List[Dict]:
        """Get recent audit logs."""
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?", (limit,))
            return [dict(row) for row in c.fetchall()]

    # === Stats ===
    def get_stats(self) -> Dict:
        """Get overall statistics."""
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT COUNT(*) as count FROM targets")
            targets = c.fetchone()["count"]
            c.execute("SELECT COUNT(*) as count FROM findings WHERE status = 'pending_review'")
            pending = c.fetchone()["count"]
            c.execute("SELECT COUNT(*) as count FROM findings WHERE severity = 'critical'")
            critical = c.fetchone()["count"]
            c.execute("SELECT COUNT(*) as count FROM scan_tasks WHERE status = 'pending'")
            pending_tasks = c.fetchone()["count"]
            c.execute("SELECT COUNT(*) as count FROM scan_tasks WHERE status = 'running'")
            running_tasks = c.fetchone()["count"]
            return {
                "targets": targets,
                "pending_findings": pending,
                "critical_findings": critical,
                "pending_tasks": pending_tasks,
                "running_tasks": running_tasks,
            }


# Global instance
db = Database()

# Initialize on import
init_db()
