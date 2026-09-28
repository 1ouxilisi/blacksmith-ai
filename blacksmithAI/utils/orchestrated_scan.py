"""
Orchestrated Scan Pipeline - Multi-agent scan that actually runs end-to-end.
Recon Agent maps attack surface -> Exploit Agent probes vulnerabilities ->
Coordinator correlates findings and generates report.
"""
import os
import json
import time
from typing import Dict, Any, List, Optional
from datetime import datetime

from utils.database import db
from utils.multi_agent import orchestrator
from utils.agent_memory import agent_memory
from utils.run_history import run_history, budget_guard
from utils.progress_tracker import progress_tracker
from utils.report_generator_pro import report_generator_pro
from utils.chain_analyzer import attack_chain_analyzer


class OrchestratedScan:
    """Full multi-agent scan pipeline that actually executes."""

    def __init__(self):
        self.container_uri = os.getenv('container_uri', 'http://localhost:9756/exec')
        self.progress_callback = None

    def set_progress_callback(self, callback):
        """Set a callback function to report progress in real-time."""
        self.progress_callback = callback

    def _report_progress(self, step: str, message: str, pct: int):
        """Report scan progress."""
        print(f"[Orchestrator] {step}: {message} ({pct}%)")
        if self.progress_callback:
            self.progress_callback(step, message, pct)

    def run_full_scan(self, target: str) -> Dict[str, Any]:
        """Run a full multi-agent scan pipeline.

        Steps:
        1. Check memory - skip if recently scanned
        2. Recon Agent: subfinder + whatweb + nmap
        3. Exploit Agent: nuclei + nikto + sqlmap
        4. Coordinator: correlate findings into chains
        5. Generate report
        6. Save to memory
        """
        run_id = run_history.start_run(target, scan_type="full-multi-agent")
        progress_tracker.start(target)`n        self._report_progress("init", f"Starting scan on {target}", 5)

        # Check memory
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        if agent_memory.should_skip(domain, days_threshold=7):
            self._report_progress("memory", "Target scanned recently, loading cached results", 100)
            return {"run_id": run_id, "status": "cached", "target": target}

        progress_tracker.update("recon", "Mapping attack surface", 15)`n        self._report_progress("recon", "Recon Agent: mapping attack surface", 15)

        # Step 1: Recon - subfinder
        try:
            import requests
            resp = requests.post(self.container_uri, json={
                "cmd": f"subfinder -d {domain} -silent",
                "timeout": 30,
            }, timeout=35)
            if resp.status_code == 200:
                subs = [s for s in resp.json().get("stdout", "").strip().split("\n") if s]
                self._report_progress("recon", f"Found {len(subs)} subdomains", 25)
        except Exception as e:
            self._report_progress("recon", f"Subfinder error: {e}", 25)

        # Step 2: Recon - whatweb
        self._report_progress("recon", "WhatWeb: fingerprinting tech stack", 30)
        try:
            import requests
            resp = requests.post(self.container_uri, json={
                "cmd": f"whatweb --color=never {target}",
                "timeout": 30,
            }, timeout=35)
            if resp.status_code == 200:
                tech = resp.json().get("stdout", "")[:200]
                self._report_progress("recon", f"Tech: {tech[:100]}", 35)
        except Exception as e:
            self._report_progress("recon", f"WhatWeb error: {e}", 35)

        # Step 3: Recon - nmap quick
        self._report_progress("recon", "Nmap: quick port scan", 40)
        try:
            import requests
            resp = requests.post(self.container_uri, json={
                "cmd": f"nmap -sT -Pn --top-ports 100 {domain}",
                "timeout": 60,
            }, timeout=65)
            if resp.status_code == 200:
                output = resp.json().get("stdout", "")
                open_ports = [l for l in output.split("\n") if "/open/" in l]
                self._report_progress("recon", f"Found {len(open_ports)} open ports", 45)
        except Exception as e:
            self._report_progress("recon", f"Nmap error: {e}", 45)

        # Step 4: Exploit - nuclei
        progress_tracker.update("exploit", "Scanning for vulnerabilities", 50)`n        self._report_progress("exploit", "Exploit Agent: nuclei vulnerability scan", 50)
        try:
            import requests
            resp = requests.post(self.container_uri, json={
                "cmd": f"nuclei -u {target} -j -silent -severity critical,high,medium",
                "timeout": 120,
            }, timeout=125)
            if resp.status_code == 200:
                output = resp.json().get("stdout", "")
                vuln_count = 0
                for line in output.split("\n"):
                    line = line.strip()
                    if line:
                        try:
                            data = json.loads(line)
                            vuln_count += 1
                            # Store in database
                            db.add_finding(
                                target_url=target,
                                vuln_type=data.get("info", {}).get("classification", {}).get("cwe", "unknown"),
                                title=data.get("info", {}).get("name", "Unknown"),
                                description=data.get("templateID", ""),
                                evidence=line[:500],
                                severity=data.get("info", {}).get("severity", "medium"),
                                confidence=0.8,
                            )
                        except json.JSONDecodeError:
                            pass
                self._report_progress("exploit", f"Nuclei found {vuln_count} vulnerabilities", 65)
        except Exception as e:
            self._report_progress("exploit", f"Nuclei error: {e}", 65)

        # Step 5: Exploit - nikto
        self._report_progress("exploit", "Nikto: web server scan", 70)
        try:
            import requests
            resp = requests.post(self.container_uri, json={
                "cmd": f"nikto -h {target} -nointeract",
                "timeout": 120,
            }, timeout=125)
            if resp.status_code == 200:
                output = resp.json().get("stdout", "")
                nikto_lines = [l.strip() for l in output.split("\n") if l.strip().startswith("+")]
                self._report_progress("exploit", f"Nikto found {len(nikto_lines)} issues", 75)
                # Store Nikto findings in database
                for line in nikto_lines[:10]:  # Limit to 10
                    if len(line) > 10:  # Skip short lines
                        db.add_finding(
                            target_url=target,
                            vuln_type="web_server_misconfig",
                            title=line[:80],
                            description=line,
                            evidence=line,
                            severity="low",
                            confidence=0.6,
                        )
        except Exception as e:
            self._report_progress("exploit", f"Nikto error: {e}", 75)

        # Step 6: Coordinator - analyze chains
        progress_tracker.update("coordinator", "Analyzing attack chains", 80)`n        self._report_progress("coordinator", "Correlating findings into attack chains", 80)
        chain_summary = attack_chain_analyzer.get_chain_summary()
        self._report_progress("coordinator", f"Found {chain_summary['total_chains']} attack chains", 85)

        # Step 6: PoC Validation - auto-verify findings
        self._report_progress("poc", "Validating findings with PoC tests", 86)
        try:
            from utils.poc_validator import poc_validator
            findings = db.get_findings(limit=10)
            verified = 0
            for f in findings[:5]:  # Limit to 5 to save time
                result = poc_validator.validate_finding(f["id"])
                if result.success:
                    verified += 1
            self._report_progress("poc", f"PoC validation: {verified}/{len(findings)} verified", 87)
        except Exception as e:
            self._report_progress("poc", f"PoC validation error: {e}", 87)

        # Step 6.5: AI Analysis - use local LLM to analyze findings
        progress_tracker.update("ai", "AI analyzing findings", 88)`n        self._report_progress("ai", "AI analyzing findings with local LLM", 88)
        try:
            from utils.llm_analyzer import llm_analyzer
            if llm_analyzer.available:
                ai_result = llm_analyzer.correlate_findings(db.get_findings(limit=10))
                self._report_progress("ai", f"AI analysis complete - overall risk assessed", 89)
            else:
                self._report_progress("ai", "Ollama not available, skipping AI analysis", 89)
        except Exception as e:
            self._report_progress("ai", f"AI analysis error: {e}", 89)

        # Step 7: Generate report
        progress_tracker.update("report", "Generating report", 90)`n        self._report_progress("report", "Generating professional report", 90)
        report_path = report_generator_pro.generate_report(target)
        self._report_progress("report", f"Report saved: {report_path}", 95)

        # Step 8: Save to memory
        findings = db.get_findings(limit=100)
        agent_memory.remember_target(domain, {
            "findings": findings,
            "subdomains": [],
            "open_ports": [],
        })

        # Complete run
        run_history.complete_run(run_id, {
            "findings_count": len(findings),
            "status": "completed",
        })

        progress_tracker.complete(len(findings))`n        self._report_progress("done", "Scan completed successfully", 100)

        return {
            "run_id": run_id,
            "status": "completed",
            "target": target,
            "findings_count": len(findings),
            "chains_count": chain_summary["total_chains"],
            "report_path": report_path,
        }


# Global instance
orchestrated_scan = OrchestratedScan()




