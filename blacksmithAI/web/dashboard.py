"""
Web Dashboard - Simple Flask-based web interface for monitoring hunts and reviewing findings.
"""
import os
import json
from flask import Flask, jsonify, render_template_string
from utils.asset_collector import asset_collector
from utils.task_queue import task_queue
from utils.fp_filter import fp_filter
from utils.auto_hunt import auto_hunt
from utils.audit_logger import audit_logger


app = Flask(__name__)

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BlacksmithAI Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; }
        h1 { color: #38bdf8; margin-bottom: 20px; font-size: 28px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }
        .stat-card { background: #1e293b; border-radius: 8px; padding: 20px; border-left: 4px solid #38bdf8; }
        .stat-card.high { border-left-color: #ef4444; }
        .stat-card.medium { border-left-color: #f59e0b; }
        .stat-value { font-size: 32px; font-weight: bold; margin: 8px 0; }
        .stat-label { color: #94a3b8; font-size: 14px; }
        .section { background: #1e293b; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
        .section h2 { color: #38bdf8; margin-bottom: 16px; font-size: 20px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #334155; }
        th { color: #94a3b8; font-weight: 600; font-size: 14px; }
        tr:hover { background: #334155; }
        .badge { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
        .badge.critical { background: #7f1d1d; color: #fca5a5; }
        .badge.high { background: #991b1b; color: #fecaca; }
        .badge.medium { background: #92400e; color: #fde68a; }
        .badge.low { background: #166534; color: #bbf7d0; }
        .badge.info { background: #1e40af; color: #bfdbfe; }
        .badge.confirmed { background: #166534; color: #bbf7d0; }
        .badge.likely { background: #92400e; color: #fde68a; }
        .badge.fp { background: #374151; color: #9ca3af; }
        .refresh { color: #38bdf8; cursor: pointer; text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <nav style="margin-bottom: 20px;">
            <a href="/" style="color: #38bdf8; margin-right: 20px; text-decoration: none;">Dashboard</a>
            <a href="/targets" style="color: #38bdf8; margin-right: 20px; text-decoration: none;">Targets</a>
            <a href="/findings" style="color: #38bdf8; margin-right: 20px; text-decoration: none;">Findings</a>
            <a href="/new-scan" style="color: #22c55e; margin-right: 20px; text-decoration: none; font-weight: bold;">+ New Scan</a>
        </nav>
        <h1>馃敤 BlacksmithAI Dashboard</h1>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Collected Targets</div>
                <div class="stat-value">{{ stats.targets }}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Pending Tasks</div>
                <div class="stat-value">{{ stats.pending }}</div>
            </div>
            <div class="stat-card medium">
                <div class="stat-label">Running</div>
                <div class="stat-value">{{ stats.running }}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Completed</div>
                <div class="stat-value">{{ stats.completed }}</div>
            </div>
            <div class="stat-card high">
                <div class="stat-label">Review Queue</div>
                <div class="stat-value">{{ stats.review_queue }}</div>
            </div>
        </div>

        <div class="section">
            <h2>馃搵 Review Queue (寰呬汉宸ュ瀹? <span class="refresh" onclick="location.reload()">Refresh</span></h2>
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Target</th>
                        <th>Type</th>
                        <th>Title</th>
                        <th>Severity</th>
                        <th>Confidence</th>
                        <th>Decision</th>
                    </tr>
                </thead>
                <tbody>
                    {% for item in review_list %}
                    <tr>
                        <td>{{ loop.index }}</td>
                        <td>{{ item.target }}</td>
                        <td>{{ item.type }}</td>
                        <td>{{ item.title }}</td>
                        <td><span class="badge {{ item.severity }}">{{ item.severity }}</span></td>
                        <td>{{ "%.0f"|format(item.confidence * 100) }}%</td>
                        <td><span class="badge {{ item.decision }}">{{ item.decision }}</span></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>馃搳 Triage Stats</h2>
            <div class="stats-grid">
                {% for key, value in triage_stats.items() %}
                <div class="stat-card">
                    <div class="stat-label">{{ key }}</div>
                    <div class="stat-value">{{ value }}</div>
                </div>
                {% endfor %}
            </div>
        </div>
    </div>
    <script>
        setTimeout(() => location.reload(), 10000);
    </script>
</body>
</html>
"""


@app.route("/")
def dashboard():
    from utils.database import db

    # Get real stats from SQLite database
    db_stats = db.get_stats()

    # Get real findings from database
    findings = db.get_findings(limit=50)

    review_list = []
    for f in findings:
        review_list.append({
            "target": f["target_url"],
            "type": f["vuln_type"],
            "title": f["title"],
            "severity": f["severity"],
            "confidence": f["confidence"],
            "decision": f["status"],
        })

    stats = {
        "targets": db_stats["targets"],
        "pending": db_stats["pending_tasks"],
        "running": db_stats["running_tasks"],
        "completed": db_stats["targets"],
        "review_queue": db_stats["pending_findings"],
    }

    triage_stats = {
        "pending_findings": db_stats["pending_findings"],
        "critical_findings": db_stats["critical_findings"],
        "total_targets": db_stats["targets"],
    }

    return render_template_string(
        DASHBOARD_HTML,
        stats=stats,
        review_list=review_list,
        triage_stats=triage_stats,
    )


@app.route("/api/stats")
def api_stats():
    return jsonify({
        "targets": len(asset_collector.targets),
        "tasks": task_queue.get_stats(),
        "triage": fp_filter.get_stats(),
        "review_queue": len(fp_filter.get_review_queue()),
    })


@app.route("/api/review")
def api_review():
    review_queue = fp_filter.get_review_queue()
    return jsonify([
        {
            "target": r.raw_finding.target,
            "type": r.raw_finding.vuln_type,
            "title": r.raw_finding.title,
            "severity": r.suggested_severity,
            "confidence": r.confidence,
            "reasoning": r.reasoning,
        }
        for r in review_queue
    ])


@app.route("/api/hunt/start", methods=["POST"])
def api_start_hunt():
    """Start a batch hunt."""
    from flask import request
    source = request.json.get("source", "fofa")
    query = request.json.get("query", "")
    max_targets = request.json.get("max_targets", 10)

    if not query:
        return jsonify({"error": "Query is required"}), 400

    # Start in background thread
    import threading
    def run():
        auto_hunt.collect_targets(source, query, size=max_targets)
        auto_hunt.probe_targets()
        auto_hunt.build_scan_queue(max_targets)
        auto_hunt.run_batch(max_targets)
        auto_hunt.generate_review_report()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()

    return jsonify({"status": "started", "source": source, "query": query})


@app.route("/api/hunt/stop", methods=["POST"])
def api_stop_hunt():
    """Stop the running hunt."""
    auto_hunt.stop()
    return jsonify({"status": "stopped"})


@app.route("/api/scan/start", methods=["POST"])
def api_start_scan():
    """Start a real scan on a target using scan_engine.

    POST body:
        target: URL to scan (e.g., https://example.com)
        scan_type: quick or full (default: quick)
    """
    from flask import request
    from utils.scan_engine import scan_engine

    target = request.json.get("target", "")
    scan_type = request.json.get("scan_type", "quick")

    if not target:
        return jsonify({"error": "Target URL is required"}), 400

    # Start scan in background thread
    import threading
    def run():
        if scan_type == "full":
            scan_engine.full_scan(target)
        else:
            scan_engine.quick_scan(target)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()

    return jsonify({
        "status": "started",
        "target": target,
        "scan_type": scan_type,
        "message": f"Scan started for {target}. Results will appear in Targets and Findings pages."
    })


@app.route("/api/scan/status")
def api_scan_status():
    """Get current scan status from database."""
    from utils.database import db
    stats = db.get_stats()
    return jsonify(stats)


@app.route("/new-scan")
def new_scan_page():
    """Page to start a new scan."""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>New Scan - BlacksmithAI</title>
        <style>
            body { font-family: sans-serif; background: #0f172a; color: #e2e8f0; padding: 20px; }
            .container { max-width: 600px; margin: 50px auto; }
            .form-group { margin: 20px 0; }
            label { display: block; margin-bottom: 8px; color: #94a3b8; }
            input, select { width: 100%; padding: 12px; background: #1e293b; border: 1px solid #334155; border-radius: 8px; color: #e2e8f0; font-size: 16px; }
            button { width: 100%; padding: 14px; background: #38bdf8; color: #0f172a; border: none; border-radius: 8px; font-size: 16px; font-weight: bold; cursor: pointer; }
            button:hover { background: #0ea5e9; }
            nav a { color: #38bdf8; margin-right: 20px; }
            h1 { color: #38bdf8; }
        </style>
    </head>
    <body>
        <nav><a href="/">Dashboard</a><a href="/targets">Targets</a><a href="/findings">Findings</a><a href="/new-scan">+ New Scan</a></nav>
        <div class="container">
            <h1>馃攳 New Scan</h1>
            <form id="scanForm">
                <div class="form-group">
                    <label>Target URL</label>
                    <input type="text" id="target" placeholder="https://example.com" required>
                </div>
                <div class="form-group">
                    <label>Scan Type</label>
                    <select id="scanType">
                        <option value="quick">Quick (nuclei only)</option>
                        <option value="full">Full (nmap + nuclei + gobuster + subfinder)</option>
                    </select>
                </div>
                <button type="submit">Start Scan</button>
            </form>
            <div id="result" style="margin-top: 20px;"></div>
        </div>
        <script>
            document.getElementById('scanForm').onsubmit = async (e) => {
                e.preventDefault();
                const target = document.getElementById('target').value;
                const scanType = document.getElementById('scanType').value;
                const res = await fetch('/api/scan/start', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({target, scan_type: scanType})
                });
                const data = await res.json();
                document.getElementById('result').innerHTML =
                    `<div style="background:#1e293b;padding:16px;border-radius:8px;color:#22c55e;">${data.message || data.error}</div>`;
            };
        </script>
    </body>
    </html>
    """
    return html


@app.route("/api/history")
def api_history():
    """Get scan history."""
    from utils.history_comparator import history_comparator
    snapshots = history_comparator.load_snapshots("autohunt")
    return jsonify([
        {
            "timestamp": s.get("timestamp"),
            "name": s.get("name"),
        }
        for s in snapshots
    ])


@app.route("/api/report/html")
def api_html_report():
    """Generate and return HTML report."""
    from utils.html_report import html_report_generator
    from utils.report_generator import report_generator
    from datetime import datetime

    findings = report_generator.findings
    target = report_generator.target or "unknown"

    output_path = f"./outputs/reports/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    html_report_generator.generate_html_report(
        target=target,
        findings=findings,
        output_path=output_path,
    )

    return jsonify({"report_path": output_path})


@app.route("/targets")
def targets_page():
    """Show all targets from database."""
    from utils.database import db

    targets = db.get_targets(limit=100)

    targets_html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Targets - BlacksmithAI</title>
        <style>
            body { font-family: sans-serif; background: #0f172a; color: #e2e8f0; padding: 20px; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; }
            th, td { padding: 12px; text-align: left; border-bottom: 1px solid #334155; }
            th { color: #94a3b8; }
            .completed { color: #22c55e; }
            .scanning { color: #38bdf8; }
            .pending { color: #94a3b8; }
            nav a { color: #38bdf8; margin-right: 20px; }
        </style>
    </head>
    <body>
        <nav><a href="/">Dashboard</a><a href="/targets">Targets</a><a href="/findings">Findings</a><a href="/plugins">Plugins</a></nav>
        <h1 style="margin-top: 20px;">馃幆 Targets</h1>
        <table>
            <thead><tr><th>URL</th><th>IP</th><th>Port</th><th>Score</th><th>Status</th><th>Collected</th></tr></thead>
            <tbody>
    """
    for t in targets:
        status_class = t["status"]
        targets_html += f"<tr><td>{t['url']}</td><td>{t['ip']}</td><td>{t['port']}</td><td>{t['score']:.0f}</td><td class='{status_class}'>鈼?{t['status']}</td><td>{t['collected_at']}</td></tr>"

    targets_html += """
            </tbody>
        </table>
    </body>
    </html>
    """
    return targets_html


@app.route("/findings")
def findings_page():
    """Show all findings from database."""
    from utils.database import db

    findings = db.get_findings(limit=100)

    findings_html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Findings - BlacksmithAI</title>
        <style>
            body { font-family: sans-serif; background: #0f172a; color: #e2e8f0; padding: 20px; }
            .finding { background: #1e293b; padding: 16px; margin: 10px 0; border-radius: 8px; border-left: 4px solid #38bdf8; }
            .critical { border-left-color: #ef4444; }
            .high { border-left-color: #f97316; }
            .medium { border-left-color: #eab308; }
            .low { border-left-color: #22c55e; }
            .title { font-size: 18px; font-weight: bold; margin-bottom: 8px; }
            .meta { color: #94a3b8; font-size: 14px; }
            nav a { color: #38bdf8; margin-right: 20px; }
        </style>
    </head>
    <body>
        <nav><a href="/">Dashboard</a><a href="/targets">Targets</a><a href="/findings">Findings</a><a href="/plugins">Plugins</a></nav>
        <h1 style="margin-top: 20px;">馃攳 Findings</h1>
    """
    for f in findings:
        severity = f["severity"]
        findings_html += f"""
        <div class="finding {severity}">
            <div class="title">{f['title']}</div>
            <div class="meta">
                Target: {f['target_url']} |
                Type: {f['vuln_type']} |
                Severity: {severity} |
                Confidence: {f['confidence']:.0%} |
                Status: {f['status']}
            </div>
            <p style="margin-top: 8px;">{f['description'][:200]}</p>
        </div>
        """

    findings_html += "</body></html>"
    return findings_html


@app.route("/plugins")
def plugins_page():
    """Show loaded plugins."""
    from utils.plugin_manager import plugin_manager
    plugins = plugin_manager.list_plugins()

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Plugins - BlacksmithAI</title>
        <style>
            body { font-family: sans-serif; background: #0f172a; color: #e2e8f0; padding: 20px; }
            .plugin { background: #1e293b; padding: 16px; margin: 10px 0; border-radius: 8px; }
            .name { font-size: 18px; font-weight: bold; color: #38bdf8; }
            nav a { color: #38bdf8; margin-right: 20px; }
        </style>
    </head>
    <body>
        <nav><a href="/">Dashboard</a><a href="/targets">Targets</a><a href="/findings">Findings</a><a href="/plugins">Plugins</a></nav>
        <h1 style="margin-top: 20px;">馃攲 Plugins</h1>
    """
    for p in plugins:
        html += f"""
        <div class="plugin">
            <div class="name">{p['name']} v{p['version']}</div>
            <p>{p['description']}</p>
            <div class="meta">by {p['author']}</div>
        </div>
        """

    html += "</body></html>"
    return html


@app.route("/chains")
def chains_page():
    """Show attack chain analysis."""
    from utils.chain_analyzer import attack_chain_analyzer

    summary = attack_chain_analyzer.get_chain_summary()

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Attack Chains - BlacksmithAI</title>
        <style>
            body { font-family: sans-serif; background: #0f172a; color: #e2e8f0; padding: 20px; }
            .chain { background: #1e293b; padding: 20px; margin: 12px 0; border-radius: 8px; border-left: 4px solid #ef4444; }
            .high { border-left-color: #f97316; }
            .medium { border-left-color: #eab308; }
            .title { font-size: 20px; font-weight: bold; margin-bottom: 8px; }
            .impact { padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: bold; margin-left: 10px; }
            .impact.critical { background: #7f1d1d; color: #fca5a5; }
            .impact.high { background: #991b1b; color: #fecaca; }
            .steps { margin-top: 12px; padding-left: 20px; }
            .step { color: #94a3b8; margin: 4px 0; }
            nav a { color: #38bdf8; margin-right: 20px; }
        </style>
    </head>
    <body>
        <nav><a href="/">Dashboard</a><a href="/targets">Targets</a><a href="/findings">Findings</a><a href="/chains">Attack Chains</a><a href="/runs">Runs</a><a href="/new-scan">+ New Scan</a></nav>
        <h1 style="margin-top: 20px;">鉀擄笍 Attack Chain Analysis</h1>
    """

    if not summary["chains"]:
        html += "<p style='color:#94a3b8; margin-top:20px;'>No attack chains identified yet. Run scans to find correlated vulnerabilities.</p>"
    else:
        html += f"<p style='color:#94a3b8;'>Found {summary['total_chains']} potential attack chains ({summary['critical_chains']} critical, {summary['high_chains']} high)</p>"
        for c in summary["chains"]:
            html += f"""
            <div class="chain {c['impact']}">
                <div class="title">{c['title']}<span class="impact {c['impact']}">{c['impact'].upper()}</span></div>
                <p>{c['description']}</p>
                <div class="steps">
                    <div class="step">鈥?{c['steps']} vulnerability steps</div>
                </div>
            </div>
            """

    html += "</body></html>"
    return html


@app.route("/runs")
def runs_page():
    """Show scan run history."""
    from utils.run_history import run_history

    runs = run_history.list_runs(limit=30)
    cost_summary = run_history.get_cost_summary()

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Run History - BlacksmithAI</title>
        <style>
            body {{ font-family: sans-serif; background: #0f172a; color: #e2e8f0; padding: 20px; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #334155; }}
            th {{ color: #94a3b8; }}
            .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin: 20px 0; }}
            .stat {{ background: #1e293b; padding: 16px; border-radius: 8px; }}
            .stat-value {{ font-size: 24px; font-weight: bold; color: #38bdf8; }}
            .stat-label {{ color: #94a3b8; font-size: 13px; }}
            nav a {{ color: #38bdf8; margin-right: 20px; }}
        </style>
    </head>
    <body>
        <nav><a href="/">Dashboard</a><a href="/targets">Targets</a><a href="/findings">Findings</a><a href="/chains">Attack Chains</a><a href="/runs">Runs</a><a href="/new-scan">+ New Scan</a></nav>
        <h1 style="margin-top: 20px;">馃搳 Run History</h1>
        <div class="stats">
            <div class="stat"><div class="stat-value">{cost_summary['total_runs']}</div><div class="stat-label">Total Runs</div></div>
            <div class="stat"><div class="stat-value">${cost_summary['total_cost_usd']}</div><div class="stat-label">Total LLM Cost</div></div>
            <div class="stat"><div class="stat-value">${cost_summary['avg_cost_per_run']}</div><div class="stat-label">Avg Cost/Run</div></div>
            <div class="stat"><div class="stat-value">{cost_summary['total_tokens']:,}</div><div class="stat-label">Total Tokens</div></div>
        </div>
        <table>
            <thead><tr><th>Run ID</th><th>Target</th><th>Type</th><th>Status</th><th>Started</th><th>Findings</th></tr></thead>
            <tbody>
    """

    for r in runs:
        html += f"""
        <tr>
            <td>{r['run_id']}</td>
            <td>{r['target']}</td>
            <td>{r['scan_type']}</td>
            <td>{r['status']}</td>
            <td>{r['started_at']}</td>
            <td>{r.get('findings_count', 0)}</td>
        </tr>
        """

    html += """
            </tbody>
        </table>
    </body>
    </html>
    """
    return html


@app.route("/budget")
def budget_page():
    """Show budget status."""
    from utils.run_history import budget_guard

    status = budget_guard.get_status()

    daily_pct = min(100, int(status["daily_used_usd"] / status["daily_limit_usd"] * 100))
    run_pct = min(100, int(status["run_used_usd"] / status["run_limit_usd"] * 100))

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Budget - BlacksmithAI</title>
        <style>
            body {{ font-family: sans-serif; background: #0f172a; color: #e2e8f0; padding: 20px; }}
            .card {{ background: #1e293b; padding: 24px; margin: 16px 0; border-radius: 8px; }}
            .value {{ font-size: 32px; font-weight: bold; color: #38bdf8; }}
            .label {{ color: #94a3b8; margin-top: 8px; }}
            .bar {{ height: 8px; background: #334155; border-radius: 4px; margin-top: 12px; }}
            .bar-fill {{ height: 100%; background: #22c55e; border-radius: 4px; }}
            nav a {{ color: #38bdf8; margin-right: 20px; }}
        </style>
    </head>
    <body>
        <nav><a href="/">Dashboard</a><a href="/runs">Runs</a><a href="/budget">Budget</a></nav>
        <h1 style="margin-top: 20px;">馃挵 Budget Control</h1>
        <div class="card">
            <div class="value">${status['daily_used_usd']} / ${status['daily_limit_usd']}</div>
            <div class="label">Daily LLM Spend (${status['daily_remaining_usd']} remaining)</div>
            <div class="bar"><div class="bar-fill" style="width: {daily_pct}%"></div></div>
        </div>
        <div class="card">
            <div class="value">${status['run_used_usd']} / ${status['run_limit_usd']}</div>
            <div class="label">Per-Run Spend (${status['run_remaining_usd']} remaining)</div>
            <div class="bar"><div class="bar-fill" style="width: {run_pct}%"></div></div>
        </div>
    </body>
    </html>
    """
    return html


@app.route("/agents")
def agents_page():
    """Show multi-agent status and memory."""
    from utils.multi_agent import orchestrator
    from utils.agent_memory import agent_memory

    memory_summary = agent_memory.get_memory_summary()

    agents = [
        {
            "name": orchestrator.recon_agent.name,
            "role": "Reconnaissance",
            "status": "Busy" if orchestrator.recon_agent.busy else "Idle",
            "findings": len(orchestrator.recon_agent.findings),
        },
        {
            "name": orchestrator.exploit_agent.name,
            "role": "Exploitation",
            "status": "Busy" if orchestrator.exploit_agent.busy else "Idle",
            "findings": len(orchestrator.exploit_agent.findings),
        },
        {
            "name": orchestrator.name,
            "role": "Coordination",
            "status": "Busy" if orchestrator.busy else "Idle",
            "findings": len(orchestrator.all_findings),
        },
    ]

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Agents - BlacksmithAI</title>
        <style>
            body {{ font-family: sans-serif; background: #0f172a; color: #e2e8f0; padding: 20px; }}
            .agent {{ background: #1e293b; padding: 20px; margin: 12px 0; border-radius: 8px; display: flex; justify-content: space-between; align-items: center; }}
            .agent-name {{ font-size: 18px; font-weight: bold; color: #38bdf8; }}
            .agent-role {{ color: #94a3b8; font-size: 14px; margin-top: 4px; }}
            .status {{ padding: 6px 12px; border-radius: 6px; font-size: 13px; font-weight: bold; }}
            .status.Idle {{ background: #166534; color: #bbf7d0; }}
            .status.Busy {{ background: #991b1b; color: #fecaca; }}
            .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin: 20px 0; }}
            .stat {{ background: #1e293b; padding: 16px; border-radius: 8px; }}
            .stat-value {{ font-size: 28px; font-weight: bold; color: #38bdf8; }}
            .stat-label {{ color: #94a3b8; font-size: 13px; margin-top: 4px; }}
            nav a {{ color: #38bdf8; margin-right: 20px; }}
        </style>
    </head>
    <body>
        <nav><a href="/">Dashboard</a><a href="/agents">Agents</a><a href="/chains">Chains</a><a href="/runs">Runs</a><a href="/budget">Budget</a></nav>
        <h1 style="margin-top: 20px;">🤖 Multi-Agent Team</h1>
        <div class="stats">
            <div class="stat"><div class="stat-value">{memory_summary['total_targets_remembered']}</div><div class="stat-label">Targets Remembered</div></div>
            <div class="stat"><div class="stat-value">{memory_summary['total_findings_remembered']}</div><div class="stat-label">Findings in Memory</div></div>
        </div>
    """

    for agent in agents:
        html += f"""
        <div class="agent">
            <div>
                <div class="agent-name">{agent['name']}</div>
                <div class="agent-role">{agent['role']} | {agent['findings']} findings</div>
            </div>
            <span class="status {agent['status']}">{agent['status']}</span>
        </div>
        """

    html += "</body></html>"
    return html


@app.route("/orchestrated-scan")
def orchestrated_scan_page():
    """Multi-agent scan page with real-time progress."""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Orchestrated Scan - BlacksmithAI</title>
        <style>
            body { font-family: sans-serif; background: #0f172a; color: #e2e8f0; padding: 20px; }
            .container { max-width: 800px; margin: 0 auto; }
            .form-group { margin: 20px 0; }
            label { display: block; margin-bottom: 8px; color: #94a3b8; }
            input { width: 100%; padding: 12px; background: #1e293b; border: 1px solid #334155; border-radius: 8px; color: #e2e8f0; font-size: 16px; }
            button { width: 100%; padding: 14px; background: #22c55e; color: #0f172a; border: none; border-radius: 8px; font-size: 16px; font-weight: bold; cursor: pointer; }
            button:hover { background: #16a34a; }
            .progress-container { margin: 30px 0; display: none; }
            .progress-bar { width: 100%; height: 20px; background: #1e293b; border-radius: 10px; overflow: hidden; }
            .progress-fill { height: 100%; background: linear-gradient(90deg, #38bdf8, #22c55e); width: 0%; transition: width 0.5s; }
            .step { background: #1e293b; padding: 12px; margin: 8px 0; border-radius: 8px; border-left: 3px solid #38bdf8; }
            .step.done { border-left-color: #22c55e; }
            .step.current { border-left-color: #eab308; }
            nav a { color: #38bdf8; margin-right: 20px; }
            h1 { color: #38bdf8; }
        </style>
    </head>
    <body>
        <nav><a href="/">Dashboard</a><a href="/agents">Agents</a><a href="/orchestrated-scan">Multi-Agent Scan</a></nav>
        <div class="container">
            <h1>🤖 Multi-Agent Orchestrated Scan</h1>
            <p style="color:#94a3b8;">Full pipeline: Recon Agent -> Exploit Agent -> Coordinator -> Report</p>
            <form id="scanForm">
                <div class="form-group">
                    <label>Target URL</label>
                    <input type="text" id="target" placeholder="https://example.com" required>
                </div>
                <button type="submit">🚀 Start Multi-Agent Scan</button>
            </form>
            <div class="progress-container" id="progress">
                <div class="progress-bar"><div class="progress-fill" id="progressFill"></div></div>
                <div id="steps"></div>
            </div>
        </div>
        <script>
            document.getElementById('scanForm').onsubmit = async (e) => {
                e.preventDefault();
                const target = document.getElementById('target').value;
                document.getElementById('progress').style.display = 'block';
                document.getElementById('progressFill').style.width = '5%';
                document.getElementById('steps').innerHTML = '<div class="step current">Starting...</div>';

                try {
                    const res = await fetch('/api/orchestrated/start', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({target})
                    });
                    const data = await res.json();
                    document.getElementById('progressFill').style.width = '100%';
                    document.getElementById('steps').innerHTML =
                        '<div class="step done">✅ Scan completed! Found ' + data.findings_count + ' findings</div>' +
                        '<div class="step done">📄 Report: ' + data.report_path + '</div>';
                } catch (err) {
                    document.getElementById('steps').innerHTML = '<div class="step">Error: ' + err.message + '</div>';
                }
            };
        </script>
    </body>
    </html>
    """
    return html


@app.route("/api/orchestrated/start", methods=["POST"])
def api_orchestrated_start():
    """Start an orchestrated multi-agent scan."""
    from flask import request
    from utils.orchestrated_scan import orchestrated_scan

    target = request.json.get("target", "")
    if not target:
        return jsonify({"error": "Target required"}), 400

    import threading
    def run():
        orchestrated_scan.run_full_scan(target)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()

    return jsonify({"status": "started", "target": target})


@app.route("/ai")
def ai_page():
    """AI analysis page using local LLM."""
    from utils.llm_analyzer import llm_analyzer
    from utils.database import db

    status = llm_analyzer.get_status()
    findings = db.get_findings(limit=20)

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>AI Analysis - BlacksmithAI</title>
        <style>
            body { font-family: sans-serif; background: #0f172a; color: #e2e8f0; padding: 20px; }
            .container { max-width: 900px; margin: 0 auto; }
            .card { background: #1e293b; padding: 20px; margin: 16px 0; border-radius: 8px; }
            .status { display: inline-block; padding: 4px 12px; border-radius: 6px; font-size: 13px; font-weight: bold; }
            .status.online { background: #166534; color: #bbf7d0; }
            .status.offline { background: #991b1b; color: #fecaca; }
            .model { color: #38bdf8; font-size: 18px; font-weight: bold; }
            button { padding: 12px 24px; background: #8b5cf6; color: white; border: none; border-radius: 8px; font-size: 15px; cursor: pointer; }
            button:hover { background: #7c3aed; }
            .result { background: #0f172a; padding: 16px; border-radius: 8px; margin-top: 16px; white-space: pre-wrap; font-family: monospace; }
            nav a { color: #38bdf8; margin-right: 20px; }
            h1 { color: #38bdf8; }
        </style>
    </head>
    <body>
        <nav><a href="/">Dashboard</a><a href="/ai">AI Analysis</a><a href="/orchestrated-scan">Scan</a></nav>
        <div class="container">
            <h1>🧠 AI Analysis (Local LLM)</h1>
            <div class="card">
                <div>Status: <span class="status """"""+("online" if status["ollama_available"] else "offline")+"""">"""+("ONLINE" if status["ollama_available"] else "OFFLINE")+"""</span></div>
                <div class="model" style="margin-top:8px;">Model: """+status["default_model"]+"""</div>
                <div style="color:#94a3b8; margin-top:4px;">Running locally via Ollama - no cloud API needed</div>
            </div>
            <div class="card">
                <h3 style="margin-bottom:12px;">Analyze Recent Findings</h3>
                <p style="color:#94a3b8; margin-bottom:16px;">""" + str(len(findings)) + " findings in database" + """</p>
                <button onclick="runAnalysis()">🤖 Run AI Analysis</button>
                <div id="result" class="result" style="display:none;"></div>
            </div>
        </div>
        <script>
            async function runAnalysis() {
                document.getElementById('result').style.display = 'block';
                document.getElementById('result').textContent = 'Analyzing... (12B model, may take 30-60 seconds)';
                try {
                    const res = await fetch('/api/ai/analyze');
                    const data = await res.json();
                    document.getElementById('result').textContent = JSON.stringify(data, null, 2);
                } catch (err) {
                    document.getElementById('result').textContent = 'Error: ' + err.message;
                }
            }
        </script>
    </body>
    </html>
    """
    return html


@app.route("/api/ai/analyze")
def api_ai_analyze():
    """Run AI analysis on recent findings."""
    from utils.llm_analyzer import llm_analyzer
    from utils.database import db

    findings = db.get_findings(limit=5)
    if not findings:
        return jsonify({"message": "No findings to analyze. Run a scan first."})

    result = llm_analyzer.correlate_findings(findings)
    return jsonify(result)


@app.route("/health")
def health_page():
    """System health check - all modules status."""
    checks = []

    # 1. Database
    try:
        from utils.database import db
        stats = db.get_stats()
        checks.append(("SQLite Database", "OK", f"{stats['targets']} targets"))
    except Exception as e:
        checks.append(("SQLite Database", "FAIL", str(e)))

    # 2. Docker container
    try:
        import requests
        resp = requests.get("http://localhost:9756/", timeout=3)
        checks.append(("Docker Executor", "OK", "Port 9756"))
    except Exception as e:
        checks.append(("Docker Executor", "FAIL", "Not reachable"))

    # 3. LLM (Ollama)
    try:
        from utils.llm_analyzer import llm_analyzer
        if llm_analyzer.available:
            checks.append(("Local LLM (Ollama)", "OK", llm_analyzer.default_model))
        else:
            checks.append(("Local LLM (Ollama)", "OFFLINE", "Not running"))
    except Exception as e:
        checks.append(("Local LLM (Ollama)", "FAIL", str(e)))

    # 4. Scan Engine
    try:
        from utils.scan_engine import scan_engine
        checks.append(("Scan Engine", "OK", "7 tools available"))
    except Exception as e:
        checks.append(("Scan Engine", "FAIL", str(e)))

    # 5. PoC Validator
    try:
        from utils.poc_validator import poc_validator
        checks.append(("PoC Validator", "OK", "5 vuln types"))
    except Exception as e:
        checks.append(("PoC Validator", "FAIL", str(e)))

    # 6. Multi-Agent
    try:
        from utils.multi_agent import orchestrator
        checks.append(("Multi-Agent System", "OK", "3 agents"))
    except Exception as e:
        checks.append(("Multi-Agent System", "FAIL", str(e)))

    # 7. Agent Memory
    try:
        from utils.agent_memory import agent_memory
        mem = agent_memory.get_memory_summary()
        checks.append(("Agent Memory", "OK", f"{mem['total_targets_remembered']} targets"))
    except Exception as e:
        checks.append(("Agent Memory", "FAIL", str(e)))

    # 8. Budget
    try:
        from utils.run_history import budget_guard
        budget = budget_guard.get_status()
        checks.append(("Budget Control", "OK", f"${budget['daily_used_usd']}/${budget['daily_limit_usd']}"))
    except Exception as e:
        checks.append(("Budget Control", "FAIL", str(e)))

    # 9. Report Generator
    try:
        from utils.report_generator_pro import report_generator_pro
        checks.append(("Report Generator", "OK", "HTML reports"))
    except Exception as e:
        checks.append(("Report Generator", "FAIL", str(e)))

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>System Health - BlacksmithAI</title>
        <style>
            body { font-family: sans-serif; background: #0f172a; color: #e2e8f0; padding: 20px; }
            .container { max-width: 800px; margin: 0 auto; }
            .check { background: #1e293b; padding: 16px; margin: 8px 0; border-radius: 8px; display: flex; justify-content: space-between; align-items: center; }
            .name { font-size: 16px; }
            .detail { color: #94a3b8; font-size: 13px; margin-top: 4px; }
            .status { padding: 6px 12px; border-radius: 6px; font-size: 13px; font-weight: bold; }
            .status.OK { background: #166534; color: #bbf7d0; }
            .status.FAIL { background: #991b1b; color: #fecaca; }
            .status.OFFLINE { background: #92400e; color: #fde68a; }
            nav a { color: #38bdf8; margin-right: 20px; }
            h1 { color: #38bdf8; }
        </style>
    </head>
    <body>
        <nav><a href="/">Dashboard</a><a href="/health">System Health</a></nav>
        <div class="container">
            <h1>🩺 System Health Check</h1>
    """

    for name, status, detail in checks:
        html += f"""
        <div class="check">
            <div>
                <div class="name">{name}</div>
                <div class="detail">{detail}</div>
            </div>
            <span class="status {status}">{status}</span>
        </div>
        """

    html += """
        </div>
    </body>
    </html>
    """
    return html


@app.route("/remediation")
def remediation_page():
    """AI-powered fix recommendations page."""
    from utils.database import db
    from utils.remediation_advisor import remediation_advisor

    findings = db.get_findings(limit=20)
    plan = remediation_advisor.get_fix_plan(findings)

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Remediation - BlacksmithAI</title>
        <style>
            body { font-family: sans-serif; background: #0f172a; color: #e2e8f0; padding: 20px; }
            .container { max-width: 900px; margin: 0 auto; }
            .summary { background: #1e293b; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
            .issue { background: #1e293b; padding: 16px; margin: 10px 0; border-radius: 8px; border-left: 4px solid #ef4444; }
            .issue.high { border-left-color: #f97316; }
            .issue.medium { border-left-color: #eab308; }
            .issue.low { border-left-color: #22c55e; }
            .order { display: inline-block; background: #334155; color: #38bdf8; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; margin-right: 8px; }
            .title { font-size: 16px; font-weight: bold; }
            .target { color: #94a3b8; font-size: 13px; margin-top: 4px; }
            nav a { color: #38bdf8; margin-right: 20px; }
            h1 { color: #38bdf8; }
        </style>
    </head>
    <body>
        <nav><a href="/">Dashboard</a><a href="/findings">Findings</a><a href="/remediation">Fix Plan</a><a href="/ai">AI Analysis</a></nav>
        <div class="container">
            <h1>🔧 AI-Powered Fix Plan</h1>
            <div class="summary">
                <div>Total issues: <strong>""" + str(plan["total_issues"]) + """</strong></div>
                <div style="margin-top:8px;">
                    <span style="color:#ef4444;">Critical: """ + str(plan["critical"]) + """</span> |
                    <span style="color:#f97316; margin-left:12px;">High: """ + str(plan["high"]) + """</span>
                </div>
            </div>
    """

    for item in plan["fix_order"]:
        html += f"""
        <div class="issue {item['severity']}">
            <div class="title">
                <span class="order">#{item['order']}</span>
                {item['title']}
            </div>
            <div class="target">{item['target']}</div>
        </div>
        """

    if not plan["fix_order"]:
        html += "<p style='color:#94a3b8;'>No findings yet. Run a scan first.</p>"

    html += """
        </div>
    </body>
    </html>
    """
    return html


@app.route("/api/export/json")
def api_export_json():
    """Export all findings as JSON."""
    from flask import Response
    import json
    from utils.database import db

    findings = db.get_findings(limit=500)
    targets = db.get_targets(limit=200)

    data = {
        "exported_at": datetime.now().isoformat(),
        "targets": targets,
        "findings": findings,
        "summary": {
            "total_targets": len(targets),
            "total_findings": len(findings),
            "critical": sum(1 for f in findings if f["severity"] == "critical"),
            "high": sum(1 for f in findings if f["severity"] == "high"),
        }
    }

    return Response(
        json.dumps(data, indent=2, ensure_ascii=False, default=str),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=blacksmith_export.json"}
    )


@app.route("/api-docs")
def api_docs_page():
    """API documentation page."""
    endpoints = [
        {"method": "POST", "path": "/api/scan/start", "description": "Start a quick scan", "body": '{"target": "https://example.com", "scan_type": "quick"}'},
        {"method": "GET", "path": "/api/scan/status", "description": "Get current scan status", "body": ""},
        {"method": "POST", "path": "/api/orchestrated/start", "description": "Start full multi-agent scan", "body": '{"target": "https://example.com"}'},
        {"method": "GET", "path": "/api/ai/analyze", "description": "Run AI analysis on findings", "body": ""},
        {"method": "GET", "path": "/api/export/json", "description": "Export all findings as JSON", "body": ""},
        {"method": "GET", "path": "/api/history", "description": "Get scan history", "body": ""},
        {"method": "GET", "path": "/api/stats", "description": "Get system stats", "body": ""},
        {"method": "GET", "path": "/api/report/html", "description": "Generate HTML report", "body": ""},
    ]

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>API Docs - BlacksmithAI</title>
        <style>
            body { font-family: sans-serif; background: #0f172a; color: #e2e8f0; padding: 20px; }
            .container { max-width: 900px; margin: 0 auto; }
            .endpoint { background: #1e293b; padding: 16px; margin: 12px 0; border-radius: 8px; }
            .method { display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: bold; margin-right: 8px; }
            .method.POST { background: #166534; color: #bbf7d0; }
            .method.GET { background: #1e40af; color: #bfdbfe; }
            .path { font-family: monospace; font-size: 15px; color: #38bdf8; }
            .desc { color: #94a3b8; margin-top: 6px; font-size: 14px; }
            .body { background: #0f172a; padding: 10px; border-radius: 6px; margin-top: 8px; font-family: monospace; font-size: 13px; color: #22c55e; }
            nav a { color: #38bdf8; margin-right: 20px; }
            h1 { color: #38bdf8; }
        </style>
    </head>
    <body>
        <nav><a href="/">Dashboard</a><a href="/api-docs">API Docs</a></nav>
        <div class="container">
            <h1>📚 API Documentation</h1>
            <p style="color:#94a3b8; margin-bottom:20px;">Base URL: http://localhost:8501</p>
    """

    for ep in endpoints:
        html += f"""
        <div class="endpoint">
            <span class="method {ep['method']}">{ep['method']}</span>
            <span class="path">{ep['path']}</span>
            <div class="desc">{ep['description']}</div>
            {"<div class='body'>" + ep['body'] + "</div>" if ep['body'] else ""}
        </div>
        """

    html += """
        </div>
    </body>
    </html>
    """
    return html


@app.route("/api/progress")
def api_progress():
    """Get current scan progress."""
    from utils.progress_tracker import progress_tracker
    return jsonify(progress_tracker.get_state())


@app.route("/llm-security")
def llm_security_page():
    """LLM security testing page."""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>LLM Security - BlacksmithAI</title>
        <style>
            body { font-family: sans-serif; background: #0f172a; color: #e2e8f0; padding: 20px; }
            .container { max-width: 800px; margin: 0 auto; }
            .form-group { margin: 20px 0; }
            label { display: block; margin-bottom: 8px; color: #94a3b8; }
            input { width: 100%; padding: 12px; background: #1e293b; border: 1px solid #334155; border-radius: 8px; color: #e2e8f0; font-size: 16px; }
            button { width: 100%; padding: 14px; background: #8b5cf6; color: white; border: none; border-radius: 8px; font-size: 16px; font-weight: bold; cursor: pointer; }
            button:hover { background: #7c3aed; }
            .feature { background: #1e293b; padding: 16px; margin: 10px 0; border-radius: 8px; }
            nav a { color: #38bdf8; margin-right: 20px; }
            h1 { color: #8b5cf6; }
            .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; background: #7c3aed; color: white; margin-left: 8px; }
        </style>
    </head>
    <body>
        <nav><a href="/">Dashboard</a><a href="/llm-security">LLM Security</a></nav>
        <div class="container">
            <h1>🔒 LLM Security Testing <span class="badge">NEW</span></h1>
            <p style="color:#94a3b8; margin-bottom: 20px;">Test AI/LLM applications for security vulnerabilities</p>
            
            <div class="feature">
                <h3>What we test:</h3>
                <ul style="margin-top: 12px; padding-left: 20px; color: #94a3b8;">
                    <li>Prompt Injection - Can the LLM be manipulated?</li>
                    <li>RAG Poisoning - Can the knowledge base be poisoned?</li>
                    <li>Agent Hijacking - Can AI agents be hijacked?</li>
                    <li>Data Exfiltration - Can sensitive data be extracted?</li>
                </ul>
            </div>

            <form id="testForm">
                <div class="form-group">
                    <label>LLM API Endpoint URL</label>
                    <input type="text" id="endpoint" placeholder="http://localhost:11434/api/generate" required>
                </div>
                <button type="submit">🚀 Run LLM Security Test</button>
            </form>
            <div id="result" style="margin-top: 20px;"></div>
        </div>
        <script>
            document.getElementById('testForm').onsubmit = async (e) => {
                e.preventDefault();
                const endpoint = document.getElementById('endpoint').value;
                document.getElementById('result').innerHTML = '<div style="background:#1e293b;padding:16px;border-radius:8px;">Testing...</div>';
                try {
                    const res = await fetch('/api/llm-security/test', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({endpoint})
                    });
                    const data = await res.json();
                    document.getElementById('result').innerHTML = 
                        '<div style="background:#1e293b;padding:16px;border-radius:8px;">' +
                        '<h3>Results</h3>' +
                        '<p>Overall Risk: <strong>' + data.overall_risk + '</strong></p>' +
                        '<p>Prompt Injection Vulnerable: ' + data.tests.prompt_injection.vulnerable + '</p>' +
                        '</div>';
                } catch (err) {
                    document.getElementById('result').innerHTML = '<div style="background:#7f1d1d;padding:16px;border-radius:8px;">Error: ' + err.message + '</div>';
                }
            };
        </script>
    </body>
    </html>
    """
    return html


@app.route("/api/llm-security/test", methods=["POST"])
def api_llm_security_test():
    """Run LLM security test on an endpoint."""
    from flask import request
    from utils.llm_security import llm_security_tester

    endpoint = request.json.get("endpoint", "")
    if not endpoint:
        return jsonify({"error": "Endpoint required"}), 400

    result = llm_security_tester.run_full_llm_security_test(endpoint)
    return jsonify(result)


@app.route("/llm")
def llm_home():
    """LLM Security main page - the new focus."""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>LLM Security - BlacksmithAI</title>
        <style>
            body { font-family: sans-serif; background: #0f172a; color: #e2e8f0; padding: 20px; }
            .container { max-width: 1000px; margin: 0 auto; }
            .header { background: linear-gradient(135deg, #7c3aed 0%, #4f46e5 100%); padding: 30px; border-radius: 12px; margin-bottom: 24px; }
            .header h1 { color: white; font-size: 28px; }
            .header p { color: #c4b5fd; margin-top: 8px; }
            .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; }
            .card { background: #1e293b; padding: 20px; border-radius: 8px; }
            .card h3 { color: #8b5cf6; margin-bottom: 12px; }
            .card p { color: #94a3b8; font-size: 14px; line-height: 1.6; }
            .card a { display: inline-block; margin-top: 12px; color: #8b5cf6; text-decoration: none; font-weight: bold; }
            .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; margin-left: 8px; }
            .badge.critical { background: #7f1d1d; color: #fca5a5; }
            .badge.high { background: #991b1b; color: #fecaca; }
            .badge.medium { background: #92400e; color: #fde68a; }
            nav a { color: #38bdf8; margin-right: 20px; }
        </style>
    </head>
    <body>
        <nav><a href="/">Dashboard</a><a href="/llm">LLM Security</a><a href="/llm-security">Test LLM</a></nav>
        <div class="container">
            <div class="header">
                <h1>🔒 LLM Security Testing Platform</h1>
                <p>OWASP Top 10 for LLM Applications 2025 | Prompt Injection | RAG Security | Agent Security</p>
            </div>
            
            <div class="grid">
                <div class="card">
                    <h3>LLM01: Prompt Injection <span class="badge critical">CRITICAL</span></h3>
                    <p>Test if the LLM can be manipulated via direct or indirect prompt injection attacks.</p>
                    <a href="/llm-security">Test Now →</a>
                </div>
                
                <div class="card">
                    <h3>LLM02: Sensitive Data Leak <span class="badge high">HIGH</span></h3>
                    <p>Check if the LLM reveals API keys, passwords, secrets, or PII.</p>
                    <a href="/llm-security">Test Now →</a>
                </div>
                
                <div class="card">
                    <h3>LLM06: Excessive Agency <span class="badge critical">CRITICAL</span></h3>
                    <p>Test if AI agents have too many tools or permissions that can be misused.</p>
                    <a href="/llm-security">Test Now →</a>
                </div>
                
                <div class="card">
                    <h3>LLM07: System Prompt Leak <span class="badge high">HIGH</span></h3>
                    <p>Can an attacker extract the system prompt and learn internal instructions?</p>
                    <a href="/llm-security">Test Now →</a>
                </div>
                
                <div class="card">
                    <h3>LLM04: RAG Poisoning <span class="badge high">HIGH</span></h3>
                    <p>Test if the RAG knowledge base can be poisoned with malicious documents.</p>
                    <a href="/llm-security">Test Now →</a>
                </div>
                
                <div class="card">
                    <h3>OWASP Top 10 Report</h3>
                    <p>Full compliance report against OWASP LLM Top 10 standard.</p>
                    <a href="/api/export/json">Export Report →</a>
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    return html


@app.route("/llm-remediation")
def llm_remediation_page():
    """LLM security remediation advice page."""
    from utils.llm_remediation import llm_remediation

    recs = llm_remediation.get_all_recommendations()

    cards_html = ""
    for r in recs:
        sev_color = {
            "critical": "#dc2626",
            "high": "#ea580c",
        }.get(r["severity"], "#6b7280")

        cards_html += f"""
        <div style="background:#1e293b; padding:20px; margin:16px 0; border-radius:8px; border-left: 4px solid {sev_color};">
            <h3 style="color:{sev_color}; margin:0;">{r['name']}</h3>
            <p style="color:#94a3b8; margin:8px 0;">Severity: {r['severity']}</p>
            <pre style="white-space: pre-wrap; color:#e2e8f0; font-size:14px; background:#0f172a; padding:12px; border-radius:6px; margin:12px 0;">{r['fix']}</pre>
            <pre style="white-space: pre-wrap; color:#22c55e; font-size:13px; background:#0f172a; padding:12px; border-radius:6px;">{r['code_example']}</pre>
        </div>
        """

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>LLM Remediation - BlacksmithAI</title>
        <style>
            body {{ font-family: sans-serif; background: #0f172a; color: #e2e8f0; padding: 20px; }}
            .container {{ max-width: 900px; margin: 0 auto; }}
            nav a {{ color: #38bdf8; margin-right: 20px; }}
            h1 {{ color: #8b5cf6; }}
        </style>
    </head>
    <body>
        <nav><a href="/">Dashboard</a><a href="/llm">LLM Security</a><a href="/llm-remediation">Remediation</a></nav>
        <div class="container">
            <h1>🔧 LLM Security Remediation Guide</h1>
            <p style="color:#94a3b8; margin-bottom:24px;">How to fix each OWASP LLM vulnerability</p>
            {cards_html}
        </div>
    </body>
    </html>
    """
    return html


@app.route("/llm-history")
def llm_history_page():
    """LLM security test history page."""
    from utils.llm_history import llm_history

    history = llm_history.get_history(limit=20)
    trend = llm_history.get_trend()

    trend_emoji = {
        "improving": "📈",
        "worsening": "📉",
        "stable": "➡️",
        "not_enough_data": "📊",
    }.get(trend["trend"], "📊")

    history_html = ""
    for h in history:
        sev = h["summary"]["by_severity"]
        history_html += f"""
        <div style="background:#1e293b; padding:16px; margin:12px 0; border-radius:8px;">
            <h3 style="color:#38bdf8; margin:0;">{h['target']}</h3>
            <p style="color:#94a3b8; margin:4px 0;">{h['timestamp']}</p>
            <p style="margin:8px 0;">
                🔴 Critical: {sev['critical']} |
                🟠 High: {sev['high']} |
                🟡 Medium: {sev['medium']} |
                🟢 Low: {sev['low']}
            </p>
        </div>
        """

    if not history_html:
        history_html = '<p style="color:#94a3b8;">No tests yet. Run your first LLM security test!</p>'

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>LLM History - BlacksmithAI</title>
        <style>
            body {{ font-family: sans-serif; background: #0f172a; color: #e2e8f0; padding: 20px; }}
            .container {{ max-width: 800px; margin: 0 auto; }}
            nav a {{ color: #38bdf8; margin-right: 20px; }}
            h1 {{ color: #8b5cf6; }}
            .trend {{ background: #1e293b; padding: 20px; border-radius: 8px; margin-bottom: 20px; text-align: center; }}
            .trend .emoji {{ font-size: 48px; }}
        </style>
    </head>
    <body>
        <nav><a href="/">Dashboard</a><a href="/llm">LLM Security</a><a href="/llm-history">History</a></nav>
        <div class="container">
            <h1>📊 LLM Security Test History</h1>
            
            <div class="trend">
                <div class="emoji">{trend_emoji}</div>
                <p style="font-size: 20px; margin: 8px 0;">Trend: {trend['trend']}</p>
                <p style="color:#94a3b8;">{trend.get('tests', 0)} tests recorded</p>
            </div>

            <h2>Recent Tests</h2>
            {history_html}
        </div>
    </body>
    </html>
    """
    return html


@app.route("/llm-attack-chain")
def llm_attack_chain_page():
    """Multi-turn attack chain testing page."""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Attack Chains - BlacksmithAI</title>
        <style>
            body { font-family: sans-serif; background: #0f172a; color: #e2e8f0; padding: 20px; }
            .container { max-width: 800px; margin: 0 auto; }
            .form-group { margin: 20px 0; }
            label { display: block; margin-bottom: 8px; color: #94a3b8; }
            input { width: 100%; padding: 12px; background: #1e293b; border: 1px solid #334155; border-radius: 8px; color: #e2e8f0; font-size: 16px; }
            button { width: 100%; padding: 14px; background: #dc2626; color: white; border: none; border-radius: 8px; font-size: 16px; font-weight: bold; cursor: pointer; }
            button:hover { background: #b91c1c; }
            .chain { background: #1e293b; padding: 16px; margin: 12px 0; border-radius: 8px; }
            .chain h3 { color: #dc2626; margin: 0 0 8px 0; }
            .chain p { color: #94a3b8; font-size: 14px; }
            nav a { color: #38bdf8; margin-right: 20px; }
            h1 { color: #dc2626; }
        </style>
    </head>
    <body>
        <nav><a href="/">Dashboard</a><a href="/llm">LLM Security</a><a href="/llm-attack-chain">Attack Chains</a></nav>
        <div class="container">
            <h1>⚔️ Multi-Turn Attack Chains</h1>
            <p style="color:#94a3b8; margin-bottom: 24px;">Multi-turn prompt injection attacks (inspired by Microsoft PyRIT)</p>

            <div class="chain">
                <h3>1. Gradual System Prompt Extraction</h3>
                <p>4 turns - Gradually extract the system prompt through conversation</p>
            </div>
            <div class="chain">
                <h3>2. Role Play Jailbreak</h3>
                <p>3 turns - Use role-playing to bypass safety restrictions</p>
            </div>
            <div class="chain">
                <h3>3. Data Exfiltration Chain</h3>
                <p>3 turns - Gradually extract sensitive data</p>
            </div>

            <form id="testForm">
                <div class="form-group">
                    <label>LLM API Endpoint URL</label>
                    <input type="text" id="endpoint" placeholder="http://localhost:11434/api/generate" required>
                </div>
                <button type="submit">⚔️ Run Attack Chains</button>
            </form>
            <div id="result" style="margin-top: 20px;"></div>
        </div>
        <script>
            document.getElementById('testForm').onsubmit = async (e) => {
                e.preventDefault();
                const endpoint = document.getElementById('endpoint').value;
                document.getElementById('result').innerHTML = '<div style="background:#1e293b;padding:16px;border-radius:8px;">Running attack chains (this may take a minute)...</div>';
                try {
                    const res = await fetch('/api/llm/attack-chain', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({endpoint})
                    });
                    const data = await res.json();
                    let html = '<div style="background:#1e293b;padding:16px;border-radius:8px;">';
                    html += '<h3>Results</h3>';
                    for (const chain of data.results) {
                        const status = chain.success ? '🔴 VULNERABLE' : '✅ SECURE';
                        html += `<p><strong>${chain.chain_name}:</strong> ${status}</p>`;
                        html += `<p style="color:#94a3b8;font-size:13px;">Turns: ${chain.turn_results.length}</p>`;
                    }
                    html += '</div>';
                    document.getElementById('result').innerHTML = html;
                } catch (err) {
                    document.getElementById('result').innerHTML = '<div style="background:#7f1d1d;padding:16px;border-radius:8px;">Error: ' + err.message + '</div>';
                }
            };
        </script>
    </body>
    </html>
    """
    return html


@app.route("/api/llm/attack-chain", methods=["POST"])
def api_llm_attack_chain():
    """Run multi-turn attack chains."""
    from flask import request
    from utils.multi_turn_attacker import multi_turn_attacker

    endpoint = request.json.get("endpoint", "")
    if not endpoint:
        return jsonify({"error": "Endpoint required"}), 400

    results = multi_turn_attacker.run_attack_chain(endpoint)
    return jsonify({"results": results})


@app.route("/llm-agentic")
def llm_agentic_page():
    """OWASP Agentic Top 10 testing page."""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Agent Security - BlacksmithAI</title>
        <style>
            body { font-family: sans-serif; background: #0f172a; color: #e2e8f0; padding: 20px; }
            .container { max-width: 800px; margin: 0 auto; }
            .form-group { margin: 20px 0; }
            label { display: block; margin-bottom: 8px; color: #94a3b8; }
            input { width: 100%; padding: 12px; background: #1e293b; border: 1px solid #334155; border-radius: 8px; color: #e2e8f0; font-size: 16px; }
            button { width: 100%; padding: 14px; background: #7c3aed; color: white; border: none; border-radius: 8px; font-size: 16px; font-weight: bold; cursor: pointer; }
            button:hover { background: #6d28d9; }
            .category { background: #1e293b; padding: 12px; margin: 8px 0; border-radius: 6px; }
            .sev-critical { color: #dc2626; }
            .sev-high { color: #ea580c; }
            .sev-medium { color: #ca8a04; }
            nav a { color: #38bdf8; margin-right: 20px; }
            h1 { color: #7c3aed; }
        </style>
    </head>
    <body>
        <nav><a href="/">Dashboard</a><a href="/llm">LLM Security</a><a href="/llm-agentic">Agent Security</a></nav>
        <div class="container">
            <h1>🤖 OWASP Agentic Top 10 (2026)</h1>
            <p style="color:#94a3b8; margin-bottom: 24px;">AI Agent security testing - purpose-built for agents with tools, memory, and actions</p>

            <h3>Categories tested:</h3>
            <div class="category">
                <span class="sev-critical">🔴 AST01: Agent Goal Hijacking</span>
                <p style="color:#94a3b8; margin:4px 0 0 0; font-size:13px;">Can attacker change the agent's goals?</p>
            </div>
            <div class="category">
                <span class="sev-critical">🔴 AST02: Tool Misuse</span>
                <p style="color:#94a3b8; margin:4px 0 0 0; font-size:13px;">Can agent tools be abused?</p>
            </div>
            <div class="category">
                <span class="sev-high">🟠 AST05: Memory Poisoning</span>
                <p style="color:#94a3b8; margin:4px 0 0 0; font-size:13px;">Can long-term memory be poisoned?</p>
            </div>
            <div class="category">
                <span class="sev-high">🟠 AST07: Prompt Leakage</span>
                <p style="color:#94a3b8; margin:4px 0 0 0; font-size:13px;">Can system prompt be extracted?</p>
            </div>
            <div class="category">
                <span class="sev-high">🟠 AST08: Sensitive Info Disclosure</span>
                <p style="color:#94a3b8; margin:4px 0 0 0; font-size:13px;">Can agent leak sensitive data via tools?</p>
            </div>

            <form id="testForm">
                <div class="form-group">
                    <label>LLM API Endpoint URL</label>
                    <input type="text" id="endpoint" placeholder="http://localhost:11434/api/generate" required>
                </div>
                <button type="submit">🤖 Run Agent Security Test</button>
            </form>
            <div id="result" style="margin-top: 20px;"></div>
        </div>
        <script>
            document.getElementById('testForm').onsubmit = async (e) => {
                e.preventDefault();
                const endpoint = document.getElementById('endpoint').value;
                document.getElementById('result').innerHTML = '<div style="background:#1e293b;padding:16px;border-radius:8px;">Testing agent security...</div>';
                try {
                    const res = await fetch('/api/llm/agentic', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({endpoint})
                    });
                    const data = await res.json();
                    let html = '<div style="background:#1e293b;padding:16px;border-radius:8px;">';
                    html += '<h3>Results</h3>';
                    html += '<p>Found ' + data.results.length + ' vulnerabilities</p>';
                    for (const r of data.results) {
                        html += `<p><span class="sev-${r.severity}">[${r.severity.toUpperCase()}]</span> ${r.owasp_id}: ${r.name}</p>`;
                    }
                    html += '</div>';
                    document.getElementById('result').innerHTML = html;
                } catch (err) {
                    document.getElementById('result').innerHTML = '<div style="background:#7f1d1d;padding:16px;border-radius:8px;">Error: ' + err.message + '</div>';
                }
            };
        </script>
    </body>
    </html>
    """
    return html


@app.route("/api/llm/agentic", methods=["POST"])
def api_llm_agentic():
    """Run OWASP Agentic Top 10 test."""
    from flask import request
    from utils.owasp_agentic_tester import owasp_agentic_tester

    endpoint = request.json.get("endpoint", "")
    if not endpoint:
        return jsonify({"error": "Endpoint required"}), 400

    results = owasp_agentic_tester.test_agent(endpoint)
    return jsonify({"results": results})


def run_dashboard(host="0.0.0.0", port=8501):
    """Start the web dashboard."""
    print(f"[Dashboard] Starting on http://{host}:{port}")
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    run_dashboard()















