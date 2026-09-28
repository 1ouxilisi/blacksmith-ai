from langchain.tools import tool
import requests
import os
from langgraph.config import get_stream_writer
import json
from langchain_mcp_adapters.client import MultiServerMCPClient
import asyncio
from utils.vectors import storage_manager
from agents.base import init_embedding_model

config_tools = json.load(open("./config.json", "r"))['tools']
code_interpreter_config = json.load(open("./mcp/mcp-code-interpreter.json", "r"))['mcpServers']
playwright_config = json.load(open("./mcp/mcp-playwright.json", "r"))['mcpServers']
mcp_full = json.load(open("./mcp/mcp.json", "r"))['mcpServers']
sleep = 2


@tool
def pentest_shell(command: str, timeout: int = 300) -> dict:
    """Run a shell command for penetration testing in an isolated container.

    Available tool categories:
    - reconnaissance: whois, dig, dnsrecon, assetfinder, subfinder
    - scanning_enumeration: nmap, masscan, enum4linux-ng, gobuster, wpscan
    - vulnerability_mapping: nuclei, sslscan
    - exploitation: sqlmap, hydra, medusa, ncrack
    - post_exploitation: netcat, socat, hping3, impacket CLIs
    - general: python3, curl, httpie, openssh-client

    Args:
        command: bash command to execute, e.g. "nmap -sV -p 80,21 10.10.1.173"
        timeout: command execution timeout in seconds (default: 300)
    """

    # initialize custom stream writer
    writer = get_stream_writer()
    writer(f"running command {command}")

    response = requests.post(
        os.getenv('container_uri', 'http://localhost:9756/exec'),
        json={"cmd": command, "timeout": timeout}
    )

    if response.status_code != 200:
        writer(f"command execution failed with status code {response.status_code}")
        return f"Error: Command execution failed with status code {response.status_code}"
    
    writer("command executed, processing response...")

    return response.json()

# initialize vector store for tool documentation
embedding_model = init_embedding_model().get_model()

shell_documentation_vector_store = storage_manager(
        collection_name="tools_documentation",
        persist_directory="./store/vector_db",
        embedding_function=embedding_model
    )

# tool for shell command documentation
@tool
def shell_documentation(query: str) -> str:
    """Search documentation for pentest shell commands available in the pentest shell tool.

    Args:
        query: The documentation query string to search for.
    """
    # initialize custom stream writer
    writer = get_stream_writer()
    writer(f"searching documentation for query: {query}")
    results = shell_documentation_vector_store.query(query, n_results=5)
    writer(f"found {len(results)} relevant documents.")
    docs_content = "\n\n".join([doc.page_content for doc in results])
    return f"Here are some relevant documentation snippets:\n\n{docs_content}"

#####################################################################################
# MCP Tools
#####################################################################################

async def browser():
    """
    Returns MCP Playwright browser tools with responses wrapped to extract text content.
    This ensures tool responses are plain strings compatible with all LLM providers.
    """
    mcp_data = MultiServerMCPClient(playwright_config)
    tools = await mcp_data.get_tools()
    await asyncio.sleep(sleep)
    
    return tools

async def code_executor():

    mcp_data = MultiServerMCPClient(code_interpreter_config)
    tools = await mcp_data.get_tools()
    await asyncio.sleep(sleep)

    return tools


#####################################################################################
# Enhanced Modules (Audit, Attack Chain, Approval, Knowledge Base, Reporting)
#####################################################################################

from utils.audit_logger import audit_logger
from utils.attack_chain import chain_manager, AttackNode, ChainPhase, ChainStatus
from utils.approval import approval_gate, RiskLevel, ApprovalDecision
from utils.knowledge_base import knowledge_base
from utils.report_generator import report_generator


@tool
def log_finding(
    title: str,
    severity: str,
    description: str,
    cve: str = "",
    affected_target: str = "",
) -> str:
    """Log a security finding to the audit trail and report.

    Args:
        title: Short title of the finding
        severity: critical, high, medium, low, or info
        description: Detailed description of the vulnerability
        cve: CVE identifier if applicable
        affected_target: The affected system or component
    """
    evidence = ""
    finding_id = audit_logger.log_finding(
        agent="Orchestrator",
        title=title,
        severity=severity,
        description=description,
        cve=cve if cve else None,
        affected_target=affected_target if affected_target else None,
    )
    report_generator.add_finding(
        title=title,
        severity=severity,
        description=description,
        cve=cve if cve else None,
        affected_component=affected_target if affected_target else None,
    )
    return f"Finding logged: {finding_id} - {title} ({severity})"


@tool
def add_attack_node(
    phase: str,
    title: str,
    description: str,
    status: str = "discovered",
    parent_ids: str = "",
    severity: str = "info",
) -> str:
    """Add a node to the attack chain visualization.

    Args:
        phase: reconnaissance, scanning_enumeration, vulnerability_mapping, exploitation, post_exploitation
        title: Short title of this step
        description: What was found or done
        status: discovered, confirmed, exploited, or blocked
        parent_ids: Comma-separated parent node IDs (for dependency tracking)
        severity: critical, high, medium, low, info
    """
    phase_map = {
        "reconnaissance": ChainPhase.RECON,
        "scanning_enumeration": ChainPhase.SCAN,
        "vulnerability_mapping": ChainPhase.VULN,
        "exploitation": ChainPhase.EXPLOIT,
        "post_exploitation": ChainPhase.POST_EXPLOIT,
    }
    status_map = {
        "discovered": ChainStatus.DISCOVERED,
        "confirmed": ChainStatus.CONFIRMED,
        "exploited": ChainStatus.EXPLOITED,
        "blocked": ChainStatus.BLOCKED,
    }

    node_id = f"node_{len(chain_manager.chains.get('default', chain_manager.create_chain('unknown')).nodes) + 1:03d}"

    node = AttackNode(
        node_id=node_id,
        phase=phase_map.get(phase, ChainPhase.RECON),
        title=title,
        description=description,
        status=status_map.get(status, ChainStatus.DISCOVERED),
        severity=severity,
        parent_ids=parent_ids.split(",") if parent_ids else [],
    )

    chain = chain_manager.chains.get("default")
    if not chain:
        chain = chain_manager.create_chain("unknown")
    chain.add_node(node)

    return f"Attack node added: {node_id} - {title} ({status})"


@tool
def request_approval(command: str, reason: str) -> str:
    """Request human approval for a high-risk operation.
    Use this before executing destructive or highly intrusive commands.

    Args:
        command: The command to be executed
        reason: Why this action is needed and what it does
    """
    risk = approval_gate.assess_risk(command)
    decision = approval_gate.request_approval(
        agent="Orchestrator",
        command=command,
        reason=reason,
        risk_level=risk,
    )
    return f"Approval decision: {decision.value} (risk level: {risk.value})"


@tool
def query_knowledge_base(query: str, n_results: int = 3) -> str:
    """Query the penetration testing knowledge base for methodology and guidance.

    Args:
        query: What you want to know (e.g., "how to enumerate SMB shares")
        n_results: Number of results to return
    """
    results = knowledge_base.query(query, n_results=n_results)
    if not results:
        return "No relevant knowledge found."

    output = "=== Knowledge Base Results ===\n\n"
    for i, r in enumerate(results, 1):
        output += f"[{i}] {r['content'][:300]}\n\n"
    return output


@tool
def generate_report(output_format: str = "markdown") -> str:
    """Generate the final penetration test report.
    Call this at the end of an engagement to produce a comprehensive report.

    Args:
        output_format: markdown or json
    """
    import os
    os.makedirs("./outputs/reports", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if output_format.lower() == "json":
        path = f"./outputs/reports/report_{timestamp}.json"
        report_generator.generate_json_report(path)
    else:
        path = f"./outputs/reports/report_{timestamp}.md"
        report_generator.generate_markdown_report(path)

    # Also export audit log
    audit_logger.export_report(f"./outputs/reports/audit_{timestamp}.json")

    return f"Report generated: {path}"


#####################################################################################
# Auto Hunter - Batch Vulnerability Hunting Pipeline
#####################################################################################

from utils.asset_collector import asset_collector
from utils.task_queue import task_queue
from utils.fp_filter import fp_filter, RawFinding
from utils.auto_hunt import auto_hunt


@tool
def collect_targets(source: str, query: str, size: int = 100) -> str:
    """Collect targets from asset search engines for batch hunting.

    Args:
        source: fofa, quake, or shodan
        query: Search query (e.g., 'app="Apache-Shiro" && country="CN"')
        size: Number of targets to fetch
    """
    count = auto_hunt.collect_targets(source, query, size)
    return f"Collected {count} targets from {source}"


@tool
def probe_targets_alive() -> str:
    """Probe all collected targets to check which are alive.
    Call this after collecting targets to filter out dead ones.
    """
    alive = auto_hunt.probe_targets()
    return f"{alive} targets are alive"


@tool
def build_scan_queue(top_n: int = 50) -> str:
    """Build the scan queue from top scored targets.

    Args:
        top_n: Number of top targets to add to queue
    """
    stats = auto_hunt.build_queue(top_n)
    return f"Queue built: {stats}"


@tool
def run_batch_hunt(max_targets: int = 20) -> str:
    """Run automated batch vulnerability hunting on queued targets.
    This will scan each target and filter false positives via LLM.

    Args:
        max_targets: Maximum number of targets to scan in this batch
    """
    auto_hunt.run_batch(max_targets)
    summary = auto_hunt.generate_review_report()
    return f"Batch hunt complete. Review queue: {summary['review_queue_size']} findings"


@tool
def get_review_list() -> str:
    """Get the list of findings ready for human review.
    These have been filtered by LLM to remove obvious false positives.
    """
    review_queue = fp_filter.get_review_queue()
    if not review_queue:
        return "No findings in review queue."

    output = f"=== Review Queue ({len(review_queue)} findings) ===\n\n"
    for i, r in enumerate(review_queue[:20], 1):
        output += f"[{i}] {r.raw_finding.target}\n"
        output += f"    Type: {r.raw_finding.vuln_type}\n"
        output += f"    Title: {r.raw_finding.title}\n"
        output += f"    Suggested Severity: {r.suggested_severity}\n"
        output += f"    Confidence: {r.confidence:.0%}\n"
        output += f"    Reasoning: {r.reasoning[:100]}\n\n"
    return output


@tool
def get_hunt_stats() -> str:
    """Get statistics about the current batch hunt session."""
    task_stats = task_queue.get_stats()
    triage_stats = fp_filter.get_stats()
    output = "=== Auto Hunt Stats ===\n\n"
    output += f"Targets collected: {len(asset_collector.targets)}\n"
    output += f"Tasks: {task_stats}\n"
    output += f"Triage: {triage_stats}\n"
    output += f"Review queue: {len(fp_filter.get_review_queue())}\n"
    return output


#####################################################################################
# Advanced Features - Verification, Strategy, History, HTML Reports
#####################################################################################

from utils.exploit_verifier import exploit_verifier
from utils.html_report import html_report_generator
from utils.strategy_planner import strategy_planner
from utils.history_comparator import history_comparator


@tool
def verify_finding(title: str, target: str, vuln_type: str) -> str:
    """Verify if a reported vulnerability is actually exploitable.
    Runs targeted PoC checks to confirm findings.

    Args:
        title: Finding title
        target: Target URL
        vuln_type: Type of vulnerability (sql_injection, xss, directory_listing, etc.)
    """
    finding = RawFinding(
        target=target,
        vuln_type=vuln_type,
        title=title,
        description="",
        evidence="",
    )
    result = exploit_verifier.verify_finding(finding)
    return f"Verification result: verified={result['verified']}, method={result['method']}, confidence boost={result['confidence_boost']}"


@tool
def generate_html_report(target: str) -> str:
    """Generate a beautiful HTML penetration test report.

    Args:
        target: Target name
    """
    import os
    from utils.report_generator import report_generator
    os.makedirs("./outputs/reports", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = f"./outputs/reports/report_{timestamp}.html"

    html_report_generator.generate_html_report(
        target=target,
        findings=report_generator.findings,
        output_path=output_path,
    )
    return f"HTML report generated: {output_path}"


@tool
def plan_next_action(target: str, current_progress: str = "") -> str:
    """Use AI strategy planner to decide the best next action.

    Args:
        target: Current target
        current_progress: Description of what's been done so far
    """
    findings = []
    result = strategy_planner.plan_next_action(target, current_progress, findings)
    return f"Next action: {result.action_type.value}\nTarget: {result.target}\nPriority: {result.priority}/10\nReason: {result.reason}\nEstimated: {result.estimated_duration}"


@tool
def compare_scans(scan_name: str = "autohunt") -> str:
    """Compare the two most recent scans to find new and resolved vulnerabilities.

    Args:
        scan_name: Name of the scan series to compare
    """
    diff = history_comparator.compare_latest(scan_name)
    if not diff:
        return "Not enough historical data to compare."

    output = "=== Scan Comparison ===\n\n"
    output += f"New findings: {len(diff.new_findings)}\n"
    output += f"Resolved findings: {len(diff.resolved_findings)}\n"
    output += f"New targets: {len(diff.new_targets)}\n"
    output += f"Offline targets: {len(diff.offline_targets)}\n"
    return output


#####################################################################################
# Ultra Features - CVE DB, Auto Exploit, Ollama, Plugins
#####################################################################################

from utils.cve_db import cve_db
from utils.auto_exploiter import auto_exploiter
from utils.ollama_manager import ollama_manager
from utils.plugin_manager import plugin_manager


@tool
def lookup_cve(cve_id: str) -> str:
    """Look up CVE details and find public exploits.

    Args:
        cve_id: CVE identifier (e.g., CVE-2021-44228)
    """
    cve = cve_db.get_full_info(cve_id)
    if not cve:
        return f"CVE {cve_id} not found"

    output = f"=== CVE: {cve.cve_id} ===\n\n"
    output += f"Severity: {cve.severity.upper()} (CVSS: {cve.cvss_score})\n"
    output += f"Description: {cve.description[:300]}\n\n"
    if cve.exploits:
        output += f"Public Exploits Found: {len(cve.exploits)}\n"
        for exp in cve.exploits[:5]:
            output += f"  - {exp['title']} ({exp['stars']} stars)\n"
            output += f"    {exp['url']}\n"
    return output


@tool
def exploit_vulnerability(target: str, vuln_type: str) -> str:
    """Automatically exploit a vulnerability using appropriate tools.

    Args:
        target: Target URL or IP
        vuln_type: Type of vulnerability (sql_injection, lfi, default_creds, etc.)
    """
    result = auto_exploiter.run_exploit_chain(target, vuln_type)
    return f"Exploit result: vulnerable={result.get('vulnerable')}, details={result.get('raw_output', result.get('error', ''))[:200]}"


@tool
def list_plugins() -> str:
    """List all loaded custom plugins."""
    plugins = plugin_manager.list_plugins()
    if not plugins:
        return "No plugins loaded. Add .py files to ./plugins directory."

    output = "=== Loaded Plugins ===\n\n"
    for p in plugins:
        output += f"- {p['name']} v{p['version']} by {p['author']}\n"
        output += f"  {p['description']}\n"
    return output


@tool
def list_local_models() -> str:
    """List available local LLM models via Ollama."""
    if not ollama_manager.available:
        return "Ollama is not running. Start Ollama to use local models."

    models = ollama_manager.list_models()
    if not models:
        return "No local models found. Pull a model first."

    return "Available local models:\n" + "\n".join(f"- {m}" for m in models)


#####################################################################################
# Enterprise Features - More Scanners, Remediation, Email Notifications
#####################################################################################

from utils.additional_scanners import additional_scanners
from utils.remediation_advisor import remediation_advisor
from utils.email_notifier import email_notifier


@tool
def scan_wordpress(url: str) -> str:
    """Run WPScan against a WordPress site.

    Args:
        url: WordPress site URL
    """
    result = additional_scanners.scan_wordpress(url)
    return f"WPScan completed for {url}"


@tool
def scan_nikto(url: str) -> str:
    """Run Nikto web server scanner.

    Args:
        url: Target URL
    """
    result = additional_scanners.scan_nikto(url)
    return f"Nikto scan completed for {url}"


@tool
def get_remediation_advice(title: str, severity: str, description: str) -> str:
    """Get AI-generated remediation advice for a vulnerability.

    Args:
        title: Finding title
        severity: Severity level
        description: Vulnerability description
    """
    advice = remediation_advisor.get_remediation(title, severity, description)
    return f"Remediation advice:\n\n{advice}"


@tool
def get_compliance_checklist(target_type: str = "web_application") -> str:
    """Get a security compliance checklist.

    Args:
        target_type: web_application, network, or api
    """
    checklist = remediation_advisor.get_compliance_checklist(target_type)
    output = f"=== Compliance Checklist ({target_type}) ===\n\n"
    for i, item in enumerate(checklist, 1):
        output += f"{i}. {item}\n"
    return output


#####################################################################################
# REAL PRODUCTION MODULES - SQLite DB, Real Parsers, Scan Engine
#####################################################################################

from utils.database import db
from utils.scan_engine import scan_engine


@tool
def scan_target_full(target_url: str) -> str:
    """Run a FULL scan against a target - real scanning with parsing and DB storage.

    This actually runs nmap, nuclei, gobuster, whatweb, parses results,
    and stores findings in the database permanently.

    Args:
        target_url: Target URL (e.g., https://example.com)
    """
    result = scan_engine.full_scan(target_url)
    output = f"=== Full Scan Complete: {target_url} ===\n\n"
    output += f"Open Ports: {len(result['ports'])}\n"
    for p in result['ports'][:10]:
        output += f"  - {p['port']}/{p['protocol']} {p['service']} {p['version']}\n"
    output += f"\nVulnerabilities Found: {len(result['vulnerabilities'])}\n"
    for v in result['vulnerabilities'][:10]:
        output += f"  [{v['severity'].upper()}] {v['title']}\n"
        output += f"    {v['evidence']}\n"
    output += f"\nDirectories Found: {len(result['directories'])}\n"
    return output


@tool
def get_database_stats() -> str:
    """Get database statistics - real numbers from SQLite.

    Shows actual persisted data, not in-memory counters.
    Data survives restarts.
    """
    stats = db.get_stats()
    output = "=== Database Statistics (Persistent) ===\n\n"
    output += f"Total Targets: {stats['targets']}\n"
    output += f"Pending Findings: {stats['pending_findings']}\n"
    output += f"Critical Findings: {stats['critical_findings']}\n"
    output += f"Pending Tasks: {stats['pending_tasks']}\n"
    output += f"Running Tasks: {stats['running_tasks']}\n"
    return output


@tool
def list_findings(severity: str = "", limit: int = 20) -> str:
    """List findings from the database with real persistence.

    Args:
        severity: Filter by severity (critical, high, medium, low)
        limit: Max number of findings to return
    """
    findings = db.get_findings(severity=severity or None, limit=limit)
    if not findings:
        return "No findings in database."

    output = f"=== Findings ({len(findings)}) ===\n\n"
    for i, f in enumerate(findings, 1):
        output += f"[{i}] [{f['severity'].upper()}] {f['title']}\n"
        output += f"    Target: {f['target_url']}\n"
        output += f"    Type: {f['vuln_type']}\n"
        output += f"    Confidence: {f['confidence']:.0%}\n"
        output += f"    Status: {f['status']}\n\n"
    return output


@tool
def list_targets(status: str = "", limit: int = 50) -> str:
    """List all targets in the database.

    Args:
        status: Filter by status (pending, scanning, completed)
        limit: Max number of targets
    """
    targets = db.get_targets(status=status or None, limit=limit)
    if not targets:
        return "No targets in database."

    output = f"=== Targets ({len(targets)}) ===\n\n"
    for i, t in enumerate(targets, 1):
        output += f"[{i}] {t['url']} (score: {t['score']:.0f}, status: {t['status']})\n"
    return output
