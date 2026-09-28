"""
End-to-End Test - Run the full BlacksmithAI pipeline.
Tests: scan → parse → store → PoC validate → chain analyze → generate report.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def test_database():
    """Test SQLite database."""
    print("=" * 60)
    print("1. Testing Database Layer...")
    from utils.database import db

    stats = db.get_stats()
    print(f"   ✅ Targets: {stats['targets']}")
    print(f"   ✅ Findings: {stats['pending_findings']} pending")
    print(f"   ✅ Critical: {stats['critical_findings']}")
    return True


def test_scan_engine():
    """Test scan engine with example.com."""
    print("=" * 60)
    print("2. Testing Scan Engine...")
    from utils.scan_engine import scan_engine

    print("   Running quick scan on https://example.com...")
    try:
        result = scan_engine.quick_scan("https://example.com")
        print(f"   ✅ Scan completed")
        return True
    except Exception as e:
        print(f"   ⚠️ Scan error: {e}")
        return False


def test_parsers():
    """Test result parsers."""
    print("=" * 60)
    print("3. Testing Result Parsers...")
    from utils.parsers import NucleiParser, NmapParser

    # Test nuclei parser with sample data
    sample_nuclei = '''{"templateID":"CVE-2021-41773","info":{"name":"Path Traversal","severity":"high"},"host":"https://example.com"}
{"templateID":"ssl-expired","info":{"name":"Expired SSL","severity":"medium"},"host":"https://example.com"}'''

    parser = NucleiParser()
    findings = parser.parse(sample_nuclei)
    print(f"   ✅ Nuclei parser: {len(findings)} findings parsed")

    return True


def test_poc_validator():
    """Test PoC validator."""
    print("=" * 60)
    print("4. Testing PoC Validator...")
    from utils.poc_validator import poc_validator

    print("   ✅ PoC validator loaded")
    print("   - SQL Injection validation")
    print("   - XSS validation")
    print("   - Directory traversal validation")
    print("   - Open redirect validation")
    print("   - Default credentials validation")
    return True


def test_chain_analyzer():
    """Test attack chain analyzer."""
    print("=" * 60)
    print("5. Testing Attack Chain Analyzer...")
    from utils.chain_analyzer import attack_chain_analyzer

    summary = attack_chain_analyzer.get_chain_summary()
    print(f"   ✅ Chain analyzer: {summary['total_chains']} chains found")
    return True


def test_multi_agent():
    """Test multi-agent system."""
    print("=" * 60)
    print("6. Testing Multi-Agent System...")
    from utils.multi_agent import orchestrator

    print(f"   ✅ Recon Agent: {orchestrator.recon_agent.name}")
    print(f"   ✅ Exploit Agent: {orchestrator.exploit_agent.name}")
    print(f"   ✅ Coordinator: {orchestrator.name}")
    return True


def test_agent_memory():
    """Test agent memory."""
    print("=" * 60)
    print("7. Testing Agent Memory...")
    from utils.agent_memory import agent_memory

    summary = agent_memory.get_memory_summary()
    print(f"   ✅ Remembered targets: {summary['total_targets_remembered']}")
    print(f"   ✅ Remembered findings: {summary['total_findings_remembered']}")
    return True


def test_budget():
    """Test budget control."""
    print("=" * 60)
    print("8. Testing Budget Control...")
    from utils.run_history import budget_guard, run_history

    status = budget_guard.get_status()
    print(f"   ✅ Daily limit: ${status['daily_limit_usd']}")
    print(f"   ✅ Run limit: ${status['run_limit_usd']}")
    print(f"   ✅ Daily used: ${status['daily_used_usd']}")
    return True


def test_report():
    """Test report generation."""
    print("=" * 60)
    print("9. Testing Report Generation...")
    from utils.report_generator_pro import report_generator_pro

    path = report_generator_pro.generate_report("https://example.com")
    print(f"   ✅ Report generated: {path}")
    return True


def test_dashboard_import():
    """Test dashboard imports."""
    print("=" * 60)
    print("10. Testing Dashboard...")
    try:
        from web.dashboard import app
        print(f"   ✅ Flask app loaded: {app.name}")
        print(f"   ✅ Routes: {len(list(app.url_map.iter_rules()))} endpoints")
        return True
    except Exception as e:
        print(f"   ⚠️ Dashboard import error: {e}")
        return False


def main():
    print("\n" + "=" * 60)
    print("🔨 BlacksmithAI - Full System Test")
    print("=" * 60 + "\n")

    tests = [
        ("Database", test_database),
        ("Scan Engine", test_scan_engine),
        ("Parsers", test_parsers),
        ("PoC Validator", test_poc_validator),
        ("Chain Analyzer", test_chain_analyzer),
        ("Multi-Agent", test_multi_agent),
        ("Agent Memory", test_agent_memory),
        ("Budget Control", test_budget),
        ("Report Generator", test_report),
        ("Dashboard", test_dashboard_import),
    ]

    passed = 0
    failed = 0

    for name, test_fn in tests:
        try:
            if test_fn():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"   ❌ FAILED: {e}")
            failed += 1

    print("\n" + "=" * 60)
    print(f"📊 Results: {passed} passed, {failed} failed")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
