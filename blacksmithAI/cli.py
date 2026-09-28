#!/usr/bin/env python
"""
BlacksmithAI CLI - For CI/CD integration.
Usage:
  python cli.py test-llm --endpoint http://localhost:11434/api/generate
  python cli.py test-agent --endpoint http://localhost:11434/api/generate
  python cli.py test-all --endpoint http://localhost:11434/api/generate
"""
import sys
import json
import argparse


def test_llm(endpoint: str):
    """Run OWASP LLM Top 10 test."""
    from utils.owasp_llm_tester import owasp_tester

    print(f"[*] Testing LLM endpoint: {endpoint}")
    results = owasp_tester.test_endpoint(endpoint)
    summary = owasp_tester.get_summary()

    print(f"[+] Found {len(results)} vulnerabilities")
    print(json.dumps(summary, indent=2))

    # Return exit code based on critical findings
    if summary["by_severity"]["critical"] > 0:
        return 1  # Fail
    return 0  # Pass


def test_agent(endpoint: str):
    """Run OWASP Agentic Top 10 test."""
    from utils.owasp_agentic_tester import owasp_agentic_tester

    print(f"[*] Testing Agent endpoint: {endpoint}")
    results = owasp_agentic_tester.test_agent(endpoint)

    print(f"[+] Found {len(results)} vulnerabilities")
    for r in results:
        print(f"  [{r['severity'].upper()}] {r['owasp_id']}: {r['name']}")

    critical = sum(1 for r in results if r["severity"] == "critical")
    if critical > 0:
        return 1
    return 0


def test_all(endpoint: str):
    """Run all tests."""
    print("[*] Running full LLM security test suite...")

    llm_result = test_llm(endpoint)
    agent_result = test_agent(endpoint)

    if llm_result != 0 or agent_result != 0:
        print("[!] Security issues found - FAIL")
        return 1

    print("[+] All tests passed - no critical vulnerabilities")
    return 0


def main():
    parser = argparse.ArgumentParser(description="BlacksmithAI LLM Security CLI")
    parser.add_argument("command", choices=["test-llm", "test-agent", "test-all"], help="Test command")
    parser.add_argument("--endpoint", required=True, help="LLM API endpoint URL")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format")

    args = parser.parse_args()

    if args.command == "test-llm":
        sys.exit(test_llm(args.endpoint))
    elif args.command == "test-agent":
        sys.exit(test_agent(args.endpoint))
    elif args.command == "test-all":
        sys.exit(test_all(args.endpoint))


if __name__ == "__main__":
    main()
