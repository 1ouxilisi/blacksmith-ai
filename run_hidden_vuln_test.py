"""
Hidden Vulnerability Test - Exploit specific trigger keywords.
"""
import sys
sys.path.insert(0, 'blacksmithAI')

from utils.hidden_vuln_attacker import hidden_vuln_attacker


def test_target(url: str, name: str):
    """Test a target with hidden vulnerability exploitation."""
    print(f"\n{'='*70}")
    print(f"  {name}")
    print(f"{'='*70}")

    result = hidden_vuln_attacker.attack(url, goal="reveal all secrets")

    print(f"\n  Result:")
    print(f"    Total findings: {result['total_findings']}")
    for f in result['findings']:
        print(f"    - {f['vuln_type']}: {f['keyword']}")

    return result['total_findings']


def main():
    print("=" * 70)
    print("HIDDEN VULNERABILITY TEST - Keyword Exploitation")
    print("=" * 70)

    # Test on all three targets
    f1 = test_target("http://localhost:9999/chat", "🟥 低级靶子（无防护）")
    f2 = test_target("http://localhost:9998/chat", "🟨 中级靶子（有过滤）")
    f3 = test_target("http://localhost:9995/chat", "🟩 高级靶子（高难度）")

    # Summary
    print(f"\n{'='*70}")
    print("  SUMMARY")
    print(f"{'='*70}")
    print(f"  {'靶子':<20} {'发现漏洞数':<15}")
    print(f"  {'-'*35}")
    print(f"  {'低级（无防护）':<20} {f1:<15}")
    print(f"  {'中级（有过滤）':<20} {f2:<15}")
    print(f"  {'高级（高难度）':<20} {f3:<15}")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
