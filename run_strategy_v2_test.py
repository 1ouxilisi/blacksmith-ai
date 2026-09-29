"""
Strategy Planner V2 Test - Intelligent strategy selection.
"""
import sys
sys.path.insert(0, 'blacksmithAI')

from utils.strategy_planner_v2 import strategy_planner_v2


def test_target(url: str, name: str):
    """Test intelligent strategy selection on a target."""
    print(f"\n{'='*70}")
    print(f"  {name}")
    print(f"{'='*70}")

    # Step 1: Analyze target
    print(f"\n  [1] Analyzing target behavior...")
    analysis = strategy_planner_v2.analyze_target(url)
    print(f"      Defense type: {analysis['defense_type']}")
    print(f"      Recommended strategies: {analysis['recommended_strategies']}")

    # Step 2: Execute recommended strategies
    total_findings = 0
    for strategy in analysis['recommended_strategies']:
        print(f"\n  [2] Executing strategy: {strategy}")
        result = strategy_planner_v2.execute_strategy(url, strategy)
        print(f"      Payloads tested: {result['payloads_tested']}")
        print(f"      Success: {'✅' if result['success'] else '❌'}")
        if result['success']:
            print(f"      Findings: {len(result['findings'])}")
            total_findings += len(result['findings'])

    print(f"\n  Total findings: {total_findings}")
    return total_findings


def main():
    print("=" * 70)
    print("STRATEGY PLANNER V2 TEST - Intelligent Strategy Selection")
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
