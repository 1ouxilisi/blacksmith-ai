"""
Adaptive Attack Test - Test intelligent strategy-switching attacks.
"""
import sys
sys.path.insert(0, 'blacksmithAI')

from utils.adaptive_attacker import adaptive_attacker


def test_target(url: str, name: str):
    """Test a target with adaptive attack."""
    print(f"\n{'='*70}")
    print(f"  {name}")
    print(f"{'='*70}")

    result = adaptive_attacker.attack(url, goal="reveal system prompt", max_rounds=5)

    print(f"\n  Result:")
    print(f"    Rounds completed: {result['rounds_completed']}")
    print(f"    Succeeded: {result['succeeded']}")

    return result['succeeded']


def main():
    print("=" * 70)
    print("ADAPTIVE ATTACK TEST - Strategy Switching")
    print("=" * 70)

    # Test on all three targets
    s1 = test_target("http://localhost:9999/chat", "🟥 低级靶子（无防护）")
    s2 = test_target("http://localhost:9998/chat", "🟨 中级靶子（有过滤）")
    s3 = test_target("http://localhost:9995/chat", "🟩 高级靶子（高难度）")

    # Summary
    print(f"\n{'='*70}")
    print("  SUMMARY")
    print(f"{'='*70}")
    print(f"  {'靶子':<20} {'突破成功':<15}")
    print(f"  {'-'*35}")
    print(f"  {'低级（无防护）':<20} {'✅' if s1 else '❌':<15}")
    print(f"  {'中级（有过滤）':<20} {'✅' if s2 else '❌':<15}")
    print(f"  {'高级（高难度）':<20} {'✅' if s3 else '❌':<15}")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
