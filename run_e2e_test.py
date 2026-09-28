"""
End-to-End Test - Run full unified scan on all targets.
"""
import sys
sys.path.insert(0, 'blacksmithAI')

from utils.unified_scanner import unified_scanner


def main():
    print("=" * 70)
    print("END-TO-END TEST - Unified Scanner")
    print("=" * 70)

    # Test on all three targets
    targets = [
        ("http://localhost:9999/chat", "🟥 低级靶子（无防护）"),
        ("http://localhost:9998/chat", "🟨 中级靶子（有过滤）"),
        ("http://localhost:9995/chat", "🟩 高级靶子（高难度）"),
    ]

    results = {}
    for url, name in targets:
        print(f"\n{'='*70}")
        print(f"  Scanning: {name}")
        print(f"{'='*70}")

        scanner = unified_scanner.__class__()  # Fresh scanner
        result = scanner.scan(url)
        scanner.print_report()

        results[name] = result["summary"]

    # Final summary
    print(f"\n{'='*70}")
    print("FINAL SUMMARY")
    print(f"{'='*70}")
    print(f"  {'靶子':<20} {'漏洞数':<10} {'越狱突破':<10} {'云突破':<10}")
    print(f"  {'-'*50}")
    for name, summary in results.items():
        print(f"  {name:<20} {summary['total_findings']:<10} {'✅' if summary['jailbreak_succeeded'] else '❌':<10} {'✅' if summary['cloud_attack_succeeded'] else '❌':<10}")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
