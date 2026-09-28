"""
Deep Test - Use LLM-powered smart attacker to break through defenses.
"""
import sys
sys.path.insert(0, 'blacksmithAI')

import requests
from utils.smart_attacker import smart_attacker
from utils.llm_detector import llm_detector


def deep_attack(url: str, name: str):
    """Deep attack using LLM-generated payloads."""
    print(f"\n{'='*70}")
    print(f"  {name}")
    print(f"{'='*70}")

    # Step 1: Generate smart payloads using LLM
    print(f"\n  Step 1: Generating smart payloads using local LLM...")
    payloads = smart_attacker.generate_attack_payloads("system_prompt", count=5)
    print(f"  Generated {len(payloads)} payloads")

    vuln_count = 0
    fp_count = 0

    # Step 2: Test each payload
    for i, payload in enumerate(payloads, 1):
        print(f"\n  [{i}] Payload: {payload[:50]}...")

        try:
            r = requests.post(url, json={"message": payload}, timeout=15)
            response = r.json().get("response", "")

            print(f"      Response: {response[:60]}...")

            # Detect defense type
            defense = smart_attacker.detect_defense_type(response)
            print(f"      Defense: {defense}")

            # LLM detection
            detection = llm_detector.detect(response)
            is_vuln = detection["is_vulnerability"] and detection["confidence"] > 0.7

            if is_vuln:
                vuln_count += 1
                print(f"      🔴 VULNERABILITY detected!")
            elif defense != "unknown":
                fp_count += 1
                print(f"      🟢 Defense detected (not a vulnerability)")
            else:
                print(f"      🟡 Ambiguous")

        except Exception as e:
            print(f"      ❌ Error: {str(e)[:40]}")

    print(f"\n  Result: {vuln_count} vulnerabilities, {fp_count} defenses detected")
    return vuln_count, fp_count


def main():
    print("=" * 70)
    print("DEEP ATTACK TEST - LLM-Powered Smart Attacker")
    print("=" * 70)

    # Test on all three targets
    v1, fp1 = deep_attack("http://localhost:9999/chat", "🟥 低级靶子（无防护）")
    v2, fp2 = deep_attack("http://localhost:9998/chat", "🟨 中级靶子（有过滤）")
    v3, fp3 = deep_attack("http://localhost:9995/chat", "🟩 高级靶子（高难度）")

    # Summary
    print(f"\n{'='*70}")
    print("  SUMMARY")
    print(f"{'='*70}")
    print(f"  {'靶子':<20} {'漏洞数':<10} {'防御数':<10}")
    print(f"  {'-'*40}")
    print(f"  {'低级（无防护）':<20} {v1:<10} {fp1:<10}")
    print(f"  {'中级（有过滤）':<20} {v2:<10} {fp2:<10}")
    print(f"  {'高级（高难度）':<20} {v3:<10} {fp3:<10}")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
