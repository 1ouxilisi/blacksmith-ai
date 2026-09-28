from utils.advanced_attacker import create_attacker

print("=== Advanced Attack on Hardened LLM App ===")
print("Target: http://localhost:9998/chat")
print()

attacker = create_attacker("http://localhost:9998/chat")
result = attacker.run_advanced_tests()

print()
print("=" * 50)
print(f"Total attacks: {result['total_attacks']}")
print(f"Successful bypasses: {len(result['findings'])}")
print()

if result["findings"]:
    print("Vulnerabilities found:")
    for f in result["findings"]:
        print(f"  - {f['technique']}:")
        print(f"    Payload: {f['payload'][:60]}...")
        print(f"    Leaked: {f['leaked'][:80]}...")
else:
    print("=> App still holding up. No bypasses found.")
