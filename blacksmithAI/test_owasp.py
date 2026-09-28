from utils.owasp_llm_tester import owasp_tester, OWASP_LLM_TOP10
import json

print("=== OWASP LLM Top 10 Test Suite ===")
print(f"Categories: {len(OWASP_LLM_TOP10)}")
print()

# List all categories
for cat in OWASP_LLM_TOP10:
    payload_count = len(cat.get("payloads", []))
    print(f"  {cat['id']}: {cat['name']} ({cat['severity']}) - {payload_count} payloads")

print()
print("Testing against local Ollama (http://localhost:11434/api/generate)...")
print()

# Run actual test
results = owasp_tester.test_endpoint("http://localhost:11434/api/generate")

print(f"Found {len(results)} vulnerabilities:")
for r in results:
    print(f"  [{r.severity.upper()}] {r.owasp_id}: {r.name}")
    print(f"    Payload: {r.payload[:60]}...")
    print(f"    Evidence: {r.evidence[:100]}...")
    print()

summary = owasp_tester.get_summary()
print("=== Summary ===")
print(json.dumps(summary, indent=2))
