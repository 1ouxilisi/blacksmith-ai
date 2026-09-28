from utils.owasp_llm_tester import owasp_tester
import json

print("=== Running Real LLM Security Test ===")
print("Target: local Ollama (mistral-nemo:12b-pentest)")
print()

results = owasp_tester.test_endpoint("http://localhost:11434/api/generate")

print(f"Found {len(results)} vulnerabilities:")
print()
for r in results:
    print(f"  [{r.severity.upper()}] {r.owasp_id}: {r.name}")
    print(f"    Payload: {r.payload[:60]}...")
    print(f"    Evidence: {r.evidence[:100]}...")
    print()

summary = owasp_tester.get_summary()
print("=== Summary ===")
print(json.dumps(summary, indent=2))
