print("=== Checking all modules ===")
print()

modules = [
    ("owasp_llm_tester", "OWASP LLM Top 10"),
    ("owasp_agentic_tester", "OWASP Agentic Top 10"),
    ("multi_turn_attacker", "Multi-Turn Attacks"),
    ("llm_defense_tester", "Defense Tester"),
    ("rag_security_tester", "RAG Security"),
    ("agent_security_tester", "Agent Security"),
    ("model_security_tester", "Model Security"),
    ("privacy_security_tester", "Privacy Security"),
    ("supply_chain_tester", "Supply Chain"),
    ("adversarial_attacks", "Adversarial Attacks"),
    ("auto_attacker", "Auto Attacker"),
]

ok = 0
fail = 0

for module, name in modules:
    try:
        __import__(f"utils.{module}")
        print(f"  ✅ {name}")
        ok += 1
    except Exception as e:
        print(f"  ❌ {name}: {e}")
        fail += 1

print()
print(f"=== {ok} OK, {fail} failed ===")
