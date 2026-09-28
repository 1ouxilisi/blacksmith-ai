"""
Real Case Test - Test a realistic RAG LLM application.
"""
import sys
sys.path.insert(0, 'blacksmithAI')

from utils.owasp_llm_tester import owasp_tester
from utils.owasp_agentic_tester import owasp_agentic_tester
from utils.rag_security_tester import rag_tester
from utils.privacy_security_tester import privacy_tester
from utils.supply_chain_tester import supply_chain_tester


def main():
    print("=" * 70)
    print("REAL CASE TEST - Acme Corp Customer Service RAG App")
    print("=" * 70)
    print()

    # Target endpoint
    endpoint = "http://localhost:9993/api/chat"

    print(f"Target: {endpoint}")
    print()

    # Test 1: OWASP LLM Top 10
    print("1. OWASP LLM Top 10 Test")
    print("-" * 70)
    try:
        results = owasp_tester.test_endpoint(endpoint)
        print(f"   Found {len(results)} vulnerabilities")
        for r in results[:5]:
            print(f"   [{r.severity.upper()}] {r.owasp_id}: {r.name}")
        if len(results) > 5:
            print(f"   ... and {len(results) - 5} more")
    except Exception as e:
        print(f"   Error: {e}")
    print()

    # Test 2: RAG Security
    print("2. RAG Security Test")
    print("-" * 70)
    try:
        rag_results = rag_tester.test_endpoint(endpoint)
        print(f"   Found {len(rag_results)} RAG vulnerabilities")
        for r in rag_results[:5]:
            print(f"   [{r.severity.upper()}] {r.name}")
    except Exception as e:
        print(f"   Error: {e}")
    print()

    # Test 3: Privacy
    print("3. Privacy Security Test")
    print("-" * 70)
    try:
        privacy_results = privacy_tester.test_endpoint(endpoint)
        print(f"   Found {len(privacy_results)} privacy issues")
        for r in privacy_results[:5]:
            print(f"   [{r.severity.upper()}] {r.name}")
    except Exception as e:
        print(f"   Error: {e}")
    print()

    # Test 4: Supply Chain
    print("4. Supply Chain Security Test")
    print("-" * 70)
    try:
        sc_results = supply_chain_tester.test_endpoint(endpoint)
        print(f"   Found {len(sc_results)} supply chain issues")
    except Exception as e:
        print(f"   Error: {e}")
    print()

    print("=" * 70)
    print("Test Complete!")
    print("=" * 70)


if __name__ == "__main__":
    main()
