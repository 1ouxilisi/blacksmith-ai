"""
Quick Start Example - How to use BlacksmithAI.
"""
import sys
sys.path.insert(0, '..')

from utils.owasp_llm_tester import owasp_tester
from utils.owasp_agentic_tester import owasp_agentic_tester
from utils.rag_security_tester import rag_tester
from utils.privacy_security_tester import privacy_tester


def main():
    print("=" * 60)
    print("BlacksmithAI - Quick Start Example")
    print("=" * 60)
    print()

    # Example 1: Test an LLM endpoint
    print("1. Testing LLM endpoint...")
    endpoint = "http://localhost:11434/api/generate"

    # Run OWASP LLM Top 10 test
    results = owasp_tester.test_endpoint(endpoint)
    print(f"   Found {len(results)} vulnerabilities")
    for r in results:
        print(f"   [{r.severity.upper()}] {r.owasp_id}: {r.name}")
    print()

    # Example 2: Test RAG security
    print("2. Testing RAG security...")
    rag_results = rag_tester.test_endpoint(endpoint)
    print(f"   Found {len(rag_results)} RAG vulnerabilities")
    print()

    # Example 3: Test privacy
    print("3. Testing privacy...")
    privacy_results = privacy_tester.test_endpoint(endpoint)
    print(f"   Found {len(privacy_results)} privacy issues")
    print()

    print("=" * 60)
    print("Done! Check the reports/ directory for full reports.")
    print("=" * 60)


if __name__ == "__main__":
    main()
