"""
Benchmark Module - Compare against industry standards.
Compares BlacksmithAI results against known benchmarks:
- OWASP LLM Top 10 standard coverage
- Garak (NVIDIA) baseline
- PyRIT (Microsoft) baseline
- LLM Guard baseline
"""
from typing import List, Dict, Any


class Benchmark:
    """Benchmark and compare against industry standards."""

    def __init__(self):
        # Industry standard benchmarks
        self.standards = {
            "owasp_llm_top10": {
                "name": "OWASP LLM Top 10",
                "categories": [
                    "LLM01: Prompt Injection",
                    "LLM02: Sensitive Information Disclosure",
                    "LLM03: Supply Chain",
                    "LLM04: Data and Model Poisoning",
                    "LLM05: Improper Output Handling",
                    "LLM06: Excessive Agency",
                    "LLM07: System Prompt Leakage",
                    "LLM08: Vector and Embedding Weaknesses",
                    "LLM09: Misinformation",
                    "LLM10: Unbounded Consumption",
                ],
                "expected_payloads": 100,  # Typical open-source tool has 100+ payloads
            },
            "garak": {
                "name": "Garak (NVIDIA)",
                "categories": 50,
                "payloads": 500,
                "detection_methods": 20,
            },
            "pyrit": {
                "name": "PyRIT (Microsoft)",
                "categories": 40,
                "payloads": 300,
                "auto_generation": True,
            },
            "llm_guard": {
                "name": "LLM Guard",
                "scanners": 15,
                "input_scanners": 10,
                "output_scanners": 5,
            }
        }

    def compare_owasp_coverage(self, our_categories: List[str]) -> Dict[str, Any]:
        """Compare our OWASP coverage against standard."""
        standard = self.standards["owasp_llm_top10"]
        standard_cats = set(standard["categories"])
        our_cats = set(our_categories)

        covered = standard_cats & our_cats
        missing = standard_cats - our_cats

        coverage_pct = len(covered) / len(standard_cats) * 100

        return {
            "standard": standard["name"],
            "total_categories": len(standard_cats),
            "covered": len(covered),
            "missing": list(missing),
            "coverage_percentage": round(coverage_pct, 1),
            "grade": self._get_grade(coverage_pct),
        }

    def compare_garak(self, our_payloads: int, our_detections: int) -> Dict[str, Any]:
        """Compare against Garak baseline."""
        garak = self.standards["garak"]

        return {
            "standard": garak["name"],
            "our_payloads": our_payloads,
            "their_payloads": garak["payloads"],
            "payload_comparison": f"{round(our_payloads / garak['payloads'] * 100, 1)}% of Garak",
            "our_detections": our_detections,
            "their_detections": garak["detection_methods"],
            "detection_comparison": f"{round(our_detections / garak['detection_methods'] * 100, 1)}% of Garak",
        }

    def compare_pyrit(self, our_auto_gen: bool, our_categories: int) -> Dict[str, Any]:
        """Compare against PyRIT baseline."""
        pyrit = self.standards["pyrit"]

        return {
            "standard": pyrit["name"],
            "auto_generation": "Yes" if our_auto_gen else "No",
            "auto_gen_comparison": "On par" if our_auto_gen else "Gap: no auto-generation",
            "our_categories": our_categories,
            "their_categories": pyrit["categories"],
            "category_comparison": f"{round(our_categories / pyrit['categories'] * 100, 1)}% of PyRIT",
        }

    def get_overall_assessment(self) -> Dict[str, Any]:
        """Get overall assessment of where we stand."""
        return {
            "summary": "BlacksmithAI is a comprehensive LLM security testing platform",
            "strengths": [
                "Complete OWASP LLM Top 10 coverage",
                "Multi-layer testing (application, architecture, model, privacy, supply chain)",
                "Both offensive and defensive testing",
                "Productized with Dashboard and reports",
            ],
            "gaps": [
                "Auto-attack generation is basic (no reinforcement learning)",
                "No ML-based detection heuristics",
                "Limited real-world case studies",
                "No enterprise SSO integration",
            ],
            "market_position": "Mid-tier open-source tool, comparable to Garak/PyRIT in coverage",
        }

    def _get_grade(self, percentage: float) -> str:
        """Get grade based on coverage percentage."""
        if percentage >= 90:
            return "A"
        elif percentage >= 80:
            return "B"
        elif percentage >= 70:
            return "C"
        elif percentage >= 60:
            return "D"
        else:
            return "F"


# Global instance
benchmark = Benchmark()
