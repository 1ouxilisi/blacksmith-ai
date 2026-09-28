"""Test script - run a real scan and check DB."""
from utils.scan_engine import scan_engine
from utils.database import db

print("=== Starting Quick Scan ===")
result = scan_engine.quick_scan("https://example.com")

print("\n=== Scan Result ===")
print("Vulnerabilities:", len(result["vulnerabilities"]))
for v in result["vulnerabilities"][:5]:
    print(f"  [{v['severity']}] {v['title']}")
    print(f"    Evidence: {v['evidence'][:100]}")

print("\n=== DB Stats ===")
print(db.get_stats())

print("\n=== Findings in DB ===")
findings = db.get_findings()
print(f"Total: {len(findings)}")
for f in findings[:5]:
    print(f"  [{f['severity']}] {f['title']} - {f['target_url']}")

print("\n=== Targets in DB ===")
targets = db.get_targets()
print(f"Total: {len(targets)}")
for t in targets:
    print(f"  {t['url']} - status: {t['status']}")
