"""Check database findings."""
import sys
sys.path.insert(0, '.')
from utils.database import db

stats = db.get_stats()
print('Targets:', stats['targets'])
print('Findings:', stats['pending_findings'])
print('Critical:', stats['critical_findings'])
print()
findings = db.get_findings(limit=10)
print('Recent findings:')
for f in findings:
    sev = f['severity']
    title = f['title'][:60]
    print(f'  - [{sev}] {title}')
