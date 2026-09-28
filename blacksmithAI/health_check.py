"""System health check script."""
import sys
sys.path.insert(0, '.')

checks = []

# 1. Database
try:
    from utils.database import db
    stats = db.get_stats()
    checks.append(('SQLite Database', 'OK', f"{stats['targets']} targets"))
except Exception as e:
    checks.append(('SQLite Database', 'FAIL', str(e)))

# 2. Docker
try:
    import requests
    resp = requests.get('http://localhost:9756/', timeout=3)
    checks.append(('Docker Executor', 'OK', 'Port 9756'))
except:
    checks.append(('Docker Executor', 'FAIL', 'Not reachable'))

# 3. LLM
try:
    from utils.llm_analyzer import llm_analyzer
    if llm_analyzer.available:
        checks.append(('Local LLM (Ollama)', 'OK', llm_analyzer.default_model))
    else:
        checks.append(('Local LLM (Ollama)', 'OFFLINE', 'Not running'))
except Exception as e:
    checks.append(('Local LLM (Ollama)', 'FAIL', str(e)))

# 4. Scan Engine
try:
    from utils.scan_engine import scan_engine
    checks.append(('Scan Engine', 'OK', '7 tools'))
except Exception as e:
    checks.append(('Scan Engine', 'FAIL', str(e)))

# 5. PoC Validator
try:
    from utils.poc_validator import poc_validator
    checks.append(('PoC Validator', 'OK', '5 vuln types'))
except Exception as e:
    checks.append(('PoC Validator', 'FAIL', str(e)))

# 6. Multi-Agent
try:
    from utils.multi_agent import orchestrator
    checks.append(('Multi-Agent System', 'OK', '3 agents'))
except Exception as e:
    checks.append(('Multi-Agent System', 'FAIL', str(e)))

# 7. Agent Memory
try:
    from utils.agent_memory import agent_memory
    mem = agent_memory.get_memory_summary()
    checks.append(('Agent Memory', 'OK', f"{mem['total_targets_remembered']} targets"))
except Exception as e:
    checks.append(('Agent Memory', 'FAIL', str(e)))

# 8. Budget
try:
    from utils.run_history import budget_guard
    budget = budget_guard.get_status()
    checks.append(('Budget Control', 'OK', f"${budget['daily_used_usd']}/${budget['daily_limit_usd']}"))
except Exception as e:
    checks.append(('Budget Control', 'FAIL', str(e)))

# 9. Report Generator
try:
    from utils.report_generator_pro import report_generator_pro
    checks.append(('Report Generator', 'OK', 'HTML reports'))
except Exception as e:
    checks.append(('Report Generator', 'FAIL', str(e)))

print('=== System Health Check ===')
print()
ok = 0
fail = 0
for name, status, detail in checks:
    icon = '✅' if status == 'OK' else ('⚠️' if status == 'OFFLINE' else '❌')
    print(f'{icon} {name}: {status} - {detail}')
    if status == 'OK':
        ok += 1
    else:
        fail += 1

print()
print(f'Total: {ok} OK, {fail} issues')
