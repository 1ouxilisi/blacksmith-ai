# BlacksmithAI - Autonomous AI Security Testing Platform

Multi-agent AI penetration testing tool with local LLM support.
Inspired by Strix (42K stars) and PentAGI (23K stars).

## Features

### Core
- **Multi-Agent Architecture**: Recon Agent -> Exploit Agent -> Coordinator
- **Local LLM**: Uses Ollama with pentest-optimized models (no cloud API needed)
- **PoC Validation**: Auto-verifies findings, not just "potential issues"
- **Attack Chain Analysis**: Correlates findings into full exploit paths
- **Agent Memory**: Remembers past scans, skips recently tested targets
- **Budget Control**: LLM spend limits to prevent surprise bills

### Scan Tools (7)
- nmap - Port scanning
- nuclei - Vulnerability template scanning
- gobuster - Directory enumeration
- subfinder - Subdomain discovery
- whatweb - Technology fingerprinting
- nikto - Web server vulnerability scanning
- sqlmap - SQL injection detection

### Dashboard Pages (13)
- `/` - Main dashboard
- `/targets` - All scanned targets
- `/findings` - All vulnerability findings
- `/orchestrated-scan` - Start multi-agent scan
- `/agents` - Multi-agent team status
- `/chains` - Attack chain analysis
- `/runs` - Run history and cost tracking
- `/budget` - LLM budget control
- `/ai` - AI analysis with local LLM
- `/remediation` - AI-powered fix recommendations
- `/health` - System health check
- `/new-scan` - Quick scan form
- `/plugins` - Plugin management

## Quick Start

### Prerequisites
1. Docker Desktop
2. Python 3.11+
3. Ollama (for AI features)

### Installation
```bash
# 1. Start Docker container
docker start shell-executor

# 2. Install Python dependencies
cd blacksmithAI
pip install -r requirements.txt

# 3. (Optional) Pull pentest model for AI features
ollama pull mistral-nemo:12b-pentest

# 4. Start dashboard
start.bat
```

### One-Click Launch (Windows)
```
Double-click start.bat
```

### Stop Services
```
Double-click stop.bat
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/scan/start` | POST | Start a scan |
| `/api/scan/status` | GET | Get scan status |
| `/api/orchestrated/start` | POST | Start multi-agent scan |
| `/api/ai/analyze` | GET | Run AI analysis |
| `/api/export/json` | GET | Export all findings as JSON |
| `/api/history` | GET | Get scan history |

## Configuration

Environment variables (`.env`):
```
OPENROUTER_API_KEY=your_key  # Optional, for cloud LLM
container_uri=http://localhost:9756/exec
DAILY_BUDGET_USD=5.0
RUN_BUDGET_USD=1.0
```

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ Recon Agent │ --> │ Exploit Agent│ --> │ Coordinator │
│ (subfinder, │     │ (nuclei,    │     │ (chain      │
│  whatweb,   │     │  nikto,     │     │  analysis,  │
│  nmap)      │     │  sqlmap)    │     │  report)    │
└─────────────┘     └─────────────┘     └─────────────┘
                                              │
                                              ▼
                                    ┌─────────────────┐
                                    │  Local LLM      │
                                    │  (Ollama)       │
                                    │  mistral-nemo   │
                                    └─────────────────┘
```

## License
MIT
