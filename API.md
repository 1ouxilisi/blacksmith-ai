# BlacksmithAI API Documentation

## Base URL

```
http://localhost:8501
```

## Authentication

All API endpoints require an API key. Include it in the header:

```
X-API-Key: bs_your_api_key_here
```

---

## Endpoints

### 1. Health Check

```
GET /health
```

Response:
```json
{
  "status": "ok",
  "version": "1.0.0"
}
```

---

### 2. OWASP LLM Top 10 Scan

```
POST /api/llm/owasp
```

Request Body:
```json
{
  "endpoint": "http://localhost:11434/api/generate",
  "categories": ["LLM01", "LLM02", "LLM07"]
}
```

Response:
```json
{
  "scan_id": "scan_123456",
  "findings": [
    {
      "id": "LLM01",
      "name": "Prompt Injection",
      "severity": "critical",
      "evidence": "Model revealed system prompt",
      "remediation": "Add input filtering"
    }
  ]
}
```

---

### 3. RAG Security Scan

```
POST /api/llm/rag
```

Request Body:
```json
{
  "endpoint": "http://localhost:8000/api/rag/query"
}
```

Response:
```json
{
  "scan_id": "scan_789012",
  "findings": [...]
}
```

---

### 4. Smart Detection

```
POST /api/detect
```

Request Body:
```json
{
  "response": "The API key is sk-abc123..."
}
```

Response:
```json
{
  "score": 15,
  "is_vulnerability": true,
  "confidence": "high",
  "categories": ["api_key"]
}
```

---

### 5. False Positive Filter

```
POST /api/fp-filter
```

Request Body:
```json
{
  "response": "I can't share that...",
  "vuln_type": "prompt_injection"
}
```

Response:
```json
{
  "is_fp": true,
  "confidence": 0.9,
  "reason": "Model refused"
}
```

---

### 6. Get Report

```
GET /api/reports/{scan_id}
```

Response:
```json
{
  "scan_id": "scan_123456",
  "status": "completed",
  "findings": [...],
  "summary": {
    "critical": 2,
    "high": 5,
    "medium": 3,
    "low": 1
  }
}
```

---

## Error Codes

| Code | Description |
|------|-------------|
| 400 | Bad request - missing parameters |
| 401 | Unauthorized - invalid API key |
| 403 | Forbidden - quota exceeded |
| 404 | Not found |
| 500 | Internal server error |

---

## Rate Limits

| Tier | Requests/minute |
|------|-----------------|
| Free | 10 |
| Pro | 100 |
| Enterprise | Unlimited |

---

## SDK Examples

### Python

```python
import requests

api_key = "bs_your_api_key"
headers = {"X-API-Key": api_key}

# Run scan
r = requests.post(
    "http://localhost:8501/api/llm/owasp",
    json={"endpoint": "http://localhost:11434/api/generate"},
    headers=headers
)
print(r.json())
```

### curl

```bash
curl -X POST http://localhost:8501/api/llm/owasp \
  -H "X-API-Key: bs_your_api_key" \
  -H "Content-Type: application/json" \
  -d '{"endpoint": "http://localhost:11434/api/generate"}'
```
