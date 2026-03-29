<div align="center">
  <img src="logo.svg" width="262" height="72" alt="cortado"/>
  <br/><br/>
  <p>Threat modeling tool for REST APIs — input a Postman Collection, get a threat report.</p>
</div>

---

Cortado parses a Postman Collection v2.1 and runs it through 17 rules based on STRIDE and OWASP API Security Top 10 (2023). The output is a risk score from 0–100 plus a full list of findings with mitigations, exportable as JSON or Markdown.

## Installation

```bash
git clone <repo>
cd cortado

python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open `http://localhost:8000/docs` for the Swagger UI.

## Usage

**From a file:**
```bash
curl -s -X POST http://localhost:8000/analyze/upload \
  -F "file=@collection.json" | jq .
```

**From a request body:**
```bash
curl -s -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"content": "<postman json string>", "format": "json"}'
```

**Markdown output:**
```bash
curl -s -X POST "http://localhost:8000/analyze/upload?format=markdown" \
  -F "file=@collection.json"
```

To export a collection from Postman: right-click the collection → Export → Collection v2.1.

## Output

```json
{
  "meta": { "generated_at", "api_title", "source_type", "total_endpoints" },
  "summary": {
    "risk_score": 54,
    "risk_level": "HIGH",
    "total_threats": 9,
    "severity_distribution": { "CRITICAL": 1, "HIGH": 3, "MEDIUM": 4, "LOW": 1 },
    "owasp_distribution": { "API1:2023": 1, "API2:2023": 2 },
    "top_affected_endpoints": ["GET /users/{id}", "POST /admin/users"]
  },
  "threats": [{
    "rule_id": "BOLA-001",
    "title": "Broken Object Level Authorization",
    "severity": "CRITICAL",
    "owasp": "API1:2023",
    "stride": ["Spoofing", "Elevation of Privilege"],
    "affected_endpoint": "/users/{id}",
    "affected_method": "GET",
    "mitigation": "..."
  }]
}
```

Risk score: `>= 70` CRITICAL · `>= 40` HIGH · `>= 20` MEDIUM · `> 0` LOW · `0` SAFE

## Rules

| Rule | Condition | OWASP | Severity |
|------|-----------|-------|----------|
| BOLA-001 | Path param `{id}`/`:id` + no auth | API1 | CRITICAL |
| BAUTH-001 | POST/PUT/PATCH/DELETE + no auth | API2 | HIGH |
| BAUTH-002 | Auth type = `apikey` | API2 | MEDIUM |
| BAUTH-003 | Auth type = `basic` | API2 | MEDIUM |
| BOPLA-001 | PUT/PATCH + JSON body (mass assignment) | API3 | MEDIUM |
| INFO-001 | `token`/`password`/`secret` in query params | API3 | HIGH |
| URC-001 | GET collection with no pagination params | API4 | MEDIUM |
| URC-002 | Path contains `/upload` `/import` `/ingest` | API4 | MEDIUM |
| URC-003 | Path contains `/bulk` `/export` `/batch` `/dump` | API4 | HIGH |
| BFLA-001 | Path contains `/admin` `/internal` `/debug` `/config` | API5 | HIGH / MEDIUM |
| BFLA-002 | Path contains `/metrics` `/actuator` `/prometheus` | API5 | HIGH / LOW |
| UASBF-001 | Path contains `/checkout` `/payment` `/transfer` `/order` | API6 | HIGH |
| UASBF-002 | Path contains `/register` `/reset` `/otp` `/verify` | API6 | MEDIUM |
| SSRF-001 | Query param named `url`/`redirect`/`host`/`callback` | API7 | HIGH |
| SECM-001 | Path contains `/swagger` `/api-docs` `/openapi` | API8 | HIGH / MEDIUM |
| SECM-002 | HTTP (not HTTPS) URL in collection | API8 | MEDIUM |
| IIM-001 | Path contains `/v0/` `/beta/` `/alpha/` `/test/` `/dev/` | API9 | MEDIUM |
| UCA-001 | Path contains `/webhook` `/proxy` `/callback` `/relay` | API10 | MEDIUM |

BFLA-001 and BFLA-002 drop one severity level when the endpoint already has auth.

## Structure

```
app/
├── main.py              FastAPI, /analyze and /analyze/upload endpoints
├── parser/postman.py    Postman Collection v2.1 parser
├── rules/engine.py      17-rule STRIDE + OWASP engine
├── scorer/risk.py       Risk score 0–100 calculator
└── report/generator.py  JSON + Markdown report builder
```

## Requirements

- Python 3.10+
- `fastapi`, `uvicorn[standard]`, `python-multipart`
