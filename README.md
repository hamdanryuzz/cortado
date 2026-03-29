<div align="center">
  <img src="logo.svg" width="262" height="72" alt="cortado logo"/>
  <br/><br/>
  <p><strong>API Threat Modeling Tool</strong></p>
  <p>
    Analyzes Postman Collections for security vulnerabilities using<br/>
    <strong>STRIDE</strong> methodology mapped to <strong>OWASP API Security Top 10 (2023)</strong>
  </p>
  <p>
    <img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white" alt="Python"/>
    <img src="https://img.shields.io/badge/FastAPI-0.110%2B-009688?logo=fastapi&logoColor=white" alt="FastAPI"/>
    <img src="https://img.shields.io/badge/OWASP_API_2023-covered-orange" alt="OWASP"/>
    <img src="https://img.shields.io/badge/rules-17-blueviolet" alt="Rules"/>
    <img src="https://img.shields.io/badge/license-MIT-green" alt="License"/>
  </p>
</div>

---

## What is cortado?

**cortado** takes a Postman Collection v2.1 JSON and runs it through a rule-based security engine, producing a prioritized threat model report in JSON or Markdown. No cloud, no signup — runs fully offline.

```
Postman Collection
      │
      ▼
  Parser          ← flatten nested folders, extract method / path / auth / params
      │
      ▼
  Rule Engine     ← 17 STRIDE + OWASP API Top 10 (2023) rules
      │
      ▼
  Risk Scorer     ← weighted score 0–100, 5-level risk label
      │
      ▼
  Report          ← JSON report  or  Markdown report
```

---

## Features

- **17 security rules** covering all 10 OWASP API Security categories
- **STRIDE threat classification** per finding
- **Risk score 0–100** with CRITICAL / HIGH / MEDIUM / LOW / SAFE label
- **Severity-weighted scoring** — CRITICAL=10, HIGH=7, MEDIUM=4, LOW=1
- **Two input modes** — JSON body or multipart file upload
- **Two output formats** — structured JSON or human-readable Markdown
- **Zero external dependencies** beyond FastAPI + uvicorn

---

## Installation

```bash
git clone <repo-url>
cd cortado

python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -r requirements.txt
```

---

## Running

```bash
uvicorn app.main:app --reload
```

| URL | Description |
|-----|-------------|
| `http://localhost:8000/docs` | Swagger UI |
| `http://localhost:8000/redoc` | ReDoc |
| `http://localhost:8000/health` | Health check |

---

## Usage

### Health check

```bash
curl http://localhost:8000/health
```

```json
{"status": "ok", "service": "api-threat-modeling"}
```

---

### Analyze from JSON body

```bash
curl -s -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "content": "<raw postman collection json string>",
    "format": "json"
  }' | jq .
```

For Markdown output:
```bash
curl -s -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"content": "...", "format": "markdown"}'
```

---

### Analyze from file upload

```bash
# JSON output (default)
curl -s -X POST http://localhost:8000/analyze/upload \
  -F "file=@my_collection.json" | jq .

# Markdown output
curl -s -X POST "http://localhost:8000/analyze/upload?format=markdown" \
  -F "file=@my_collection.json"
```

---

### Export collection from Postman

1. Open Postman → right-click your collection → **Export**
2. Select **Collection v2.1** → Save as `.json`
3. Upload via `/analyze/upload` or paste content into `/analyze`

---

## Output Structure

### JSON Report

```json
{
  "meta": {
    "generated_at": "2026-03-29T10:00:00+00:00",
    "api_title": "My API",
    "source_type": "postman",
    "total_endpoints": 12
  },
  "summary": {
    "risk_score": 54,
    "risk_level": "HIGH",
    "total_threats": 9,
    "severity_distribution": {
      "CRITICAL": 1,
      "HIGH": 3,
      "MEDIUM": 4,
      "LOW": 1
    },
    "owasp_distribution": {
      "API1:2023": 1,
      "API2:2023": 2,
      "API4:2023": 2,
      "API5:2023": 1,
      "API6:2023": 1,
      "API8:2023": 1,
      "API9:2023": 1
    },
    "top_affected_endpoints": [
      "GET /users/{id}",
      "POST /admin/users",
      "GET /users"
    ]
  },
  "threats": [
    {
      "rule_id": "BOLA-001",
      "title": "Broken Object Level Authorization",
      "description": "...",
      "owasp": "API1:2023",
      "owasp_name": "Broken Object Level Authorization",
      "stride": ["Spoofing", "Elevation of Privilege"],
      "severity": "CRITICAL",
      "mitigation": "...",
      "affected_endpoint": "/users/{id}",
      "affected_method": "GET"
    }
  ]
}
```

### Risk Levels

| Score | Level |
|-------|-------|
| 0 | ✅ SAFE |
| 1–19 | 🟢 LOW |
| 20–39 | 🟡 MEDIUM |
| 40–69 | 🟠 HIGH |
| ≥ 70 | 🔴 CRITICAL |

---

## Rule Reference (17 rules)

| Rule ID | Category | Condition | OWASP | Severity |
|---------|----------|-----------|-------|----------|
| `BOLA-001` | BOLA | Path param `{id}`/`:id` + no auth | API1:2023 | 🔴 CRITICAL |
| `BAUTH-001` | Auth | POST/PUT/PATCH/DELETE + no auth | API2:2023 | 🟠 HIGH |
| `BAUTH-002` | Auth | Auth type = `apikey` | API2:2023 | 🟡 MEDIUM |
| `BAUTH-003` | Auth | Auth type = `basic` | API2:2023 | 🟡 MEDIUM |
| `BOPLA-001` | Mass Assignment | PUT/PATCH with JSON body | API3:2023 | 🟡 MEDIUM |
| `INFO-001` | Sensitive Params | Token/password/secret in query params | API3:2023 | 🟠 HIGH |
| `URC-001` | Pagination | GET collection, no limit/page/size/offset | API4:2023 | 🟡 MEDIUM |
| `URC-002` | File Upload | Path contains `/upload` `/import` `/ingest` `/file` | API4:2023 | 🟡 MEDIUM |
| `URC-003` | Bulk/Export | Path contains `/bulk` `/export` `/batch` `/dump` | API4:2023 | 🟠 HIGH |
| `BFLA-001` | Admin Paths | `/admin` `/internal` `/debug` `/config` `/secret` `/env` | API5:2023 | 🟠 HIGH / 🟡 MEDIUM |
| `BFLA-002` | Monitoring | `/metrics` `/actuator` `/prometheus` `/health` | API5:2023 | 🟠 HIGH / 🟢 LOW |
| `UASBF-001` | Business Flow | `/checkout` `/payment` `/transfer` `/order` `/vote` | API6:2023 | 🟠 HIGH |
| `UASBF-002` | Account Flow | `/register` `/reset` `/otp` `/verify` `/confirm` | API6:2023 | 🟡 MEDIUM |
| `SSRF-001` | SSRF | Query params: `url`, `redirect`, `host`, `callback`, `target`… | API7:2023 | 🟠 HIGH |
| `SECM-001` | API Docs | `/swagger` `/api-docs` `/openapi` `/graphiql` `/redoc` | API8:2023 | 🟠 HIGH / 🟡 MEDIUM |
| `SECM-002` | Transport | HTTP (non-HTTPS) URL in collection | API8:2023 | 🟡 MEDIUM |
| `IIM-001` | Inventory | `/v0/` `/beta/` `/alpha/` `/test/` `/dev/` `/staging/` | API9:2023 | 🟡 MEDIUM |
| `UCA-001` | Callback | `/webhook` `/proxy` `/callback` `/relay` | API10:2023 | 🟡 MEDIUM |

> **Adaptive severity**: `BFLA-001` and `BFLA-002` adjust severity based on whether the endpoint has authentication.

---

## STRIDE Mapping

| STRIDE Category | Rules |
|-----------------|-------|
| **Spoofing** | BOLA-001, BAUTH-001, BAUTH-002, BAUTH-003, SSRF-001, UASBF-002, UCA-001 |
| **Tampering** | BAUTH-001, UASBF-001, URC-002, UCA-001, BOPLA-001, SECM-002 |
| **Information Disclosure** | BFLA-001, BFLA-002, SECM-001, SECM-002, INFO-001, IIM-001, URC-003, BAUTH-003 |
| **Denial of Service** | URC-001, URC-002, URC-003 |
| **Elevation of Privilege** | BOLA-001, BFLA-001, BFLA-002, BOPLA-001 |

---

## Project Structure

```
cortado/
├── app/
│   ├── main.py               ← FastAPI app, 3 endpoints
│   ├── parser/
│   │   └── postman.py        ← Postman Collection v2.1 parser
│   ├── rules/
│   │   └── engine.py         ← 17-rule STRIDE + OWASP engine
│   ├── scorer/
│   │   └── risk.py           ← Risk score 0–100 calculator
│   └── report/
│       └── generator.py      ← JSON + Markdown report builder
├── logo.svg
├── requirements.txt
└── README.md
```

---

## API Reference

### `POST /analyze`

**Request body:**
```json
{
  "content": "<raw Postman Collection v2.1 JSON string>",
  "format": "json"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `content` | string | ✅ | Raw Postman Collection v2.1 JSON |
| `format` | `"json"` \| `"markdown"` | ❌ | Output format (default: `json`) |

---

### `POST /analyze/upload`

**Form data:** multipart file upload

| Param | Type | Required | Description |
|-------|------|----------|-------------|
| `file` | `.json` file | ✅ | Postman Collection v2.1 (max 10 MB) |
| `format` | query param | ❌ | `json` or `markdown` (default: `json`) |

---

### `GET /health`

Returns `{"status": "ok", "service": "api-threat-modeling"}`.

---

## Requirements

```
fastapi>=0.110.0
uvicorn[standard]>=0.27.0
python-multipart>=0.0.9
Python 3.10+
```

---

## License

MIT
