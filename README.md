<div align="center">
  <img src="logo.svg" width="262" height="72" alt="cortado"/>
  <br/><br/>
  <p>Threat modeling tool untuk REST API — input Postman Collection, output laporan ancaman.</p>
</div>

---

Cortado mem-parsing Postman Collection v2.1 lalu menjalankan 17 rule berbasis STRIDE dan OWASP API Security Top 10 (2023). Hasilnya berupa risk score 0–100 plus daftar temuan lengkap dengan mitigation, bisa di-export ke JSON atau Markdown.

## Instalasi

```bash
git clone <repo>
cd cortado

python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

pip install -r requirements.txt
uvicorn app.main:app --reload
```

Buka `http://localhost:8000/docs` untuk Swagger UI.

## Cara pakai

**Dari file:**
```bash
curl -s -X POST http://localhost:8000/analyze/upload \
  -F "file=@collection.json" | jq .
```

**Dari body:**
```bash
curl -s -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"content": "<postman json string>", "format": "json"}'
```

**Format Markdown:**
```bash
curl -s -X POST "http://localhost:8000/analyze/upload?format=markdown" \
  -F "file=@collection.json"
```

Export collection dari Postman: klik kanan collection → Export → Collection v2.1.

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

| Rule | Kondisi | OWASP | Severity |
|------|---------|-------|----------|
| BOLA-001 | Path param `{id}`/`:id` + no auth | API1 | CRITICAL |
| BAUTH-001 | POST/PUT/PATCH/DELETE + no auth | API2 | HIGH |
| BAUTH-002 | Auth type = `apikey` | API2 | MEDIUM |
| BAUTH-003 | Auth type = `basic` | API2 | MEDIUM |
| BOPLA-001 | PUT/PATCH + JSON body (mass assignment) | API3 | MEDIUM |
| INFO-001 | `token`/`password`/`secret` di query params | API3 | HIGH |
| URC-001 | GET collection tanpa pagination params | API4 | MEDIUM |
| URC-002 | Path `/upload` `/import` `/ingest` | API4 | MEDIUM |
| URC-003 | Path `/bulk` `/export` `/batch` `/dump` | API4 | HIGH |
| BFLA-001 | Path `/admin` `/internal` `/debug` `/config` | API5 | HIGH / MEDIUM |
| BFLA-002 | Path `/metrics` `/actuator` `/prometheus` | API5 | HIGH / LOW |
| UASBF-001 | Path `/checkout` `/payment` `/transfer` `/order` | API6 | HIGH |
| UASBF-002 | Path `/register` `/reset` `/otp` `/verify` | API6 | MEDIUM |
| SSRF-001 | Query param `url`/`redirect`/`host`/`callback` | API7 | HIGH |
| SECM-001 | Path `/swagger` `/api-docs` `/openapi` | API8 | HIGH / MEDIUM |
| SECM-002 | HTTP (bukan HTTPS) di URL collection | API8 | MEDIUM |
| IIM-001 | Path `/v0/` `/beta/` `/alpha/` `/test/` `/dev/` | API9 | MEDIUM |
| UCA-001 | Path `/webhook` `/proxy` `/callback` `/relay` | API10 | MEDIUM |

BFLA-001 dan BFLA-002 severity-nya turun satu level kalau endpoint sudah punya auth.

## Struktur

```
app/
├── main.py            FastAPI, endpoint /analyze dan /analyze/upload
├── parser/postman.py  Parse Postman Collection v2.1
├── rules/engine.py    17 rule STRIDE + OWASP
├── scorer/risk.py     Hitung risk score 0–100
└── report/generator.py  Build JSON + Markdown report
```

## Requirements

- Python 3.10+
- `fastapi`, `uvicorn[standard]`, `python-multipart`
