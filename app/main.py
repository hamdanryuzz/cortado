"""
FastAPI application — API Threat Modeling Tool.

Endpoints
---------
GET  /health                      Health check
POST /analyze                     Analyze collection from JSON body
POST /analyze/upload              Analyze collection from multipart file upload
"""
from __future__ import annotations

import json
import logging
from typing import Any, Literal

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, field_validator

from app.parser.postman import ParsedCollection, parse_collection
from app.report.generator import build_json_report, build_markdown_report
from app.rules.engine import Threat, run_engine
from app.scorer.risk import RiskScore, calculate_score

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="API Threat Modeling Tool",
    description=(
        "Accepts a Postman Collection v2.1 and produces a threat model report "
        "using STRIDE methodology mapped to OWASP API Security Top 10 (2023)."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

_MAX_FILE_BYTES = 10 * 1024 * 1024  # 10 MB

# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class AnalyzeRequest(BaseModel):
    content: str
    format: Literal["json", "markdown"] = "json"

    @field_validator("content")
    @classmethod
    def content_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("content must not be empty")
        return v

    model_config = {
        "json_schema_extra": {
            "example": {
                "content": '{"info":{"name":"My API","schema":"…"},"item":[…]}',
                "format": "json",
            }
        }
    }


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _parse_postman_json(raw: str) -> dict[str, Any]:
    """
    Deserialise raw string → dict.
    Raises HTTPException(422) on malformed JSON or missing required fields.
    """
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid JSON: {exc.msg} at line {exc.lineno}, column {exc.colno}.",
        ) from exc

    if not isinstance(data, dict):
        raise HTTPException(
            status_code=422,
            detail="Postman collection must be a JSON object.",
        )
    if "info" not in data or "item" not in data:
        raise HTTPException(
            status_code=422,
            detail=(
                "Not a valid Postman Collection v2.1: "
                "missing required top-level keys 'info' and/or 'item'."
            ),
        )
    return data


def _run_pipeline(
    data: dict[str, Any],
) -> tuple[ParsedCollection, list[Threat], RiskScore]:
    """Parse → rule engine → scorer."""
    try:
        collection = parse_collection(data)
        threats = run_engine(collection.endpoints)
        risk = calculate_score(threats)
        return collection, threats, risk
    except Exception as exc:
        logger.exception("Pipeline error during analysis")
        raise HTTPException(
            status_code=500,
            detail=f"Analysis pipeline error: {exc}",
        ) from exc


def _format_response(
    collection: ParsedCollection,
    threats: list[Threat],
    risk: RiskScore,
    fmt: str,
) -> JSONResponse | PlainTextResponse:
    if fmt == "markdown":
        md = build_markdown_report(collection, threats, risk)
        return PlainTextResponse(
            content=md,
            media_type="text/markdown; charset=utf-8",
        )
    report = build_json_report(collection, threats, risk)
    return JSONResponse(content=report)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get(
    "/health",
    tags=["Health"],
    summary="Health check",
    response_description="Service status",
)
async def health() -> dict[str, str]:
    """Returns a simple liveness indicator."""
    return {"status": "ok", "service": "api-threat-modeling"}


@app.post(
    "/analyze",
    tags=["Analysis"],
    summary="Analyze from JSON body",
    response_description="Threat model report (JSON or Markdown)",
)
async def analyze(request: AnalyzeRequest) -> JSONResponse | PlainTextResponse:
    """
    Analyze a Postman Collection v2.1 provided as a raw JSON string embedded
    in the request body.

    - **content** – Raw Postman Collection JSON string
    - **format** – `json` (default) or `markdown`
    """
    logger.info("POST /analyze — format=%s", request.format)
    data = _parse_postman_json(request.content)
    collection, threats, risk = _run_pipeline(data)
    logger.info(
        "Analysis complete: %d endpoints, %d threats, score=%d (%s)",
        len(collection.endpoints),
        len(threats),
        risk.score,
        risk.level,
    )
    return _format_response(collection, threats, risk, request.format)


@app.post(
    "/analyze/upload",
    tags=["Analysis"],
    summary="Analyze from file upload",
    response_description="Threat model report (JSON or Markdown)",
)
async def analyze_upload(
    file: UploadFile = File(
        ...,
        description="Postman Collection v2.1 .json file (max 10 MB)",
    ),
    format: Literal["json", "markdown"] = Query(
        "json",
        description="Output format — json or markdown",
    ),
) -> JSONResponse | PlainTextResponse:
    """
    Analyze a Postman Collection uploaded as a multipart `.json` file.

    - **file** – `.json` file (multipart/form-data)
    - **format** – `json` (default) or `markdown` (query param)
    """
    filename = file.filename or ""
    logger.info("POST /analyze/upload — file=%s format=%s", filename, format)

    if not filename.lower().endswith(".json"):
        raise HTTPException(
            status_code=422,
            detail="Only .json files are accepted.",
        )

    raw_bytes = await file.read()

    if len(raw_bytes) > _MAX_FILE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=(
                f"File size ({len(raw_bytes):,} bytes) exceeds the "
                f"{_MAX_FILE_BYTES // 1024 // 1024} MB limit."
            ),
        )

    if len(raw_bytes) == 0:
        raise HTTPException(status_code=422, detail="Uploaded file is empty.")

    try:
        raw_str = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(
            status_code=422,
            detail="File must be UTF-8 encoded.",
        ) from exc

    data = _parse_postman_json(raw_str)
    collection, threats, risk = _run_pipeline(data)
    logger.info(
        "Analysis complete: %d endpoints, %d threats, score=%d (%s)",
        len(collection.endpoints),
        len(threats),
        risk.score,
        risk.level,
    )
    return _format_response(collection, threats, risk, format)
