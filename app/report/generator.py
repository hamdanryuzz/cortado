"""
Report generator: builds JSON dict and Markdown string from analysis results.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any

from app.parser.postman import ParsedCollection
from app.rules.engine import OWASP_NAMES, Threat
from app.scorer.risk import RiskScore

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SEVERITY_EMOJI: dict[str, str] = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "SAFE":     "✅",
}

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def _top_affected_endpoints(threats: list[Threat], n: int = 5) -> list[str]:
    counter: Counter[str] = Counter(
        f"{t.affected_method} {t.affected_endpoint}" for t in threats
    )
    return [ep for ep, _ in counter.most_common(n)]


def _owasp_distribution(threats: list[Threat]) -> dict[str, int]:
    dist: dict[str, int] = {}
    for t in threats:
        dist[t.owasp] = dist.get(t.owasp, 0) + 1
    return dict(sorted(dist.items()))


# ---------------------------------------------------------------------------
# JSON report
# ---------------------------------------------------------------------------

def build_json_report(
    collection: ParsedCollection,
    threats: list[Threat],
    risk: RiskScore,
) -> dict[str, Any]:
    return {
        "meta": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "api_title": collection.title,
            "source_type": "postman",
            "total_endpoints": len(collection.endpoints),
        },
        "summary": {
            "risk_score": risk.score,
            "risk_level": risk.level,
            "total_threats": len(threats),
            "severity_distribution": risk.severity_distribution,
            "owasp_distribution": _owasp_distribution(threats),
            "top_affected_endpoints": _top_affected_endpoints(threats),
        },
        "threats": [
            {
                "rule_id":           t.rule_id,
                "title":             t.title,
                "description":       t.description,
                "owasp":             t.owasp,
                "owasp_name":        t.owasp_name,
                "stride":            t.stride,
                "severity":          t.severity,
                "mitigation":        t.mitigation,
                "affected_endpoint": t.affected_endpoint,
                "affected_method":   t.affected_method,
            }
            for t in threats
        ],
    }


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------

def build_markdown_report(
    collection: ParsedCollection,
    threats: list[Threat],
    risk: RiskScore,
) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    level_emoji = _SEVERITY_EMOJI.get(risk.level, "")
    dist = risk.severity_distribution
    owasp_dist = _owasp_distribution(threats)

    lines: list[str] = [
        f"# Threat Model Report — {collection.title}",
        "",
        f"> **Generated:** {now}  ",
        f"> **Source:** Postman Collection  ",
        f"> **Endpoints Analyzed:** {len(collection.endpoints)}",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Risk Score | **{risk.score} / 100** |",
        f"| Risk Level | {level_emoji} **{risk.level}** |",
        f"| Total Threats | {len(threats)} |",
        f"| 🔴 Critical | {dist.get('CRITICAL', 0)} |",
        f"| 🟠 High | {dist.get('HIGH', 0)} |",
        f"| 🟡 Medium | {dist.get('MEDIUM', 0)} |",
        f"| 🟢 Low | {dist.get('LOW', 0)} |",
        "",
    ]

    # OWASP distribution table
    if owasp_dist:
        lines += [
            "## OWASP API Top 10 (2023) Coverage",
            "",
            "| OWASP ID | Name | Findings |",
            "|----------|------|----------|",
        ]
        for owasp_id, count in owasp_dist.items():
            name = OWASP_NAMES.get(owasp_id, "")
            lines.append(f"| {owasp_id} | {name} | {count} |")
        lines.append("")

    # Top affected endpoints
    top = _top_affected_endpoints(threats)
    if top:
        lines += ["## Top Affected Endpoints", ""]
        for ep in top:
            lines.append(f"- `{ep}`")
        lines.append("")

    # Per-threat detail, grouped by severity
    if threats:
        lines += ["---", "", "## Threat Details", ""]

        for sev in _SEVERITY_ORDER:
            sev_threats = [t for t in threats if t.severity == sev]
            if not sev_threats:
                continue

            sev_emoji = _SEVERITY_EMOJI.get(sev, "")
            lines += [f"### {sev_emoji} {sev} ({len(sev_threats)})", ""]

            for idx, t in enumerate(sev_threats, start=1):
                lines += [
                    f"#### {idx}. [{t.rule_id}] {t.title}",
                    "",
                    f"| Field | Value |",
                    f"|-------|-------|",
                    f"| **Endpoint** | `{t.affected_method} {t.affected_endpoint}` |",
                    f"| **OWASP** | {t.owasp} — {t.owasp_name} |",
                    f"| **STRIDE** | {', '.join(t.stride)} |",
                    f"| **Severity** | {sev_emoji} {t.severity} |",
                    "",
                    f"**Description:**",
                    f"{t.description}",
                    "",
                    f"**Mitigation:**",
                    f"{t.mitigation}",
                    "",
                ]
    else:
        lines += [
            "",
            "## ✅ No Threats Detected",
            "",
            "> No security threats were identified in the provided collection.",
            "",
        ]

    lines += [
        "---",
        "",
        "*Report generated by API Threat Modeling Tool*",
    ]

    return "\n".join(lines)
