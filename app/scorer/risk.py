"""
Risk scorer: converts a list of Threats into a capped 0-100 score with a
human-readable risk level label.
"""
from __future__ import annotations

from dataclasses import dataclass

from app.rules.engine import Threat

# Points awarded per severity finding
_SEVERITY_POINTS: dict[str, int] = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1,
}

# Ordered thresholds (descending) → level label
_THRESHOLDS: list[tuple[int, str]] = [
    (70, "CRITICAL"),
    (40, "HIGH"),
    (20, "MEDIUM"),
    (1,  "LOW"),
    (0,  "SAFE"),
]


@dataclass
class RiskScore:
    score: int                          # 0–100 (capped)
    level: str                          # CRITICAL | HIGH | MEDIUM | LOW | SAFE
    severity_distribution: dict[str, int]  # counts per severity label


def calculate_score(threats: list[Threat]) -> RiskScore:
    """
    Tally threat points, cap at 100, and derive an overall risk level.

    Scoring:
        CRITICAL = 10 pts  |  HIGH = 7 pts  |  MEDIUM = 4 pts  |  LOW = 1 pt
    Risk level:
        score ≥ 70 → CRITICAL  |  ≥ 40 → HIGH  |  ≥ 20 → MEDIUM
        > 0  → LOW             |  = 0  → SAFE
    """
    distribution: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    raw_points = 0

    for threat in threats:
        sev = threat.severity.upper()
        distribution[sev] = distribution.get(sev, 0) + 1
        raw_points += _SEVERITY_POINTS.get(sev, 0)

    score = min(raw_points, 100)

    level = "SAFE"
    for threshold, label in _THRESHOLDS:
        if score >= threshold:
            level = label
            break

    return RiskScore(score=score, level=level, severity_distribution=distribution)
