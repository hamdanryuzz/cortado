"""
STRIDE + OWASP API Security Top 10 (2023) Rule Engine.

Each rule function inspects a single ParsedEndpoint and returns zero or more
Threat objects. The public entry point is ``run_engine()``.

Rule inventory (17 rules):
  BOLA-001  BAUTH-001  BAUTH-002  BAUTH-003
  BFLA-001  BFLA-002
  UASBF-001  UASBF-002
  URC-001  URC-002  URC-003
  IIM-001
  UCA-001
  SECM-001  SECM-002
  SSRF-001
  INFO-001
  BOPLA-001
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

from app.parser.postman import ParsedEndpoint

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

OWASP_NAMES: dict[str, str] = {
    "API1:2023": "Broken Object Level Authorization",
    "API2:2023": "Broken Authentication",
    "API3:2023": "Broken Object Property Level Authorization",
    "API4:2023": "Unrestricted Resource Consumption",
    "API5:2023": "Broken Function Level Authorization",
    "API6:2023": "Unrestricted Access to Sensitive Business Flows",
    "API7:2023": "Server Side Request Forgery",
    "API8:2023": "Security Misconfiguration",
    "API9:2023": "Improper Inventory Management",
    "API10:2023": "Unsafe Consumption of APIs",
}

_WRITE_METHODS    = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_PAGINATION_PARAMS = frozenset({"limit", "page", "size", "offset", "per_page", "count"})

# ── path matchers ────────────────────────────────────────────────────────────
_RE_SENSITIVE = re.compile(
    r"/(admin|internal|debug|config|secret|env)(/|$)", re.IGNORECASE
)
_RE_BUSINESS_CRITICAL = re.compile(
    r"/(checkout|payment|transfer|withdraw|order|vote|cart|invoice|billing|refund)(/|$)",
    re.IGNORECASE,
)
_RE_LEGACY = re.compile(
    r"/(v0|beta|alpha|test|dev|staging|sandbox)/", re.IGNORECASE
)
_RE_WEBHOOK = re.compile(
    r"/(webhook|proxy|callback|relay|forward|hook)(/|$)", re.IGNORECASE
)
_RE_API_DOCS = re.compile(
    r"/(swagger|api-docs?|openapi|redoc|graphiql|graphql/?(playground|explorer)?)(/|$)",
    re.IGNORECASE,
)
_RE_MONITORING = re.compile(
    r"/(metrics|actuator|prometheus|health/?detail|readyz?|livez?|info|env|configprops|"
    r"threaddump|heapdump|loggers?|auditevents)(/|$)",
    re.IGNORECASE,
)
_RE_FILE_UPLOAD = re.compile(
    r"/(upload|import|ingest|attach|file|attachment|media|asset|image|avatar)s?(/|$)",
    re.IGNORECASE,
)
_RE_BULK = re.compile(
    r"/(bulk|batch|export|dump|all|sync|migrate|seed|load)(/|$)", re.IGNORECASE
)
_RE_AUTH_FLOW = re.compile(
    r"/(register|signup|sign-up|reset|forgot|otp|verify|confirm|activate|"
    r"resend|unlock|unsubscribe)(/|$)",
    re.IGNORECASE,
)

# ── query-param name matchers ────────────────────────────────────────────────
_SSRF_PARAMS = frozenset({
    "url", "uri", "href", "redirect", "redirect_uri", "return_url", "returnurl",
    "next", "dest", "destination", "callback", "endpoint", "target", "host",
    "domain", "site", "feed", "path", "continue", "goto",
})
_SENSITIVE_PARAMS = frozenset({
    "token", "access_token", "auth_token", "api_key", "apikey", "key",
    "secret", "password", "passwd", "pwd", "pass", "credential", "ssn",
    "cvv", "pin", "otp", "code", "refresh_token",
})


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Threat:
    rule_id: str
    title: str
    description: str
    owasp: str
    owasp_name: str
    stride: list[str]
    severity: str           # CRITICAL | HIGH | MEDIUM | LOW
    mitigation: str
    affected_endpoint: str
    affected_method: str


# ---------------------------------------------------------------------------
# Internal factory
# ---------------------------------------------------------------------------

def _threat(
    *,
    rule_id: str,
    title: str,
    description: str,
    owasp: str,
    stride: list[str],
    severity: str,
    mitigation: str,
    endpoint: ParsedEndpoint,
) -> Threat:
    return Threat(
        rule_id=rule_id,
        title=title,
        description=description,
        owasp=owasp,
        owasp_name=OWASP_NAMES.get(owasp, ""),
        stride=stride,
        severity=severity,
        mitigation=mitigation,
        affected_endpoint=endpoint.path,
        affected_method=endpoint.method,
    )


# ---------------------------------------------------------------------------
# ── ORIGINAL 8 RULES ────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

def _rule_bola_001(ep: ParsedEndpoint) -> list[Threat]:
    """BOLA-001 — path param + no auth → CRITICAL (API1:2023)."""
    if not (ep.has_path_param and not ep.has_auth):
        return []
    return [
        _threat(
            rule_id="BOLA-001",
            title="Broken Object Level Authorization",
            description=(
                f"Endpoint «{ep.name}» exposes object-level access via a path "
                f"parameter ({ep.path}) without requiring authentication. An attacker "
                "can enumerate IDs and access data belonging to other users."
            ),
            owasp="API1:2023",
            stride=["Spoofing", "Elevation of Privilege"],
            severity="CRITICAL",
            mitigation=(
                "Implement object-level authorization checks on every request that "
                "references a resource ID. Verify the authenticated caller owns or is "
                "permitted to access the referenced object. Add authentication to "
                "this endpoint immediately."
            ),
            endpoint=ep,
        )
    ]


def _rule_bauth_001(ep: ParsedEndpoint) -> list[Threat]:
    """BAUTH-001 — write method + no auth → HIGH (API2:2023)."""
    if not (ep.method in _WRITE_METHODS and not ep.has_auth):
        return []
    return [
        _threat(
            rule_id="BAUTH-001",
            title="Unauthenticated State-Changing Operation",
            description=(
                f"Endpoint «{ep.name}» ({ep.method} {ep.path}) performs a "
                "state-changing operation without requiring authentication. Any "
                "anonymous actor can create, update, or delete data."
            ),
            owasp="API2:2023",
            stride=["Spoofing", "Tampering"],
            severity="HIGH",
            mitigation=(
                "Require authentication for all state-changing endpoints (POST, PUT, "
                "PATCH, DELETE). Implement OAuth2 / JWT bearer tokens with short "
                "expiry. Enforce authentication at the API gateway layer as a safety net."
            ),
            endpoint=ep,
        )
    ]


def _rule_bauth_002(ep: ParsedEndpoint) -> list[Threat]:
    """BAUTH-002 — API key authentication → MEDIUM (API2:2023)."""
    if ep.auth_type != "apikey":
        return []
    return [
        _threat(
            rule_id="BAUTH-002",
            title="Weak Authentication — Static API Key",
            description=(
                f"Endpoint «{ep.name}» relies on static API key authentication. "
                "API keys have no built-in expiry, are frequently leaked in logs, "
                "client-side code, or version control history, and cannot be "
                "granularly scoped or rotated without service disruption."
            ),
            owasp="API2:2023",
            stride=["Spoofing"],
            severity="MEDIUM",
            mitigation=(
                "Replace static API keys with short-lived OAuth2 / JWT bearer tokens "
                "with refresh rotation. If keys are unavoidable, transmit them only "
                "via headers (never query params), enforce TLS, set expiry, and "
                "scope them to the minimum required permissions."
            ),
            endpoint=ep,
        )
    ]


def _rule_bauth_003(ep: ParsedEndpoint) -> list[Threat]:
    """BAUTH-003 — HTTP Basic auth → MEDIUM (API2:2023)."""
    if ep.auth_type != "basic":
        return []
    return [
        _threat(
            rule_id="BAUTH-003",
            title="Weak Authentication — HTTP Basic Auth",
            description=(
                f"Endpoint «{ep.name}» uses HTTP Basic authentication, which "
                "transmits credentials as a Base64 string on every request. "
                "Without strict TLS enforcement, credentials are trivially decoded "
                "in transit. Basic auth also lacks token revocation or expiry."
            ),
            owasp="API2:2023",
            stride=["Spoofing", "Information Disclosure"],
            severity="MEDIUM",
            mitigation=(
                "Migrate to token-based authentication (OAuth2 / JWT). If Basic auth "
                "must remain, enforce TLS everywhere, never transmit credentials in "
                "URLs, and rotate them regularly. Consider multi-factor authentication "
                "for privileged operations."
            ),
            endpoint=ep,
        )
    ]


def _rule_bfla_001(ep: ParsedEndpoint) -> list[Threat]:
    """BFLA-001 — admin/internal/debug path → HIGH (no auth) / MEDIUM (API5:2023)."""
    if not _RE_SENSITIVE.search(ep.path):
        return []
    severity = "MEDIUM" if ep.has_auth else "HIGH"
    auth_note = (
        "No authentication is present, making this particularly severe."
        if not ep.has_auth
        else (
            "Authentication is present but function-level authorization "
            "may still be insufficient to prevent privilege escalation."
        )
    )
    return [
        _threat(
            rule_id="BFLA-001",
            title="Sensitive / Administrative Endpoint Exposed",
            description=(
                f"Endpoint «{ep.name}» ({ep.path}) exposes administrative or "
                f"sensitive functionality. {auth_note}"
            ),
            owasp="API5:2023",
            stride=["Information Disclosure", "Elevation of Privilege"],
            severity=severity,
            mitigation=(
                "Implement role-based access control (RBAC) and verify the caller's "
                "role before executing sensitive operations. Restrict /admin, "
                "/internal, /debug, /config, /secret, and /env paths to privileged "
                "roles only. Disable or remove debug/config endpoints in production."
            ),
            endpoint=ep,
        )
    ]


def _rule_bfla_002(ep: ParsedEndpoint) -> list[Threat]:
    """BFLA-002 — observability/monitoring endpoints → HIGH (no auth) / LOW (API5:2023)."""
    if not _RE_MONITORING.search(ep.path):
        return []
    severity = "HIGH" if not ep.has_auth else "LOW"
    return [
        _threat(
            rule_id="BFLA-002",
            title="Observability Endpoint Exposed",
            description=(
                f"Endpoint «{ep.name}» ({ep.path}) exposes internal operational "
                "data (metrics, health details, environment variables, thread dumps, "
                "etc.). "
                + (
                    "Without authentication this data is publicly accessible."
                    if not ep.has_auth
                    else "Ensure role checking is enforced even with authentication."
                )
            ),
            owasp="API5:2023",
            stride=["Information Disclosure", "Elevation of Privilege"],
            severity=severity,
            mitigation=(
                "Restrict observability endpoints to internal networks or operations "
                "roles only. Disable verbose actuator endpoints in production "
                "(e.g. Spring Boot: management.endpoints.web.exposure.include=health). "
                "Never expose heap dumps, thread dumps, or env vars publicly."
            ),
            endpoint=ep,
        )
    ]


def _rule_uasbf_001(ep: ParsedEndpoint) -> list[Threat]:
    """UASBF-001 — payment/order/financial paths → HIGH (API6:2023)."""
    if not _RE_BUSINESS_CRITICAL.search(ep.path):
        return []
    return [
        _threat(
            rule_id="UASBF-001",
            title="Unrestricted Access to Sensitive Business Flow",
            description=(
                f"Endpoint «{ep.name}» ({ep.path}) handles a sensitive business "
                "transaction (payment, order, transfer, etc.) susceptible to "
                "automation abuse, enumeration, or replay attacks without proper "
                "flow-level protection."
            ),
            owasp="API6:2023",
            stride=["Tampering"],
            severity="HIGH",
            mitigation=(
                "Apply per-user rate limiting and anomaly detection to business-critical "
                "flows. Consider CAPTCHA or device fingerprinting for high-value "
                "transactions. Require re-authentication for sensitive actions and "
                "implement idempotency keys to prevent replays."
            ),
            endpoint=ep,
        )
    ]


def _rule_uasbf_002(ep: ParsedEndpoint) -> list[Threat]:
    """UASBF-002 — auth/account management flows → MEDIUM (API6:2023)."""
    if not _RE_AUTH_FLOW.search(ep.path):
        return []
    return [
        _threat(
            rule_id="UASBF-002",
            title="Account Management Flow — Brute-Force / Enumeration Risk",
            description=(
                f"Endpoint «{ep.name}» ({ep.path}) is part of an account "
                "management flow (registration, password reset, OTP, verification). "
                "Without rate limiting and enumeration protection, these flows "
                "can be abused for account takeover or user enumeration."
            ),
            owasp="API6:2023",
            stride=["Spoofing"],
            severity="MEDIUM",
            mitigation=(
                "Implement strict rate limiting (e.g. max 5 attempts / 15 min per IP). "
                "Return identical responses regardless of whether the account exists "
                "to prevent user enumeration. Enforce OTP expiry (< 10 min) and "
                "invalidate tokens after single use. Log and alert on suspicious patterns."
            ),
            endpoint=ep,
        )
    ]


def _rule_urc_001(ep: ParsedEndpoint) -> list[Threat]:
    """URC-001 — GET collection without pagination → MEDIUM (API4:2023)."""
    if ep.method != "GET" or ep.has_path_param:
        return []
    if _PAGINATION_PARAMS & set(ep.query_params):
        return []
    return [
        _threat(
            rule_id="URC-001",
            title="Unbounded Resource Consumption — No Pagination",
            description=(
                f"Endpoint «{ep.name}» (GET {ep.path}) appears to return a "
                "collection without pagination parameters (limit, page, size, "
                "offset). An attacker can trigger large data dumps that exhaust "
                "server memory and database resources."
            ),
            owasp="API4:2023",
            stride=["Denial of Service"],
            severity="MEDIUM",
            mitigation=(
                "Add mandatory pagination query parameters with a server-enforced "
                "maximum page size (e.g. max 100 items). Return paginated responses "
                "with total count metadata. Implement query timeouts and result-set "
                "size limits at the database layer."
            ),
            endpoint=ep,
        )
    ]


def _rule_urc_002(ep: ParsedEndpoint) -> list[Threat]:
    """URC-002 — file upload endpoint → MEDIUM (API4:2023)."""
    if not _RE_FILE_UPLOAD.search(ep.path):
        return []
    return [
        _threat(
            rule_id="URC-002",
            title="Unrestricted File Upload — Resource Exhaustion Risk",
            description=(
                f"Endpoint «{ep.name}» ({ep.path}) accepts file uploads. Without "
                "strict file size limits, type validation, and rate limiting, "
                "an attacker can exhaust storage, CPU (malicious archives, "
                "polyglot files), or upload malware for later execution."
            ),
            owasp="API4:2023",
            stride=["Denial of Service", "Tampering"],
            severity="MEDIUM",
            mitigation=(
                "Enforce maximum file size and request body limits at the gateway. "
                "Validate MIME type via magic bytes (not just extension). "
                "Store uploads outside the web root, scan with antivirus, and "
                "serve via a CDN with content-type sniffing disabled. "
                "Rate-limit upload requests per user."
            ),
            endpoint=ep,
        )
    ]


def _rule_urc_003(ep: ParsedEndpoint) -> list[Threat]:
    """URC-003 — bulk/export endpoint → HIGH (API4:2023)."""
    if not _RE_BULK.search(ep.path):
        return []
    return [
        _threat(
            rule_id="URC-003",
            title="Bulk / Export Operation — Mass Data Extraction Risk",
            description=(
                f"Endpoint «{ep.name}» ({ep.path}) exposes a bulk or export "
                "operation that may allow mass data extraction, large-payload "
                "write operations, or resource exhaustion without proper controls."
            ),
            owasp="API4:2023",
            stride=["Information Disclosure", "Denial of Service"],
            severity="HIGH",
            mitigation=(
                "Enforce row/record limits on bulk operations (e.g. max 1,000 per "
                "request). Require authentication and appropriate roles. Implement "
                "async job processing for large exports and deliver results via "
                "signed, expiring download links. Rate-limit and audit bulk operations."
            ),
            endpoint=ep,
        )
    ]


def _rule_iim_001(ep: ParsedEndpoint) -> list[Threat]:
    """IIM-001 — legacy/pre-production API version → MEDIUM (API9:2023)."""
    if not _RE_LEGACY.search(ep.path):
        return []
    return [
        _threat(
            rule_id="IIM-001",
            title="Improper Inventory Management — Legacy API Version",
            description=(
                f"Endpoint «{ep.name}» ({ep.path}) belongs to a legacy or "
                "pre-production API version (v0, beta, alpha, test, dev, staging, "
                "sandbox). These versions are often overlooked during security reviews "
                "and may lack controls present in the production API."
            ),
            owasp="API9:2023",
            stride=["Information Disclosure"],
            severity="MEDIUM",
            mitigation=(
                "Maintain a complete API inventory. Decommission or restrict access "
                "to legacy and pre-production versions in production environments. "
                "Apply the same security controls to all versions and use an API "
                "gateway to enforce versioning policy."
            ),
            endpoint=ep,
        )
    ]


def _rule_uca_001(ep: ParsedEndpoint) -> list[Threat]:
    """UCA-001 — webhook/proxy/callback path → MEDIUM (API10:2023)."""
    if not _RE_WEBHOOK.search(ep.path):
        return []
    return [
        _threat(
            rule_id="UCA-001",
            title="Unsafe API Consumption — SSRF / Callback Abuse",
            description=(
                f"Endpoint «{ep.name}» ({ep.path}) involves a webhook, proxy, "
                "or callback mechanism. If caller-supplied URLs are not validated, "
                "this may be exploited for Server-Side Request Forgery (SSRF) to "
                "reach internal services or relay malicious payloads."
            ),
            owasp="API10:2023",
            stride=["Spoofing", "Tampering"],
            severity="MEDIUM",
            mitigation=(
                "Validate and sanitize all caller-supplied URLs against an allowlist "
                "of permitted destinations. Disable automatic redirects, enforce "
                "connection timeouts, and block private/link-local IP ranges. "
                "Authenticate incoming webhook calls using HMAC signatures."
            ),
            endpoint=ep,
        )
    ]


# ---------------------------------------------------------------------------
# ── NEW RULES ────────────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

def _rule_secm_001(ep: ParsedEndpoint) -> list[Threat]:
    """SECM-001 — API documentation endpoint exposed → HIGH (no auth) / MEDIUM (API8:2023)."""
    if not _RE_API_DOCS.search(ep.path):
        return []
    severity = "MEDIUM" if ep.has_auth else "HIGH"
    return [
        _threat(
            rule_id="SECM-001",
            title="API Documentation Endpoint Publicly Exposed",
            description=(
                f"Endpoint «{ep.name}» ({ep.path}) serves interactive API "
                "documentation (Swagger UI, ReDoc, GraphiQL, etc.). "
                + (
                    "Without authentication, attackers gain a complete, interactive "
                    "map of all available endpoints, parameters, and schemas."
                    if not ep.has_auth
                    else "Ensure docs are restricted to authorised roles in production."
                )
            ),
            owasp="API8:2023",
            stride=["Information Disclosure"],
            severity=severity,
            mitigation=(
                "Disable or access-control interactive API documentation in production. "
                "Restrict to internal network / VPN, or require authentication with an "
                "admin/developer role. Consider serving read-only, non-interactive "
                "specs via authenticated endpoints only."
            ),
            endpoint=ep,
        )
    ]


def _rule_secm_002(ep: ParsedEndpoint) -> list[Threat]:
    """SECM-002 — HTTP (non-HTTPS) URL in collection → MEDIUM (API8:2023)."""
    if ep.scheme != "http":
        return []
    return [
        _threat(
            rule_id="SECM-002",
            title="Insecure Transport — HTTP Instead of HTTPS",
            description=(
                f"Endpoint «{ep.name}» ({ep.path}) uses plain HTTP, transmitting "
                "all data—including credentials, tokens, and PII—in cleartext. "
                "An attacker on the same network can trivially intercept or "
                "modify traffic via a man-in-the-middle attack."
            ),
            owasp="API8:2023",
            stride=["Information Disclosure", "Tampering"],
            severity="MEDIUM",
            mitigation=(
                "Enforce HTTPS (TLS 1.2+) on all endpoints. Redirect HTTP to HTTPS "
                "at the load balancer/gateway level. Enable HTTP Strict Transport "
                "Security (HSTS) with a long max-age. Renew certificates before "
                "expiry and monitor for certificate mis-issuance."
            ),
            endpoint=ep,
        )
    ]


def _rule_ssrf_001(ep: ParsedEndpoint) -> list[Threat]:
    """SSRF-001 — URL-like query param names → HIGH (API7:2023)."""
    matched = _SSRF_PARAMS & set(ep.query_params)
    if not matched:
        return []
    params_str = ", ".join(sorted(matched))
    return [
        _threat(
            rule_id="SSRF-001",
            title="Potential Server-Side Request Forgery (SSRF)",
            description=(
                f"Endpoint «{ep.name}» ({ep.method} {ep.path}) accepts "
                f"query parameter(s) that suggest server-side URL resolution: "
                f"{params_str}. If the server fetches the supplied URL, an attacker "
                "can pivot to internal network services, cloud metadata endpoints "
                "(169.254.169.254), or trigger blind SSRF via DNS rebinding."
            ),
            owasp="API7:2023",
            stride=["Spoofing", "Information Disclosure"],
            severity="HIGH",
            mitigation=(
                "Validate all URL parameters against a strict allowlist of permitted "
                "schemes, hosts, and ports. Block requests to private/loopback/link-local "
                "ranges (RFC 1918, 169.254.0.0/16, ::1). Disable redirects and enforce "
                "network-level egress filtering (firewall rules). "
                "Log all outbound requests made on behalf of user input."
            ),
            endpoint=ep,
        )
    ]


def _rule_info_001(ep: ParsedEndpoint) -> list[Threat]:
    """INFO-001 — sensitive data in query params → HIGH (API3:2023)."""
    matched = _SENSITIVE_PARAMS & set(ep.query_params)
    if not matched:
        return []
    params_str = ", ".join(sorted(matched))
    return [
        _threat(
            rule_id="INFO-001",
            title="Sensitive Data Exposed in Query Parameters",
            description=(
                f"Endpoint «{ep.name}» ({ep.method} {ep.path}) transmits "
                f"sensitive values via query parameters: {params_str}. "
                "Query strings are logged by web servers, proxies, browser history, "
                "and CDN access logs, making these credentials trivially harvestable."
            ),
            owasp="API3:2023",
            stride=["Information Disclosure"],
            severity="HIGH",
            mitigation=(
                "Move sensitive values (tokens, passwords, secrets) from query "
                "parameters to request headers or a POST body over TLS. "
                "Audit access logs and proxy configurations to ensure sensitive "
                "values are stripped. Rotate any credentials that may have been logged."
            ),
            endpoint=ep,
        )
    ]


def _rule_bopla_001(ep: ParsedEndpoint) -> list[Threat]:
    """BOPLA-001 — PUT/PATCH with JSON body → mass assignment risk → MEDIUM (API3:2023)."""
    if ep.method not in ("PUT", "PATCH"):
        return []
    body = ep.body or {}
    body_mode = body.get("mode", "")
    if body_mode not in ("raw", "graphql", "") and body_mode:
        return []
    # Only flag if there's actually a body present or no body restriction is visible
    return [
        _threat(
            rule_id="BOPLA-001",
            title="Mass Assignment / Broken Object Property Level Authorization",
            description=(
                f"Endpoint «{ep.name}» ({ep.method} {ep.path}) accepts an update "
                "payload without explicit property filtering. If the server binds "
                "the request body directly to an ORM/model object, attackers may "
                "inject privileged fields (e.g. is_admin, role, account_balance) "
                "to escalate privileges or corrupt data."
            ),
            owasp="API3:2023",
            stride=["Tampering", "Elevation of Privilege"],
            severity="MEDIUM",
            mitigation=(
                "Use an explicit allowlist (DTO / serializer schema) for every "
                "update endpoint — never bind raw request bodies directly to ORM "
                "models. Define exactly which properties clients are permitted to "
                "modify. Apply separate input schemas for different roles and "
                "reject unexpected fields with a 400 error."
            ),
            endpoint=ep,
        )
    ]


# ---------------------------------------------------------------------------
# Rule registry & public API
# ---------------------------------------------------------------------------

_RULES: list[Callable[[ParsedEndpoint], list[Threat]]] = [
    # API1 — BOLA
    _rule_bola_001,
    # API2 — Broken Authentication
    _rule_bauth_001,
    _rule_bauth_002,
    _rule_bauth_003,
    # API3 — Object Property Level
    _rule_bopla_001,
    _rule_info_001,
    # API4 — Resource Consumption
    _rule_urc_001,
    _rule_urc_002,
    _rule_urc_003,
    # API5 — Function Level Authorization
    _rule_bfla_001,
    _rule_bfla_002,
    # API6 — Business Flows
    _rule_uasbf_001,
    _rule_uasbf_002,
    # API7 — SSRF
    _rule_ssrf_001,
    # API8 — Security Misconfiguration
    _rule_secm_001,
    _rule_secm_002,
    # API9 — Inventory Management
    _rule_iim_001,
    # API10 — Unsafe Consumption
    _rule_uca_001,
]


def analyze_endpoint(endpoint: ParsedEndpoint) -> list[Threat]:
    """Run all rules against a single endpoint."""
    threats: list[Threat] = []
    for rule in _RULES:
        threats.extend(rule(endpoint))
    return threats


def run_engine(endpoints: list[ParsedEndpoint]) -> list[Threat]:
    """Run the full rule engine across all endpoints."""
    threats: list[Threat] = []
    for ep in endpoints:
        threats.extend(analyze_endpoint(ep))
    return threats
