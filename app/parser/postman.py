"""
Postman Collection v2.1 parser.

Flattens nested folders and extracts per-request metadata needed by the
threat-modeling rule engine.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse

# Matches {id}, {userId}, :id, :userId patterns
_PATH_PARAM_RE = re.compile(r"\{[^}]+\}|:[a-zA-Z_][a-zA-Z0-9_]*")


@dataclass
class ParsedEndpoint:
    name: str
    method: str
    path: str
    auth_type: Optional[str]          # "bearer" | "basic" | "apikey" | "oauth2" | None
    has_auth: bool
    has_path_param: bool               # True if path contains {x} or :x
    headers: list[dict[str, str]]
    body: Optional[dict[str, Any]]
    query_params: list[str]           # lowercase param names from the URL
    scheme: Optional[str]             # "http" | "https" | None


@dataclass
class ParsedCollection:
    title: str
    endpoints: list[ParsedEndpoint] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_scheme(url: Any) -> Optional[str]:
    """Return 'http' or 'https' if detectable, else None."""
    raw: str = ""
    if isinstance(url, str):
        raw = url
    elif isinstance(url, dict):
        raw = url.get("raw") or url.get("protocol") or ""
    if raw.startswith("https"):
        return "https"
    if raw.startswith("http"):
        return "http"
    return None


def _extract_path(url: Any) -> str:
    """Return normalised path string from a URL value (string or dict)."""
    if isinstance(url, str):
        # Raw string — strip scheme+host if present
        if url.startswith(("http://", "https://")):
            try:
                return urlparse(url).path or "/"
            except Exception:
                pass
        # Could be just a path or contain {{variables}} — return as-is
        return url.split("?")[0]  # strip query string

    if isinstance(url, dict):
        raw: str = url.get("raw", "")
        if raw:
            # Strip scheme+host from raw
            if raw.startswith(("http://", "https://")):
                try:
                    return urlparse(raw).path or "/"
                except Exception:
                    pass
            return raw.split("?")[0]

        # Fallback: reconstruct from path array
        path_array = url.get("path", [])
        if path_array:
            segments: list[str] = []
            for seg in path_array:
                if isinstance(seg, str):
                    segments.append(seg)
                elif isinstance(seg, dict):
                    segments.append(seg.get("value", ""))
            return "/" + "/".join(segments)

    return "/"


def _extract_query_params(url: Any) -> list[str]:
    """Return lowercase list of query param key names."""
    if not isinstance(url, dict):
        return []
    return [
        q["key"].lower()
        for q in url.get("query", [])
        if isinstance(q, dict) and q.get("key")
    ]


def _resolve_auth(
    request_auth: Any,
    inherited_auth: Optional[str],
) -> tuple[Optional[str], bool]:
    """
    Determine auth type and whether the endpoint is authenticated.
    Returns (auth_type, has_auth).
    """
    if isinstance(request_auth, dict):
        auth_type = (request_auth.get("type") or "").lower()
        if auth_type in ("", "noauth"):
            # Explicitly no-auth — ignore inheritance
            return None, False
        return auth_type, True

    # No request-level auth: inherit from parent scope
    if request_auth is None and inherited_auth:
        return inherited_auth, True

    return None, False


def _flatten_items(
    items: list[Any],
    parent_auth: Optional[str],
) -> list[ParsedEndpoint]:
    """
    Recursively walk the item tree, yielding ParsedEndpoint objects.
    Folders can carry an auth override that their children inherit.
    """
    endpoints: list[ParsedEndpoint] = []

    for item in items:
        if not isinstance(item, dict):
            continue

        # Resolve the auth context for this folder/item
        item_auth_obj = item.get("auth")
        folder_auth: Optional[str] = None
        if isinstance(item_auth_obj, dict):
            t = (item_auth_obj.get("type") or "").lower()
            if t and t != "noauth":
                folder_auth = t

        effective_auth = folder_auth or parent_auth

        # Folder — recurse
        if "item" in item:
            endpoints.extend(_flatten_items(item["item"], effective_auth))
            continue

        # Request leaf
        request = item.get("request")
        if not isinstance(request, dict):
            continue

        name: str = item.get("name") or "Unnamed"
        method: str = (request.get("method") or "GET").upper()

        url_val = request.get("url", "")
        path = _extract_path(url_val)
        query_params = _extract_query_params(url_val)
        scheme = _extract_scheme(url_val)

        auth_type, has_auth = _resolve_auth(request.get("auth"), effective_auth)
        has_path_param = bool(_PATH_PARAM_RE.search(path))

        headers: list[dict[str, str]] = [
            {"key": h.get("key", ""), "value": h.get("value", "")}
            for h in request.get("header", [])
            if isinstance(h, dict)
        ]

        body = request.get("body")

        endpoints.append(
            ParsedEndpoint(
                name=name,
                method=method,
                path=path,
                auth_type=auth_type,
                has_auth=has_auth,
                has_path_param=has_path_param,
                headers=headers,
                body=body if isinstance(body, dict) else None,
                query_params=query_params,
                scheme=scheme,
            )
        )

    return endpoints


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_collection(data: dict[str, Any]) -> ParsedCollection:
    """
    Parse a Postman Collection v2.1 dict into a ``ParsedCollection``.

    Raises:
        KeyError / TypeError: if the dict is structurally invalid (let the
        caller handle this and wrap into an HTTPException).
    """
    info = data.get("info") or {}
    title: str = info.get("name") or "Untitled Collection"

    # Collection-level auth (inherited by all items unless overridden)
    collection_auth: Optional[str] = None
    coll_auth_obj = data.get("auth")
    if isinstance(coll_auth_obj, dict):
        t = (coll_auth_obj.get("type") or "").lower()
        if t and t != "noauth":
            collection_auth = t

    endpoints = _flatten_items(data.get("item", []), collection_auth)

    return ParsedCollection(title=title, endpoints=endpoints)
