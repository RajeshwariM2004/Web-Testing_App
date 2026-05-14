"""
Reflected XSS heuristic: inject marker payload and check reflection in response.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests

from scanner.http_client import DEFAULT_TIMEOUT_SECONDS, request_with_retries

logger = logging.getLogger(__name__)

XSS_PAYLOAD = "<script>alert(1)</script>"


@dataclass
class XSSFinding:
    url: str
    payload: str
    parameter: str
    context: str
    evidence: str
    severity: str


def _reflection_level(body: str, payload: str) -> str:
    """
    Returns: 'full' | 'partial' | 'none'
    - full: payload (or safely-escaped equivalent) appears
    - partial: distinctive fragments suggest reflection (weaker)
    """
    if not body:
        return "none"
    if payload in body:
        return "full"
    # Decoded angle brackets sometimes appear escaped
    esc = (
        payload.replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
    if esc in body:
        return "full"
    # Partial reflection of distinctive substring
    if "alert(1)" in body and "script" in body.lower():
        return "partial"
    if "alert(1)" in body:
        return "partial"
    return "none"


def _inject_query_params(url: str, payload: str) -> list[tuple[str, str]]:
    parsed = urlparse(url)
    if not parsed.query:
        return []
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    results: list[tuple[str, str]] = []
    for i, (key, _val) in enumerate(pairs):
        new_pairs = list(pairs)
        new_pairs[i] = (key, payload)
        new_query = urlencode(new_pairs, doseq=True)
        new_url = urlunparse(
            (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, "")
        )
        results.append((new_url, key))
    return results


def test_url_get_xss(
    url: str,
    session: requests.Session,
    *,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> list[XSSFinding]:
    findings: list[XSSFinding] = []
    parsed = urlparse(url)
    if not parsed.query:
        return findings

    for fuzzed_url, param in _inject_query_params(url, XSS_PAYLOAD):
        try:
            r = request_with_retries(session, "GET", fuzzed_url, timeout=timeout)
            if not r.ok:
                continue
            level = _reflection_level(r.text or "", XSS_PAYLOAD)
            if level != "none":
                sev = "Medium" if level == "full" else "Low"
                ev = (
                    "Payload reflected in HTML response"
                    if level == "full"
                    else "Partial payload markers reflected in response"
                )
                logger.info("XSS finding (%s) at %s param=%s", sev, fuzzed_url, param)
                findings.append(
                    XSSFinding(
                        url=fuzzed_url,
                        payload=XSS_PAYLOAD,
                        parameter=param,
                        context="query",
                        evidence=ev,
                        severity=sev,
                    )
                )
        except Exception:
            continue

    return findings
