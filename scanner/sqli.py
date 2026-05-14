"""
SQL injection heuristic tests: error signatures and response length anomalies.
Educational / authorized testing only.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests

from scanner.http_client import DEFAULT_TIMEOUT_SECONDS, build_session, request_with_retries

logger = logging.getLogger(__name__)

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "'--",
    "' OR 1=1--",
    '" OR "1"="1',
]

# Common DB/driver error snippets (heuristic; may false-positive)
SQL_ERROR_PATTERNS = [
    r"sql syntax",
    r"database error",
    r"\bmysql\b",
    r"\bwarning\b",
    r"\berror\b",
    r"mysql_fetch",
    r"mysqli?_",
    r"PostgreSQL.*?ERROR",
    r"Warning:\s*pg_",
    r"valid MySQL result",
    r"ODBC SQL Server Driver",
    r"SQLite3?.*?error",
    r"sqlite_master",
    r"ORA-\d{5}",
    r"Microsoft OLE DB Provider for SQL Server",
    r"Unclosed quotation mark",
    r"quoted string not properly terminated",
    r"Syntax error.*?(near|at)",
]

_COMPILED = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in SQL_ERROR_PATTERNS]


@dataclass
class SQLiFinding:
    url: str
    payload: str
    parameter: str
    context: str  # "query" | "form"
    evidence: str
    severity: str


def _body_suggests_sql_error(text: str) -> bool:
    if not text:
        return False
    for pat in _COMPILED:
        if pat.search(text):
            return True
    return False


def _evidence_from_error(body: str) -> str | None:
    if not body:
        return None
    for pat in _COMPILED:
        m = pat.search(body)
        if m:
            snippet = body[m.start() : min(len(body), m.start() + 180)].strip()
            return f"SQL error keyword matched: /{pat.pattern}/; snippet: {snippet}"
    return None


def _inject_query_params(url: str, payload: str) -> list[tuple[str, str]]:
    """Return list of (fuzzed_url, param_name) for each query key."""
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


def test_url_get_sqli(
    url: str,
    session: requests.Session,
    *,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> list[SQLiFinding]:
    """Test GET parameters on a single URL for SQLi heuristics."""
    findings: list[SQLiFinding] = []
    parsed = urlparse(url)
    if not parsed.query:
        return findings

    try:
        base = request_with_retries(session, "GET", url, timeout=timeout)
        if not base.ok:
            return findings
        base_len = base.content_length
    except Exception as e:
        logger.debug("SQLi baseline failed %s: %s", url, e)
        return findings

    for payload in SQLI_PAYLOADS:
        for fuzzed_url, param in _inject_query_params(url, payload):
            try:
                r = request_with_retries(session, "GET", fuzzed_url, timeout=timeout)
                if not r.ok:
                    continue
                evidence_parts: list[str] = []

                err_ev = _evidence_from_error(r.text)
                if err_ev:
                    evidence_parts.append(err_ev)

                delta = abs(r.content_length - base_len)
                if base_len > 0:
                    ratio = delta / max(1, base_len)
                    if delta > 600 and ratio > 0.25:
                        evidence_parts.append(f"Response length anomaly: base={base_len} inj={r.content_length} delta={delta} ({ratio:.0%})")

                if evidence_parts:
                    sev = "High" if err_ev else "Medium"
                    finding = SQLiFinding(
                        url=fuzzed_url,
                        payload=payload,
                        parameter=param,
                        context="query",
                        evidence="; ".join(evidence_parts),
                        severity=sev,
                    )
                    logger.info("SQLi finding (%s) at %s param=%s", sev, fuzzed_url, param)
                    findings.append(finding)
            except Exception:
                continue

    return findings
