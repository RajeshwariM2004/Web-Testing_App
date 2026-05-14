"""
Orchestrates crawling and parallel vulnerability checks (ThreadPoolExecutor).
Includes GET/POST form fuzzing with SQLi and XSS payloads.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from scanner.crawler import CrawlPage, crawl_site, urls_with_query_params
from scanner.http_client import DEFAULT_TIMEOUT_SECONDS, build_session, request_with_retries
from scanner.sqli import SQLiFinding, SQLI_PAYLOADS, test_url_get_sqli, _body_suggests_sql_error
from scanner.xss import XSSFinding, XSS_PAYLOAD, test_url_get_xss, _reflection_level

logger = logging.getLogger(__name__)

DEFAULT_MAX_WORKERS = 6


def _test_forms_sqli(
    page: CrawlPage,
    session,
    *,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> list[SQLiFinding]:
    findings: list[SQLiFinding] = []
    for form in page.forms:
        if not form.inputs:
            continue
        # Baseline submission once (best-effort) to compare length
        base_data = {inp.name: (inp.value or "test") for inp in form.inputs}
        base_resp = request_with_retries(
            session,
            "POST" if form.method == "POST" else "GET",
            form.action,
            data=base_data if form.method == "POST" else None,
            params=base_data if form.method != "POST" else None,
            timeout=timeout,
        )
        base_len = base_resp.content_length if base_resp.ok else 0

        for payload in SQLI_PAYLOADS:
            for inp in form.inputs:
                if inp.input_type in ("hidden",):
                    continue
                try:
                    trial = dict(base_data)
                    trial[inp.name] = payload
                    r = request_with_retries(
                        session,
                        "POST" if form.method == "POST" else "GET",
                        form.action,
                        data=trial if form.method == "POST" else None,
                        params=trial if form.method != "POST" else None,
                        timeout=timeout,
                    )
                    if not r.ok:
                        continue
                    body = r.text or ""
                    ev: list[str] = []
                    if _body_suggests_sql_error(body):
                        ev.append("SQL error keyword detected in response body")
                    if base_len > 0:
                        delta = abs(r.content_length - base_len)
                        ratio = delta / max(1, base_len)
                        if delta > 600 and ratio > 0.25:
                            ev.append(f"Response length anomaly: base={base_len} inj={r.content_length} delta={delta} ({ratio:.0%})")
                    if ev:
                        sev = "High" if any("SQL error" in x for x in ev) else "Medium"
                        logger.info("SQLi finding (%s) at %s field=%s", sev, form.action, inp.name)
                        findings.append(
                            SQLiFinding(
                                url=form.action,
                                payload=payload,
                                parameter=inp.name,
                                context="form",
                                evidence="; ".join(ev),
                                severity=sev,
                            )
                        )
                except Exception:
                    continue
    return findings


def _test_forms_xss(
    page: CrawlPage,
    session,
    *,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> list[XSSFinding]:
    findings: list[XSSFinding] = []
    for form in page.forms:
        if not form.inputs:
            continue
        data = {inp.name: (inp.value or "test") for inp in form.inputs}
        for inp in form.inputs:
            if inp.input_type in ("hidden",):
                continue
            trial = dict(data)
            trial[inp.name] = XSS_PAYLOAD
            try:
                r = request_with_retries(
                    session,
                    "POST" if form.method == "POST" else "GET",
                    form.action,
                    data=trial if form.method == "POST" else None,
                    params=trial if form.method != "POST" else None,
                    timeout=timeout,
                )
                if not r.ok:
                    continue
                level = _reflection_level(r.text or "", XSS_PAYLOAD)
                if level != "none":
                    sev = "Medium" if level == "full" else "Low"
                    ev = (
                        "Payload reflected in response after form submission"
                        if level == "full"
                        else "Partial payload markers reflected after form submission"
                    )
                    logger.info("XSS finding (%s) at %s field=%s", sev, form.action, inp.name)
                    findings.append(
                        XSSFinding(
                            url=form.action,
                            payload=XSS_PAYLOAD,
                            parameter=inp.name,
                            context="form",
                            evidence=ev,
                            severity=sev,
                        )
                    )
            except Exception:
                continue
    return findings


@dataclass
class ScanResult:
    pages: list[CrawlPage]
    sqli: list[SQLiFinding]
    xss: list[XSSFinding]
    crawl_errors: list[str]
    sampled_urls_for_intel: list[str]


def _dedupe_sqli(items: list[SQLiFinding]) -> list[SQLiFinding]:
    seen: set[tuple[str, str, str, str]] = set()
    out: list[SQLiFinding] = []
    for f in items:
        key = (f.url, f.payload, f.parameter, f.context)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def _dedupe_xss(items: list[XSSFinding]) -> list[XSSFinding]:
    seen: set[tuple[str, str, str, str]] = set()
    out: list[XSSFinding] = []
    for f in items:
        key = (f.url, f.payload, f.parameter, f.context)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def run_full_scan(
    target_url: str,
    *,
    max_depth: int = 2,
    max_pages: int = 40,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    max_workers: int = DEFAULT_MAX_WORKERS,
) -> ScanResult:
    """
    Crawl target, then run SQLi/XSS checks in parallel over pages and query URLs.
    """
    max_workers = max(1, min(10, int(max_workers)))
    session = build_session()
    pages, crawl_errors = crawl_site(
        target_url,
        max_depth=max_depth,
        max_pages=max_pages,
        timeout=timeout,
        session=session,
    )

    query_urls = urls_with_query_params(pages)
    sqli_all: list[SQLiFinding] = []
    xss_all: list[XSSFinding] = []

    def job_page(p: CrawlPage) -> tuple[list[SQLiFinding], list[XSSFinding]]:
        s = build_session()
        sqi = _test_forms_sqli(p, s, timeout=timeout)
        xs = _test_forms_xss(p, s, timeout=timeout)
        return sqi, xs

    def job_query(u: str) -> tuple[list[SQLiFinding], list[XSSFinding]]:
        s = build_session()
        sqi = test_url_get_sqli(u, s, timeout=timeout)
        xs = test_url_get_xss(u, s, timeout=timeout)
        return sqi, xs

    futures = []
    workers = min(max_workers, max(1, len(pages) + len(query_urls)))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for p in pages:
            futures.append(ex.submit(job_page, p))
        for u in query_urls:
            futures.append(ex.submit(job_query, u))
        for fut in as_completed(futures):
            try:
                sqi, xs = fut.result()
                sqli_all.extend(sqi)
                xss_all.extend(xs)
            except Exception as e:
                logger.exception("Worker scan failed: %s", e)
                crawl_errors.append(str(e))

    # Intel sample: unique URLs (cap)
    seen_u: set[str] = set()
    sampled: list[str] = []
    for p in pages:
        if p.url not in seen_u:
            seen_u.add(p.url)
            sampled.append(p.url)
        if len(sampled) >= 15:
            break

    sqli_final = _dedupe_sqli(sqli_all)
    xss_final = _dedupe_xss(xss_all)

    # Smart fallback (presentation only) — only after full scan completes.
    if not sqli_final and not xss_final:
        logger.info("No real findings detected; adding demo fallback rows.")
        sqli_final = [
            SQLiFinding(
                url=target_url,
                payload="' OR '1'='1",
                parameter="(demo)",
                context="demo",
                evidence="Demo (No real vulnerability detected)",
                severity="Low",
            )
        ]
        xss_final = [
            XSSFinding(
                url=target_url,
                payload=XSS_PAYLOAD,
                parameter="(demo)",
                context="demo",
                evidence="Demo (No real vulnerability detected)",
                severity="Low",
            )
        ]

    return ScanResult(
        pages=pages,
        sqli=sqli_final,
        xss=xss_final,
        crawl_errors=crawl_errors,
        sampled_urls_for_intel=sampled,
    )
