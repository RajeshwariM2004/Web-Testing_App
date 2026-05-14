"""
Same-domain web crawler with depth limit.
Extracts internal URLs and HTML forms for security testing.
"""

from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup

from scanner.http_client import DEFAULT_TIMEOUT_SECONDS, build_session, request_with_retries

logger = logging.getLogger(__name__)


@dataclass
class FormField:
    """Single HTML form input."""

    name: str
    input_type: str
    value: str


@dataclass
class FormInfo:
    """Parsed form metadata."""

    action: str
    method: str
    inputs: list[FormField] = field(default_factory=list)


@dataclass
class CrawlPage:
    """One crawled page with URL and forms."""

    url: str
    forms: list[FormInfo]


def _normalize_url(url: str) -> str:
    """Drop fragment; normalize scheme/host path."""
    parsed = urlparse(url)
    return urlunparse(
        (
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path or "/",
            parsed.params,
            parsed.query,
            "",
        )
    )


def _same_registrable_domain(base: str, candidate: str) -> bool:
    """
    True if candidate is on the same host as base (internal links only).
    Compares netloc including port.
    """
    b = urlparse(base)
    c = urlparse(candidate)
    if not c.netloc:
        return True
    return b.netloc.lower() == c.netloc.lower()


def _extract_forms(soup: BeautifulSoup, page_url: str) -> list[FormInfo]:
    forms: list[FormInfo] = []
    for form in soup.find_all("form"):
        action = form.get("action") or ""
        method = (form.get("method") or "get").upper()
        if method not in ("GET", "POST"):
            method = "GET"
        full_action = urljoin(page_url, action) if action else page_url
        inputs: list[FormField] = []
        for tag in form.find_all(["input", "textarea", "select"]):
            name = tag.get("name")
            if not name:
                continue
            itype = (tag.get("type") or "text").lower()
            if itype in ("submit", "button", "image", "reset"):
                continue
            if tag.name == "textarea":
                itype = "textarea"
            if tag.name == "select":
                itype = "select"
            val = tag.get("value") or ""
            inputs.append(FormField(name=name, input_type=itype, value=val))
        forms.append(FormInfo(action=_normalize_url(full_action), method=method, inputs=inputs))
    return forms


def crawl_site(
    start_url: str,
    *,
    max_depth: int = 2,
    max_pages: int = 40,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    session=None,
) -> tuple[list[CrawlPage], list[str]]:
    """
    BFS crawl of same-domain pages.

    Returns (pages, errors).
    """
    errors: list[str] = []
    sess = session or build_session()
    start_url = _normalize_url(start_url)
    parsed_start = urlparse(start_url)
    if not parsed_start.scheme or not parsed_start.netloc:
        return [], ["Invalid start URL: missing scheme or host"]

    visited: set[str] = set()
    queue: deque[tuple[str, int]] = deque([(start_url, 0)])
    pages: list[CrawlPage] = []

    while queue and len(pages) < max_pages:
        url, depth = queue.popleft()
        if url in visited:
            continue
        visited.add(url)

        try:
            resp = request_with_retries(sess, "GET", url, timeout=timeout)
            if not resp.ok and resp.error:
                errors.append(f"Request failed for {url}: {resp.error}")
                continue

            final_url = _normalize_url(resp.url)
            if not _same_registrable_domain(start_url, final_url):
                logger.debug("Skipped external redirect: %s", final_url)
                continue
            # Best-effort parse as HTML; even if content-type is wrong some sites still serve HTML.
            soup = BeautifulSoup(resp.text or "", "html.parser")
            forms = _extract_forms(soup, final_url)
            pages.append(CrawlPage(url=final_url, forms=forms))

            if depth >= max_depth:
                continue

            for a in soup.find_all("a", href=True):
                href = a["href"].strip()
                if href.startswith(("#", "javascript:", "mailto:", "tel:")):
                    continue
                next_url = _normalize_url(urljoin(final_url, href))
                if not _same_registrable_domain(start_url, next_url):
                    continue
                if next_url not in visited:
                    queue.append((next_url, depth + 1))
        except Exception as e:
            msg = f"Parse error for {url}: {e}"
            logger.exception(msg)
            errors.append(msg)

    return pages, errors


def urls_with_query_params(pages: list[CrawlPage]) -> list[str]:
    """URLs that have GET parameters (candidates for parameter fuzzing)."""
    out: list[str] = []
    for p in pages:
        if urlparse(p.url).query:
            out.append(p.url)
    return out
