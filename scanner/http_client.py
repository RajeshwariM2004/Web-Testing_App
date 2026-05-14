"""
HTTP utilities for the scanner.

Goals:
- Consistent headers (User-Agent)
- Timeout defaults
- Retries (3) via urllib3 Retry + safe handling
- Gentle throttling (small delay) to reduce load/misuse
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Literal

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 15
DEFAULT_RETRIES = 3


def build_session(*, retries: int = DEFAULT_RETRIES, backoff: float = 0.4) -> requests.Session:
    s = requests.Session()
    retry = Retry(
        total=retries,
        connect=retries,
        read=retries,
        backoff_factor=backoff,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET", "POST", "HEAD"),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s


def default_headers() -> dict[str, str]:
    return {
        "User-Agent": "WAST-EducationalScanner/2.0 (+authorized testing only)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }


@dataclass
class HttpResult:
    ok: bool
    url: str
    status_code: int | None
    text: str
    content_length: int
    error: str | None


def request_with_retries(
    session: requests.Session,
    method: Literal["GET", "POST"],
    url: str,
    *,
    params: dict[str, Any] | None = None,
    data: dict[str, Any] | None = None,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    delay_seconds: float = 0.15,
) -> HttpResult:
    """
    Wrapper around requests with retries (configured on session).
    Returns a normalized HttpResult and never raises.
    """
    if delay_seconds > 0:
        time.sleep(delay_seconds)
    try:
        if method == "POST":
            r = session.post(url, params=params, data=data, headers=default_headers(), timeout=timeout, allow_redirects=True)
        else:
            r = session.get(url, params=params, headers=default_headers(), timeout=timeout, allow_redirects=True)
        text = r.text or ""
        return HttpResult(
            ok=bool(r.ok),
            url=str(r.url),
            status_code=int(r.status_code),
            text=text,
            content_length=len(r.content or b""),
            error=None,
        )
    except (requests.Timeout, requests.ConnectionError) as e:
        logger.debug("HTTP %s failed for %s: %s", method, url, e)
        return HttpResult(ok=False, url=url, status_code=None, text="", content_length=0, error=str(e))
    except requests.RequestException as e:
        logger.debug("HTTP %s request error for %s: %s", method, url, e)
        return HttpResult(ok=False, url=url, status_code=None, text="", content_length=0, error=str(e))
