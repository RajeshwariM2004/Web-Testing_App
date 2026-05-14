"""
VirusTotal URL report (v2 public API with API key).
Rate limits apply on free tier — caller should throttle.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
import requests

logger = logging.getLogger(__name__)

VT_URL = "https://www.virustotal.com/vtapi/v2/url/report"


@dataclass
class VTResult:
    url: str
    status_label: str  # Malicious / Suspicious / Clean / Unknown / Error
    positives: int | None
    total: int | None
    permalink: str | None
    raw_message: str | None


def check_url(api_key: str, url: str, *, timeout: int = 20) -> VTResult:
    """
    Query VirusTotal for URL reputation.
    Without a scan on file, API may return response_code 0 (not present).
    """
    if not api_key or not api_key.strip():
        return VTResult(
            url=url,
            status_label="Not configured",
            positives=None,
            total=None,
            permalink=None,
            raw_message="VirusTotal API key missing in config",
        )

    params = {"apikey": api_key.strip(), "resource": url}
    try:
        r = requests.get(VT_URL, params=params, timeout=timeout)
        r.raise_for_status()
        data = r.json()
    except requests.RequestException as e:
        logger.warning("VirusTotal request failed for %s: %s", url, e)
        return VTResult(
            url=url,
            status_label="Error",
            positives=None,
            total=None,
            permalink=None,
            raw_message=str(e),
        )
    except ValueError as e:
        return VTResult(
            url=url,
            status_label="Error",
            positives=None,
            total=None,
            permalink=None,
            raw_message=f"Invalid JSON: {e}",
        )

    rc = data.get("response_code")
    if rc == 0:
        return VTResult(
            url=url,
            status_label="Unknown",
            positives=None,
            total=None,
            permalink=data.get("permalink"),
            raw_message="URL not in VirusTotal database (run manual scan in VT UI or use v3 submit)",
        )

    positives = data.get("positives")
    total = data.get("total")
    permalink = data.get("permalink")

    if positives is None or total is None:
        label = "Unknown"
    elif positives == 0:
        label = "Clean"
    elif positives <= 2:
        label = "Suspicious"
    else:
        label = "Malicious"

    return VTResult(
        url=url,
        status_label=label,
        positives=int(positives) if positives is not None else None,
        total=int(total) if total is not None else None,
        permalink=permalink,
        raw_message=None,
    )


def check_urls_throttled(
    api_key: str,
    urls: list[str],
    *,
    delay_seconds: float = 15.0,
    timeout: int = 20,
) -> list[VTResult]:
    """
    Sequential checks with delay to respect VT free-tier rate limits (~4/min).
    No delay when the API key is missing (local-only placeholder results).
    """
    out: list[VTResult] = []
    key_ok = bool(api_key and api_key.strip())
    for i, u in enumerate(urls):
        if key_ok and i > 0:
            time.sleep(delay_seconds)
        out.append(check_url(api_key, u, timeout=timeout))
    return out
