"""
Resolve host to IP and fetch geolocation/ISP from ip-api.com (no key for non-commercial).
"""

from __future__ import annotations

import logging
import socket
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

IP_API = "http://ip-api.com/json/{ip}"


@dataclass
class IPInfoResult:
    host: str
    ip: str | None
    country: str | None
    isp: str | None
    org: str | None
    error: str | None


def _hostname_from_url(url: str) -> str:
    p = urlparse(url)
    host = p.netloc or p.path
    if "@" in host:
        host = host.split("@")[-1]
    if ":" in host and not host.startswith("["):
        # strip port
        host = host.rsplit(":", 1)[0]
    return host.strip().lower()


def resolve_ip(hostname: str) -> str | None:
    try:
        return socket.gethostbyname(hostname)
    except OSError as e:
        logger.debug("DNS resolve failed for %s: %s", hostname, e)
        return None


def fetch_ip_info(target_url: str, *, timeout: int = 10) -> IPInfoResult:
    host = _hostname_from_url(target_url)
    if not host:
        return IPInfoResult(
            host="",
            ip=None,
            country=None,
            isp=None,
            org=None,
            error="Could not parse hostname from URL",
        )

    ip = resolve_ip(host)
    if not ip:
        return IPInfoResult(
            host=host,
            ip=None,
            country=None,
            isp=None,
            org=None,
            error="DNS resolution failed",
        )

    url = IP_API.format(ip=ip)
    params = {"fields": "status,message,country,isp,org,query,hosting"}
    try:
        r = requests.get(url, params=params, timeout=timeout)
        r.raise_for_status()
        data = r.json()
    except requests.RequestException as e:
        return IPInfoResult(
            host=host,
            ip=ip,
            country=None,
            isp=None,
            org=None,
            error=str(e),
        )

    if data.get("status") != "success":
        return IPInfoResult(
            host=host,
            ip=ip,
            country=None,
            isp=None,
            org=None,
            error=data.get("message") or "ip-api error",
        )

    return IPInfoResult(
        host=host,
        ip=data.get("query") or ip,
        country=data.get("country"),
        isp=data.get("isp"),
        org=data.get("org"),
        error=None,
    )
