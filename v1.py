import asyncio
import json
import os
import re
import socket
import sys
import time
from dataclasses import dataclass, asdict
from ipaddress import ip_address
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple, Callable
from urllib.parse import urljoin

import aiohttp
from aiohttp_socks import ProxyConnector
from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text


# =============================
# Configuration (defaults)
# =============================

DEFAULT_DEBUG = False

# Scraping
DEFAULT_MAX_PROXIES_PER_SOURCE = 100000
DEFAULT_SCRAPE_TIMEOUT = 120.0
DEFAULT_SCRAPE_CONNECT_TIMEOUT = 10.0
DEFAULT_SCRAPE_PROXY = ""
DEFAULT_SCRAPE_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"
)

# Checking
DEFAULT_CHECK_URL = "https://api.ipify.org?format=json"
DEFAULT_MAX_CONCURRENT_CHECKS = 1024
DEFAULT_CHECK_TIMEOUT = 60.0
DEFAULT_CHECK_CONNECT_TIMEOUT = 5.0
DEFAULT_CHECK_USER_AGENT = DEFAULT_SCRAPE_USER_AGENT
DEFAULT_ALLOW_INSECURE_SSL = True

# Output
DEFAULT_OUTPUT_PATH = Path("./out")
DEFAULT_SORT_BY_SPEED = True
DEFAULT_OUTPUT_TXT = True
DEFAULT_OUTPUT_JSON = True
DEFAULT_INCLUDE_ASN = True
DEFAULT_INCLUDE_GEO = True


# =============================
# Sources (merged from prompt + repo)
# =============================

HTTP_SOURCES = [
    # From prompt
    "https://api.proxyscrape.com/v3/free-proxy-list/get?request=getproxies&protocol=http",
    "https://api.proxyscrape.com/v3/free-proxy-list/get?request=getproxies&protocol=https",
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all",
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",
    "https://api.proxyscrape.com/v4/free-proxy-list/get?request=displayproxies&timeout=8000&country=all&ssl=all&anonymity=all",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/http/data.txt",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/https/data.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/refs/heads/main/HTTPS_RAW.txt",
    "https://raw.githubusercontent.com/sunny9577/proxy-scraper/refs/heads/master/generated/http_proxies.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/refs/heads/master/http.txt",
    # From repo
    "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/refs/heads/main/http_proxies.txt",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/http/data.txt",
    "https://raw.githubusercontent.com/ClearProxy/checked-proxy-list/refs/heads/main/http/raw/all.txt",
    "https://raw.githubusercontent.com/databay-labs/free-proxy-list/refs/heads/master/http.txt",
    "https://raw.githubusercontent.com/zloi-user/hideip.me/refs/heads/master/http.txt",
    "https://raw.githubusercontent.com/vmheaven/VMHeaven-Free-Proxy-Updated/refs/heads/main/http.txt",
    "https://xcoder.fun/p.php?r=y",
    "https://spys.me/proxy.txt",
    # From ProxyGather
    "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/proxylist.txt",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.txt",
    "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/all/data.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/all.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://github.com/zloi-user/hideip.me/raw/refs/heads/master/http.txt",
    "https://github.com/zloi-user/hideip.me/raw/refs/heads/master/https.txt",
    "https://github.com/zloi-user/hideip.me/raw/refs/heads/master/connect.txt",
    "https://raw.githubusercontent.com/ymyuuu/IPDB/refs/heads/main/BestProxy/proxy.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/refs/heads/main/online-proxies/txt/proxies.txt",
    "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/refs/heads/master/http.txt",
    "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/refs/heads/master/https.txt",
    "https://raw.githubusercontent.com/officialputuid/KangProxy/refs/heads/KangProxy/xResults/RAW.txt",
    "https://www.proxy-list.download/api/v2/get?l=en&t=http",
    "https://www.proxy-list.download/api/v2/get?l=en&t=https",
    "https://static.fatezero.org/tmp/proxy.txt",
    "http://pubproxy.com/api/proxy?limit=5&level=elite&last_check=10&speed=1&https=true&format=txt",
    "https://freeproxyupdate.com/files/txt/http.txt",
    "https://freeproxyupdate.com/files/txt/https-ssl.txt",
    "https://freeproxyupdate.com/files/txt/elite.txt",
    "https://freeproxyupdate.com/files/txt/anonymous.txt",
    "https://freeproxyupdate.com/files/txt/transparent.txt",
    "https://ab57.ru/downloads/proxyold.txt",
    "https://ab57.ru/downloads/proxylist.txt",
    # From C++ ProxyScraper
    "https://api.openproxylist.xyz/http.txt",
    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
    "https://raw.githubusercontent.com/proxy4parsing/proxy-list/main/http.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-https.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/archive/txt/proxies-https.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/archive/txt/proxies-http.txt",
    "https://www.proxy-list.download/api/v1/get?type=http",
    "https://www.proxy-list.download/api/v1/get?type=https",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    # From JavaScript proxy scraper
    "https://openproxy.space/list/http",
    "https://proxyspace.pro/http.txt",
    "https://rootjazz.com/proxies/proxies.txt",
    "https://proxyhub.me/en/all-http-proxy-list.html",
    "https://proxy-tools.com/proxy/http",
    "https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc&protocols=https",
    "https://cdn.jsdelivr.net/gh/aslisk/proxyhttps/https.txt",
    "https://cdn.jsdelivr.net/gh/clarketm/proxy-list/proxy-list-raw.txt",
    "https://cdn.jsdelivr.net/gh/hendrikbgr/Free-Proxy-Repo/proxy_list.txt",
    "https://cdn.jsdelivr.net/gh/jetkai/proxy-list/online-proxies/txt/proxies-http.txt",
    "https://cdn.jsdelivr.net/gh/mmpx12/proxy-list/https.txt",
    "https://cdn.jsdelivr.net/gh/roosterkid/openproxylist/HTTPS_RAW.txt",
    "https://cdn.jsdelivr.net/gh/ShiftyTR/Proxy-List/https.txt",
    "https://cdn.jsdelivr.net/gh/sunny9577/proxy-scraper/proxies.txt",
]

HTTPS_SOURCES = [
    # From prompt
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/https/data.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/refs/heads/main/HTTPS_RAW.txt",
    "https://raw.githubusercontent.com/sunny9577/proxy-scraper/refs/heads/master/generated/http_proxies.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/refs/heads/master/http.txt",
    # From repo
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/https/data.txt",
    "https://raw.githubusercontent.com/databay-labs/free-proxy-list/refs/heads/master/https.txt",
    "https://raw.githubusercontent.com/r00tee/Proxy-List/refs/heads/main/Https.txt",
    "https://raw.githubusercontent.com/zloi-user/hideip.me/refs/heads/master/https.txt",
    "https://raw.githubusercontent.com/vmheaven/VMHeaven-Free-Proxy-Updated/refs/heads/main/https.txt",
    "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/https/https.txt",
    "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.txt",
]

SOCKS4_SOURCES = [
    # From prompt
    "https://api.proxyscrape.com/v3/free-proxy-list/get?request=getproxies&protocol=socks4",
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks4&timeout=10000&country=all",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/socks4/data.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/refs/heads/main/SOCKS4_RAW.txt",
    "https://raw.githubusercontent.com/sunny9577/proxy-scraper/refs/heads/master/generated/socks4_proxies.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/refs/heads/master/socks4.txt",
    # From repo
    "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/refs/heads/main/socks4_proxies.txt",
    "https://raw.githubusercontent.com/ClearProxy/checked-proxy-list/refs/heads/main/socks4/raw/all.txt",
    "https://raw.githubusercontent.com/r00tee/Proxy-List/refs/heads/main/Socks4.txt",
    "https://raw.githubusercontent.com/zloi-user/hideip.me/refs/heads/master/socks4.txt",
    "https://raw.githubusercontent.com/vmheaven/VMHeaven-Free-Proxy-Updated/refs/heads/main/socks4.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt",
    "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/socks4/socks4.txt",
    "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks4/data.txt",
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt",
    # From ProxyGather
    "https://github.com/zloi-user/hideip.me/raw/refs/heads/master/socks4.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4.txt",
    "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/refs/heads/master/socks4.txt",
    "https://www.proxy-list.download/api/v2/get?l=en&t=socks4",
    "https://freeproxyupdate.com/files/txt/socks4.txt",
    # From C++ ProxyScraper
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
    "https://api.openproxylist.xyz/socks4.txt",
    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks4.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt",
    "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/socks4.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt",
    "https://www.proxy-list.download/api/v1/get?type=socks4",
    # From JavaScript proxy scraper
    "https://openproxy.space/list/socks4",
    "https://proxyspace.pro/socks4.txt",
    "https://proxyhub.me/en/all-socks4-proxy-list.html",
    "https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc&protocols=socks4",
    "https://www.my-proxy.com/free-socks-4-proxy.html",
    "https://cdn.jsdelivr.net/gh/B4RC0DE-TM/proxy-list/SOCKS4.txt",
    "https://cdn.jsdelivr.net/gh/jetkai/proxy-list/online-proxies/txt/proxies-socks4.txt",
    "https://cdn.jsdelivr.net/gh/roosterkid/openproxylist/SOCKS4_RAW.txt",
    "https://cdn.jsdelivr.net/gh/TheSpeedX/PROXY-List/socks4.txt",
]

SOCKS5_SOURCES = [
    # From prompt
    "https://api.proxyscrape.com/v3/free-proxy-list/get?request=getproxies&protocol=socks5",
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=10000&country=all",
    "https://raw.githubusercontent.com/hookzof/socks5_list/refs/heads/master/proxy.txt",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/socks5/data.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/refs/heads/main/SOCKS5_RAW.txt",
    "https://raw.githubusercontent.com/sunny9577/proxy-scraper/refs/heads/master/generated/socks5_proxies.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/refs/heads/master/socks5.txt",
    # From repo
    "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/refs/heads/main/socks5_proxies.txt",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/socks5/data.txt",
    "https://raw.githubusercontent.com/ClearProxy/checked-proxy-list/refs/heads/main/socks5/raw/all.txt",
    "https://raw.githubusercontent.com/databay-labs/free-proxy-list/refs/heads/master/socks5.txt",
    "https://raw.githubusercontent.com/r00tee/Proxy-List/refs/heads/main/Socks5.txt",
    "https://raw.githubusercontent.com/zloi-user/hideip.me/refs/heads/master/socks5.txt",
    "https://raw.githubusercontent.com/vmheaven/VMHeaven-Free-Proxy-Updated/refs/heads/main/socks5.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
    "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt",
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/tg/socks.json",
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
    "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&proxytype=socks5",
    # From ProxyGather
    "https://github.com/zloi-user/hideip.me/raw/refs/heads/master/socks5.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5.txt",
    "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/refs/heads/master/socks5.txt",
    "https://www.proxy-list.download/api/v2/get?l=en&t=socks5",
    "https://spys.me/socks.txt",
    "https://freeproxyupdate.com/files/txt/socks5.txt",
    # From C++ ProxyScraper
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "https://api.openproxylist.xyz/socks5.txt",
    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt",
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
    "https://www.proxy-list.download/api/v1/get?type=socks5",
    # From JavaScript proxy scraper
    "https://openproxy.space/list/socks5",
    "https://proxyspace.pro/socks5.txt",
    "https://proxy-tools.com/proxy/socks5",
    "https://proxyhub.me/en/all-sock5-proxy-list.html",
    "https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc&protocols=socks5",
    "https://cdn.jsdelivr.net/gh/jetkai/proxy-list/online-proxies/txt/proxies-socks5.txt",
    "https://cdn.jsdelivr.net/gh/mmpx12/proxy-list/socks5.txt",
    "https://cdn.jsdelivr.net/gh/roosterkid/openproxylist/SOCKS5_RAW.txt",
    "https://cdn.jsdelivr.net/gh/TheSpeedX/PROXY-List/socks5.txt",
]


# =============================
# Regex parsing (ported from Rust)
# =============================

PROXY_REGEX = re.compile(
    r"(?:^|[^0-9A-Za-z])"
    r"(?:(?P<protocol>https?|socks[45])://)?"
    r"(?:(?P<username>[0-9A-Za-z]{1,64}):(?P<password>[0-9A-Za-z]{1,64})@)?"
    r"(?P<host>"
    r"(?:[A-Za-z][\-.A-Za-z]{0,251}[A-Za-z]|[A-Za-z]|"
    r"(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
    r"(?:\.(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])){3}"
    r"))"
    r":(?P<port>"
    r"[0-9]|[1-9][0-9]{1,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|"
    r"65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]"
    r")(?=[^0-9A-Za-z]|$)",
    re.IGNORECASE,
)

IPV4_ONLY = re.compile(
    r"^\s*(?P<host>(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
    r"(?:\.(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])){3})"
    r"(?::(?:[0-9]|[1-9][0-9]{1,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|"
    r"65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))?\s*$",
    re.IGNORECASE,
)


def parse_ipv4(line: str) -> Optional[str]:
    m = IPV4_ONLY.match(line)
    if not m:
        return None
    return m.group("host")


@dataclass(frozen=True)
class Proxy:
    protocol: str
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None
    source: Optional[str] = None
    rtt_ms: Optional[float] = None

    def key(self) -> str:
        auth = f"{self.username}:{self.password}@" if self.username and self.password else ""
        return f"{self.protocol}://{auth}{self.host}:{self.port}"

    def addr(self) -> str:
        return f"{self.host}:{self.port}"


def normalize_protocol(p: Optional[str], expected: str) -> str:
    if not p:
        return expected
    p = p.lower()
    if p == "https":
        return "https"
    if p == "http":
        return "http"
    if p.startswith("socks4"):
        return "socks4"
    if p.startswith("socks5"):
        return "socks5"
    return expected


def extract_proxies_from_text(text: str, expected_protocol: str, source: str) -> List[Proxy]:
    found: List[Proxy] = []
    
    # Try parsing as JSON first
    try:
        data = json.loads(text)
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    ip = item.get("ip") or item.get("host") or item.get("address")
                    port = item.get("port")
                    proto = item.get("protocol") or item.get("type")
                    if ip and port:
                        try:
                            proto = normalize_protocol(proto, expected_protocol)
                            found.append(Proxy(proto, str(ip), int(port), None, None, source))
                        except (ValueError, TypeError):
                            continue
                elif isinstance(item, str):
                    # JSON array of strings like ["ip:port", ...]
                    for m in PROXY_REGEX.finditer(item):
                        proto = normalize_protocol(m.group("protocol"), expected_protocol)
                        host = m.group("host")
                        port = int(m.group("port"))
                        username = m.group("username")
                        password = m.group("password")
                        found.append(Proxy(proto, host, port, username, password, source))
        if found:
            return found
    except (json.JSONDecodeError, ValueError, TypeError):
        pass
    
    # Standard regex parsing for text content
    for m in PROXY_REGEX.finditer(text):
        proto = normalize_protocol(m.group("protocol"), expected_protocol)
        host = m.group("host")
        port = int(m.group("port"))
        username = m.group("username")
        password = m.group("password")
        found.append(Proxy(proto, host, port, username, password, source))
    return found


PLAIN_PROXY_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}:[0-9]{2,5}\b")


def extract_plain_ipports(text: str, expected_protocol: str, source: str) -> List[Proxy]:
    found: List[Proxy] = []
    for m in PLAIN_PROXY_REGEX.finditer(text):
        host, port_s = m.group(0).split(":", 1)
        try:
            port = int(port_s)
        except ValueError:
            continue
        found.append(Proxy(expected_protocol, host, port, None, None, source))
    return found


# =============================
# Networking helpers
# =============================

def _make_timeout(total: float, connect: float) -> aiohttp.ClientTimeout:
    return aiohttp.ClientTimeout(total=total, connect=connect)


async def fetch_one(
    session: aiohttp.ClientSession,
    url: str,
    expected_protocol: str,
    max_take: int,
    debug: bool,
) -> Tuple[str, List[Proxy]]:
    text = ""
    try:
        # Local file source support
        if url.startswith("file://"):
            path = url[len("file://"):]
            text = Path(path).read_text(encoding="utf-8", errors="ignore")
        elif (url.startswith("/") or re.match(r"^[A-Za-z]:\\", url) or re.match(r"^[A-Za-z]:/", url)) and Path(url).exists():
            text = Path(url).read_text(encoding="utf-8", errors="ignore")
        else:
            # Increased timeout for slower sources
            async with session.get(url, timeout=_make_timeout(60, 10)) as resp:
                text = await resp.text(errors="ignore")
    except Exception:
        if debug:
            console.print(f"[yellow]Fetch failed[/yellow]: {url}")
        return url, []

    proxies = extract_proxies_from_text(text, expected_protocol, url)
    if max_take > 0:
        proxies = proxies[:max_take]
    return url, proxies


async def fetch_sources(
    http_urls: List[str],
    https_urls: List[str],
    socks4_urls: List[str],
    socks5_urls: List[str],
    *,
    timeout_total: float,
    timeout_connect: float,
    user_agent: str,
    upstream_proxy: str,
    max_per_source: int,
    debug: bool,
) -> List[Proxy]:
    headers = {"User-Agent": user_agent}
    proxy_arg = upstream_proxy if upstream_proxy else None

    async with aiohttp.ClientSession(headers=headers, timeout=_make_timeout(timeout_total, timeout_connect)) as session:
        tasks = []
        for u in http_urls:
            tasks.append(fetch_one(session, u, "http", max_per_source, debug))
        for u in https_urls:
            tasks.append(fetch_one(session, u, "https", max_per_source, debug))
        for u in socks4_urls:
            tasks.append(fetch_one(session, u, "socks4", max_per_source, debug))
        for u in socks5_urls:
            tasks.append(fetch_one(session, u, "socks5", max_per_source, debug))

        results: List[Proxy] = []
        # Apply upstream proxy dynamically by using a request-level proxy via context if provided
        if proxy_arg:
            # Re-run with per-request proxy by monkey-patching session.get
            async def get_with_proxy(url: str):
                try:
                    async with session.get(url, proxy=proxy_arg) as resp:
                        return await resp.text(errors="ignore")
                except Exception:
                    return ""

            async def fetch_one_with_proxy(url: str, expected_protocol: str) -> Tuple[str, List[Proxy]]:
                text = await get_with_proxy(url)
                proxies = extract_proxies_from_text(text, expected_protocol, url)
                if max_per_source > 0:
                    proxies = proxies[:max_per_source]
                return url, proxies

            tasks = []
            for u in http_urls:
                tasks.append(fetch_one_with_proxy(u, "http"))
            for u in https_urls:
                tasks.append(fetch_one_with_proxy(u, "https"))
            for u in socks4_urls:
                tasks.append(fetch_one_with_proxy(u, "socks4"))
            for u in socks5_urls:
                tasks.append(fetch_one_with_proxy(u, "socks5"))

        for coro in asyncio.as_completed(tasks):
            try:
                _, items = await coro
                results.extend(items)
            except Exception:
                if debug:
                    pass
        return results


async def _fetch_text(session: aiohttp.ClientSession, url: str) -> str:
    try:
        async with session.get(url) as resp:
            return await resp.text(errors="ignore")
    except Exception:
        return ""


def _extract_links(html: str, base: str) -> List[str]:
    links: List[str] = []
    for href in re.findall(r"href=[\"']([^\"'#]+)[\"']", html, flags=re.IGNORECASE):
        try:
            links.append(urljoin(base, href))
        except Exception:
            continue
    return links


async def crawl_general_pages(
    pages: List[str],
    *,
    expected_protocol: str,
    depth: int,
    max_pages: int,
    timeout_total: float,
    timeout_connect: float,
    user_agent: str,
) -> List[Proxy]:
    headers = {"User-Agent": user_agent}
    timeout = _make_timeout(timeout_total, timeout_connect)
    visited: Set[str] = set()
    queue: List[Tuple[str, int]] = [(p, 0) for p in pages]
    out: List[Proxy] = []

    async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
        while queue and (max_pages <= 0 or len(visited) < max_pages):
            url, d = queue.pop(0)
            if url in visited:
                continue
            visited.add(url)
            html = await _fetch_text(session, url)
            if not html:
                continue
            out.extend(extract_plain_ipports(html, expected_protocol, url))
            out.extend(extract_proxies_from_text(html, expected_protocol, url))
            if d < depth:
                for link in _extract_links(html, url):
                    if link not in visited:
                        queue.append((link, d + 1))
    return out


async def check_one_http(
    proxy: Proxy,
    session: aiohttp.ClientSession,
    check_url: str,
    allow_insecure: bool,
) -> Optional[Proxy]:
    proxy_url = f"http://{proxy.addr()}"
    t0 = time.perf_counter()
    try:
        async with session.get(check_url, proxy=proxy_url, ssl=not allow_insecure) as resp:
            if resp.status == 200:
                body = await resp.text()
                rtt = (time.perf_counter() - t0) * 1000.0
                # Parse JSON response and validate IP
                try:
                    data = json.loads(body)
                    returned_ip = data.get("ip", "")
                    if returned_ip == proxy.host:
                        return Proxy(proxy.protocol, proxy.host, proxy.port, proxy.username, proxy.password, proxy.source, rtt)
                except (json.JSONDecodeError, KeyError):
                    return None
    except Exception:
        return None
    return None


async def check_one_socks(
    proxy: Proxy,
    check_url: str,
    timeout_total: float,
    timeout_connect: float,
    user_agent: str,
    allow_insecure: bool,
) -> Optional[Proxy]:
    scheme = "socks5" if proxy.protocol == "socks5" else "socks4"
    connector = ProxyConnector.from_url(f"{scheme}://{proxy.addr()}")
    headers = {"User-Agent": user_agent}
    t0 = time.perf_counter()
    try:
        async with aiohttp.ClientSession(connector=connector, headers=headers, timeout=_make_timeout(timeout_total, timeout_connect)) as session:
            async with session.get(check_url, ssl=not allow_insecure) as resp:
                if resp.status == 200:
                    body = await resp.text()
                    rtt = (time.perf_counter() - t0) * 1000.0
                    # Parse JSON response and validate IP
                    try:
                        data = json.loads(body)
                        returned_ip = data.get("ip", "")
                        if returned_ip == proxy.host:
                            return Proxy(proxy.protocol, proxy.host, proxy.port, proxy.username, proxy.password, proxy.source, rtt)
                    except (json.JSONDecodeError, KeyError):
                        return None
    except Exception:
        return None
    return None


def ip_key(p: Proxy) -> Tuple[int, str, int]:
    return (0 if p.protocol == "http" else 1 if p.protocol == "https" else 2 if p.protocol == "socks4" else 3, p.host, p.port)


def speed_key(p: Proxy) -> float:
    return p.rtt_ms if p.rtt_ms is not None else float("inf")


def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def save_txt(outdir: Path, grouped: Dict[str, List[Proxy]]) -> None:
    ensure_dir(outdir)
    all_lines: List[str] = []
    for proto, items in grouped.items():
        lines = [f"{x.addr()}" for x in items]
        (outdir / f"{proto}.txt").write_text("\n".join(lines), encoding="utf-8")
        all_lines.extend(lines)
    (outdir / "all.txt").write_text("\n".join(all_lines), encoding="utf-8")


def try_load_geo_readers() -> Tuple[Optional[object], Optional[object]]:
    try:
        from geoip2.database import Reader  # type: ignore
    except Exception:
        return None, None

    candidates = [
        Path("GeoLite2-ASN.mmdb"),
        Path("./geo/GeoLite2-ASN.mmdb"),
        Path(os.environ.get("GEOIP_ASN_DB", "")),
    ]
    asn_path = next((p for p in candidates if p and isinstance(p, Path) and p.exists()), None)

    candidates = [
        Path("GeoLite2-City.mmdb"),
        Path("./geo/GeoLite2-City.mmdb"),
        Path(os.environ.get("GEOIP_CITY_DB", "")),
    ]
    city_path = next((p for p in candidates if p and isinstance(p, Path) and p.exists()), None)

    asn_reader = Reader(str(asn_path)) if asn_path else None
    city_reader = Reader(str(city_path)) if city_path else None
    return asn_reader, city_reader


def enrich_geo(p: Proxy, asn_reader, city_reader) -> Dict:
    data = asdict(p)
    # Only try on IPv4 numeric hosts
    try:
        ip_address(p.host)
    except Exception:
        return data

    if asn_reader:
        try:
            r = asn_reader.asn(p.host)  # type: ignore[attr-defined]
            data["asn"] = {"number": r.autonomous_system_number, "org": r.autonomous_system_organization}
        except Exception:
            pass
    if city_reader:
        try:
            r = city_reader.city(p.host)  # type: ignore[attr-defined]
            data["geo"] = {
                "country": getattr(r.country, "iso_code", None),
                "city": getattr(r.city, "name", None),
                "lat": getattr(r.location, "latitude", None),
                "lon": getattr(r.location, "longitude", None),
            }
        except Exception:
            pass
    return data


def save_json(outdir: Path, items: List[Proxy], include_asn: bool, include_geo: bool) -> None:
    ensure_dir(outdir)
    asn_reader = None
    city_reader = None
    if include_asn or include_geo:
        asn_reader, city_reader = try_load_geo_readers()

    by_proto: Dict[str, List[Dict]] = {"http": [], "https": [], "socks4": [], "socks5": []}
    for p in items:
        if include_asn or include_geo:
            data = enrich_geo(p, asn_reader, city_reader)
        else:
            data = asdict(p)
        by_proto[p.protocol].append(data)

    for proto, lst in by_proto.items():
        (outdir / f"{proto}.json").write_text(json.dumps(lst, ensure_ascii=False, indent=2), encoding="utf-8")
    (outdir / "all.json").write_text(json.dumps(sum(by_proto.values(), []), ensure_ascii=False, indent=2), encoding="utf-8")


# =============================
# CLI + UI
# =============================

console = Console()


def header() -> None:
    title = Text("Proxy Scraper • Parser • Checker", style="bold cyan")
    subtitle = Text("Single-file CLI — async & fast", style="dim white")
    msg = Text()
    msg.append(title)
    msg.append("\n")
    msg.append(subtitle)
    msg.justify = "center"
    console.print(
        Panel(Align.center(msg), border_style="bright_blue", box=box.DOUBLE, padding=(1, 2))
    )


def build_argparser():
    import argparse

    p = argparse.ArgumentParser(description="Scrape, parse, check, and save proxies.")
    p.add_argument("--protocols", nargs="*", default=["http", "https", "socks4", "socks5"], choices=["http", "https", "socks4", "socks5"], help="Protocols to scrape/check")
    p.add_argument("--scrape-only", action="store_true", help="Only scrape and parse; skip checking")
    p.add_argument("--check-only", action="store_true", help="Only check already-scraped inputs from --input-file")
    # Scraping
    p.add_argument("--scrape-timeout", type=float, default=DEFAULT_SCRAPE_TIMEOUT)
    p.add_argument("--scrape-connect-timeout", type=float, default=DEFAULT_SCRAPE_CONNECT_TIMEOUT)
    p.add_argument("--scrape-proxy", default=DEFAULT_SCRAPE_PROXY, help="Proxy to use for scraping sources")
    p.add_argument("--scrape-user-agent", default=DEFAULT_SCRAPE_USER_AGENT)
    p.add_argument("--max-proxies-per-source", type=int, default=DEFAULT_MAX_PROXIES_PER_SOURCE)
    # Crawling general pages (like Proxy-Scraper)
    p.add_argument("--crawl-urls-file", default=None, help="Path to a file with general proxy pages (like urls.txt) to crawl")
    p.add_argument("--crawl-url", action="append", default=[], help="Add a general proxy page URL to crawl (repeatable)")
    p.add_argument("--crawl-depth", type=int, default=1, help="Follow links up to this depth from each page")
    p.add_argument("--crawl-max-pages", type=int, default=200, help="Maximum pages to crawl in total (0=unlimited)")
    p.add_argument("--crawl-protocol", default="http", choices=["http", "https"], help="Assumed protocol for crawled IP:port entries")
    p.add_argument("--extra-http", action="append", default=[], help="Extra HTTP source (repeatable; URL or file path)")
    p.add_argument("--extra-https", action="append", default=[], help="Extra HTTPS source (repeatable; URL or file path)")
    p.add_argument("--extra-socks4", action="append", default=[], help="Extra SOCKS4 source (repeatable; URL or file path)")
    p.add_argument("--extra-socks5", action="append", default=[], help="Extra SOCKS5 source (repeatable; URL or file path)")
    p.add_argument("--sources-file", default=None, help="Read additional sources (one per line). Lines can be 'proto,url' or just 'url' (default proto via --sources-file-proto)")
    p.add_argument("--sources-file-proto", default="http", choices=["http", "https", "socks4", "socks5"], help="Default protocol for --sources-file when not specified per line")
    p.add_argument("--input-file", default=None, help="Provide existing proxies to check (one per line; 'protocol://host:port' or 'host:port' assumed http)")
    # Checking
    p.add_argument("--check-url", default=DEFAULT_CHECK_URL)
    p.add_argument("--max-concurrent-checks", type=int, default=DEFAULT_MAX_CONCURRENT_CHECKS)
    p.add_argument("--check-timeout", type=float, default=DEFAULT_CHECK_TIMEOUT)
    p.add_argument("--check-connect-timeout", type=float, default=DEFAULT_CHECK_CONNECT_TIMEOUT)
    p.add_argument("--check-user-agent", default=DEFAULT_CHECK_USER_AGENT)
    p.add_argument("--allow-insecure-ssl", action="store_true", default=DEFAULT_ALLOW_INSECURE_SSL)
    p.add_argument("--retries", type=int, default=1, help="Retries for checking each proxy")
    p.add_argument("--backoff", type=float, default=0.5, help="Backoff (seconds) between retries")
    p.add_argument("--min-rtt-ms", type=float, default=None, help="Keep only proxies with RTT >= this (ms)")
    p.add_argument("--max-rtt-ms", type=float, default=None, help="Keep only proxies with RTT <= this (ms)")
    p.add_argument("--ports", default=None, help="Filter ports; comma-separated list (e.g., 80,443,8080)")
    p.add_argument("--allowlist", default=None, help="Regex to allow hosts (applied before blocklist)")
    p.add_argument("--blocklist", default=None, help="Regex to block hosts")
    p.add_argument("--dedupe-by", default="proto", choices=["proto", "hostport"], help="Dedupe key: by protocol or by host:port only")
    # Output
    p.add_argument("--output", default=str(DEFAULT_OUTPUT_PATH))
    p.add_argument("--sort-by-speed", action="store_true", default=DEFAULT_SORT_BY_SPEED)
    p.add_argument("--sort-by-ip", action="store_true", default=not DEFAULT_SORT_BY_SPEED)
    p.add_argument("--no-txt", action="store_true", default=not DEFAULT_OUTPUT_TXT)
    p.add_argument("--no-json", action="store_true", default=not DEFAULT_OUTPUT_JSON)
    p.add_argument("--include-asn", action="store_true", default=DEFAULT_INCLUDE_ASN)
    p.add_argument("--include-geo", action="store_true", default=DEFAULT_INCLUDE_GEO)
    p.add_argument("--output-format", default="hostport", choices=["hostport", "url"], help="TXT format: 'hostport' or full 'protocol://host:port'")
    p.add_argument("--max-results", type=int, default=0, help="Limit number of saved proxies (0 = unlimited)")
    p.add_argument("--top", type=int, default=0, help="Print top N fastest proxies in the console")
    # Misc
    p.add_argument("--debug", action="store_true", default=DEFAULT_DEBUG)
    p.add_argument("--batch-size", type=int, default=512, help="Check proxies in batches to limit open sockets (Windows-safe default: 512)")
    return p


def build_sources(selected: List[str], args=None) -> Tuple[List[str], List[str], List[str], List[str]]:
    def _dedup(seq: Iterable[str]) -> List[str]:
        seen: Set[str] = set()
        out: List[str] = []
        for x in seq:
            if x and x not in seen:
                out.append(x)
                seen.add(x)
        return out

    http = _dedup(HTTP_SOURCES) if "http" in selected else []
    https = _dedup(HTTPS_SOURCES) if "https" in selected else []
    socks4 = _dedup(SOCKS4_SOURCES) if "socks4" in selected else []
    socks5 = _dedup(SOCKS5_SOURCES) if "socks5" in selected else []

    if args is not None:
        http += args.extra_http or []
        https += args.extra_https or []
        socks4 += args.extra_socks4 or []
        socks5 += args.extra_socks5 or []

        if args.sources_file and Path(str(args.sources_file)).exists():
            for line in Path(str(args.sources_file)).read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "," in line:
                    proto, url = line.split(",", 1)
                    proto = proto.strip().lower()
                    url = url.strip()
                else:
                    proto, url = args.sources_file_proto, line
                if proto == "http":
                    http.append(url)
                elif proto == "https":
                    https.append(url)
                elif proto == "socks4":
                    socks4.append(url)
                elif proto == "socks5":
                    socks5.append(url)

    http = _dedup(http)
    https = _dedup(https)
    socks4 = _dedup(socks4)
    socks5 = _dedup(socks5)
    return http, https, socks4, socks5


def format_line(p: Proxy, fmt: str) -> str:
    if fmt == "url":
        auth = f"{p.username}:{p.password}@" if p.username and p.password else ""
        return f"{p.protocol}://{auth}{p.addr()}"
    return p.addr()


def save_txt_formatted(outdir: Path, grouped: Dict[str, List[Proxy]], fmt: str, limit: int = 0) -> None:
    ensure_dir(outdir)
    all_lines: List[str] = []
    for proto, items in grouped.items():
        subset = items[:limit] if limit > 0 else items
        lines = [format_line(x, fmt) for x in subset]
        (outdir / f"{proto}.txt").write_text("\n".join(lines), encoding="utf-8")
        all_lines.extend(lines)
    (outdir / "all.txt").write_text("\n".join(all_lines), encoding="utf-8")


def save_scraped_txt(outdir: Path, items: List[Proxy], fmt: str) -> None:
    # Save raw scraped (unchecked) proxies by protocol and combined
    ensure_dir(outdir)
    grouped: Dict[str, List[Proxy]] = {"http": [], "https": [], "socks4": [], "socks5": []}
    for p in items:
        grouped[p.protocol].append(p)
    all_lines: List[str] = []
    for proto, lst in grouped.items():
        lines = [format_line(x, fmt) for x in lst]
        (outdir / f"scraped_{proto}.txt").write_text("\n".join(lines), encoding="utf-8")
        all_lines.extend(lines)
    (outdir / "scraped_all.txt").write_text("\n".join(all_lines), encoding="utf-8")


def apply_filters(
    items: List[Proxy],
    *,
    min_rtt: Optional[float],
    max_rtt: Optional[float],
    ports: Optional[Set[int]],
    allow_re: Optional[re.Pattern],
    block_re: Optional[re.Pattern],
    countries_include: Optional[Set[str]] = None,
    countries_exclude: Optional[Set[str]] = None,
) -> List[Proxy]:
    def ok_country(p: Proxy) -> bool:
        if not countries_include and not countries_exclude:
            return True
        # Lazy import to avoid overhead if not needed
        asn_reader, city_reader = try_load_geo_readers()
        if not city_reader:
            # No geo DB available, skip country filters
            return True
        try:
            r = city_reader.city(p.host)  # type: ignore[attr-defined]
            code = getattr(r.country, "iso_code", None)
        except Exception:
            code = None
        if countries_include and (not code or code.upper() not in countries_include):
            return False
        if countries_exclude and code and code.upper() in countries_exclude:
            return False
        return True

    out: List[Proxy] = []
    for x in items:
        if min_rtt is not None and (x.rtt_ms is None or x.rtt_ms < min_rtt):
            continue
        if max_rtt is not None and (x.rtt_ms is None or x.rtt_ms > max_rtt):
            continue
        if ports is not None and x.port not in ports:
            continue
        if allow_re is not None and not allow_re.search(x.host):
            continue
        if block_re is not None and block_re.search(x.host):
            continue
        if not ok_country(x):
            continue
        out.append(x)
    return out


async def run_cli(args) -> int:
    header()

    # Silence noisy Windows Proactor reset callbacks
    if os.name == "nt":
        try:
            loop = asyncio.get_running_loop()
            def _win_reset_silencer(loop, context):
                exc = context.get("exception")
                msg = context.get("message", "")
                if isinstance(exc, ConnectionResetError):
                    # Drop known harmless socket reset noise
                    return
                loop.default_exception_handler(context)
            loop.set_exception_handler(_win_reset_silencer)
        except Exception:
            pass

    http_urls, https_urls, socks4_urls, socks5_urls = build_sources(args.protocols, args)

    info = Table(show_header=False, box=None, padding=(0, 1))
    info.add_column(style="cyan")
    info.add_column(style="white")
    info.add_row("Protocols:", ", ".join([p.upper() for p in args.protocols]))
    info.add_row("Sources:", str(len(http_urls) + len(https_urls) + len(socks4_urls) + len(socks5_urls)))
    info.add_row("Concurrency:", str(args.max_concurrent_checks))
    info.add_row("Check URL:", args.check_url or "(skipped)")
    console.print(Panel(info, border_style="blue", title="Configuration", padding=(1, 2)))

    start = time.time()
    # Clear old outputs
    outdir = Path(args.output)
    ensure_dir(outdir)
    for fname in [
        "all.txt", "http.txt", "https.txt", "socks4.txt", "socks5.txt",
        "scraped_all.txt", "scraped_http.txt", "scraped_https.txt", "scraped_socks4.txt", "scraped_socks5.txt",
        "all.json", "http.json", "https.json", "socks4.json", "socks5.json",
    ]:
        fpath = outdir / fname
        if fpath.exists():
            try:
                fpath.unlink()
            except Exception:
                pass
    scraped: List[Proxy] = []
    if not args.check_only:
        with console.status("[bold blue]Scraping sources...", spinner="dots12"):
            scraped = await fetch_sources(
                http_urls,
                https_urls,
                socks4_urls,
                socks5_urls,
                timeout_total=args.scrape_timeout,
                timeout_connect=args.scrape_connect_timeout,
                user_agent=args.scrape_user_agent,
                upstream_proxy=args.scrape_proxy,
                max_per_source=args.max_proxies_per_source,
                debug=args.debug,
            )

    # Optional: crawl general pages (Proxy-Scraper style)
    crawl_pages: List[str] = []
    if args.crawl_urls_file and Path(str(args.crawl_urls_file)).exists():
        crawl_pages.extend([
            line.strip() for line in Path(str(args.crawl_urls_file)).read_text(encoding="utf-8", errors="ignore").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ])
    crawl_pages.extend(args.crawl_url or [])
    crawl_pages = list(dict.fromkeys(crawl_pages))

    if crawl_pages and not args.check_only:
        with console.status("[bold blue]Crawling general proxy pages...", spinner="dots12"):
            crawled = await crawl_general_pages(
                crawl_pages,
                expected_protocol=args.crawl_protocol,
                depth=max(0, args.crawl_depth),
                max_pages=max(0, args.crawl_max_pages),
                timeout_total=args.scrape_timeout,
                timeout_connect=args.scrape_connect_timeout,
                user_agent=args.scrape_user_agent,
            )
        scraped.extend(crawled)

    # De-duplicate by protocol://host:port
    unique: Dict[str, Proxy] = {}

    def k(p: Proxy) -> str:
        return p.key() if args.dedupe_by == "proto" else f"{p.host}:{p.port}"

    for p in scraped:
        unique[k(p)] = p

    # If check-only, load from input file
    if args.check_only:
        if not args.input_file or not Path(str(args.input_file)).exists():
            console.print("[red]--check-only requires --input-file that exists[/red]")
            return 2
        raw = Path(str(args.input_file)).read_text(encoding="utf-8", errors="ignore").splitlines()
        for line in raw:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            proto = None
            host = None
            port = None
            if "://" in s:
                try:
                    proto, rest = s.split("://", 1)
                    if "@" in rest:
                        auth, hp = rest.split("@", 1)
                        # ignore auth in input for now
                        s2 = hp
                    else:
                        s2 = rest
                    host, port_s = s2.rsplit(":", 1)
                    port = int(port_s)
                except Exception:
                    continue
            else:
                try:
                    host, port_s = s.rsplit(":", 1)
                    port = int(port_s)
                except Exception:
                    continue
            proto = normalize_protocol(proto, "http")
            p = Proxy(proto, host, port, None, None, "input")
            unique[k(p)] = p

    all_proxies = list(unique.values())

    console.print(f"[green]✓[/green] Scraped [cyan]{len(all_proxies):,}[/cyan] proxies")

    # Save scraped immediately (unchecked)
    save_scraped_txt(outdir, all_proxies, fmt=args.output_format)

    if args.scrape_only or not args.check_url:
        console.print("[yellow]Skipping checking — no check URL provided[/yellow]")
        checked: List[Proxy] = all_proxies
    else:
        # On Windows, select()-based limits can cause 'too many file descriptors'.
        # Clamp concurrency conservatively and process in batches.
        win = (os.name == "nt")
        effective_conc = min(max(1, args.max_concurrent_checks), 512 if win else args.max_concurrent_checks)
        sem = asyncio.Semaphore(effective_conc)
        headers = {"User-Agent": args.check_user_agent}
        timeout = _make_timeout(args.check_timeout, args.check_connect_timeout)
        http_connector = aiohttp.TCPConnector(
            limit=effective_conc,
            limit_per_host=effective_conc,
            ttl_dns_cache=300,
            enable_cleanup_closed=True,
        )

        async def run_checks_with_shared_http_session() -> List[Proxy]:
            results: List[Proxy] = []
            async with aiohttp.ClientSession(headers=headers, timeout=timeout, connector=http_connector) as shared_http_session:
                async def attempt(proxy: Proxy) -> Optional[Proxy]:
                    if proxy.protocol in ("http", "https"):
                        return await check_one_http(proxy, shared_http_session, args.check_url, args.allow_insecure_ssl)
                    else:
                        return await check_one_socks(
                            proxy,
                            args.check_url,
                            args.check_timeout,
                            args.check_connect_timeout,
                            args.check_user_agent,
                            args.allow_insecure_ssl,
                        )

                async def bound_check(proxy: Proxy) -> Optional[Proxy]:
                    async with sem:
                        tries = max(1, args.retries)
                        for i in range(tries):
                            res = await attempt(proxy)
                            if res is not None:
                                return res
                            if i + 1 < tries:
                                await asyncio.sleep(args.backoff)
                        return None

                nonlocal checked
                checked = []
                total = len(all_proxies)
                batch_size = max(1, min(args.batch_size, effective_conc))
                with Progress(
                    SpinnerColumn(style="cyan"),
                    TextColumn("[blue bold]{task.description}"),
                    BarColumn(bar_width=None, style="cyan", complete_style="bright_cyan", finished_style="bright_green"),
                    TextColumn("[blue]{task.percentage:>3.0f}%"),
                    TextColumn("•", style="dim"),
                    TextColumn("[cyan]{task.completed}/{task.total}"),
                    TextColumn("•", style="dim"),
                    TextColumn("[green]✓ {task.fields[alive]} alive"),
                    TimeElapsedColumn(),
                    console=console,
                    transient=False,
                ) as progress:
                    tid = progress.add_task("Checking proxies...", total=total, alive=0)
                    for i in range(0, total, batch_size):
                        batch = all_proxies[i : i + batch_size]
                        tasks = [bound_check(p) for p in batch]
                        for coro in asyncio.as_completed(tasks):
                            try:
                                res = await coro
                                if res is not None:
                                    checked.append(res)
                                    progress.update(tid, advance=1, alive=len(checked))
                                else:
                                    progress.update(tid, advance=1)
                            except Exception:
                                progress.update(tid, advance=1)
                return checked

        checked: List[Proxy] = await run_checks_with_shared_http_session()

    # Optional filtering
    ports_set = set(int(x) for x in args.ports.split(",")) if args.ports else None
    allow_re = re.compile(args.allowlist) if args.allowlist else None
    block_re = re.compile(args.blocklist) if args.blocklist else None
    checked = apply_filters(
        checked,
        min_rtt=args.min_rtt_ms,
        max_rtt=args.max_rtt_ms,
        ports=ports_set,
        allow_re=allow_re,
        block_re=block_re,
    )

    # Sorting
    if args.sort_by_speed and any(p.rtt_ms is not None for p in checked):
        checked.sort(key=speed_key)
    else:
        checked.sort(key=ip_key)

    # Group by protocol
    grouped: Dict[str, List[Proxy]] = {"http": [], "https": [], "socks4": [], "socks5": []}
    for p in checked:
        grouped[p.protocol].append(p)

    elapsed = time.time() - start
    stats = Table(box=box.SIMPLE, show_header=False, padding=(0, 3))
    stats.add_column(style="cyan bold", width=22)
    stats.add_column(style="white", justify="right")
    stats.add_row("Total scraped", f"{len(all_proxies):,}")
    stats.add_row("Alive", f"[green]{len(checked):,}[/green]")
    stats.add_row("Elapsed", f"{elapsed:.1f}s")
    if elapsed > 0:
        stats.add_row("Checks/sec", f"{(len(all_proxies)/elapsed):.0f}")
    console.print(Panel(stats, border_style="bright_blue", title="Results", padding=(1, 2)))

    if not args.no_txt:
        save_txt_formatted(outdir, grouped, fmt=args.output_format, limit=args.max_results)
    if not args.no_json:
        items_to_save = checked[: args.max_results] if args.max_results > 0 else checked
        save_json(outdir, items_to_save, include_asn=args.include_asn, include_geo=args.include_geo)

    if args.top and checked:
        preview = Table(title="Top Fastest", show_header=True, header_style="bold magenta")
        preview.add_column("Protocol", style="cyan")
        preview.add_column("Address", style="white")
        preview.add_column("RTT (ms)", justify="right", style="green")
        for p in checked[: args.top]:
            preview.add_row(p.protocol, p.addr(), f"{p.rtt_ms:.1f}" if p.rtt_ms is not None else "-")
        console.print(preview)

    msg = Text()
    msg.append("✓ ", style="green bold")
    msg.append("Saved outputs to ", style="white")
    msg.append(str(outdir.resolve()), style="cyan bold")
    console.print(Panel(Align.center(msg), border_style="bright_green", title="Done", padding=(1, 2)))
    return 0


def main() -> int:
    parser = build_argparser()
    args = parser.parse_args()
    try:
        return asyncio.run(run_cli(args))
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted[/yellow]")
        return 130
    except Exception as e:
        console.print(Panel(f"[red]{e}", border_style="red", title="Crash"))
        return 1


if __name__ == "__main__":
    sys.exit(main())