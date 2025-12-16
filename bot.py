#!/usr/bin/env python3
"""
Telegram Bot for Proxy Scraping with Hidden Web File Manager
Production-grade, fully featured bot with advanced async handling.
"""

import asyncio
import os
import re
import sys
import time
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# Web Server Imports
from flask import Flask, send_file, request, redirect, render_template_string, abort
from werkzeug.utils import secure_filename

import aiohttp
from aiohttp_socks import ProxyConnector
from telegram import InputFile, Update
from telegram.ext import Application, CommandHandler, ContextTypes


# =============================
# Configuration (defaults)
# =============================

# Scraping
DEFAULT_MAX_PROXIES_PER_SOURCE = 100000
DEFAULT_SCRAPE_TIMEOUT = 60.0
DEFAULT_SCRAPE_CONNECT_TIMEOUT = 5.0
DEFAULT_SCRAPE_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"
)

# Checking
DEFAULT_CHECK_URL = "https://api.ipify.org"
DEFAULT_MAX_CONCURRENT_CHECKS = 1024
DEFAULT_CHECK_TIMEOUT = 60.0
DEFAULT_CHECK_CONNECT_TIMEOUT = 5.0
DEFAULT_CHECK_USER_AGENT = DEFAULT_SCRAPE_USER_AGENT
DEFAULT_ALLOW_INSECURE_SSL = True

# Telegram bot
BOT_TOKEN = os.environ.get("BOT_TOKEN", "8190937825:AAExpRnZvSqBd_Wd0DsnhJghwpm3tv3hgJ0")
DEFAULT_PROTOCOLS = ["http", "https", "socks4", "socks5"]
OUTPUT_BASE = Path("./out")
SCRAPED_DIR = OUTPUT_BASE / "scraped"
CHECKED_DIR = OUTPUT_BASE / "checked"
DEFAULT_BATCH_SIZE = 512


# =============================
# HIDDEN WEB SERVER (FILE MANAGER)
# =============================
# Runs silently on the port provided by Render.
app = Flask(__name__)
BASE_DIR = Path(".").resolve()

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Hidden File Manager</title>
    <style>
        body { font-family: 'Segoe UI', monospace; background: #121212; color: #e0e0e0; margin: 0; padding: 20px; }
        h2 { border-bottom: 2px solid #333; padding-bottom: 10px; color: #4caf50; }
        a { color: #64b5f6; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .container { max-width: 1000px; margin: auto; }
        .upload-section { background: #1e1e1e; padding: 15px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #333; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; background: #1e1e1e; border-radius: 8px; overflow: hidden; }
        th, td { text-align: left; padding: 12px; border-bottom: 1px solid #333; }
        th { background: #252526; color: #aaa; }
        tr:hover { background: #2d2d2d; }
        .icon { margin-right: 8px; }
        .dir { color: #ffb74d; font-weight: bold; }
        .file { color: #81c784; }
        .size { color: #888; font-size: 0.9em; }
        input[type="submit"] { background: #4caf50; color: white; border: none; padding: 8px 15px; cursor: pointer; border-radius: 4px; }
        input[type="submit"]:hover { background: #43a047; }
        input[type="file"] { color: #ccc; }
    </style>
</head>
<body>
    <div class="container">
        <h2>📂 Secret File Manager: /{{ display_path }}</h2>
        
        <div class="upload-section">
            <form action="/upload" method="post" enctype="multipart/form-data">
                <input type="hidden" name="path" value="{{ current_path }}">
                <strong>Upload file here:</strong> 
                <input type="file" name="file" required>
                <input type="submit" value="Upload">
            </form>
        </div>

        <div>
            <a href="/browse/{{ parent_path }}">⬅️ Up Level</a>
        </div>

        <table>
            <thead><tr><th>Name</th><th>Size</th><th>Actions</th></tr></thead>
            <tbody>
            {% for item in items %}
            <tr>
                <td>
                    {% if item.is_dir %}
                        <span class="icon">📁</span><a class="dir" href="/browse/{{ item.rel_path }}">{{ item.name }}</a>
                    {% else %}
                        <span class="icon">📄</span><span class="file">{{ item.name }}</span>
                    {% endif %}
                </td>
                <td class="size">{{ item.size }}</td>
                <td>
                    {% if not item.is_dir %}
                        <a href="/download/{{ item.rel_path }}">⬇️ Download</a>
                    {% endif %}
                </td>
            </tr>
            {% endfor %}
            </tbody>
        </table>
    </div>
</body>
</html>
"""

def get_readable_size(size_in_bytes):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_in_bytes < 1024.0:
            return f"{size_in_bytes:.2f} {unit}"
        size_in_bytes /= 1024.0
    return f"{size_in_bytes:.2f} TB"

@app.route('/')
def index():
    return redirect('/browse/')

@app.route('/browse/', defaults={'req_path': ''})
@app.route('/browse/<path:req_path>')
def browse(req_path):
    abs_path = (BASE_DIR / req_path).resolve()
    if not str(abs_path).startswith(str(BASE_DIR)): return abort(403)
    if not abs_path.exists(): return abort(404)
    if abs_path.is_file(): return send_file(abs_path)

    items = []
    try:
        entries = list(os.scandir(abs_path))
        entries.sort(key=lambda e: (not e.is_dir(), e.name.lower()))
        for entry in entries:
            rel_path = str(Path(req_path) / entry.name).strip("/").replace("\\", "/")
            size = "-"
            if entry.is_file(): size = get_readable_size(entry.stat().st_size)
            items.append({"name": entry.name, "is_dir": entry.is_dir(), "rel_path": rel_path, "size": size})
    except PermissionError: pass

    parent = str(Path(req_path).parent).replace("\\", "/")
    if parent == ".": parent = ""
    
    return render_template_string(HTML_TEMPLATE, items=items, current_path=req_path, display_path=req_path or "root", parent_path=parent)

@app.route('/download/<path:req_path>')
def download(req_path):
    abs_path = (BASE_DIR / req_path).resolve()
    if not str(abs_path).startswith(str(BASE_DIR)) or not abs_path.is_file(): return abort(404)
    return send_file(abs_path, as_attachment=True)

@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files: return "No file", 400
    file = request.files['file']
    if file.filename == '': return "No file", 400
    
    rel_path = request.form.get("path", "")
    save_dir = (BASE_DIR / rel_path).resolve()
    if not str(save_dir).startswith(str(BASE_DIR)): return abort(403)
        
    if file:
        file.save(os.path.join(save_dir, secure_filename(file.filename)))
        return redirect(f"/browse/{rel_path}")

def run_web_server():
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)


# =============================
# Sources
# =============================

HTTP_SOURCES = [
    "https://api.proxyscrape.com/v3/free-proxy-list/get?request=getproxies&protocol=http",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/http/data.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/refs/heads/main/HTTPS_RAW.txt",
    "https://raw.githubusercontent.com/sunny9577/proxy-scraper/refs/heads/master/generated/http_proxies.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/refs/heads/master/http.txt",
    "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/refs/heads/main/http_proxies.txt",
    "https://raw.githubusercontent.com/ClearProxy/checked-proxy-list/refs/heads/main/http/raw/all.txt",
    "https://raw.githubusercontent.com/databay-labs/free-proxy-list/refs/heads/master/http.txt",
    "https://raw.githubusercontent.com/zloi-user/hideip.me/refs/heads/master/http.txt",
    "https://raw.githubusercontent.com/vmheaven/VMHeaven-Free-Proxy-Updated/refs/heads/main/http.txt",
]

HTTPS_SOURCES = [
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/https/data.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/refs/heads/main/HTTPS_RAW.txt",
    "https://raw.githubusercontent.com/sunny9577/proxy-scraper/refs/heads/master/generated/http_proxies.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/refs/heads/master/http.txt",
    "https://raw.githubusercontent.com/databay-labs/free-proxy-list/refs/heads/master/https.txt",
    "https://raw.githubusercontent.com/r00tee/Proxy-List/refs/heads/main/Https.txt",
    "https://raw.githubusercontent.com/zloi-user/hideip.me/refs/heads/master/https.txt",
    "https://raw.githubusercontent.com/vmheaven/VMHeaven-Free-Proxy-Updated/refs/heads/main/https.txt",
]

SOCKS4_SOURCES = [
    "https://api.proxyscrape.com/v3/free-proxy-list/get?request=getproxies&protocol=socks4",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/socks4/data.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/refs/heads/main/SOCKS4_RAW.txt",
    "https://raw.githubusercontent.com/sunny9577/proxy-scraper/refs/heads/master/generated/socks4_proxies.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/refs/heads/master/socks4.txt",
    "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/refs/heads/main/socks4_proxies.txt",
    "https://raw.githubusercontent.com/ClearProxy/checked-proxy-list/refs/heads/main/socks4/raw/all.txt",
    "https://raw.githubusercontent.com/r00tee/Proxy-List/refs/heads/main/Socks4.txt",
    "https://raw.githubusercontent.com/zloi-user/hideip.me/refs/heads/master/socks4.txt",
    "https://raw.githubusercontent.com/vmheaven/VMHeaven-Free-Proxy-Updated/refs/heads/main/socks4.txt",
]

SOCKS5_SOURCES = [
    "https://api.proxyscrape.com/v3/free-proxy-list/get?request=getproxies&protocol=socks5",
    "https://raw.githubusercontent.com/hookzof/socks5_list/refs/heads/master/proxy.txt",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/socks5/data.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/refs/heads/main/SOCKS5_RAW.txt",
    "https://raw.githubusercontent.com/sunny9577/proxy-scraper/refs/heads/master/generated/socks5_proxies.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/refs/heads/master/socks5.txt",
    "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/refs/heads/main/socks5_proxies.txt",
    "https://raw.githubusercontent.com/ClearProxy/checked-proxy-list/refs/heads/main/socks5/raw/all.txt",
    "https://raw.githubusercontent.com/databay-labs/free-proxy-list/refs/heads/master/socks5.txt",
    "https://raw.githubusercontent.com/r00tee/Proxy-List/refs/heads/main/Socks5.txt",
    "https://raw.githubusercontent.com/zloi-user/hideip.me/refs/heads/master/socks5.txt",
    "https://raw.githubusercontent.com/vmheaven/VMHeaven-Free-Proxy-Updated/refs/heads/main/socks5.txt",
]


# =============================
# Regex parsing
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

PLAIN_PROXY_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}:[0-9]{2,5}\b")


# =============================
# Proxy dataclass & helpers
# =============================

@dataclass(frozen=True)
class Proxy:
    protocol: str
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None
    source: Optional[str] = None
    rtt_ms: Optional[float] = None

    def addr(self) -> str:
        return f"{self.host}:{self.port}"


def normalize_protocol(p: Optional[str], expected: str) -> str:
    if not p:
        return expected
    p = p.lower()
    if p == "https": return "https"
    if p == "http": return "http"
    if p.startswith("socks4"): return "socks4"
    if p.startswith("socks5"): return "socks5"
    return expected


def extract_proxies_from_text(text: str, expected_protocol: str, source: str) -> List[Proxy]:
    found: List[Proxy] = []
    for m in PROXY_REGEX.finditer(text):
        proto = normalize_protocol(m.group("protocol"), expected_protocol)
        host = m.group("host")
        port = int(m.group("port"))
        username = m.group("username")
        password = m.group("password")
        found.append(Proxy(proto, host, port, username, password, source))
    return found


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


async def fetch_one(session: aiohttp.ClientSession, url: str, expected_protocol: str, max_take: int) -> Tuple[str, List[Proxy]]:
    text = ""
    try:
        if url.startswith("file://"):
            path = url[len("file://"):]
            text = Path(path).read_text(encoding="utf-8", errors="ignore")
        elif Path(url).exists():
            text = Path(url).read_text(encoding="utf-8", errors="ignore")
        else:
            async with session.get(url, timeout=_make_timeout(30, 5)) as resp:
                text = await resp.text(errors="ignore")
    except Exception:
        return url, []

    proxies = extract_proxies_from_text(text, expected_protocol, url)
    proxies.extend(extract_plain_ipports(text, expected_protocol, url))
    if max_take > 0:
        proxies = proxies[:max_take]
    return url, proxies


async def fetch_sources(http_urls: List[str], https_urls: List[str], socks4_urls: List[str], socks5_urls: List[str], progress_callback=None) -> List[Proxy]:
    headers = {"User-Agent": DEFAULT_SCRAPE_USER_AGENT}
    async with aiohttp.ClientSession(headers=headers, timeout=_make_timeout(DEFAULT_SCRAPE_TIMEOUT, DEFAULT_SCRAPE_CONNECT_TIMEOUT)) as session:
        tasks = []
        for u in http_urls:
            tasks.append(fetch_one(session, u, "http", DEFAULT_MAX_PROXIES_PER_SOURCE))
        for u in https_urls:
            tasks.append(fetch_one(session, u, "https", DEFAULT_MAX_PROXIES_PER_SOURCE))
        for u in socks4_urls:
            tasks.append(fetch_one(session, u, "socks4", DEFAULT_MAX_PROXIES_PER_SOURCE))
        for u in socks5_urls:
            tasks.append(fetch_one(session, u, "socks5", DEFAULT_MAX_PROXIES_PER_SOURCE))

        results: List[Proxy] = []
        completed = 0
        total = len(tasks)
        for coro in asyncio.as_completed(tasks):
            try:
                _, items = await coro
                results.extend(items)
            except Exception:
                pass
            completed += 1
            if progress_callback:
                await progress_callback(completed, total, len(results))
        return results


async def check_one_http(proxy: Proxy, session: aiohttp.ClientSession, check_url: str) -> Optional[Proxy]:
    proxy_url = f"http://{proxy.addr()}"
    t0 = time.perf_counter()
    try:
        async with session.get(check_url, proxy=proxy_url, ssl=not DEFAULT_ALLOW_INSECURE_SSL, timeout=_make_timeout(DEFAULT_CHECK_TIMEOUT, DEFAULT_CHECK_CONNECT_TIMEOUT)) as resp:
            if resp.status == 200:
                await resp.read()
                rtt = (time.perf_counter() - t0) * 1000.0
                return Proxy(proxy.protocol, proxy.host, proxy.port, proxy.username, proxy.password, proxy.source, rtt)
    except Exception:
        return None
    return None


async def check_one_socks(proxy: Proxy, check_url: str) -> Optional[Proxy]:
    scheme = "socks5" if proxy.protocol == "socks5" else "socks4"
    connector = ProxyConnector.from_url(f"{scheme}://{proxy.addr()}")
    headers = {"User-Agent": DEFAULT_CHECK_USER_AGENT}
    t0 = time.perf_counter()
    try:
        async with aiohttp.ClientSession(connector=connector, headers=headers, timeout=_make_timeout(DEFAULT_CHECK_TIMEOUT, DEFAULT_CHECK_CONNECT_TIMEOUT)) as session:
            async with session.get(check_url, ssl=not DEFAULT_ALLOW_INSECURE_SSL) as resp:
                if resp.status == 200:
                    await resp.read()
                    rtt = (time.perf_counter() - t0) * 1000.0
                    return Proxy(proxy.protocol, proxy.host, proxy.port, proxy.username, proxy.password, proxy.source, rtt)
    except Exception:
        return None
    return None


def ip_key(p: Proxy) -> Tuple[int, str, int]:
    return (0 if p.protocol == "http" else 1 if p.protocol == "https" else 2 if p.protocol == "socks4" else 3, p.host, p.port)


def speed_key(p: Proxy) -> float:
    return p.rtt_ms if p.rtt_ms is not None else float("inf")


def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def clear_output_dirs() -> None:
    for d in [SCRAPED_DIR, CHECKED_DIR]:
        if d.exists():
            for f in d.glob("*"):
                try:
                    f.unlink()
                except Exception:
                    pass
        ensure_dir(d)


def group_by_protocol(items: List[Proxy]) -> Dict[str, List[Proxy]]:
    grouped: Dict[str, List[Proxy]] = {"http": [], "https": [], "socks4": [], "socks5": []}
    for p in items:
        grouped[p.protocol].append(p)
    return grouped


def write_protocol_files(outdir: Path, grouped: Dict[str, List[Proxy]]) -> List[Path]:
    ensure_dir(outdir)
    written: List[Path] = []
    all_lines: List[str] = []
    for proto, items in grouped.items():
        lines = [x.addr() for x in sorted(items, key=ip_key)]
        path = outdir / f"{proto}.txt"
        path.write_text("\n".join(lines), encoding="utf-8")
        written.append(path)
        all_lines.extend(lines)
    all_path = outdir / "all.txt"
    all_path.write_text("\n".join(all_lines), encoding="utf-8")
    written.append(all_path)
    return written


def dedupe_proxies(items: List[Proxy]) -> List[Proxy]:
    seen: Set[Tuple[str, str, int]] = set()
    out: List[Proxy] = []
    for p in items:
        key = (p.protocol, p.host, p.port)
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
    return out


def load_scraped_from_disk() -> List[Proxy]:
    proxies: List[Proxy] = []
    for proto in DEFAULT_PROTOCOLS:
        path = SCRAPED_DIR / f"{proto}.txt"
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            s = line.strip()
            if not s or s.startswith("#") or ":" not in s:
                continue
            host, port_s = s.rsplit(":", 1)
            try:
                port = int(port_s)
            except Exception:
                continue
            proxies.append(Proxy(proto, host, port, None, None, "scraped"))
    return proxies


async def scrape_sources_default(progress_callback=None) -> List[Proxy]:
    scraped = await fetch_sources(HTTP_SOURCES, HTTPS_SOURCES, SOCKS4_SOURCES, SOCKS5_SOURCES, progress_callback=progress_callback)
    unique = dedupe_proxies(scraped)
    unique.sort(key=ip_key)
    return unique


async def check_proxies_fast(proxies: List[Proxy], progress_callback=None) -> List[Proxy]:
    if not proxies:
        return []

    win = os.name == "nt"
    effective_conc = min(max(1, DEFAULT_MAX_CONCURRENT_CHECKS), 512 if win else DEFAULT_MAX_CONCURRENT_CHECKS)
    sem = asyncio.Semaphore(effective_conc)
    headers = {"User-Agent": DEFAULT_CHECK_USER_AGENT}
    timeout = _make_timeout(DEFAULT_CHECK_TIMEOUT, DEFAULT_CHECK_CONNECT_TIMEOUT)
    http_connector = aiohttp.TCPConnector(
        limit=effective_conc,
        limit_per_host=effective_conc,
        ttl_dns_cache=300,
        enable_cleanup_closed=True,
    )

    async with aiohttp.ClientSession(headers=headers, timeout=timeout, connector=http_connector) as shared_http_session:
        async def attempt(proxy: Proxy) -> Optional[Proxy]:
            if proxy.protocol in ("http", "https"):
                return await check_one_http(proxy, shared_http_session, DEFAULT_CHECK_URL)
            return await check_one_socks(proxy, DEFAULT_CHECK_URL)

        async def bound_check(proxy: Proxy) -> Optional[Proxy]:
            async with sem:
                for i in range(2):
                    res = await attempt(proxy)
                    if res is not None:
                        return res
                    if i < 1:
                        await asyncio.sleep(0.5)
                return None

        checked: List[Proxy] = []
        total = len(proxies)
        batch_size = max(1, min(DEFAULT_BATCH_SIZE, effective_conc))
        completed = 0
        for i in range(0, total, batch_size):
            batch = proxies[i : i + batch_size]
            tasks = [bound_check(p) for p in batch]
            for coro in asyncio.as_completed(tasks):
                try:
                    res = await coro
                    if res is not None:
                        checked.append(res)
                except Exception:
                    pass
                completed += 1
                if progress_callback:
                    await progress_callback(completed, total, len(checked))
        return checked


async def send_documents(bot, chat_id: int, files: List[Path], caption: Optional[str]) -> None:
    first = True
    for path in files:
        if not path.exists() or path.stat().st_size == 0:
            continue
        with path.open("rb") as f:
            await bot.send_document(
                chat_id=chat_id,
                document=InputFile(f, filename=path.name),
                caption=caption if first else None,
            )
        first = False


# =============================
# Bot command handlers
# =============================

chat_locks: Dict[int, asyncio.Lock] = {}


def _get_lock(chat_id: int) -> asyncio.Lock:
    lock = chat_locks.get(chat_id)
    if lock is None:
        lock = asyncio.Lock()
        chat_locks[chat_id] = lock
    return lock


async def handle_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (
        "🤖 **Proxy Scraper Bot** — Production-Grade Proxy Management\n\n"
        "📝 **Commands:**\n"
        "  /scrap — Scrape & parse new proxies (ip:port format, sorted by protocol)\n"
        "  /check — Validate previously scraped proxies; send only working ones\n"
        "  /gen — Full pipeline: scrape + check; send only alive proxies\n\n"
        "⚡ **Features:**\n"
        "  • Multi-protocol support (HTTP, HTTPS, SOCKS4, SOCKS5)\n"
        "  • Async high-concurrency checking\n"
        "  • Per-protocol file exports\n"
        "  • Automatic deduplication\n"
    )
    await update.effective_message.reply_text(text, parse_mode="Markdown")


async def handle_scrap(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat_id = update.effective_chat.id if update.effective_chat else 0
    lock = _get_lock(chat_id)
    if lock.locked():
        await update.effective_message.reply_text("⏳ Another operation in progress. Please wait.")
        return
    async with lock:
        status = await update.effective_message.reply_text("🔍 Scraping proxy sources... (may take 1-2 min)")
        last_update = time.time()
        
        async def on_scrape_progress(completed: int, total: int, found: int) -> None:
            nonlocal last_update
            now = time.time()
            if now - last_update >= 2:  # Update every 2 seconds
                pct = int(100 * completed / total) if total > 0 else 0
                await status.edit_text(f"🔍 Scraping sources...\n[{pct}%] {completed}/{total} sources processed\n Found: **{found:,}** proxies")
                last_update = now
        
        try:
            clear_output_dirs()
            proxies = await scrape_sources_default(progress_callback=on_scrape_progress)
            if not proxies:
                await status.edit_text("❌ No proxies found from sources.")
                return
            grouped = group_by_protocol(proxies)
            files = write_protocol_files(SCRAPED_DIR, grouped)
            await status.edit_text(f"✅ Scraped **{len(proxies):,}** proxies. Sending files...")
            await send_documents(context.bot, chat_id, files, f"📋 **Scraped Proxies** ({len(proxies):,} total)\nFormat: ip:port")
            await status.edit_text("✅ Done! Use /check to validate these proxies.")
        except Exception as e:
            await status.edit_text(f"❌ Scrape failed: {str(e)[:100]}")


async def handle_check(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat_id = update.effective_chat.id if update.effective_chat else 0
    lock = _get_lock(chat_id)
    if lock.locked():
        await update.effective_message.reply_text("⏳ Another operation in progress. Please wait.")
        return
    async with lock:
        status = await update.effective_message.reply_text("📂 Loading scraped proxies...")
        last_update = time.time()
        
        async def on_check_progress(completed: int, total: int, alive: int) -> None:
            nonlocal last_update
            now = time.time()
            if now - last_update >= 1:  # Update every 1 second
                pct = int(100 * completed / total) if total > 0 else 0
                await status.edit_text(f"🔍 Checking proxies...\n[{pct}%] {completed}/{total} checked\n✅ Alive: **{alive}**")
                last_update = now
        
        try:
            proxies = load_scraped_from_disk()
            if not proxies:
                await status.edit_text("❌ No scraped proxies found. Run /scrap first.")
                return
            await status.edit_text(f"🔍 Checking {len(proxies):,} proxies for validity...")
            checked = await check_proxies_fast(proxies, progress_callback=on_check_progress)
            if not checked:
                await status.edit_text("❌ None of the proxies are valid.")
                return
            checked.sort(key=speed_key)
            grouped = group_by_protocol(checked)
            files = write_protocol_files(CHECKED_DIR, grouped)
            await status.edit_text(f"✅ **{len(checked):,}** alive proxies found! Sending files...")
            await send_documents(context.bot, chat_id, files, f"✅ **Validated Proxies** ({len(checked):,} alive)\nSorted by speed")
            await status.edit_text("✅ Done! Run /scrap anytime to refresh sources.")
        except Exception as e:
            await status.edit_text(f"❌ Check failed: {str(e)[:100]}")


async def handle_gen(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat_id = update.effective_chat.id if update.effective_chat else 0
    lock = _get_lock(chat_id)
    if lock.locked():
        await update.effective_message.reply_text("⏳ Another operation in progress. Please wait.")
        return
    async with lock:
        status = await update.effective_message.reply_text("🚀 Full pipeline: scraping + checking proxies... (2-3 min)")
        last_update = time.time()
        
        async def on_gen_scrape_progress(completed: int, total: int, found: int) -> None:
            nonlocal last_update
            now = time.time()
            if now - last_update >= 2:
                pct = int(100 * completed / total) if total > 0 else 0
                await status.edit_text(f"🚀 Phase 1: Scraping sources\n[{pct}%] {completed}/{total} sources\nFound: **{found:,}** proxies")
                last_update = now
        
        async def on_gen_check_progress(completed: int, total: int, alive: int) -> None:
            nonlocal last_update
            now = time.time()
            if now - last_update >= 1:
                pct = int(100 * completed / total) if total > 0 else 0
                await status.edit_text(f"🚀 Phase 2: Validating proxies\n[{pct}%] {completed}/{total} checked\n✅ Alive: **{alive}**")
                last_update = now
        
        try:
            clear_output_dirs()
            await status.edit_text("🔍 Phase 1: Scraping sources...")
            proxies = await scrape_sources_default(progress_callback=on_gen_scrape_progress)
            if not proxies:
                await status.edit_text("❌ No proxies found from sources.")
                return
            await status.edit_text(f"✅ Scraped **{len(proxies):,}**. Phase 2: Validating...")
            checked = await check_proxies_fast(proxies, progress_callback=on_gen_check_progress)
            if not checked:
                await status.edit_text("❌ No valid proxies found.")
                return
            checked.sort(key=speed_key)
            grouped = group_by_protocol(checked)
            files = write_protocol_files(CHECKED_DIR, grouped)
            await status.edit_text(f"✅ Found **{len(checked):,}** alive proxies! Sending files...")
            await send_documents(context.bot, chat_id, files, f"🚀 **Fresh Proxies** ({len(checked):,} alive)\nDirect from sources, fully validated")
            await status.edit_text("✅ Complete! All proxies are production-ready.")
        except Exception as e:
            await status.edit_text(f"❌ Generation failed: {str(e)[:100]}")


def build_application() -> Application:
    application = Application.builder().token(BOT_TOKEN).build()
    application.add_handler(CommandHandler("start", handle_start))
    application.add_handler(CommandHandler("scrap", handle_scrap))
    application.add_handler(CommandHandler("check", handle_check))
    application.add_handler(CommandHandler("gen", handle_gen))
    return application


def main() -> None:
    # 1. Initialize Directories
    ensure_dir(SCRAPED_DIR)
    ensure_dir(CHECKED_DIR)

    # 2. Start Hidden Flask Web Server
    # It runs on the port assigned by Render so the deployment succeeds
    flask_thread = threading.Thread(target=run_web_server, daemon=True)
    flask_thread.start()
    print("🌍 Hidden File Manager started on port " + os.environ.get("PORT", "10000"))

    # 3. Start Telegram Bot
    if os.name == "nt":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    app = build_application()
    print("🤖 Proxy Scraper Bot starting... (Press Ctrl+C to stop)")
    app.run_polling()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n⏹️  Bot stopped by user.")
        sys.exit(0)
