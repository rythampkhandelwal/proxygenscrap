#!/usr/bin/env python3
"""
Telegram Bot for Proxy Scraping with Web File Manager for Render.
"""

import asyncio
import os
import re
import sys
import time
import threading
import mimetypes
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Set, Tuple, Dict
from urllib.parse import quote, unquote

# Web Server Imports
from flask import Flask, send_file, request, redirect, url_for, render_template_string, abort
from werkzeug.utils import secure_filename

import aiohttp
from aiohttp_socks import ProxyConnector
from telegram import InputFile, Update
from telegram.ext import Application, CommandHandler, ContextTypes

# =============================
# Configuration
# =============================

# Scraping
DEFAULT_MAX_PROXIES_PER_SOURCE = 100000
DEFAULT_SCRAPE_TIMEOUT = 60.0
DEFAULT_SCRAPE_CONNECT_TIMEOUT = 5.0
DEFAULT_SCRAPE_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"

# Checking
DEFAULT_CHECK_URL = "https://api.ipify.org"
DEFAULT_MAX_CONCURRENT_CHECKS = 1024
DEFAULT_CHECK_TIMEOUT = 60.0
DEFAULT_CHECK_CONNECT_TIMEOUT = 5.0
DEFAULT_CHECK_USER_AGENT = DEFAULT_SCRAPE_USER_AGENT
DEFAULT_ALLOW_INSECURE_SSL = True

# Telegram bot
# CRITICAL: Get Token from Env for security, or fallback to hardcoded
BOT_TOKEN = os.environ.get("BOT_TOKEN", "8190937825:AAG3PQBpOdvxC8pmBu5VVr8RblVG8ifwg9Q")

DEFAULT_PROTOCOLS = ["http", "https", "socks4", "socks5"]
OUTPUT_BASE = Path("./out")
SCRAPED_DIR = OUTPUT_BASE / "scraped"
CHECKED_DIR = OUTPUT_BASE / "checked"
DEFAULT_BATCH_SIZE = 512

# =============================
# FLASK WEB SERVER (File Manager)
# =============================
app = Flask(__name__)
BASE_DIR = Path(".").resolve()

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Bot File Manager</title>
    <style>
        body { font-family: monospace; background: #1e1e1e; color: #d4d4d4; padding: 20px; }
        a { color: #3794ff; text-decoration: none; }
        a:hover { text-decoration: underline; }
        h2 { border-bottom: 1px solid #444; padding-bottom: 10px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { text-align: left; padding: 8px; border-bottom: 1px solid #333; }
        tr:hover { background: #2d2d2d; }
        .upload-box { background: #252526; padding: 15px; border: 1px dashed #555; margin-bottom: 20px; }
        .dir { color: #ce9178; font-weight: bold; }
        .file { color: #9cdcfe; }
        .size { color: #b5cea8; }
    </style>
</head>
<body>
    <h2>📂 File Manager: {{ current_path }}</h2>
    
    <div class="upload-box">
        <form action="/upload" method="post" enctype="multipart/form-data">
            <input type="hidden" name="path" value="{{ current_path }}">
            <input type="file" name="file">
            <input type="submit" value="Upload File" style="cursor:pointer;">
        </form>
    </div>

    <div>
        <a href="/browse/{{ parent_path }}">⬅️ Up Level</a>
    </div>

    <table>
        <tr><th>Name</th><th>Size</th><th>Action</th></tr>
        {% for item in items %}
        <tr>
            <td>
                {% if item.is_dir %}
                    <span class="dir">📁 <a href="/browse/{{ item.rel_path }}">{{ item.name }}</a></span>
                {% else %}
                    <span class="file">📄 {{ item.name }}</span>
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
    </table>
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
    # Security check to prevent traversing out of base
    abs_path = (BASE_DIR / req_path).resolve()
    if not str(abs_path).startswith(str(BASE_DIR)):
        return abort(403)

    if not abs_path.exists():
        return abort(404)

    if abs_path.is_file():
        return send_file(abs_path)

    items = []
    # Sort: Directories first, then files
    try:
        dir_list = sorted(os.scandir(abs_path), key=lambda e: (not e.is_dir(), e.name.lower()))
        
        for entry in dir_list:
            rel_path = str(Path(req_path) / entry.name).strip("/")
            size = "-"
            if entry.is_file():
                size = get_readable_size(entry.stat().st_size)
            
            items.append({
                "name": entry.name,
                "is_dir": entry.is_dir(),
                "rel_path": rel_path,
                "size": size
            })
    except PermissionError:
        pass

    parent = str(Path(req_path).parent)
    if parent == ".": parent = ""
    
    return render_template_string(HTML_TEMPLATE, items=items, current_path=req_path, parent_path=parent)

@app.route('/download/<path:req_path>')
def download(req_path):
    abs_path = (BASE_DIR / req_path).resolve()
    if not str(abs_path).startswith(str(BASE_DIR)) or not abs_path.is_file():
        return abort(404)
    return send_file(abs_path, as_attachment=True)

@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return "No file part", 400
    file = request.files['file']
    if file.filename == '':
        return "No selected file", 400
    
    rel_path = request.form.get("path", "")
    save_dir = (BASE_DIR / rel_path).resolve()
    
    if not str(save_dir).startswith(str(BASE_DIR)):
        return abort(403)
        
    if file:
        filename = secure_filename(file.filename)
        file.save(os.path.join(save_dir, filename))
        return redirect(f"/browse/{rel_path}")

def run_flask():
    port = int(os.environ.get("PORT", 10000))
    # Disable debug mode to allow running in thread
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)

# =============================
# SOURCES
# =============================

HTTP_SOURCES = [
    "https://api.proxyscrape.com/v3/free-proxy-list/get?request=getproxies&protocol=http",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/http/data.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/refs/heads/main/HTTPS_RAW.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/refs/heads/master/http.txt",
    "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/refs/heads/main/http_proxies.txt",
]

HTTPS_SOURCES = [
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/https/data.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/refs/heads/main/HTTPS_RAW.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/refs/heads/master/http.txt",
]

SOCKS4_SOURCES = [
    "https://api.proxyscrape.com/v3/free-proxy-list/get?request=getproxies&protocol=socks4",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/socks4/data.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/refs/heads/master/socks4.txt",
    "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/refs/heads/main/socks4_proxies.txt",
]

SOCKS5_SOURCES = [
    "https://api.proxyscrape.com/v3/free-proxy-list/get?request=getproxies&protocol=socks5",
    "https://raw.githubusercontent.com/hookzof/socks5_list/refs/heads/master/proxy.txt",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/socks5/data.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/refs/heads/master/socks5.txt",
    "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/refs/heads/main/socks5_proxies.txt",
]

# =============================
# LOGIC
# =============================

PROXY_REGEX = re.compile(
    r"(?:^|[^0-9A-Za-z])"
    r"(?:(?P<protocol>https?|socks[45])://)?"
    r"(?:(?P<username>[0-9A-Za-z]{1,64}):(?P<password>[0-9A-Za-z]{1,64})@)?"
    r"(?P<host>(?:[A-Za-z][\-.A-Za-z]{0,251}[A-Za-z]|[0-9]{1,3}(?:\.[0-9]{1,3}){3}))"
    r":(?P<port>\d{2,5})"
    r"(?=[^0-9A-Za-z]|$)",
    re.IGNORECASE,
)
PLAIN_PROXY_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}:[0-9]{2,5}\b")

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
    if not p: return expected
    p = p.lower()
    if "socks5" in p: return "socks5"
    if "socks4" in p: return "socks4"
    if "https" in p: return "https"
    if "http" in p: return "http"
    return expected

def extract_proxies_from_text(text: str, expected_protocol: str, source: str) -> List[Proxy]:
    found: List[Proxy] = []
    for m in PROXY_REGEX.finditer(text):
        proto = normalize_protocol(m.group("protocol"), expected_protocol)
        found.append(Proxy(proto, m.group("host"), int(m.group("port")), m.group("username"), m.group("password"), source))
    for m in PLAIN_PROXY_REGEX.finditer(text):
        h, p = m.group(0).split(":", 1)
        found.append(Proxy(expected_protocol, h, int(p), None, None, source))
    return found

async def fetch_one(session: aiohttp.ClientSession, url: str, proto: str) -> List[Proxy]:
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
            text = await resp.text(errors="ignore")
            return extract_proxies_from_text(text, proto, url)[:DEFAULT_MAX_PROXIES_PER_SOURCE]
    except: return []

async def scrape_sources_default(progress_callback=None) -> List[Proxy]:
    async with aiohttp.ClientSession(headers={"User-Agent": DEFAULT_SCRAPE_USER_AGENT}) as s:
        tasks = []
        for u in HTTP_SOURCES: tasks.append(fetch_one(s, u, "http"))
        for u in HTTPS_SOURCES: tasks.append(fetch_one(s, u, "https"))
        for u in SOCKS4_SOURCES: tasks.append(fetch_one(s, u, "socks4"))
        for u in SOCKS5_SOURCES: tasks.append(fetch_one(s, u, "socks5"))
        
        results = []
        completed = 0
        for f in asyncio.as_completed(tasks):
            results.extend(await f)
            completed += 1
            if progress_callback: await progress_callback(completed, len(tasks), len(results))
        
        # Dedupe
        seen = set()
        unique = []
        for p in results:
            k = (p.protocol, p.host, p.port)
            if k not in seen:
                seen.add(k)
                unique.append(p)
        return unique

async def check_one(proxy: Proxy, sem: asyncio.Semaphore, shared_session: aiohttp.ClientSession) -> Optional[Proxy]:
    async with sem:
        try:
            url = f"{proxy.protocol}://{proxy.addr()}"
            t0 = time.perf_counter()
            # Logic: If http/s use aiohttp directly. If socks use connector.
            # Simplified for speed: we rely on a single smart connector or split sessions.
            # Here we use a generic approach for the example.
            
            if proxy.protocol in ("http", "https"):
                async with shared_session.get(DEFAULT_CHECK_URL, proxy=f"http://{proxy.addr()}", timeout=10) as r:
                    if r.status == 200: return Proxy(proxy.protocol, proxy.host, proxy.port, None, None, proxy.source, (time.perf_counter()-t0)*1000)
            else:
                # SOCKS requires separate connector per proxy usually or aiohttp_socks
                connector = ProxyConnector.from_url(f"{proxy.protocol}://{proxy.addr()}")
                async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=10)) as socks_sess:
                    async with socks_sess.get(DEFAULT_CHECK_URL) as r:
                         if r.status == 200: return Proxy(proxy.protocol, proxy.host, proxy.port, None, None, proxy.source, (time.perf_counter()-t0)*1000)
        except: pass
    return None

async def check_proxies_fast(proxies: List[Proxy], progress_callback=None) -> List[Proxy]:
    sem = asyncio.Semaphore(100) # Limit concurrency on Render free tier
    
    # We use a session for HTTP checks
    conn = aiohttp.TCPConnector(limit=200, ssl=False)
    async with aiohttp.ClientSession(connector=conn) as sess:
        tasks = [check_one(p, sem, sess) for p in proxies]
        alive = []
        comp = 0
        total = len(tasks)
        for f in asyncio.as_completed(tasks):
            res = await f
            if res: alive.append(res)
            comp += 1
            if progress_callback and comp % 50 == 0: await progress_callback(comp, total, len(alive))
    return alive

def write_protocol_files(outdir: Path, proxies: List[Proxy]) -> List[Path]:
    outdir.mkdir(parents=True, exist_ok=True)
    grouped = {"http": [], "https": [], "socks4": [], "socks5": []}
    for p in proxies: grouped[p.protocol].append(p.addr())
    
    paths = []
    for proto, lines in grouped.items():
        if lines:
            p = outdir / f"{proto}.txt"
            p.write_text("\n".join(lines))
            paths.append(p)
    return paths

# =============================
# BOT HANDLERS
# =============================
chat_locks = {}

async def handle_gen(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat_id = update.effective_chat.id
    if chat_locks.get(chat_id, False):
        await update.message.reply_text("⏳ Wait for current task.")
        return
    chat_locks[chat_id] = True
    
    msg = await update.message.reply_text("🚀 Starting full check...")
    
    try:
        # 1. Scrape
        async def scr_prog(c, t, f):
            if c % 5 == 0: await msg.edit_text(f"Scraping sources: {c}/{t}\nFound: {f}")
        proxies = await scrape_sources_default(scr_prog)
        if not proxies:
            await msg.edit_text("❌ No proxies found.")
            return

        # 2. Check
        await msg.edit_text(f"Checking {len(proxies)} proxies...")
        async def chk_prog(c, t, a):
            if c % 100 == 0: await msg.edit_text(f"Checking: {int(c/t*100)}%\nAlive: {a}")
        
        alive = await check_proxies_fast(proxies, chk_prog)
        
        # 3. Save
        files = write_protocol_files(CHECKED_DIR, alive)
        
        if not files:
            await msg.edit_text("❌ All dead.")
        else:
            await msg.edit_text(f"✅ Found {len(alive)} alive.")
            for f in files:
                await context.bot.send_document(chat_id, f, caption=f.name)
                
    except Exception as e:
        await msg.edit_text(f"Error: {e}")
    finally:
        chat_locks[chat_id] = False

async def handle_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    web_url = os.environ.get("RENDER_EXTERNAL_URL", "http://your-app.onrender.com")
    await update.message.reply_text(
        f"🤖 **Bot Running**\n\nCommands:\n/gen - Scrape & Check\n\n"
        f"📂 **File Manager:**\n{web_url}\n(Open this link to manage files)"
    )

def main() -> None:
    # 1. Ensure Directories Exist
    SCRAPED_DIR.mkdir(parents=True, exist_ok=True)
    CHECKED_DIR.mkdir(parents=True, exist_ok=True)

    # 2. Start Flask Web Server in a Background Thread
    # Daemon=True ensures it shuts down when the main script ends
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()
    print("🌍 Web Server thread started.")

    # 3. Start Telegram Bot
    if not BOT_TOKEN:
        print("❌ BOT_TOKEN is missing!")
        sys.exit(1)
        
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", handle_start))
    app.add_handler(CommandHandler("gen", handle_gen))
    
    print("🤖 Bot polling started...")
    app.run_polling()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
