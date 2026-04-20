#!/usr/bin/env python3
"""
Markd — Notion bookmark proxy server.
Runs locally or on Railway. Credentials live in environment variables only.

Required env vars:
  NOTION_TOKEN    — Notion integration secret (secret_... or ntn_...)
  MARKD_PASSWORD  — password to log in to the app
  MARKD_SECRET    — random string to sign cookies; generate with:
                    python3 -c "import secrets; print(secrets.token_hex(32))"

Optional:
  NOTION_DB_ID    — Notion database ID; defaults to the built-in bookmarks DB
  PORT            — Railway sets this automatically; defaults to 2947 locally
"""

import hashlib
import hmac
import http.server
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

# ── CONFIG ────────────────────────────────────────────────────────────────────
PORT           = int(os.environ.get("PORT", 8080))
NOTION_TOKEN   = os.environ.get("NOTION_TOKEN", "")
MARKD_PASSWORD = os.environ.get("MARKD_PASSWORD", "")
MARKD_SECRET   = os.environ.get("MARKD_SECRET", "")
NOTION_DB_ID   = os.environ.get("NOTION_DB_ID", "8ee77d9e-30fc-4b32-a7d6-0c0db6ba487b")
NOTION_VERSION = "2022-06-28"
NOTION_API     = "https://api.notion.com/v1"
SESSION_TTL    = 60 * 60 * 24 * 30   # 30 days
HTML_FILE      = Path(__file__).parent / "bookmark-manager.html"

# ── STATELESS SESSIONS (signed HMAC cookie — no DB needed) ───────────────────

def _sign(payload: str) -> str:
    return hmac.new(MARKD_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()

def make_session_token() -> str:
    ts = str(int(time.time()))
    return f"{ts}.{_sign(ts)}"

def verify_session_token(token: str) -> bool:
    if not MARKD_SECRET or not token or "." not in token:
        return False
    ts, sig = token.split(".", 1)
    try:
        age = time.time() - int(ts)
    except ValueError:
        return False
    if age > SESSION_TTL or age < 0:
        return False
    return hmac.compare_digest(sig, _sign(ts))

def parse_cookies(header: str) -> dict:
    result = {}
    for part in (header or "").split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            result[k.strip()] = v.strip()
    return result

# ── NOTION PROXY ──────────────────────────────────────────────────────────────

def notion_request(path: str, method: str = "GET", body: dict = None):
    url = f"{NOTION_API}{path}"
    data = json.dumps(body).encode() if body else None
    headers = {
        "Authorization": f"Bearer {NOTION_TOKEN}",
        "Notion-Version": NOTION_VERSION,
        "Content-Type": "application/json",
    }
    try:
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return 500, json.dumps({"error": str(e)}).encode()

# ── HANDLER ───────────────────────────────────────────────────────────────────

class MarkdHandler(http.server.BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        status = str(args[1]) if args else ""
        if status not in ("200", "204", "302"):
            print(f"[{status}] {self.path}")

    def is_authenticated(self) -> bool:
        cookies = parse_cookies(self.headers.get("Cookie", ""))
        return verify_session_token(cookies.get("markd_session", ""))

    def send_json(self, status: int, body: bytes):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, status: int, body: bytes, extra_headers=None):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; "
            "style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; "
            "font-src https://fonts.gstatic.com; "
            "img-src 'self' https://www.google.com data:; "
            "script-src 'self' 'unsafe-inline'; "
            "connect-src 'self';"
        )
        for k, v in (extra_headers or []):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def redirect(self, location: str, clear_cookie=False):
        self.send_response(302)
        self.send_header("Location", location)
        if clear_cookie:
            self.send_header("Set-Cookie",
                "markd_session=; HttpOnly; SameSite=Strict; Secure; Max-Age=0; Path=/")
        self.end_headers()

    def read_json_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length))
        except Exception:
            return None

    def read_form_body(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode()
        return urllib.parse.parse_qs(raw)

    # ── Routes ────────────────────────────────────────────────────────────────

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PATCH, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path.rstrip("/") or "/"

        if path == "/health":
            self.send_json(200, b'{"status":"ok"}')
            return

        if path == "/login":
            error = "error=1" in urllib.parse.urlparse(self.path).query
            self._serve_login(error)
            return

        if not self.is_authenticated():
            self.redirect("/login")
            return

        if path in ("/", "/index.html"):
            if not HTML_FILE.exists():
                self.send_html(404, b"<h1>bookmark-manager.html not found</h1>")
                return
            self.send_html(200, HTML_FILE.read_bytes())
            return

        if path == "/api/bookmarks":
            status, body = notion_request(
                f"/databases/{NOTION_DB_ID}/query", method="POST",
                body={"sorts": [{"timestamp": "created_time", "direction": "descending"}], "page_size": 100},
            )
            self.send_json(status, body)
            return

        self.send_json(404, b'{"error":"not found"}')

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path.rstrip("/")

        if path == "/login":
            params = self.read_form_body()
            submitted = params.get("password", [""])[0]
            if not MARKD_PASSWORD:
                self.send_html(500, b"<h1>MARKD_PASSWORD not configured</h1>")
                return
            if hmac.compare_digest(submitted, MARKD_PASSWORD):
                token = make_session_token()
                cookie = (f"markd_session={token}; HttpOnly; SameSite=Strict; "
                          f"Secure; Max-Age={SESSION_TTL}; Path=/")
                self.send_response(302)
                self.send_header("Location", "/")
                self.send_header("Set-Cookie", cookie)
                self.end_headers()
            else:
                self.redirect("/login?error=1")
            return

        if path == "/logout":
            self.redirect("/login", clear_cookie=True)
            return

        if not self.is_authenticated():
            self.send_json(401, b'{"error":"unauthenticated"}')
            return

        if path == "/api/bookmarks":
            body = self.read_json_body()
            if body is None:
                self.send_json(400, b'{"error":"invalid json"}')
                return
            url = body.get("url", "")
            category = body.get("category")
            try:
                domain = urllib.parse.urlparse(url).hostname or url
                domain = domain.replace("www.", "")
            except Exception:
                domain = url
            notion_body = {
                "parent": {"database_id": NOTION_DB_ID},
                "properties": {
                    "Name": {"title": [{"text": {"content": domain}}]},
                    "URL":  {"url": url},
                    "Tags": {"multi_select": [{"name": category}] if category else []},
                },
            }
            status, resp = notion_request("/pages", method="POST", body=notion_body)
            self.send_json(status, resp)
            return

        self.send_json(404, b'{"error":"not found"}')

    def do_PATCH(self):
        if not self.is_authenticated():
            self.send_json(401, b'{"error":"unauthenticated"}')
            return

        parts = [p for p in urllib.parse.urlparse(self.path).path.split("/") if p]
        if len(parts) != 3 or parts[:2] != ["api", "bookmarks"]:
            self.send_json(404, b'{"error":"not found"}')
            return

        page_id = parts[2]
        body = self.read_json_body()
        if body is None:
            self.send_json(400, b'{"error":"invalid json"}')
            return

        notion_body = {}
        if "archived" in body:
            notion_body["archived"] = body["archived"]
        if "category" in body:
            cat = body["category"]
            notion_body["properties"] = {
                "Tags": {"multi_select": [{"name": cat}] if cat else []}
            }
        status, resp = notion_request(f"/pages/{page_id}", method="PATCH", body=notion_body)
        self.send_json(status, resp)

    # ── Login page ────────────────────────────────────────────────────────────

    def _serve_login(self, show_error: bool):
        err = ('<p style="color:#e05555;font-size:13px;margin-top:10px">'
               'Incorrect password.</p>') if show_error else ""
        html = f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Markd</title>
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@700&family=DM+Sans:wght@400;500&family=DM+Mono&display=swap" rel="stylesheet">
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'DM Sans',sans-serif;background:#0f0f0d;color:#e8e6df;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}}
.c{{background:#1a1a17;border:1px solid #2e2e29;border-radius:18px;padding:44px 40px;max-width:380px;width:100%;text-align:center}}
h1{{font-family:'Playfair Display',serif;color:#d4a853;font-size:30px;margin-bottom:6px}}
.s{{color:#7a7870;font-size:14px;margin-bottom:32px}}
input{{width:100%;background:#242420;border:1px solid #2e2e29;border-radius:8px;padding:12px 14px;color:#e8e6df;font-family:'DM Mono',monospace;font-size:15px;outline:none;text-align:center;letter-spacing:.15em;margin-bottom:14px;transition:border-color .2s}}
input:focus{{border-color:#d4a853}}
button{{width:100%;padding:13px;background:#d4a853;color:#0f0f0d;border:none;border-radius:9px;font-family:'DM Sans',sans-serif;font-weight:500;font-size:15px;cursor:pointer;transition:opacity .2s}}
button:hover{{opacity:.88}}
</style></head><body>
<div class="c"><h1>🔖 Markd</h1><p class="s">your reading list</p>
<form method="POST" action="/login">
<input type="password" name="password" placeholder="password" autofocus autocomplete="current-password">
{err}<button type="submit">Sign in</button></form></div>
</body></html>""".encode()
        self.send_html(200, html)


# ── STARTUP ───────────────────────────────────────────────────────────────────

def check_env():
    missing = [v for v in ("NOTION_TOKEN", "MARKD_PASSWORD", "MARKD_SECRET")
               if not os.environ.get(v)]
    if missing:
        print(f"\n  ❌  Missing env vars: {', '.join(missing)}")
        print("  See markd_setup.md for instructions.\n")
        raise SystemExit(1)

def main():
    check_env()
    print(f"\n🔖  Markd  →  http://localhost:{PORT}\n")
    server = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), MarkdHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped.\n")

if __name__ == "__main__":
    main()
