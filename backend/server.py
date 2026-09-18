#!/usr/bin/env python3
"""Personal Hub - multi-account email dashboard + calendar + journal.

Single-user app (password gate). Gmail via OAuth2 (each account connected once),
Google Calendar merged across accounts, private journal with email linking,
and optional AI helpers (summarize email, daily journal prompt) via OpenAI.

Routes (all /api/* except /oauth/callback need the session cookie):
  GET  /                      -> login page or app
  POST /api/login             {password}
  POST /api/logout
  GET  /api/me                -> {"ok": true} when logged in
  GET  /api/oauth/url         -> {"url": google auth url}
  GET  /oauth/callback        -> google redirect (public, state-checked)
  GET  /api/accounts          -> [{id, email, color}]
  DELETE /api/accounts/{id}
  GET  /api/mail?view=all|ID&q=&tokens=   -> {messages:[...], nextTokens:{}}
  GET  /api/mail/{aid}/{mid}  -> full message
  POST /api/mail/{aid}/{mid}/read    {read: bool}
  POST /api/mail/{aid}/{mid}/archive
  POST /api/mail/{aid}/{mid}/trash
  POST /api/mail/send         {account_id, to, subject, body}
  POST /api/mail/{aid}/{mid}/summarize -> {summary}
  GET  /api/calendar?from=&to= -> {events:[...]}
  POST /api/calendar/events   {account_id, title, start, end, description}
  GET  /api/journal           -> [...]
  POST /api/journal           {date, title, body, email_refs}
  PUT  /api/journal/{id}
  DELETE /api/journal/{id}
  POST /api/journal/prompt    -> {prompt}
  GET  /api/health

Env:
  GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET (owner pastes from Google Cloud)
  APP_PASSWORD      (login password for the app itself)
  FERNET_KEY        (encrypts OAuth refresh tokens at rest)
  DATABASE_URL      (Render Postgres)
  OPENAI_API_KEY    (optional, enables AI helpers)
  BASE_URL          (optional, e.g. https://personal-hub.onrender.com)
  PORT
"""
import base64
import hashlib
import hmac
import html as htmlmod
import json
import os
import re
import secrets
import time
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime, timezone
from email.mime.text import MIMEText
from email.utils import parseaddr, formatdate
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie

# ---------------------------------------------------------------- config
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
APP_PASSWORD = os.environ.get("APP_PASSWORD", "")
FERNET_KEY = os.environ.get("FERNET_KEY", "")
DATABASE_URL = os.environ.get("DATABASE_URL", "")
OPENAI_KEY = os.environ.get("OPENAI_API_KEY", "")
BASE_URL = os.environ.get("BASE_URL", "").rstrip("/")
PORT = int(os.environ.get("PORT", "10000"))

SCOPES = " ".join([
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/calendar",
    "https://www.googleapis.com/auth/userinfo.email",
    "openid",
])
OAUTH_AUTH = "https://accounts.google.com/o/oauth2/v2/auth"
OAUTH_TOKEN = "https://oauth2.googleapis.com/token"
GMAIL_API = "https://gmail.googleapis.com/gmail/v1"
CAL_API = "https://www.googleapis.com/calendar/v3"

PALETTE = ["#2563eb", "#059669", "#d97706", "#dc2626", "#7c3aed",
           "#0891b2", "#db2777", "#65a30d"]

# ---------------------------------------------------------------- tiny db
import psycopg2

_db = None


def db():
    global _db
    if _db is None or _db.closed:
        _db = psycopg2.connect(DATABASE_URL)
        _db.autocommit = True
    return _db


def init_db():
    c = db().cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS accounts(
        id SERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL,
        refresh_token TEXT NOT NULL, color TEXT NOT NULL,
        created_at TIMESTAMPTZ DEFAULT now())""")
    c.execute("""CREATE TABLE IF NOT EXISTS journal(
        id SERIAL PRIMARY KEY, day DATE NOT NULL, title TEXT NOT NULL DEFAULT '',
        body TEXT NOT NULL DEFAULT '', email_refs TEXT NOT NULL DEFAULT '[]',
        created_at TIMESTAMPTZ DEFAULT now(), updated_at TIMESTAMPTZ DEFAULT now())""")
    c.execute("""CREATE TABLE IF NOT EXISTS sessions(
        token TEXT PRIMARY KEY, created_at TIMESTAMPTZ DEFAULT now())""")
    c.close()


# ---------------------------------------------------------------- crypto
from cryptography.fernet import Fernet

_fernet = None


def fernet():
    global _fernet
    if _fernet is None:
        _fernet = Fernet(FERNET_KEY.encode())
    return _fernet


def enc(s):
    return fernet().encrypt(s.encode()).decode()


def dec(s):
    return fernet().decrypt(s.encode()).decode()


# ---------------------------------------------------------------- sessions
def new_session():
    tok = secrets.token_urlsafe(32)
    c = db().cursor()
    c.execute("INSERT INTO sessions(token) VALUES(%s)", (tok,))
    # prune sessions older than 30 days
    c.execute("DELETE FROM sessions WHERE created_at < now() - interval '30 days'")
    c.close()
    return tok


def valid_session(tok):
    if not tok:
        return False
    c = db().cursor()
    c.execute("SELECT 1 FROM sessions WHERE token=%s", (tok,))
    ok = c.fetchone() is not None
    c.close()
    return ok


def drop_session(tok):
    c = db().cursor()
    c.execute("DELETE FROM sessions WHERE token=%s", (tok,))
    c.close()


# ---------------------------------------------------------------- http util
def http_json(method, url, token=None, data=None, params=None, timeout=30):
    if params:
        url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            detail = e.read().decode()[:300]
        except Exception:
            detail = ""
        return e.code, {"_http_error": detail}


def http_form(url, fields, timeout=30):
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            detail = e.read().decode()[:300]
        except Exception:
            detail = ""
        return e.code, {"_http_error": detail}


# ---------------------------------------------------------------- google
_oauth_states = {}          # state -> expiry ts (callback CSRF)
_access_cache = {}          # account_id -> (access_token, expiry_ts)


def redirect_uri(host):
    base = BASE_URL or ("https://" + host)
    return base.rstrip("/") + "/oauth/callback"


def google_auth_url(host):
    state = secrets.token_urlsafe(24)
    _oauth_states[state] = time.time() + 600
    q = urllib.parse.urlencode({
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": redirect_uri(host),
        "response_type": "code",
        "scope": SCOPES,
        "access_type": "offline",
        "prompt": "consent",
        "state": state,
    })
    return OAUTH_AUTH + "?" + q


def exchange_code(code, host):
    return http_form(OAUTH_TOKEN, {
        "code": code, "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": redirect_uri(host),
        "grant_type": "authorization_code",
    })


def refresh_access(account_id):
    """Return a fresh access token for the account (cached)."""
    now = time.time()
    hit = _access_cache.get(account_id)
    if hit and hit[1] > now + 60:
        return hit[0]
    c = db().cursor()
    c.execute("SELECT refresh_token FROM accounts WHERE id=%s", (account_id,))
    row = c.fetchone()
    c.close()
    if not row:
        raise RuntimeError("account not found")
    st, tok = http_form(OAUTH_TOKEN, {
        "refresh_token": dec(row[0]), "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET, "grant_type": "refresh_token",
    })
    if st != 200 or "access_token" not in tok:
        raise RuntimeError("google refresh failed")
    _access_cache[account_id] = (tok["access_token"], now + int(tok.get("expires_in", 3600)))
    return tok["access_token"]


def gapi(method, path, account_id, data=None, params=None):
    token = refresh_access(account_id)
    st, out = http_json(method, GMAIL_API + path, token=token, data=data, params=params)
    if st == 401 and "_http_error" in out:
        _access_cache.pop(account_id, None)
        token = refresh_access(account_id)
        st, out = http_json(method, GMAIL_API + path, token=token, data=data, params=params)
    return st, out


def capi(method, path, account_id, data=None, params=None):
    token = refresh_access(account_id)
    st, out = http_json(method, CAL_API + path, token=token, data=data, params=params)
    if st == 401 and "_http_error" in out:
        _access_cache.pop(account_id, None)
        token = refresh_access(account_id)
        st, out = http_json(method, CAL_API + path, token=token, data=data, params=params)
    return st, out


def get_accounts():
    c = db().cursor()
    c.execute("SELECT id, email, color FROM accounts ORDER BY id")
    rows = [{"id": r[0], "email": r[1], "color": r[2]} for r in c.fetchall()]
    c.close()
    return rows

# ---------------------------------------------------------------- gmail
def _headers(payload, *names):
    out = {}
    for h in payload.get("headers", []):
        if h["name"] in names:
            out[h["name"]] = h["value"]
    return out


def _nice_from(raw):
    name, addr = parseaddr(raw or "")
    return {"name": name or addr, "email": addr}


def _fmt_date(ms):
    try:
        return datetime.fromtimestamp(int(ms) / 1000, tz=timezone.utc).isoformat()
    except Exception:
        return ""


def list_messages(account_id, q, max_results=25, page_token=None):
    params = {"q": q or "in:inbox", "maxResults": max_results}
    if page_token:
        params["pageToken"] = page_token
    st, out = gapi("GET", "/users/me/messages", account_id, params=params)
    if st != 200:
        return {"_error": out.get("_http_error", "gmail error")}
    items = []
    for m in out.get("messages", []):
        st2, full = gapi("GET", f"/users/me/messages/{m['id']}", account_id,
                         params={"format": "metadata",
                                 "metadataHeaders": ["From", "Subject", "Date"]})
        if st2 != 200:
            continue
        h = _headers(full.get("payload", {}), "From", "Subject", "Date")
        labels = full.get("labelIds", [])
        items.append({
            "id": m["id"],
            "from": _nice_from(h.get("From", "")),
            "subject": h.get("Subject", "(no subject)"),
            "snippet": htmlmod.unescape(full.get("snippet", "")),
            "date": _fmt_date(m.get("internalDate", 0)),
            "unread": "UNREAD" in labels,
        })
    return {"messages": items, "nextPageToken": out.get("nextPageToken")}


def _walk_parts(payload):
    """Yield (mimeType, decoded_text) for text parts, html preferred later."""
    mime = payload.get("mimeType", "")
    body = payload.get("body", {})
    data = body.get("data")
    if data and mime.startswith("text/"):
        try:
            yield mime, base64.urlsafe_b64decode(data).decode("utf-8", "replace")
        except Exception:
            pass
    for p in payload.get("parts", []) or []:
        yield from _walk_parts(p)


def get_message(account_id, msg_id):
    st, full = gapi("GET", f"/users/me/messages/{msg_id}", account_id,
                    params={"format": "full"})
    if st != 200:
        return {"_error": full.get("_http_error", "gmail error")}
    h = _headers(full.get("payload", {}), "From", "To", "Subject", "Date")
    html_body, text_body = None, None
    for mime, txt in _walk_parts(full.get("payload", {})):
        if mime == "text/html" and html_body is None:
            html_body = txt
        elif mime == "text/plain" and text_body is None:
            text_body = txt
    import bleach
    if html_body:
        body_html = bleach.clean(
            html_body,
            tags=["p", "br", "div", "span", "a", "b", "strong", "i", "em", "u",
                  "ul", "ol", "li", "table", "tr", "td", "th", "thead", "tbody",
                  "h1", "h2", "h3", "h4", "blockquote", "pre", "code", "hr", "img"],
            attributes={"a": ["href", "title"], "img": ["src", "alt", "width", "height"],
                        "*": ["style"]},
            strip=True)
    else:
        body_html = "<pre style='white-space:pre-wrap;font-family:inherit'>%s</pre>" % \
            htmlmod.escape(text_body or "")
    return {
        "id": msg_id,
        "from": _nice_from(h.get("From", "")),
        "to": h.get("To", ""),
        "subject": h.get("Subject", "(no subject)"),
        "date": h.get("Date", ""),
        "body_html": body_html,
        "body_text": text_body or re.sub(r"<[^>]+>", " ", html_body or "")[:20000],
        "unread": "UNREAD" in full.get("labelIds", []),
    }


def modify_message(account_id, msg_id, add=(), remove=()):
    st, out = gapi("POST", f"/users/me/messages/{msg_id}/modify", account_id,
                   data={"addLabelIds": list(add), "removeLabelIds": list(remove)})
    return st == 200


def trash_message(account_id, msg_id):
    st, out = gapi("POST", f"/users/me/messages/{msg_id}/trash", account_id)
    return st == 200


def send_message(account_id, to, subject, body, in_reply_to=None, thread_id=None):
    c = db().cursor()
    c.execute("SELECT email FROM accounts WHERE id=%s", (account_id,))
    row = c.fetchone()
    c.close()
    if not row:
        return False, "account not found"
    msg = MIMEText(body or "", "plain", "utf-8")
    msg["From"] = row[0]
    msg["To"] = to
    msg["Subject"] = subject or ""
    msg["Date"] = formatdate(localtime=True)
    if in_reply_to:
        msg["In-Reply-To"] = in_reply_to
    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
    payload = {"raw": raw}
    if thread_id:
        payload["threadId"] = thread_id
    st, out = gapi("POST", "/users/me/messages/send", account_id, data=payload)
    return (st == 200), out.get("_http_error", "") if st != 200 else ""


# ---------------------------------------------------------------- calendar
def list_events(account_id, time_min, time_max):
    st, cals = capi("GET", "/users/me/calendarList", account_id)
    if st != 200:
        return {"_error": cals.get("_http_error", "calendar error")}
    events = []
    for cal in cals.get("items", []):
        st2, ev = capi("GET", f"/users/me/calendars/{urllib.parse.quote(cal['id'], safe='')}/events",
                       account_id,
                       params={"timeMin": time_min, "timeMax": time_max,
                               "singleEvents": "true", "orderBy": "startTime",
                               "maxResults": 100})
        if st2 != 200:
            continue
        for e in ev.get("items", []):
            if e.get("status") == "cancelled":
                continue
            s, en = e.get("start", {}), e.get("end", {})
            events.append({
                "id": e["id"], "cal": cal.get("summary", ""),
                "title": e.get("summary", "(no title)"),
                "start": s.get("dateTime", s.get("date", "")),
                "end": en.get("dateTime", en.get("date", "")),
                "allDay": "date" in s,
                "location": e.get("location", ""),
                "description": (e.get("description", "") or "")[:500],
            })
    events.sort(key=lambda e: e["start"])
    return {"events": events}


def create_event(account_id, title, start, end, description="", all_day=False):
    body = {"summary": title, "description": description}
    if all_day:
        body["start"] = {"date": start[:10]}
        body["end"] = {"date": end[:10]}
    else:
        body["start"] = {"dateTime": start}
        body["end"] = {"dateTime": end}
    st, out = capi("POST", "/users/me/calendars/primary/events", account_id, data=body)
    return st == 200


# ---------------------------------------------------------------- openai
def ask_openai(system, user_text, max_tokens=500):
    if not OPENAI_KEY:
        return {"_error": "AI not configured (no API key)"}
    body = json.dumps({
        "model": "gpt-4o-mini", "max_tokens": max_tokens, "temperature": 0.3,
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": user_text[:6000]}],
    }).encode()
    req = urllib.request.Request("https://api.openai.com/v1/chat/completions",
                                 data=body, method="POST")
    req.add_header("Authorization", "Bearer " + OPENAI_KEY)
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            d = json.load(r)
        return {"text": d["choices"][0]["message"]["content"].strip()}
    except Exception as e:
        return {"_error": f"{type(e).__name__}"}

# ---------------------------------------------------------------- http
LOGIN_PAGE = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Personal Hub - sign in</title>
<style>body{font-family:system-ui;background:#0f172a;color:#e2e8f0;display:flex;
align-items:center;justify-content:center;min-height:100vh;margin:0}
.box{background:#1e293b;padding:32px;border-radius:12px;width:min(360px,90vw)}
h1{margin:0 0 16px;font-size:22px}input{width:100%;padding:10px;margin:8px 0;
border-radius:8px;border:1px solid #334155;background:#0f172a;color:#fff;box-sizing:border-box}
button{width:100%;padding:10px;background:#2563eb;border:0;color:#fff;border-radius:8px;
font-size:16px;cursor:pointer}.err{color:#f87171;margin-top:8px;min-height:20px}</style>
</head><body><div class="box"><h1>Personal Hub</h1>
<input id="pw" type="password" placeholder="Password" autocomplete="current-password">
<button onclick="go()">Sign in</button><div class="err" id="e"></div>
<script>function go(){fetch('/api/login',{method:'POST',
headers:{'Content-Type':'application/json'},
body:JSON.stringify({password:document.getElementById('pw').value})})
.then(r=>r.json()).then(d=>{if(d.ok)location.reload();
else document.getElementById('e').textContent='Wrong password';});}
document.getElementById('pw').addEventListener('keydown',e=>{if(e.key==='Enter')go();});</script>
</div></body></html>"""

APP_PAGE_PATH = os.path.join(os.path.dirname(__file__), "..", "frontend", "index.html")


class Handler(BaseHTTPRequestHandler):
    # -- helpers
    def _cookie_token(self):
        c = SimpleCookie(self.headers.get("Cookie", ""))
        return c["session"].value if "session" in c else None

    def _authed(self):
        return valid_session(self._cookie_token())

    def _json(self, code, obj, cookie=None):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def _html(self, code, text, cookie=None):
        body = text.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
        except Exception:
            n = 0
        try:
            return json.loads(self.rfile.read(n) or b"{}") if n else {}
        except Exception:
            return {}

    def _need_auth(self):
        if not self._authed():
            self._json(401, {"error": "login required"})
            return False
        return True

    def _serve_app(self):
        try:
            with open(APP_PAGE_PATH, encoding="utf-8") as f:
                page = f.read()
        except Exception:
            page = "<h1>frontend not found</h1>"
        self._html(200, page)

    # -- routing
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path, qs = parsed.path, urllib.parse.parse_qs(parsed.query)
        host = self.headers.get("Host", "")

        if path == "/api/health":
            return self._json(200, {"ok": True})
        if path == "/":
            if self._authed():
                return self._serve_app()
            return self._html(200, LOGIN_PAGE)
        if path == "/app":
            if self._authed():
                return self._serve_app()
            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return

        # public: google oauth callback
        if path == "/oauth/callback":
            if qs.get("error"):
                return self._html(400, "<h1>Google sign-in cancelled</h1><a href='/'>Back</a>")
            state, code = qs.get("state", [""])[0], qs.get("code", [""])[0]
            if not state or state not in _oauth_states or _oauth_states[state] < time.time():
                return self._html(400, "<h1>Session expired, try again</h1><a href='/'>Back</a>")
            _oauth_states.pop(state, None)
            st, tok = exchange_code(code, host)
            if st != 200 or "refresh_token" not in tok:
                return self._html(400, "<h1>Google sign-in failed</h1><a href='/'>Back</a>")
            # who is this?
            at = tok["access_token"]
            st2, me = http_json("GET", "https://www.googleapis.com/oauth2/v2/userinfo",
                                token=at)
            email = me.get("email", "unknown") if st2 == 200 else "unknown"
            c = db().cursor()
            c.execute("SELECT id, color FROM accounts")
            used = {r[1] for r in c.fetchall()}
            color = next((x for x in PALETTE if x not in used), PALETTE[0])
            c.execute("""INSERT INTO accounts(email, refresh_token, color)
                         VALUES(%s,%s,%s)
                         ON CONFLICT(email) DO UPDATE SET refresh_token=EXCLUDED.refresh_token
                         RETURNING id""", (email, enc(tok["refresh_token"]), color))
            aid = c.fetchone()[0]
            c.close()
            _access_cache.pop(aid, None)
            self.send_response(302)
            self.send_header("Location", "/#accounts")
            self.end_headers()
            return

        if not self._need_auth():
            return

        if path == "/api/me":
            return self._json(200, {"ok": True})
        if path == "/api/oauth/url":
            if not GOOGLE_CLIENT_ID:
                return self._json(500, {"error": "Google not configured yet (see README)"})
            return self._json(200, {"url": google_auth_url(host)})
        if path == "/api/accounts":
            return self._json(200, {"accounts": get_accounts()})

        m = re.match(r"^/api/mail/(\d+)/([^/]+)$", path)
        if m and "summarize" not in path:
            aid, mid = int(m.group(1)), m.group(2)
            try:
                msg = get_message(aid, mid)
            except Exception as e:
                return self._json(502, {"error": "gmail unreachable"})
            if "_error" in msg:
                return self._json(502, {"error": msg["_error"]})
            return self._json(200, msg)

        if path == "/api/mail":
            view = qs.get("view", ["all"])[0]
            q = qs.get("q", ["in:inbox"])[0]
            try:
                tokens = json.loads(qs.get("tokens", ["{}"])[0])
            except Exception:
                tokens = {}
            accts = get_accounts()
            if view != "all":
                accts = [a for a in accts if str(a["id"]) == view]
            msgs, next_tokens = [], {}
            for a in accts:
                try:
                    r = list_messages(a["id"], q, 25, tokens.get(str(a["id"])))
                except Exception:
                    continue
                if "_error" in r:
                    continue
                for x in r["messages"]:
                    x.update({"account_id": a["id"], "account_email": a["email"],
                              "color": a["color"]})
                    msgs.append(x)
                if r.get("nextPageToken"):
                    next_tokens[str(a["id"])] = r["nextPageToken"]
            msgs.sort(key=lambda x: x["date"], reverse=True)
            return self._json(200, {"messages": msgs[:40], "nextTokens": next_tokens})

        if path == "/api/calendar":
            tmin = qs.get("from", [datetime.now(timezone.utc).isoformat()])[0]
            tmax = qs.get("to", [""])[0]
            events = []
            for a in get_accounts():
                try:
                    r = list_events(a["id"], tmin, tmax)
                except Exception:
                    continue
                if "_error" in r:
                    continue
                for e in r["events"]:
                    e.update({"account_id": a["id"], "account_email": a["email"],
                              "color": a["color"]})
                    events.append(e)
            events.sort(key=lambda e: e["start"])
            return self._json(200, {"events": events})

        if path == "/api/journal":
            c = db().cursor()
            c.execute("SELECT id, day::text, title, body, email_refs, "
                      "created_at FROM journal ORDER BY day DESC, id DESC LIMIT 200")
            rows = [{"id": r[0], "date": r[1], "title": r[2], "body": r[3],
                     "email_refs": json.loads(r[4] or "[]"),
                     "created_at": r[5].isoformat()} for r in c.fetchall()]
            c.close()
            return self._json(200, {"entries": rows})

        return self._json(404, {"error": "not found"})

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        host = self.headers.get("Host", "")

        if path == "/api/login":
            data = self._body()
            if APP_PASSWORD and hmac.compare_digest(str(data.get("password", "")), APP_PASSWORD):
                tok = new_session()
                return self._json(200, {"ok": True},
                                  cookie=f"session={tok}; HttpOnly; Path=/; "
                                         f"Max-Age=2592000; SameSite=Lax; Secure")
            time.sleep(1)
            return self._json(401, {"error": "wrong password"})

        if not self._need_auth():
            return
        data = self._body()

        if path == "/api/logout":
            drop_session(self._cookie_token())
            return self._json(200, {"ok": True},
                              cookie="session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax; Secure")

        m = re.match(r"^/api/mail/(\d+)/([^/]+)/(read|archive|trash|summarize)$", path)
        if m:
            aid, mid, act = int(m.group(1)), m.group(2), m.group(3)
            try:
                if act == "read":
                    ok = modify_message(aid, mid,
                                        add=[] if data.get("read") else ["UNREAD"],
                                        remove=["UNREAD"] if data.get("read") else [])
                elif act == "archive":
                    ok = modify_message(aid, mid, remove=["INBOX"])
                elif act == "trash":
                    ok = trash_message(aid, mid)
                elif act == "summarize":
                    msg = get_message(aid, mid)
                    if "_error" in msg:
                        return self._json(502, {"error": msg["_error"]})
                    out = ask_openai(
                        "Summarize this email in 3-5 short bullet points. "
                        "Note any action items, dates, or deadlines.",
                        f"From: {msg['from']['name']} <{msg['from']['email']}>\n"
                        f"Subject: {msg['subject']}\n\n{msg['body_text'][:6000]}")
                    if "_error" in out:
                        return self._json(502, {"error": out["_error"]})
                    return self._json(200, {"summary": out["text"]})
                return self._json(200, {"ok": ok})
            except Exception as e:
                return self._json(502, {"error": "gmail unreachable"})

        if path == "/api/mail/send":
            try:
                ok, err = send_message(data.get("account_id"), data.get("to", ""),
                                       data.get("subject", ""), data.get("body", ""))
            except Exception:
                return self._json(502, {"error": "gmail unreachable"})
            if not ok:
                return self._json(502, {"error": err or "send failed"})
            return self._json(200, {"ok": True})

        if path == "/api/calendar/events":
            try:
                ok = create_event(data.get("account_id"), data.get("title", ""),
                                  data.get("start", ""), data.get("end", ""),
                                  data.get("description", ""),
                                  bool(data.get("all_day")))
            except Exception:
                return self._json(502, {"error": "calendar unreachable"})
            return self._json(200, {"ok": ok})

        if path == "/api/journal":
            c = db().cursor()
            c.execute("INSERT INTO journal(day, title, body, email_refs) "
                      "VALUES(%s,%s,%s,%s) RETURNING id",
                      (data.get("date") or datetime.now().date().isoformat(),
                       data.get("title", "")[:200], data.get("body", ""),
                       json.dumps(data.get("email_refs", []))))
            nid = c.fetchone()[0]
            c.close()
            return self._json(200, {"ok": True, "id": nid})

        if path == "/api/journal/prompt":
            # gather today's context: unread subjects + today's events
            bits = []
            for a in get_accounts():
                try:
                    r = list_messages(a["id"], "in:inbox newer_than:1d", 10)
                    if "_error" not in r:
                        for x in r["messages"][:5]:
                            bits.append(f"- {x['from']['name']}: {x['subject']}")
                except Exception:
                    pass
            now = datetime.now(timezone.utc)
            evs = []
            for a in get_accounts():
                try:
                    r = list_events(a["id"], now.isoformat(),
                                    now.replace(hour=23, minute=59).isoformat())
                    if "_error" not in r:
                        evs += [e["title"] for e in r["events"][:5]]
                except Exception:
                    pass
            ctx = "Inbox today:\n" + ("\n".join(bits) or "(quiet)") + \
                  "\n\nOn the calendar:\n" + ("\n".join("- " + e for e in evs) or "(nothing)")
            out = ask_openai("Write 3 short, personal journal prompts based on the "
                             "user's day below. Plain text, numbered.", ctx)
            if "_error" in out:
                return self._json(502, {"error": out["_error"]})
            return self._json(200, {"prompt": out["text"]})

        return self._json(404, {"error": "not found"})

    def do_PUT(self):
        m = re.match(r"^/api/journal/(\d+)$", urllib.parse.urlparse(self.path).path)
        if not m or not self._need_auth():
            return self._json(404, {"error": "not found"})
        data = self._body()
        c = db().cursor()
        c.execute("UPDATE journal SET day=%s, title=%s, body=%s, email_refs=%s, "
                  "updated_at=now() WHERE id=%s",
                  (data.get("date"), data.get("title", "")[:200], data.get("body", ""),
                   json.dumps(data.get("email_refs", [])), int(m.group(1))))
        c.close()
        return self._json(200, {"ok": True})

    def do_DELETE(self):
        path = urllib.parse.urlparse(self.path).path
        if not self._need_auth():
            return
        m = re.match(r"^/api/accounts/(\d+)$", path)
        if m:
            aid = int(m.group(1))
            _access_cache.pop(aid, None)
            c = db().cursor()
            c.execute("DELETE FROM accounts WHERE id=%s", (aid,))
            c.close()
            return self._json(200, {"ok": True})
        m = re.match(r"^/api/journal/(\d+)$", path)
        if m:
            c = db().cursor()
            c.execute("DELETE FROM journal WHERE id=%s", (int(m.group(1)),))
            c.close()
            return self._json(200, {"ok": True})
        return self._json(404, {"error": "not found"})

    def log_message(self, *args):
        pass


def main():
    if not DATABASE_URL:
        raise SystemExit("DATABASE_URL is required")
    if not APP_PASSWORD:
        raise SystemExit("APP_PASSWORD is required")
    if not FERNET_KEY:
        raise SystemExit("FERNET_KEY is required")
    init_db()
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
