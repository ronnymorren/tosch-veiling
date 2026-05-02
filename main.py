import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import string
import time
import urllib.request
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path

import psycopg2
import psycopg2.extras
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jinja2 import Environment, FileSystemLoader
import anthropic
from ddgs import DDGS

# ── Configuratie ──────────────────────────────────────────────────────────────

load_dotenv(dotenv_path=Path(__file__).parent.parent.parent / ".env")   # gedeelde keys
load_dotenv(dotenv_path=Path(__file__).parent / ".env", override=True)  # project-specifiek

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "tosch2024")
SESSION_COOKIE = "tosch_admin"
SESSION_TTL    = 8 * 3600   # 8 uur
USER_COOKIE    = "tosch_user"
USER_TTL       = 8 * 3600   # 8 uur
DATABASE_URL   = os.getenv("DATABASE_URL", "")

# Windows = lokale dev; Linux/Mac = Vercel/server (voor afbeeldingslogica)
IS_VERCEL = os.name != "nt"


# ── Admin-sessie: gesigneerd cookie (geen server-side state nodig) ────────────

def _sign(ts: str) -> str:
    return hmac.new(ADMIN_PASSWORD.encode(), ts.encode(), hashlib.sha256).hexdigest()[:24]

def maak_admin_token() -> str:
    ts  = str(int(time.time()))
    raw = f"{ts}.{_sign(ts)}"
    return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")

def is_admin(request: Request) -> bool:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return False
    try:
        padded  = token + "=" * (4 - len(token) % 4)
        decoded = base64.urlsafe_b64decode(padded).decode()
        ts_str, sig = decoded.rsplit(".", 1)
        if int(time.time()) - int(ts_str) > SESSION_TTL:
            return False
        return hmac.compare_digest(sig, _sign(ts_str))
    except Exception:
        return False


# ── Bieder-sessie: gesigneerd cookie (geen server-side state) ─────────────────

def maak_user_token(naam: str, email: str) -> str:
    ts          = str(int(time.time()))
    payload_str = json.dumps({"naam": naam, "email": email, "ts": ts}, separators=(',', ':'))
    payload_b64 = base64.urlsafe_b64encode(payload_str.encode()).decode().rstrip("=")
    sig         = hmac.new(ADMIN_PASSWORD.encode(), payload_b64.encode(), hashlib.sha256).hexdigest()[:24]
    raw         = f"{payload_b64}.{sig}"
    return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")

def get_user(request: Request) -> dict | None:
    token = request.cookies.get(USER_COOKIE)
    if not token:
        return None
    try:
        padded      = token + "=" * (4 - len(token) % 4)
        decoded     = base64.urlsafe_b64decode(padded).decode()
        payload_b64, sig = decoded.rsplit(".", 1)
        expected    = hmac.new(ADMIN_PASSWORD.encode(), payload_b64.encode(), hashlib.sha256).hexdigest()[:24]
        if not hmac.compare_digest(sig, expected):
            return None
        padded2  = payload_b64 + "=" * (4 - len(payload_b64) % 4)
        payload  = json.loads(base64.urlsafe_b64decode(padded2).decode())
        if int(time.time()) - int(payload["ts"]) > USER_TTL:
            return None
        return {"naam": payload["naam"], "email": payload["email"]}
    except Exception:
        return None


# ── E-mail helper ─────────────────────────────────────────────────────────────

def stuur_email(to: str, subject: str, html_body: str, text_body: str):
    payload = json.dumps({
        "api_key":   os.getenv("SMTP2GO_API_KEY", ""),
        "to":        [to],
        "sender":    os.getenv("SMTP_FROM", "veilingen@tosch.nl"),
        "subject":   subject,
        "html_body": html_body,
        "text_body": text_body,
    }).encode()
    req = urllib.request.Request(
        "https://api.smtp2go.com/v3/email/send",
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        result = json.loads(r.read().decode())
    if result.get("data", {}).get("succeeded", 0) == 0:
        raise RuntimeError("SMTP2GO fout: " + str(result))


# ── Database ──────────────────────────────────────────────────────────────────

def get_conn():
    return psycopg2.connect(DATABASE_URL)

def get_cur(conn):
    return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

def init_db():
    conn = get_conn()
    cur  = get_cur(conn)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS auctions (
            id                         SERIAL  PRIMARY KEY,
            title                      TEXT    NOT NULL,
            description                TEXT,
            image_url                  TEXT,
            specs                      TEXT,
            start_price                FLOAT   NOT NULL,
            current_price              FLOAT   NOT NULL,
            min_increment              FLOAT   DEFAULT 1.0,
            end_time                   TEXT    NOT NULL,
            access_code                TEXT    UNIQUE NOT NULL,
            status                     TEXT    DEFAULT 'active',
            require_email_verification INTEGER DEFAULT 0,
            allowed_domains            TEXT    DEFAULT '',
            archived                   INTEGER DEFAULT 0
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS bids (
            id          SERIAL  PRIMARY KEY,
            auction_id  INTEGER NOT NULL,
            bidder_name TEXT    NOT NULL,
            amount      FLOAT   NOT NULL,
            timestamp   TEXT    NOT NULL,
            FOREIGN KEY (auction_id) REFERENCES auctions(id)
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS email_verifications (
            id         SERIAL  PRIMARY KEY,
            email      TEXT    NOT NULL,
            auction_id INTEGER NOT NULL,
            code       TEXT    NOT NULL,
            expires_at TEXT    NOT NULL,
            used       INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()

# Direct initialiseren bij import
try:
    init_db()
except Exception:
    pass


# ── App ───────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        init_db()
    except Exception:
        pass
    yield

app = FastAPI(lifespan=lifespan)

BASE = Path(__file__).parent
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
jinja_env = Environment(loader=FileSystemLoader(str(BASE / "templates")), cache_size=0)
jinja_env.filters["euro"] = lambda v: "€\xa0" + f"{v:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
templates = Jinja2Templates(env=jinja_env)


# ── Pagina's ──────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    if get_user(request):
        return RedirectResponse(url="/veilingen", status_code=303)
    return templates.TemplateResponse(request, "home.html")


@app.get("/veilingen", response_class=HTMLResponse)
async def veilingen_page(request: Request):
    user = get_user(request)
    if not user:
        return RedirectResponse(url="/", status_code=303)
    email  = user["email"]
    domain = email.split("@")[1] if "@" in email else ""
    conn = get_conn()
    cur  = get_cur(conn)
    cur.execute("SELECT * FROM auctions WHERE archived = 0 ORDER BY id DESC")
    rows = cur.fetchall()
    conn.close()
    now = datetime.now().isoformat()
    auctions = []
    for r in rows:
        d = dict(r)
        d["is_ended"] = now > d["end_time"]
        allowed_raw = (d.get("allowed_domains") or "").strip()
        if allowed_raw:
            allowed = [x.strip().lower() for x in allowed_raw.split(",") if x.strip()]
            if domain not in allowed:
                continue
        auctions.append(d)
    return templates.TemplateResponse(request, "veilingen.html", {"auctions": auctions, "user": user})


@app.get("/uitloggen")
async def uitloggen():
    resp = RedirectResponse(url="/", status_code=303)
    resp.delete_cookie(USER_COOKIE)
    return resp


# ── Admin: login / logout ─────────────────────────────────────────────────────

@app.get("/admin/login", response_class=HTMLResponse)
async def admin_login_get(request: Request, next: str = "/admin/overzicht"):
    if is_admin(request):
        return RedirectResponse(url=next, status_code=303)
    return templates.TemplateResponse(request, "admin_login.html", {"next": next})

@app.post("/admin/login", response_class=HTMLResponse)
async def admin_login_post(request: Request):
    form     = await request.form()
    password = str(form.get("password", ""))
    next_url = str(form.get("next", "/admin/overzicht"))

    if password != ADMIN_PASSWORD:
        return templates.TemplateResponse(request, "admin_login.html",
            {"error": "Verkeerd wachtwoord. Probeer opnieuw.", "next": next_url},
            status_code=401)

    token = maak_admin_token()
    resp  = RedirectResponse(url=next_url, status_code=303)
    resp.set_cookie(SESSION_COOKIE, token, httponly=True, max_age=SESSION_TTL, samesite="lax")
    return resp

@app.get("/admin/logout")
async def admin_logout():
    resp = RedirectResponse(url="/admin/login", status_code=303)
    resp.delete_cookie(SESSION_COOKIE)
    return resp


# ── Admin: pagina's (cookie-beschermd) ───────────────────────────────────────

@app.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request):
    if not is_admin(request):
        return RedirectResponse(url="/admin/login?next=/admin", status_code=303)
    return templates.TemplateResponse(request, "admin.html")

@app.get("/admin/overzicht", response_class=HTMLResponse)
async def admin_overzicht(request: Request):
    if not is_admin(request):
        return RedirectResponse(url="/admin/login?next=/admin/overzicht", status_code=303)
    conn = get_conn()
    cur  = get_cur(conn)
    cur.execute("""
        SELECT a.*, COUNT(b.id) as bid_count
        FROM auctions a
        LEFT JOIN bids b ON b.auction_id = a.id
        GROUP BY a.id
        ORDER BY a.id DESC
    """)
    rows = cur.fetchall()
    conn.close()
    now = datetime.now().isoformat()
    actief, archief = [], []
    for r in rows:
        d = dict(r)
        d["is_ended"] = now > d["end_time"]
        if d.get("archived"):
            archief.append(d)
        else:
            actief.append(d)
    return templates.TemplateResponse(request, "admin_overzicht.html",
        {"auctions": actief, "archief": archief})

@app.get("/veiling/{auction_id}", response_class=HTMLResponse)
async def auction_page(request: Request, auction_id: int):
    user = get_user(request)
    if not user:
        return RedirectResponse(url=f"/?next=/veiling/{auction_id}", status_code=303)
    conn = get_conn()
    cur  = get_cur(conn)
    cur.execute("SELECT id FROM auctions WHERE id = %s", (auction_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Veiling niet gevonden")
    return templates.TemplateResponse(request, "auction.html", {
        "auction_id": auction_id,
        "mijn_naam":  user["naam"],
        "mijn_email": user["email"],
    })


# ── API: veiling zoeken op code ───────────────────────────────────────────────

@app.get("/api/find")
async def find_auction(code: str):
    code = code.strip().upper()
    conn = get_conn()
    cur  = get_cur(conn)
    cur.execute("SELECT id FROM auctions WHERE access_code = %s", (code,))
    row = cur.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Code niet gevonden")
    return JSONResponse({"auction_id": row["id"]})


# ── API: product info (AI + foto) ─────────────────────────────────────────────

@app.post("/api/product-info")
async def product_info(request: Request):
    data = await request.json()
    product_name = data.get("product_name", "").strip()
    if not product_name:
        raise HTTPException(status_code=400, detail="Geen productnaam opgegeven")

    client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
    response = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=600,
        messages=[{
            "role": "user",
            "content": (
                f"Geef specificaties voor: {product_name}\n\n"
                "Geef de specs in dit exacte JSON formaat:\n"
                '{"beschrijving": "korte productomschrijving in 1 zin", '
                '"specs": [{"naam": "spec naam", "waarde": "spec waarde"}, ...]}\n\n'
                "Geef max 8 belangrijke specs. Antwoord ALLEEN met het JSON object."
            )
        }]
    )
    raw   = response.content[0].text
    match = re.search(r'\{.*\}', raw, re.DOTALL)
    try:
        product_data = json.loads(match.group()) if match else {}
    except Exception:
        product_data = {}

    beschrijving = product_data.get("beschrijving", product_name)
    specs        = product_data.get("specs", [])

    img_dir = BASE / "static" / "images"
    if not IS_VERCEL:
        img_dir.mkdir(exist_ok=True)

    zoekqueries = [
        f"{product_name} product white background PNG",
        f"{product_name} product foto wit",
        f"{product_name} official product photo",
    ]

    def probeer_download(url: str) -> str:
        if not url.startswith("https://"):
            return ""
        if IS_VERCEL:
            return url
        ext   = ".png" if ".png" in url.lower() else ".jpg"
        fname = secrets.token_hex(8) + ext
        dest  = img_dir / fname
        req   = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            raw_data = resp.read()
        if len(raw_data) < 5000:
            return ""
        with open(dest, "wb") as f:
            f.write(raw_data)
        return f"/static/images/{fname}"

    image_urls = []
    try:
        for query in zoekqueries:
            if len(image_urls) >= 5:
                break
            results = list(DDGS().images(query, max_results=20))
            check_field = "thumbnail" if IS_VERCEL else "image"
            results.sort(key=lambda r: 0 if ".png" in r.get(check_field, "").lower() else 1)
            for r in results:
                if len(image_urls) >= 5:
                    break
                ext_url   = r.get("image", "")
                thumb_url = r.get("thumbnail", "")
                if IS_VERCEL:
                    if thumb_url.startswith("https://"):
                        use_url = thumb_url
                    elif ext_url.startswith("https://"):
                        use_url = ext_url
                    else:
                        continue
                else:
                    if not ext_url.startswith("https://"):
                        continue
                    use_url = ext_url
                try:
                    local = probeer_download(use_url)
                    if local and local not in image_urls:
                        image_urls.append(local)
                except Exception:
                    continue
    except Exception:
        pass

    return JSONResponse({
        "beschrijving": beschrijving,
        "specs":        specs,
        "image_urls":   image_urls,
        "image_url":    image_urls[0] if image_urls else "",
    })


# ── API: veiling aanmaken ─────────────────────────────────────────────────────

@app.post("/api/auction/create")
async def create_auction(request: Request):
    data = await request.json()

    if data.get("admin_password") != ADMIN_PASSWORD:
        raise HTTPException(status_code=403, detail="Verkeerd beheerderswachtwoord")

    access_code = "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(6))

    conn = get_conn()
    cur  = get_cur(conn)
    cur.execute("""
        INSERT INTO auctions
            (title, description, image_url, specs, start_price, current_price,
             min_increment, end_time, access_code,
             require_email_verification, allowed_domains)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id
    """, (
        data["title"],
        data.get("description", ""),
        data.get("image_url", ""),
        json.dumps(data.get("specs", [])),
        float(data["start_price"]),
        float(data["start_price"]),
        float(data.get("min_increment", 1.0)),
        data["end_time"],
        access_code,
        1 if data.get("require_email_verification") else 0,
        data.get("allowed_domains", "").strip(),
    ))
    auction_id = cur.fetchone()["id"]
    conn.commit()
    conn.close()

    return JSONResponse({"auction_id": auction_id, "access_code": access_code})


# ── API: image proxy (omzeilt hotlink-beveiliging van externe URLs) ───────────

@app.get("/api/image-proxy")
async def image_proxy(url: str):
    if not url.startswith("https://"):
        raise HTTPException(400, "Ongeldige URL")
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                "Referer": "https://www.bing.com/",
                "Accept": "image/webp,image/apng,image/*,*/*;q=0.8",
            },
        )
        with urllib.request.urlopen(req, timeout=8) as r:
            content      = r.read()
            content_type = r.headers.get("Content-Type", "image/jpeg").split(";")[0]
        return Response(content=content, media_type=content_type,
                        headers={"Cache-Control": "public, max-age=86400"})
    except Exception:
        raise HTTPException(404, "Afbeelding niet beschikbaar")


# ── API: veiling ophalen ──────────────────────────────────────────────────────

@app.get("/api/auction/{auction_id}")
async def get_auction(auction_id: int):
    conn = get_conn()
    cur  = get_cur(conn)
    cur.execute("SELECT * FROM auctions WHERE id = %s", (auction_id,))
    row = cur.fetchone()
    cur.execute(
        "SELECT * FROM bids WHERE auction_id = %s ORDER BY amount DESC LIMIT 20",
        (auction_id,)
    )
    bids = cur.fetchall()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Veiling niet gevonden")

    end_time  = datetime.fromisoformat(row["end_time"])
    is_ended  = datetime.now() > end_time or row["status"] == "ended"
    req_email = bool(row["require_email_verification"])

    winner = None
    if is_ended and bids:
        winner = bids[0]["bidder_name"]

    return JSONResponse({
        "id":                         row["id"],
        "title":                      row["title"],
        "description":                row["description"],
        "image_url":                  row["image_url"],
        "specs":                      json.loads(row["specs"] or "[]"),
        "start_price":                row["start_price"],
        "current_price":              row["current_price"],
        "min_increment":              row["min_increment"],
        "end_time":                   row["end_time"],
        "status":                     "ended" if is_ended else "active",
        "winner":                     winner,
        "bids":                       [dict(b) for b in bids],
        "require_email_verification": req_email,
        "access_code":                row["access_code"] if not req_email else None,
    })


# ── API: e-mailverificatie – code versturen ───────────────────────────────────

@app.post("/api/auth/send-code")
async def send_code(request: Request):
    data       = await request.json()
    email      = data.get("email", "").strip().lower()
    auction_id = int(data.get("auction_id", 0))

    if not email or "@" not in email or "." not in email.split("@")[-1]:
        raise HTTPException(400, "Ongeldig e-mailadres")

    conn = get_conn()
    cur  = get_cur(conn)
    cur.execute("SELECT * FROM auctions WHERE id = %s", (auction_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "Veiling niet gevonden")

    allowed_raw = (row["allowed_domains"] or "").strip()
    if allowed_raw:
        allowed = [d.strip().lower() for d in allowed_raw.split(",") if d.strip()]
        domain  = email.split("@")[1]
        if domain not in allowed:
            conn.close()
            raise HTTPException(403, f"Alleen e-mailadressen van {', '.join(allowed)} zijn toegestaan")

    code       = "".join(secrets.choice("0123456789") for _ in range(6))
    expires_at = (datetime.now() + timedelta(minutes=10)).isoformat()

    cur.execute("DELETE FROM email_verifications WHERE email = %s AND auction_id = %s", (email, auction_id))
    cur.execute(
        "INSERT INTO email_verifications (email, auction_id, code, expires_at) VALUES (%s, %s, %s, %s)",
        (email, auction_id, code, expires_at)
    )
    conn.commit()
    conn.close()

    html = f"""
    <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto">
      <div style="background:#FF6F00;padding:20px 24px;border-radius:12px 12px 0 0">
        <h1 style="color:#fff;margin:0;font-size:1.3rem;font-weight:800">Tosch Veiling</h1>
      </div>
      <div style="background:#fff;padding:32px 24px;border:1px solid #e5e7eb;border-radius:0 0 12px 12px">
        <p style="color:#374151;margin:0 0 24px">
          Gebruik onderstaande code om deel te nemen aan de veiling
          <strong>{row['title']}</strong>:
        </p>
        <div style="background:#f9fafb;border:2px solid #e5e7eb;border-radius:12px;
                    padding:28px;text-align:center;margin-bottom:24px">
          <div style="font-size:2.8rem;font-weight:800;letter-spacing:14px;
                      color:#111827;font-family:monospace">{code}</div>
        </div>
        <p style="color:#6b7280;font-size:.875rem;margin:0">
          Deze code is 10 minuten geldig. Niet aangevraagd? Dan kun je deze mail negeren.
        </p>
      </div>
    </div>"""

    try:
        stuur_email(
            email,
            f"Verificatiecode – {row['title']}",
            html,
            f"Uw verificatiecode: {code}\n\nGeldig voor 10 minuten.",
        )
    except Exception as e:
        detail = str(e)
        raise HTTPException(500, f"E-mail versturen mislukt: {detail}")

    return JSONResponse({"ok": True})


# ── API: e-mailverificatie – code controleren ─────────────────────────────────

@app.post("/api/auth/verify-code")
async def verify_code(request: Request):
    data       = await request.json()
    email      = data.get("email", "").strip().lower()
    code       = data.get("code", "").strip()
    auction_id = int(data.get("auction_id", 0))

    conn = get_conn()
    cur  = get_cur(conn)
    cur.execute(
        "SELECT * FROM email_verifications "
        "WHERE email = %s AND auction_id = %s AND used = 0 "
        "ORDER BY id DESC LIMIT 1",
        (email, auction_id)
    )
    row = cur.fetchone()

    if not row:
        conn.close()
        raise HTTPException(400, "Geen actieve code gevonden. Vraag een nieuwe code aan.")
    if datetime.now() > datetime.fromisoformat(row["expires_at"]):
        conn.close()
        raise HTTPException(400, "Code verlopen. Vraag een nieuwe code aan.")
    if row["code"] != code:
        conn.close()
        raise HTTPException(400, "Onjuiste code. Probeer opnieuw.")

    cur.execute("UPDATE email_verifications SET used = 1 WHERE id = %s", (row["id"],))
    conn.commit()
    cur.execute("SELECT access_code FROM auctions WHERE id = %s", (auction_id,))
    auction = cur.fetchone()
    conn.close()

    return JSONResponse({"ok": True, "access_code": auction["access_code"]})


# ── API: globale login – code versturen ──────────────────────────────────────

@app.post("/api/auth/send-login-code")
async def send_login_code(request: Request):
    data  = await request.json()
    naam  = data.get("naam", "").strip()
    email = data.get("email", "").strip().lower()

    if not naam:
        raise HTTPException(400, "Vul je naam in")
    if not email or "@" not in email or "." not in email.split("@")[-1]:
        raise HTTPException(400, "Ongeldig e-mailadres")

    code       = "".join(secrets.choice("0123456789") for _ in range(6))
    expires_at = (datetime.now() + timedelta(minutes=10)).isoformat()

    conn = get_conn()
    cur  = get_cur(conn)
    # auction_id = 0 is schildwacht voor globale login (geen specifieke veiling)
    cur.execute("DELETE FROM email_verifications WHERE email = %s AND auction_id = 0", (email,))
    cur.execute(
        "INSERT INTO email_verifications (email, auction_id, code, expires_at) VALUES (%s, 0, %s, %s)",
        (email, code, expires_at)
    )
    conn.commit()
    conn.close()

    html = f"""
    <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto">
      <div style="background:#FF6F00;padding:20px 24px;border-radius:12px 12px 0 0">
        <h1 style="color:#fff;margin:0;font-size:1.3rem;font-weight:800">Tosch Veiling</h1>
      </div>
      <div style="background:#fff;padding:32px 24px;border:1px solid #e5e7eb;border-radius:0 0 12px 12px">
        <p style="color:#374151;margin:0 0 24px">
          Hallo <strong>{naam}</strong>,<br><br>
          Gebruik onderstaande code om in te loggen op de Tosch Veiling:
        </p>
        <div style="background:#f9fafb;border:2px solid #e5e7eb;border-radius:12px;
                    padding:28px;text-align:center;margin-bottom:24px">
          <div style="font-size:2.8rem;font-weight:800;letter-spacing:14px;
                      color:#111827;font-family:monospace">{code}</div>
        </div>
        <p style="color:#6b7280;font-size:.875rem;margin:0">
          Deze code is 10 minuten geldig. Niet aangevraagd? Dan kun je deze mail negeren.
        </p>
      </div>
    </div>"""

    try:
        stuur_email(email, "Inlogcode – Tosch Veiling", html,
                    f"Jouw inlogcode: {code}\n\nGeldig voor 10 minuten.")
    except Exception as e:
        raise HTTPException(500, f"E-mail versturen mislukt: {e}")

    return JSONResponse({"ok": True})


# ── API: globale login – code controleren ─────────────────────────────────────

@app.post("/api/auth/verify-login-code")
async def verify_login_code(request: Request):
    data  = await request.json()
    naam  = data.get("naam", "").strip()
    email = data.get("email", "").strip().lower()
    code  = data.get("code", "").strip()

    if not naam or not email or not code:
        raise HTTPException(400, "Ontbrekende gegevens")

    conn = get_conn()
    cur  = get_cur(conn)
    cur.execute(
        "SELECT * FROM email_verifications "
        "WHERE email = %s AND auction_id = 0 AND used = 0 "
        "ORDER BY id DESC LIMIT 1",
        (email,)
    )
    row = cur.fetchone()

    if not row:
        conn.close()
        raise HTTPException(400, "Geen actieve code gevonden. Vraag een nieuwe code aan.")
    if datetime.now() > datetime.fromisoformat(row["expires_at"]):
        conn.close()
        raise HTTPException(400, "Code verlopen. Vraag een nieuwe code aan.")
    if row["code"] != code:
        conn.close()
        raise HTTPException(400, "Onjuiste code. Probeer opnieuw.")

    cur.execute("UPDATE email_verifications SET used = 1 WHERE id = %s", (row["id"],))
    conn.commit()
    conn.close()

    token = maak_user_token(naam, email)
    resp  = JSONResponse({"ok": True})
    resp.set_cookie(USER_COOKIE, token, httponly=True, max_age=USER_TTL, samesite="lax")
    return resp


# ── API: bod plaatsen ─────────────────────────────────────────────────────────

@app.post("/api/bid")
async def place_bid(request: Request):
    user = get_user(request)
    if not user:
        raise HTTPException(status_code=403, detail="Niet ingelogd — ga naar de homepage")

    data        = await request.json()
    auction_id  = int(data["auction_id"])
    amount      = float(data["amount"])
    bidder_name = user["naam"]
    email       = user["email"]

    conn = get_conn()
    cur  = get_cur(conn)
    cur.execute("SELECT * FROM auctions WHERE id = %s", (auction_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Veiling niet gevonden")

    # Domeincontrole
    allowed_raw = (row["allowed_domains"] or "").strip()
    if allowed_raw:
        allowed = [d.strip().lower() for d in allowed_raw.split(",") if d.strip()]
        domain  = email.split("@")[1] if "@" in email else ""
        if domain not in allowed:
            conn.close()
            raise HTTPException(status_code=403, detail="Je e-mailadres heeft geen toegang tot deze veiling")

    end_time = datetime.fromisoformat(row["end_time"])
    if datetime.now() > end_time:
        conn.close()
        raise HTTPException(status_code=400, detail="De veiling is al afgelopen")

    cur.execute("SELECT 1 FROM bids WHERE auction_id = %s LIMIT 1", (auction_id,))
    heeft_biedingen = cur.fetchone() is not None
    min_bid = (row["current_price"] + row["min_increment"]) if heeft_biedingen else row["start_price"]
    if amount < min_bid:
        conn.close()
        raise HTTPException(status_code=400, detail=f"Minimaal bod is €{min_bid:.2f}")

    timestamp = datetime.now().isoformat()
    cur.execute(
        "INSERT INTO bids (auction_id, bidder_name, amount, timestamp) VALUES (%s, %s, %s, %s)",
        (auction_id, bidder_name, amount, timestamp)
    )
    cur.execute("UPDATE auctions SET current_price = %s WHERE id = %s", (amount, auction_id))
    conn.commit()
    conn.close()

    return JSONResponse({"success": True})


# ── API: bod verwijderen (admin) ──────────────────────────────────────────────

@app.delete("/api/bid/{bid_id}")
async def delete_bid(bid_id: int, request: Request):
    if not is_admin(request):
        raise HTTPException(status_code=403, detail="Geen toegang")

    conn = get_conn()
    cur  = get_cur(conn)
    cur.execute("SELECT * FROM bids WHERE id = %s", (bid_id,))
    bid = cur.fetchone()
    if not bid:
        conn.close()
        raise HTTPException(status_code=404, detail="Bod niet gevonden")

    auction_id = bid["auction_id"]
    cur.execute("DELETE FROM bids WHERE id = %s", (bid_id,))
    cur.execute("SELECT MAX(amount) as top FROM bids WHERE auction_id = %s", (auction_id,))
    top = cur.fetchone()
    cur.execute("SELECT start_price FROM auctions WHERE id = %s", (auction_id,))
    auction = cur.fetchone()
    new_price = top["top"] if top["top"] is not None else auction["start_price"]
    cur.execute("UPDATE auctions SET current_price = %s WHERE id = %s", (new_price, auction_id))
    conn.commit()
    conn.close()

    return JSONResponse({"ok": True, "new_price": new_price})


# ── API: archiveren ───────────────────────────────────────────────────────────

@app.post("/api/auction/{auction_id}/archive")
async def archive_auction(auction_id: int, request: Request):
    if not is_admin(request):
        raise HTTPException(status_code=403, detail="Geen toegang")
    conn = get_conn()
    cur  = get_cur(conn)
    cur.execute("UPDATE auctions SET archived = 1 WHERE id = %s", (auction_id,))
    conn.commit()
    conn.close()
    return JSONResponse({"ok": True})

@app.post("/api/auction/{auction_id}/unarchive")
async def unarchive_auction(auction_id: int, request: Request):
    if not is_admin(request):
        raise HTTPException(status_code=403, detail="Geen toegang")
    conn = get_conn()
    cur  = get_cur(conn)
    cur.execute("UPDATE auctions SET archived = 0 WHERE id = %s", (auction_id,))
    conn.commit()
    conn.close()
    return JSONResponse({"ok": True})


# ── Admin: biedingenbeheer ────────────────────────────────────────────────────

@app.get("/admin/veiling/{auction_id}/biedingen", response_class=HTMLResponse)
async def admin_biedingen(request: Request, auction_id: int):
    if not is_admin(request):
        return RedirectResponse(
            url=f"/admin/login?next=/admin/veiling/{auction_id}/biedingen", status_code=303
        )
    conn = get_conn()
    cur  = get_cur(conn)
    cur.execute("SELECT * FROM auctions WHERE id = %s", (auction_id,))
    auction = cur.fetchone()
    if not auction:
        conn.close()
        raise HTTPException(status_code=404, detail="Veiling niet gevonden")
    cur.execute(
        "SELECT * FROM bids WHERE auction_id = %s ORDER BY amount DESC", (auction_id,)
    )
    bids = cur.fetchall()
    conn.close()
    return templates.TemplateResponse(request, "admin_biedingen.html", {
        "auction": dict(auction),
        "bids":    [dict(b) for b in bids],
    })
