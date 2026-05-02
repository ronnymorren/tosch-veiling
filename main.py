import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import string
import time
import urllib.request
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path

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

IS_VERCEL      = bool(os.environ.get("VERCEL"))
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "tosch2024")
SESSION_COOKIE = "tosch_admin"
SESSION_TTL    = 8 * 3600   # 8 uur

# Windows = lokale dev → naast main.py; Linux/Mac = Vercel/server → /tmp
# (betrouwbaarder dan VERCEL env var die soms te laat beschikbaar is)
if os.name == "nt":
    DB_PATH = Path(__file__).parent / "veiling.db"
else:
    DB_PATH = Path("/tmp/veiling.db")


# ── Admin-sessie: gesigneerd cookie (geen server-side state nodig) ────────────
# Werkt op serverless omdat er geen in-memory dict nodig is.

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
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS auctions (
            id                         INTEGER PRIMARY KEY AUTOINCREMENT,
            title                      TEXT    NOT NULL,
            description                TEXT,
            image_url                  TEXT,
            specs                      TEXT,
            start_price                REAL    NOT NULL,
            current_price              REAL    NOT NULL,
            min_increment              REAL    DEFAULT 1.0,
            end_time                   TEXT    NOT NULL,
            access_code                TEXT    UNIQUE NOT NULL,
            status                     TEXT    DEFAULT 'active',
            require_email_verification INTEGER DEFAULT 0,
            allowed_domains            TEXT    DEFAULT ''
        )
    """)
    for col, dfn in [
        ("require_email_verification", "INTEGER DEFAULT 0"),
        ("allowed_domains",            "TEXT DEFAULT ''"),
        ("archived",                   "INTEGER DEFAULT 0"),
    ]:
        try:
            conn.execute(f"ALTER TABLE auctions ADD COLUMN {col} {dfn}")
            conn.commit()
        except Exception:
            pass
    conn.execute("""
        CREATE TABLE IF NOT EXISTS bids (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            auction_id  INTEGER NOT NULL,
            bidder_name TEXT    NOT NULL,
            amount      REAL    NOT NULL,
            timestamp   TEXT    NOT NULL,
            FOREIGN KEY (auction_id) REFERENCES auctions(id)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS email_verifications (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            email      TEXT    NOT NULL,
            auction_id INTEGER NOT NULL,
            code       TEXT    NOT NULL,
            expires_at TEXT    NOT NULL,
            used       INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()

# Direct initialiseren bij import (fallback voor Vercel zonder lifespan)
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
templates = Jinja2Templates(env=jinja_env)


# ── Pagina's ──────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(request, "home.html")


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
    rows = conn.execute("""
        SELECT a.*, COUNT(b.id) as bid_count
        FROM auctions a
        LEFT JOIN bids b ON b.auction_id = a.id
        GROUP BY a.id
        ORDER BY a.id DESC
    """).fetchall()
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
    conn = get_conn()
    row = conn.execute("SELECT id FROM auctions WHERE id = ?", (auction_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Veiling niet gevonden")
    return templates.TemplateResponse(request, "auction.html", {"auction_id": auction_id})


# ── API: veiling zoeken op code ───────────────────────────────────────────────

@app.get("/api/find")
async def find_auction(code: str):
    code = code.strip().upper()
    conn = get_conn()
    row = conn.execute("SELECT id FROM auctions WHERE access_code = ?", (code,)).fetchone()
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

    # Afbeeldingen zoeken
    # Op Vercel: externe URL direct gebruiken (geen schrijftoegang buiten /tmp)
    # Lokaal: downloaden naar static/images/
    img_dir = BASE / "static" / "images"
    if not IS_VERCEL:
        img_dir.mkdir(exist_ok=True)

    zoekqueries = [
        f"{product_name} product white background PNG",
        f"{product_name} product foto wit",
        f"{product_name} official product photo",
    ]

    def probeer_download(url: str) -> str:
        if IS_VERCEL:
            return url  # externe URL direct bewaren
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
            results.sort(key=lambda r: 0 if ".png" in r.get("image", "").lower() else 1)
            for r in results:
                if len(image_urls) >= 5:
                    break
                ext_url = r.get("image", "")
                if not ext_url.startswith("https"):
                    continue
                try:
                    local = probeer_download(ext_url)
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
    cursor = conn.execute("""
        INSERT INTO auctions
            (title, description, image_url, specs, start_price, current_price,
             min_increment, end_time, access_code,
             require_email_verification, allowed_domains)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
    auction_id = cursor.lastrowid
    conn.commit()
    conn.close()

    return JSONResponse({"auction_id": auction_id, "access_code": access_code})


# ── API: veiling ophalen ──────────────────────────────────────────────────────

# ── API: image proxy (omzeilt hotlink-beveiliging van externe URLs) ───────────

@app.get("/api/image-proxy")
async def image_proxy(url: str):
    if not url.startswith("https://"):
        raise HTTPException(400, "Ongeldige URL")
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (compatible; ToschVeiling/1.0)"},
        )
        with urllib.request.urlopen(req, timeout=8) as r:
            content      = r.read()
            content_type = r.headers.get("Content-Type", "image/jpeg").split(";")[0]
        return Response(content=content, media_type=content_type,
                        headers={"Cache-Control": "public, max-age=86400"})
    except Exception:
        raise HTTPException(404, "Afbeelding niet beschikbaar")


@app.get("/api/auction/{auction_id}")
async def get_auction(auction_id: int):
    conn = get_conn()
    row  = conn.execute("SELECT * FROM auctions WHERE id = ?", (auction_id,)).fetchone()
    bids = conn.execute(
        "SELECT * FROM bids WHERE auction_id = ? ORDER BY amount DESC LIMIT 20",
        (auction_id,)
    ).fetchall()
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
    row  = conn.execute("SELECT * FROM auctions WHERE id = ?", (auction_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "Veiling niet gevonden")

    allowed_raw = (row["allowed_domains"] or "").strip()
    if allowed_raw:
        allowed = [d.strip().lower() for d in allowed_raw.split(",") if d.strip()]
        domain  = email.split("@")[1]
        if domain not in allowed:
            raise HTTPException(403, f"Alleen e-mailadressen van {', '.join(allowed)} zijn toegestaan")

    code       = "".join(secrets.choice("0123456789") for _ in range(6))
    expires_at = (datetime.now() + timedelta(minutes=10)).isoformat()

    conn = get_conn()
    conn.execute("DELETE FROM email_verifications WHERE email = ? AND auction_id = ?", (email, auction_id))
    conn.execute(
        "INSERT INTO email_verifications (email, auction_id, code, expires_at) VALUES (?, ?, ?, ?)",
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
        # Geef de exacte SMTP2GO-fout terug zodat problemen zichtbaar zijn
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
    row  = conn.execute(
        "SELECT * FROM email_verifications "
        "WHERE email = ? AND auction_id = ? AND used = 0 "
        "ORDER BY id DESC LIMIT 1",
        (email, auction_id)
    ).fetchone()

    if not row:
        conn.close()
        raise HTTPException(400, "Geen actieve code gevonden. Vraag een nieuwe code aan.")
    if datetime.now() > datetime.fromisoformat(row["expires_at"]):
        conn.close()
        raise HTTPException(400, "Code verlopen. Vraag een nieuwe code aan.")
    if row["code"] != code:
        conn.close()
        raise HTTPException(400, "Onjuiste code. Probeer opnieuw.")

    conn.execute("UPDATE email_verifications SET used = 1 WHERE id = ?", (row["id"],))
    conn.commit()
    auction = conn.execute("SELECT access_code FROM auctions WHERE id = ?", (auction_id,)).fetchone()
    conn.close()

    return JSONResponse({"ok": True, "access_code": auction["access_code"]})


# ── API: bod plaatsen ─────────────────────────────────────────────────────────

@app.post("/api/bid")
async def place_bid(request: Request):
    data        = await request.json()
    auction_id  = int(data["auction_id"])
    bidder_name = data["bidder_name"].strip()
    amount      = float(data["amount"])
    access_code = data["access_code"].strip().upper()

    if not bidder_name:
        raise HTTPException(status_code=400, detail="Vul je naam in")

    conn = get_conn()
    row  = conn.execute("SELECT * FROM auctions WHERE id = ?", (auction_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Veiling niet gevonden")
    if row["access_code"] != access_code:
        conn.close()
        raise HTTPException(status_code=403, detail="Toegang geweigerd")

    end_time = datetime.fromisoformat(row["end_time"])
    if datetime.now() > end_time:
        conn.close()
        raise HTTPException(status_code=400, detail="De veiling is al afgelopen")

    heeft_biedingen = conn.execute(
        "SELECT 1 FROM bids WHERE auction_id = ? LIMIT 1", (auction_id,)
    ).fetchone() is not None
    min_bid = (row["current_price"] + row["min_increment"]) if heeft_biedingen else row["start_price"]
    if amount < min_bid:
        conn.close()
        raise HTTPException(status_code=400, detail=f"Minimaal bod is €{min_bid:.2f}")

    timestamp = datetime.now().isoformat()
    conn.execute(
        "INSERT INTO bids (auction_id, bidder_name, amount, timestamp) VALUES (?, ?, ?, ?)",
        (auction_id, bidder_name, amount, timestamp)
    )
    conn.execute("UPDATE auctions SET current_price = ? WHERE id = ?", (amount, auction_id))
    conn.commit()
    conn.close()

    return JSONResponse({"success": True})


# ── API: bod verwijderen (admin) ──────────────────────────────────────────────

@app.delete("/api/bid/{bid_id}")
async def delete_bid(bid_id: int, request: Request):
    if not is_admin(request):
        raise HTTPException(status_code=403, detail="Geen toegang")

    conn = get_conn()
    bid  = conn.execute("SELECT * FROM bids WHERE id = ?", (bid_id,)).fetchone()
    if not bid:
        conn.close()
        raise HTTPException(status_code=404, detail="Bod niet gevonden")

    auction_id = bid["auction_id"]
    conn.execute("DELETE FROM bids WHERE id = ?", (bid_id,))

    top     = conn.execute("SELECT MAX(amount) as top FROM bids WHERE auction_id = ?", (auction_id,)).fetchone()
    auction = conn.execute("SELECT start_price FROM auctions WHERE id = ?", (auction_id,)).fetchone()
    new_price = top["top"] if top["top"] is not None else auction["start_price"]
    conn.execute("UPDATE auctions SET current_price = ? WHERE id = ?", (new_price, auction_id))
    conn.commit()
    conn.close()

    return JSONResponse({"ok": True, "new_price": new_price})


# ── API: archiveren ───────────────────────────────────────────────────────────

@app.post("/api/auction/{auction_id}/archive")
async def archive_auction(auction_id: int, request: Request):
    if not is_admin(request):
        raise HTTPException(status_code=403, detail="Geen toegang")
    conn = get_conn()
    conn.execute("UPDATE auctions SET archived = 1 WHERE id = ?", (auction_id,))
    conn.commit()
    conn.close()
    return JSONResponse({"ok": True})

@app.post("/api/auction/{auction_id}/unarchive")
async def unarchive_auction(auction_id: int, request: Request):
    if not is_admin(request):
        raise HTTPException(status_code=403, detail="Geen toegang")
    conn = get_conn()
    conn.execute("UPDATE auctions SET archived = 0 WHERE id = ?", (auction_id,))
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
    conn    = get_conn()
    auction = conn.execute("SELECT * FROM auctions WHERE id = ?", (auction_id,)).fetchone()
    if not auction:
        conn.close()
        raise HTTPException(status_code=404, detail="Veiling niet gevonden")
    bids = conn.execute(
        "SELECT * FROM bids WHERE auction_id = ? ORDER BY amount DESC", (auction_id,)
    ).fetchall()
    conn.close()
    return templates.TemplateResponse(request, "admin_biedingen.html", {
        "auction": dict(auction),
        "bids":    [dict(b) for b in bids],
    })
