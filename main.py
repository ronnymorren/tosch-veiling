import base64
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import string
import sys
import time
import urllib.request
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

AMS = ZoneInfo("Europe/Amsterdam")

def nu() -> datetime:
    """Huidige tijd in Amsterdam-tijdzone (naïef ISO-formaat voor DB-opslag)."""
    return datetime.now(AMS).replace(tzinfo=None)

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

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")      # niet meer vereist, behouden voor backward compat
SESSION_SECRET = os.getenv("SESSION_SECRET")
DATABASE_URL   = os.getenv("DATABASE_URL", "")
SESSION_COOKIE = "tosch_admin"
SESSION_TTL    = 40 * 3600
USER_COOKIE    = "tosch_user"
USER_TTL       = 30 * 24 * 3600   # 30 dagen geldig
USER_REFRESH_NA = 24 * 3600       # cookie ouder dan 1 dag? → stilzwijgend verlengen bij activiteit

# Vaste eigenaren — worden bij opstart in de database gezaaid
EIGENAREN = ["rm@tosch.nl", "dm@tosch.nl"]

if not SESSION_SECRET:
    raise RuntimeError("SESSION_SECRET is niet ingesteld. Voeg toe aan .env of Vercel Environment Variables.")

# Windows = lokale dev; Linux/Mac = Vercel/server (voor afbeeldingslogica)
IS_VERCEL = os.name != "nt"


# ── Rolgebaseerde toegangscontrole ────────────────────────────────────────────

def haal_rol(cur, email: str) -> str:
    """Rol opzoeken via een al geopende cursor — voorkomt een extra
    databaseverbinding (elke verbinding kost een TLS-handshake op serverless)."""
    cur.execute("SELECT role FROM users WHERE email = %s", (email,))
    row = cur.fetchone()
    return (row["role"] or "participant") if row else "participant"

def get_user_role(email: str) -> str:
    """Haal de rol op van een gebruiker uit de database. Standaard: 'participant'.
    Opent een eigen verbinding — gebruik in page-routes liever haal_rol(cur, email)."""
    try:
        conn = get_conn()
        cur  = get_cur(conn)
        role = haal_rol(cur, email)
        conn.close()
        return role
    except Exception:
        return "participant"

def is_admin(request: Request) -> bool:
    """True als de ingelogde gebruiker beheerder of eigenaar is."""
    user = get_user(request)
    if not user:
        return False
    return get_user_role(user["email"]) in ("manager", "owner")

def is_owner(request: Request) -> bool:
    """True als de ingelogde gebruiker eigenaar is."""
    user = get_user(request)
    if not user:
        return False
    return get_user_role(user["email"]) == "owner"

def log_audit(actor_email: str, action: str, target: str = None, ip: str = None):
    """Schrijf een beheersactie naar de auditlog."""
    try:
        conn = get_conn()
        cur  = get_cur(conn)
        cur.execute(
            "INSERT INTO admin_audit (actor_email, action, target, ip, created_at) "
            "VALUES (%s, %s, %s, %s, %s)",
            (actor_email, action, target, ip, nu().isoformat())
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


# ── Bieder-sessie: gesigneerd cookie (geen server-side state) ─────────────────

def maak_user_token(naam: str, email: str) -> str:
    ts          = str(int(time.time()))
    payload_str = json.dumps({"naam": naam, "email": email, "ts": ts}, separators=(',', ':'))
    payload_b64 = base64.urlsafe_b64encode(payload_str.encode()).decode().rstrip("=")
    sig         = hmac.new(SESSION_SECRET.encode(), payload_b64.encode(), hashlib.sha256).hexdigest()[:24]  # 🔒 Fix 3
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
        expected    = hmac.new(SESSION_SECRET.encode(), payload_b64.encode(), hashlib.sha256).hexdigest()[:24]  # 🔒 Fix 3
        if not hmac.compare_digest(sig, expected):
            return None
        padded2  = payload_b64 + "=" * (4 - len(payload_b64) % 4)
        payload  = json.loads(base64.urlsafe_b64decode(padded2).decode())
        if int(time.time()) - int(payload["ts"]) > USER_TTL:
            return None
        return {"naam": payload["naam"], "email": payload["email"], "ts": int(payload["ts"])}
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


# ── IP-adres helper ──────────────────────────────────────────────────────────

def get_client_ip(request: Request) -> str:
    """Haal het werkelijke IP-adres op (ook achter Vercel's proxy)."""
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[-1].strip()  # 🔒 Fix 4: laatste IP = door Vercel toegevoegd, niet aanvaller-controleerbaar
    return request.client.host if request.client else ""


# ── Afloopmail ────────────────────────────────────────────────────────────────

def stuur_afloop_mail(to: str, titel: str, winnaar: str, winnend_bod: float, is_winner: bool):
    """Stuur een afloopmail naar een deelnemer. Winnaar krijgt felicitaties, rest een 'afgelopen'-melding."""
    bod_str = f"€\xa0{winnend_bod:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")

    if is_winner:
        onderwerp = f"🎉 Gefeliciteerd! Je hebt gewonnen — {titel}"
        intro     = f"Gefeliciteerd, {winnaar}!<br><br>Je hebt de veiling <strong>{titel}</strong> gewonnen met het hoogste bod van <strong>{bod_str}</strong>."
        intro_txt = f"Gefeliciteerd, {winnaar}!\n\nJe hebt de veiling '{titel}' gewonnen met het hoogste bod van {bod_str}."
    else:
        onderwerp = f"Veiling afgelopen — {titel}"
        intro     = f"De veiling <strong>{titel}</strong> is afgelopen. De winnaar is <strong>{winnaar}</strong> met een bod van <strong>{bod_str}</strong>. Helaas was jouw bod niet het hoogste."
        intro_txt = f"De veiling '{titel}' is afgelopen.\n\nDe winnaar is {winnaar} met een bod van {bod_str}.\nHelaas was jouw bod niet het hoogste."

    html = f"""
    <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto">
      <div style="background:#FF6F00;padding:20px 24px;border-radius:12px 12px 0 0">
        <h1 style="color:#fff;margin:0;font-size:1.3rem;font-weight:800">Tosch Veiling</h1>
      </div>
      <div style="background:#fff;padding:32px 24px;border:1px solid #e5e7eb;border-radius:0 0 12px 12px">
        <p style="color:#374151;margin:0 0 24px">{intro}</p>
        <p style="color:#6b7280;font-size:.875rem;margin:0">
          Bedankt voor jouw deelname. Houd onze volgende veilingen in de gaten via
          <a href="https://veiling.tosch.nl" style="color:#FF6F00">veiling.tosch.nl</a>.
        </p>
      </div>
    </div>"""

    stuur_email(to, onderwerp, html, intro_txt)


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
            archived                   INTEGER DEFAULT 0,
            notified                   INTEGER DEFAULT 0
        )
    """)
    cur.execute("ALTER TABLE auctions ADD COLUMN IF NOT EXISTS notified INTEGER DEFAULT 0")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS bids (
            id          SERIAL  PRIMARY KEY,
            auction_id  INTEGER NOT NULL,
            bidder_name TEXT    NOT NULL,
            amount      FLOAT   NOT NULL,
            timestamp   TEXT    NOT NULL,
            email       TEXT,
            ip_address  TEXT,
            FOREIGN KEY (auction_id) REFERENCES auctions(id)
        )
    """)
    # Migratie: kolommen toevoegen als ze nog niet bestaan
    cur.execute("ALTER TABLE bids ADD COLUMN IF NOT EXISTS email TEXT")
    cur.execute("ALTER TABLE bids ADD COLUMN IF NOT EXISTS ip_address TEXT")
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
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id         SERIAL  PRIMARY KEY,
            email      TEXT    UNIQUE NOT NULL,
            naam       TEXT    NOT NULL,
            created_at TEXT    NOT NULL,
            role       TEXT    DEFAULT 'participant'
        )
    """)
    cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'participant'")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS admin_audit (
            id          SERIAL  PRIMARY KEY,
            actor_email TEXT    NOT NULL,
            action      TEXT    NOT NULL,
            target      TEXT,
            ip          TEXT,
            created_at  TEXT    NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS feedback (
            id           SERIAL PRIMARY KEY,
            email        TEXT   NOT NULL,
            naam         TEXT   NOT NULL,
            bericht      TEXT   NOT NULL,
            created_at   TEXT   NOT NULL,
            status       TEXT   DEFAULT 'open',
            status_reden TEXT,
            status_door  TEXT,
            status_at    TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS feedback_votes (
            id          SERIAL  PRIMARY KEY,
            feedback_id INTEGER NOT NULL REFERENCES feedback(id) ON DELETE CASCADE,
            email       TEXT    NOT NULL,
            created_at  TEXT    NOT NULL,
            UNIQUE (feedback_id, email)
        )
    """)

    # Zaai vaste eigenaren — update alleen de rol als ze al bestaan
    for seed_email, seed_naam in [("rm@tosch.nl", "Ronny Morren"), ("dm@tosch.nl", "Eigenaar")]:
        cur.execute("""
            INSERT INTO users (email, naam, created_at, role)
            VALUES (%s, %s, %s, 'owner')
            ON CONFLICT (email) DO UPDATE SET role = 'owner'
        """, (seed_email, seed_naam, nu().isoformat()))

    conn.commit()
    conn.close()

def init_db_indien_nodig():
    """Volledige init_db alleen draaien als het schema nog niet compleet is —
    scheelt ~10 statements bij elke koude start op Vercel.
    ⚠️ Nieuwe tabel of kolom toegevoegd? Pas dan de schemacheck hieronder aan
    naar het nieuwste schema-element, anders draait de migratie nooit."""
    try:
        conn = get_conn()
        cur  = get_cur(conn)
        cur.execute("SELECT 1 FROM feedback_votes LIMIT 1")  # nieuwste tabel
        conn.close()
    except Exception:
        try:
            init_db()
        except Exception:
            pass

# Direct initialiseren bij import
init_db_indien_nodig()


# ── App ───────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db_indien_nodig()
    yield

app = FastAPI(
    lifespan=lifespan,
    docs_url=None,     # 🔒 Fix 6: Swagger UI uitgeschakeld in productie
    redoc_url=None,
    openapi_url=None,
)

@app.middleware("http")
async def ververs_user_cookie(request: Request, call_next):
    """Sliding sessie: geldige cookie ouder dan USER_REFRESH_NA wordt bij elk
    bezoek stilzwijgend vernieuwd — actieve gebruikers hoeven zo nooit opnieuw
    in te loggen; pas na 30 dagen inactiviteit verloopt de sessie."""
    response = await call_next(request)
    user = get_user(request)
    if user and int(time.time()) - user["ts"] > USER_REFRESH_NA:
        # Routes die zelf het cookie zetten/wissen (login, logout, naam-edit)
        # niet overschrijven — anders maakt de refresh bv. een logout ongedaan.
        al_gezet = any(h.startswith(USER_COOKIE + "=") for h in response.headers.getlist("set-cookie"))
        if not al_gezet:
            token = maak_user_token(user["naam"], user["email"])
            response.set_cookie(USER_COOKIE, token, max_age=USER_TTL, httponly=True, samesite="lax")
    return response


BASE = Path(__file__).parent
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
jinja_env = Environment(
    loader=FileSystemLoader(str(BASE / "templates")),
    autoescape=True,   # 🔒 Fix 5: XSS-bescherming voor alle templates
    # Python 3.14 heeft een hashability-bug in de templatecache; op 3.12 (Vercel)
    # is de cache veilig en scheelt hercompileren per request.
    cache_size=0 if sys.version_info >= (3, 14) else 400,
)
jinja_env.filters["euro"] = lambda v: "€\xa0" + f"{v:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
templates = Jinja2Templates(env=jinja_env)


# ── Open redirect bescherming ─────────────────────────────────────────────────

def valideer_next(next_url: str, standaard: str = "/") -> str:
    """Sta alleen lokale paden toe — voorkomt open redirect-aanvallen."""  # 🔒 Fix 7
    if next_url.startswith("/") and not next_url.startswith("//"):
        return next_url
    return standaard


# ── Pagina's ──────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    user = get_user(request)
    if user:
        return RedirectResponse(url="/veilingen", status_code=303)
    return templates.TemplateResponse(request, "home.html")


AUTO_ARCHIEF_DAGEN = 5

def auto_archiveer(cur) -> int:
    """Archiveer veilingen die AUTO_ARCHIEF_DAGEN of langer geleden zijn afgelopen.
    Wordt lazy aangeroepen bij het laden van /veilingen en het Beheersoverzicht —
    Vercel serverless heeft geen achtergrondtaken. Caller moet committen."""
    grens = (nu() - timedelta(days=AUTO_ARCHIEF_DAGEN)).isoformat()
    cur.execute(
        "UPDATE auctions SET archived = 1 WHERE archived = 0 AND end_time < %s",
        (grens,)
    )
    return cur.rowcount


def verstuur_afloopmails(cur, conn) -> None:
    """Stuur afloopmails voor beëindigde veilingen waar nog niet voor gemaild is.
    Vangnet naast de polling op de veilingpagina: had niemand die pagina open
    toen de veiling eindigde, dan gaan de mails alsnog bij de eerstvolgende
    lading van /veilingen of het Beheersoverzicht. Atomisch per veiling via
    notified 0→1, net als in de poll-route."""
    now = nu().strftime("%Y-%m-%dT%H:%M:%S")
    cur.execute("SELECT * FROM auctions WHERE notified = 0 AND end_time < %s", (now,))
    for row in cur.fetchall():
        cur.execute("UPDATE auctions SET notified = 1 WHERE id = %s AND notified = 0", (row["id"],))
        conn.commit()
        if cur.rowcount == 0:
            continue  # andere instantie was eerder
        cur.execute("SELECT * FROM bids WHERE auction_id = %s ORDER BY amount DESC", (row["id"],))
        bids = cur.fetchall()
        if not bids:
            continue  # geen deelnemers, niets te mailen
        winner        = bids[0]["bidder_name"]
        winnend_bod   = bids[0]["amount"]
        winnaar_email = bids[0].get("email")
        cur.execute(
            "SELECT DISTINCT email FROM bids WHERE auction_id = %s AND email IS NOT NULL",
            (row["id"],)
        )
        for d in cur.fetchall():
            try:
                stuur_afloop_mail(
                    to          = d["email"],
                    titel       = row["title"],
                    winnaar     = winner,
                    winnend_bod = winnend_bod,
                    is_winner   = (d["email"] == winnaar_email),
                )
            except Exception:
                pass


@app.get("/veilingen", response_class=HTMLResponse)
async def veilingen_page(request: Request):
    user = get_user(request)
    if not user:
        return RedirectResponse(url="/", status_code=303)
    email  = user["email"]
    domain = email.split("@")[1] if "@" in email else ""
    conn = get_conn()
    cur  = get_cur(conn)
    verstuur_afloopmails(cur, conn)
    if auto_archiveer(cur):
        conn.commit()
    cur.execute("SELECT * FROM auctions WHERE archived = 0 ORDER BY id DESC")
    rows = cur.fetchall()
    now = nu().strftime("%Y-%m-%dT%H:%M:%S")
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
    ended_ids = [a["id"] for a in auctions if a["is_ended"]]
    if ended_ids:
        cur.execute(
            """SELECT DISTINCT ON (auction_id) auction_id, bidder_name
               FROM bids WHERE auction_id = ANY(%s)
               ORDER BY auction_id, amount DESC""",
            (ended_ids,),
        )
        winnaars = {w["auction_id"]: w["bidder_name"] for w in cur.fetchall()}
        for a in auctions:
            a["winnaar"] = winnaars.get(a["id"])
    role = haal_rol(cur, email)
    conn.close()
    return templates.TemplateResponse(request, "veilingen.html", {
        "auctions": auctions,
        "user": user,
        "is_admin": role in ("manager", "owner"),
        "is_owner": role == "owner",
    })


@app.get("/uitloggen")
async def uitloggen():
    resp = RedirectResponse(url="/", status_code=303)
    resp.delete_cookie(USER_COOKIE)
    return resp


@app.post("/api/profiel/naam")
async def update_naam(request: Request):
    user = get_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Niet ingelogd")
    data = await request.json()
    naam = data.get("naam", "").strip()
    if not naam:
        raise HTTPException(status_code=400, detail="Naam mag niet leeg zijn")
    if len(naam) > 80:
        raise HTTPException(status_code=400, detail="Naam is te lang")
    conn = get_conn()
    cur  = get_cur(conn)
    cur.execute("UPDATE users SET naam = %s WHERE email = %s", (naam, user["email"]))
    conn.commit()
    conn.close()
    # Geef nieuw cookie terug met bijgewerkte naam
    token = maak_user_token(naam, user["email"])
    resp  = JSONResponse({"ok": True})
    resp.set_cookie(USER_COOKIE, token, max_age=USER_TTL, httponly=True, samesite="lax")
    return resp


FEEDBACK_STATUSSEN = ("open", "gepland", "doorgevoerd", "afgewezen")

@app.post("/api/feedback")
async def api_feedback(request: Request):
    """Slaat feedback op voor het feedback-bord en mailt rm@tosch.nl."""
    user = get_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Niet ingelogd")
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Ongeldige aanvraag")
    bericht = (data.get("bericht") or "").strip()[:2000]
    if not bericht:
        raise HTTPException(status_code=400, detail="Bericht is verplicht")

    # Eerst opslaan — de mail mag falen zonder dat de feedback verloren gaat
    conn = get_conn()
    cur  = get_cur(conn)
    cur.execute(
        "INSERT INTO feedback (email, naam, bericht, created_at) "
        "VALUES (%s, %s, %s, %s) RETURNING id",
        (user["email"], user["naam"], bericht, nu().isoformat())
    )
    feedback_id = cur.fetchone()["id"]
    conn.commit()
    conn.close()

    afzender  = f"{user['naam']} <{user['email']}>"
    bord_link = f"https://veiling.tosch.nl/feedback#fb-{feedback_id}"
    html_body = (
        f"<p><b>Van:</b> {html.escape(afzender)}</p>"
        "<p><b>Bericht:</b></p>"
        "<blockquote style='border-left:3px solid #ccc;padding-left:12px'>"
        f"{html.escape(bericht).replace(chr(10), '<br>')}"
        "</blockquote>"
        f"<p><a href='{bord_link}'>Bekijk op het feedback-bord</a></p>"
        "<p style='color:#888;font-size:12px'>Verstuurd via Tosch Veiling</p>"
    )
    text_body = f"Van: {afzender}\n\n{bericht}\n\nFeedback-bord: {bord_link}\n\nVerstuurd via Tosch Veiling"
    # Synchroon versturen: op Vercel serverless overleeft een achtergrond-thread
    # de response niet, dus de mail moet vóór het antwoord de deur uit zijn.
    try:
        stuur_email("rm@tosch.nl", f"Veiling feedback van {user['naam']}", html_body, text_body)
    except Exception:
        pass  # feedback staat al op het bord
    return JSONResponse({"ok": True, "id": feedback_id})


@app.get("/feedback", response_class=HTMLResponse)
async def feedback_page(request: Request):
    """Feedback-bord: alle feedback, stemmen en (voor de eigenaar) status beheren."""
    user = get_user(request)
    if not user:
        return RedirectResponse(url="/", status_code=303)
    conn = get_conn()
    cur  = get_cur(conn)
    cur.execute("""
        SELECT f.*,
               COUNT(v.id)                                          AS stemmen,
               BOOL_OR(v.email = %s)                                AS zelf_gestemd
        FROM feedback f
        LEFT JOIN feedback_votes v ON v.feedback_id = f.id
        GROUP BY f.id
        ORDER BY (f.status = 'open') DESC, COUNT(v.id) DESC, f.id DESC
    """, (user["email"],))
    items = [dict(r) for r in cur.fetchall()]
    role  = haal_rol(cur, user["email"])
    conn.close()
    for it in items:
        it["zelf_gestemd"] = bool(it["zelf_gestemd"])
        it["datum"] = (it["created_at"] or "")[:10]
    return templates.TemplateResponse(request, "feedback.html", {
        "items": items,
        "user": user,
        "is_admin": role in ("manager", "owner"),
        "is_owner": role == "owner",
    })


@app.post("/api/feedback/{feedback_id}/stem")
async def api_feedback_stem(feedback_id: int, request: Request):
    """Duimpje aan/uit op een feedback-item (toggle, 1 stem per persoon)."""
    user = get_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Niet ingelogd")
    conn = get_conn()
    cur  = get_cur(conn)
    cur.execute("SELECT id FROM feedback WHERE id = %s", (feedback_id,))
    if not cur.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="Feedback niet gevonden")
    cur.execute(
        "DELETE FROM feedback_votes WHERE feedback_id = %s AND email = %s",
        (feedback_id, user["email"])
    )
    gestemd = False
    if cur.rowcount == 0:
        cur.execute(
            "INSERT INTO feedback_votes (feedback_id, email, created_at) VALUES (%s, %s, %s) "
            "ON CONFLICT (feedback_id, email) DO NOTHING",
            (feedback_id, user["email"], nu().isoformat())
        )
        gestemd = True
    cur.execute("SELECT COUNT(*) AS n FROM feedback_votes WHERE feedback_id = %s", (feedback_id,))
    stemmen = cur.fetchone()["n"]
    conn.commit()
    conn.close()
    return JSONResponse({"ok": True, "gestemd": gestemd, "stemmen": stemmen})


FEEDBACK_STATUS_LABELS = {
    "open": "Open", "gepland": "Gepland",
    "doorgevoerd": "Doorgevoerd", "afgewezen": "Niet doorgevoerd",
}

@app.post("/api/feedback/{feedback_id}/status")
async def api_feedback_status(feedback_id: int, request: Request):
    """Eigenaar zet status (open/gepland/doorgevoerd/afgewezen) + reden.
    Bij een wijziging krijgt de indiener een mailtje."""
    user = get_user(request)
    if not user:
        raise HTTPException(status_code=403, detail="Alleen voor de eigenaar")
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Ongeldige aanvraag")
    status = (data.get("status") or "").strip()
    reden  = (data.get("reden") or "").strip()[:1000]
    if status not in FEEDBACK_STATUSSEN:
        raise HTTPException(status_code=400, detail="Ongeldige status")
    if status == "afgewezen" and not reden:
        raise HTTPException(status_code=400, detail="Geef een reden bij afwijzen")
    conn = get_conn()
    cur  = get_cur(conn)
    if haal_rol(cur, user["email"]) != "owner":
        conn.close()
        raise HTTPException(status_code=403, detail="Alleen voor de eigenaar")
    cur.execute("SELECT email, naam, bericht, status FROM feedback WHERE id = %s", (feedback_id,))
    oud = cur.fetchone()
    if not oud:
        conn.close()
        raise HTTPException(status_code=404, detail="Feedback niet gevonden")
    cur.execute(
        "UPDATE feedback SET status = %s, status_reden = %s, status_door = %s, status_at = %s "
        "WHERE id = %s",
        (status, reden or None, user["naam"], nu().isoformat(), feedback_id)
    )
    conn.commit()
    conn.close()
    ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip() or None
    log_audit(user["email"], "feedback_status", f"#{feedback_id} → {status}", ip)

    # Mail de indiener bij een echte wijziging — niet bij eigen feedback of terug naar 'open'
    if status != oud["status"] and status != "open" and oud["email"] != user["email"]:
        label     = FEEDBACK_STATUS_LABELS.get(status, status)
        bord_link = f"https://veiling.tosch.nl/feedback#fb-{feedback_id}"
        korte     = (oud["bericht"] or "")[:200]
        html_body = (
            f"<p>Hoi {html.escape(oud['naam'])},</p>"
            f"<p>Je feedback op Tosch Veiling heeft een update: <b>{html.escape(label)}</b></p>"
            "<blockquote style='border-left:3px solid #ccc;padding-left:12px'>"
            f"{html.escape(korte)}</blockquote>"
            + (f"<p><b>Toelichting van {html.escape(user['naam'])}:</b> {html.escape(reden)}</p>" if reden else "")
            + f"<p><a href='{bord_link}'>Bekijk op het feedback-bord</a></p>"
            "<p style='color:#888;font-size:12px'>Verstuurd via Tosch Veiling</p>"
        )
        text_body = (
            f"Hoi {oud['naam']},\n\nJe feedback heeft een update: {label}\n\n\"{korte}\"\n"
            + (f"\nToelichting van {user['naam']}: {reden}\n" if reden else "")
            + f"\nFeedback-bord: {bord_link}\n\nVerstuurd via Tosch Veiling"
        )
        try:
            stuur_email(oud["email"], f"Update op je feedback: {label}", html_body, text_body)
        except Exception:
            pass  # status is al opgeslagen
    return JSONResponse({"ok": True})


@app.delete("/api/feedback/{feedback_id}")
async def api_feedback_delete(feedback_id: int, request: Request):
    """Eigenaar verwijdert een feedback-item (spam/dubbelingen)."""
    user = get_user(request)
    if not user:
        raise HTTPException(status_code=403, detail="Alleen voor de eigenaar")
    conn = get_conn()
    cur  = get_cur(conn)
    if haal_rol(cur, user["email"]) != "owner":
        conn.close()
        raise HTTPException(status_code=403, detail="Alleen voor de eigenaar")
    cur.execute("DELETE FROM feedback WHERE id = %s", (feedback_id,))
    gevonden = cur.rowcount > 0
    conn.commit()
    conn.close()
    if not gevonden:
        raise HTTPException(status_code=404, detail="Feedback niet gevonden")
    ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip() or None
    log_audit(user["email"], "feedback_verwijderd", f"#{feedback_id}", ip)
    return JSONResponse({"ok": True})


# ── Admin: login / logout ─────────────────────────────────────────────────────

@app.get("/admin/login")
async def admin_login_redirect(request: Request, next: str = "/admin/overzicht"):
    # Wachtwoord-gebaseerde login vervangen door rol-gebaseerde login via e-mail
    safe_next = valideer_next(next, "/admin/overzicht")
    if is_admin(request):
        return RedirectResponse(url=safe_next, status_code=303)
    return RedirectResponse(url=f"/?next={safe_next}", status_code=303)

@app.post("/admin/login")
async def admin_login_post_redirect():
    return RedirectResponse(url="/", status_code=303)

@app.get("/admin/logout")
async def admin_logout():
    resp = RedirectResponse(url="/", status_code=303)
    resp.delete_cookie(USER_COOKIE)
    resp.delete_cookie(SESSION_COOKIE)
    return resp


# ── Admin: pagina's (cookie-beschermd) ───────────────────────────────────────

@app.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request):
    user = get_user(request)
    if not user:
        return RedirectResponse(url="/?next=/admin", status_code=303)
    role = get_user_role(user["email"])
    if role not in ("manager", "owner"):
        return RedirectResponse(url="/?next=/admin", status_code=303)
    return templates.TemplateResponse(request, "admin.html", {"user": user, "is_owner": role == "owner"})

@app.get("/admin/overzicht", response_class=HTMLResponse)
async def admin_overzicht(request: Request):
    user = get_user(request)
    if not user:
        return RedirectResponse(url="/?next=/admin/overzicht", status_code=303)
    conn = get_conn()
    cur  = get_cur(conn)
    role = haal_rol(cur, user["email"])
    if role not in ("manager", "owner"):
        conn.close()
        return RedirectResponse(url="/?next=/admin/overzicht", status_code=303)
    verstuur_afloopmails(cur, conn)
    if auto_archiveer(cur):
        conn.commit()
    cur.execute("""
        SELECT a.*, COUNT(b.id) as bid_count
        FROM auctions a
        LEFT JOIN bids b ON b.auction_id = a.id
        GROUP BY a.id
        ORDER BY a.id DESC
    """)
    rows = cur.fetchall()
    conn.close()
    now = nu().strftime("%Y-%m-%dT%H:%M:%S")
    actief, archief = [], []
    for r in rows:
        d = dict(r)
        d["is_ended"] = now > d["end_time"]
        if d.get("archived"):
            archief.append(d)
        else:
            actief.append(d)
    return templates.TemplateResponse(request, "admin_overzicht.html",
        {"auctions": actief, "archief": archief, "user": user, "is_owner": role == "owner"})

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




# ── API: product info (AI + foto) ─────────────────────────────────────────────

@app.post("/api/product-info")
async def product_info(request: Request):
    if not is_admin(request):  # 🔒 Fix 11: alleen admin mag AI + DuckDuckGo gebruiken
        raise HTTPException(status_code=403, detail="Geen toegang")
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
    if not is_admin(request):  # 🔒 Fix 10: cookie-auth i.p.v. wachtwoord in JSON-body
        raise HTTPException(status_code=403, detail="Geen toegang")
    data = await request.json()

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
        float(data.get("min_increment", 5.0)),
        data["end_time"],
        access_code,
        1 if data.get("require_email_verification") else 0,
        data.get("allowed_domains", "").strip(),
    ))
    auction_id = cur.fetchone()["id"]
    conn.commit()
    conn.close()

    actor = get_user(request)
    if actor:
        log_audit(actor["email"], "veiling_aangemaakt", target=data["title"],
                  ip=get_client_ip(request))

    return JSONResponse({"auction_id": auction_id, "access_code": access_code})


# ── API: image proxy (omzeilt hotlink-beveiliging van externe URLs) ───────────

@app.get("/api/image-proxy")
async def image_proxy(url: str, request: Request):
    if not is_admin(request):  # 🔒 Fix 11: SSRF-bescherming — alleen admin mag proxy gebruiken
        raise HTTPException(status_code=403, detail="Geen toegang")
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

    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Veiling niet gevonden")

    cur.execute(
        "SELECT * FROM bids WHERE auction_id = %s ORDER BY amount DESC LIMIT 20",
        (auction_id,)
    )
    bids = cur.fetchall()

    end_time  = datetime.fromisoformat(row["end_time"])
    is_ended  = nu() > end_time or row["status"] == "ended"
    req_email = bool(row["require_email_verification"])

    winner = None
    if is_ended and bids:
        winner = bids[0]["bidder_name"]

    # ── Afloopmail: één keer versturen zodra de veiling eindigt ──────────────
    if is_ended and bids and not row["notified"]:
        # Atomisch: alleen de instantie die notified van 0→1 zet stuurt de mails
        cur.execute(
            "UPDATE auctions SET notified = 1 WHERE id = %s AND notified = 0",
            (row["id"],)
        )
        conn.commit()
        if cur.rowcount > 0:
            # Verzamel alle deelnemers met een e-mailadres
            cur.execute(
                "SELECT DISTINCT email, bidder_name FROM bids WHERE auction_id = %s AND email IS NOT NULL",
                (row["id"],)
            )
            deelnemers = cur.fetchall()
            winnend_bod   = bids[0]["amount"]
            winnaar_email = bids[0].get("email")
            for d in deelnemers:
                try:
                    stuur_afloop_mail(
                        to          = d["email"],
                        titel       = row["title"],
                        winnaar     = winner,
                        winnend_bod = winnend_bod,
                        is_winner   = (d["email"] == winnaar_email),
                    )
                except Exception:
                    pass  # Mail mislukt? Niet fataal

    conn.close()

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
        "bids":                       [  # 🔒 Fix 12: geen email/IP in publieke response
            {"id": b["id"], "bidder_name": b["bidder_name"],
             "amount": b["amount"], "timestamp": b["timestamp"]}
            for b in bids
        ],
        "require_email_verification": req_email,
        "access_code":                row["access_code"] if not req_email else None,
    })


# ── API: globale login – code versturen ──────────────────────────────────────

@app.post("/api/auth/send-login-code")
async def send_login_code(request: Request):
    data  = await request.json()
    email = data.get("email", "").strip().lower()

    if not email or "@" not in email or "." not in email.split("@")[-1]:
        raise HTTPException(400, "Ongeldig e-mailadres")

    # Check of dit e-mailadres al bekend is
    conn = get_conn()
    cur  = get_cur(conn)
    cur.execute("SELECT naam FROM users WHERE email = %s", (email,))
    user_row = cur.fetchone()
    known = user_row is not None
    begroeting = user_row["naam"] if known else "Hoi"

    code       = "".join(secrets.choice("0123456789") for _ in range(6))
    expires_at = (nu() + timedelta(minutes=10)).isoformat()

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
          {begroeting},<br><br>
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

    return JSONResponse({"ok": True, "known": known})


# ── API: globale login – code controleren ─────────────────────────────────────

@app.post("/api/auth/verify-login-code")
async def verify_login_code(request: Request):
    data  = await request.json()
    email = data.get("email", "").strip().lower()
    code  = data.get("code", "").strip()
    naam_nieuw = data.get("naam", "").strip()  # alleen verplicht voor nieuwe gebruikers

    if not email or not code:
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
    if nu() > datetime.fromisoformat(row["expires_at"]):
        conn.close()
        raise HTTPException(400, "Code verlopen. Vraag een nieuwe code aan.")
    if not hmac.compare_digest(row["code"], code):  # 🔒 Fix 9: timing-safe OTP vergelijking
        conn.close()
        raise HTTPException(400, "Onjuiste code. Probeer opnieuw.")

    cur.execute("UPDATE email_verifications SET used = 1 WHERE id = %s", (row["id"],))

    # Naam ophalen of opslaan
    cur.execute("SELECT naam FROM users WHERE email = %s", (email,))
    user_row = cur.fetchone()
    if user_row:
        naam = user_row["naam"]
    else:
        if not naam_nieuw:
            conn.close()
            raise HTTPException(400, "Vul je naam in — het is je eerste keer")
        naam = naam_nieuw
        cur.execute(
            "INSERT INTO users (email, naam, created_at) VALUES (%s, %s, %s)",
            (email, naam, nu().isoformat())
        )

    conn.commit()
    conn.close()

    role = get_user_role(email)
    log_audit(email, "login", ip=get_client_ip(request))

    token = maak_user_token(naam, email)
    resp  = JSONResponse({"ok": True, "role": role})
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
    if nu() > end_time:
        conn.close()
        raise HTTPException(status_code=400, detail="De veiling is al afgelopen")

    cur.execute("SELECT 1 FROM bids WHERE auction_id = %s LIMIT 1", (auction_id,))
    heeft_biedingen = cur.fetchone() is not None
    min_bid = (row["current_price"] + row["min_increment"]) if heeft_biedingen else row["start_price"]
    if amount < min_bid:
        conn.close()
        raise HTTPException(status_code=400, detail=f"Minimaal bod is €{min_bid:.2f}")

    timestamp  = nu().isoformat()
    ip_address = get_client_ip(request)
    cur.execute(
        "INSERT INTO bids (auction_id, bidder_name, amount, timestamp, email, ip_address) VALUES (%s, %s, %s, %s, %s, %s)",
        (auction_id, bidder_name, amount, timestamp, email, ip_address)
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

@app.delete("/api/auction/{auction_id}")
async def delete_auction(auction_id: int, request: Request):
    if not is_admin(request):
        raise HTTPException(status_code=403, detail="Geen toegang")
    conn = get_conn()
    cur  = get_cur(conn)
    cur.execute("SELECT title FROM auctions WHERE id = %s", (auction_id,))
    auction_row = cur.fetchone()
    cur.execute("DELETE FROM bids WHERE auction_id = %s", (auction_id,))
    cur.execute("DELETE FROM email_verifications WHERE auction_id = %s", (auction_id,))
    cur.execute("DELETE FROM auctions WHERE id = %s", (auction_id,))
    conn.commit()
    conn.close()
    actor = get_user(request)
    if actor and auction_row:
        log_audit(actor["email"], "veiling_verwijderd", target=auction_row["title"],
                  ip=get_client_ip(request))
    return JSONResponse({"ok": True})


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
    user = get_user(request)
    if not user:
        return RedirectResponse(url=f"/?next=/admin/veiling/{auction_id}/biedingen", status_code=303)
    conn = get_conn()
    cur  = get_cur(conn)
    role = haal_rol(cur, user["email"])
    if role not in ("manager", "owner"):
        conn.close()
        return RedirectResponse(url=f"/?next=/admin/veiling/{auction_id}/biedingen", status_code=303)
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
        "auction":  dict(auction),
        "bids":     [dict(b) for b in bids],
        "user":     user,
        "is_owner": role == "owner",
    })


# ── Admin: gebruikersbeheer (eigenaren only) ─────────────────────────────────

@app.get("/admin/gebruikers", response_class=HTMLResponse)
async def admin_gebruikers(request: Request):
    user = get_user(request)
    if not user:
        return RedirectResponse(url="/?next=/admin/gebruikers", status_code=303)
    conn = get_conn()
    cur  = get_cur(conn)
    if haal_rol(cur, user["email"]) != "owner":
        conn.close()
        return RedirectResponse(url="/?next=/admin/gebruikers", status_code=303)
    cur.execute("SELECT email, naam, created_at FROM users WHERE role = 'manager' ORDER BY created_at DESC")
    managers = [dict(r) for r in cur.fetchall()]
    conn.close()
    return templates.TemplateResponse(request, "admin_gebruikers.html",
        {"managers": managers, "user": user, "is_owner": True})


@app.post("/api/admin/gebruikers")
async def voeg_manager_toe(request: Request):
    if not is_owner(request):
        raise HTTPException(status_code=403, detail="Geen toegang")
    data  = await request.json()
    email = data.get("email", "").strip().lower()
    naam  = data.get("naam", "").strip()
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Ongeldig e-mailadres")
    if not naam:
        raise HTTPException(status_code=400, detail="Vul een naam in")
    if email in EIGENAREN:
        raise HTTPException(status_code=400, detail="Dit e-mailadres is een eigenaar en kan niet als beheerder worden toegevoegd")

    conn = get_conn()
    cur  = get_cur(conn)
    cur.execute("SELECT role FROM users WHERE email = %s", (email,))
    row = cur.fetchone()
    if row:
        cur.execute("UPDATE users SET role = 'manager', naam = %s WHERE email = %s", (naam, email))
    else:
        cur.execute(
            "INSERT INTO users (email, naam, created_at, role) VALUES (%s, %s, %s, 'manager')",
            (email, naam, nu().isoformat())
        )
    conn.commit()
    conn.close()

    actor = get_user(request)
    if actor:
        log_audit(actor["email"], "manager_toegevoegd", target=email, ip=get_client_ip(request))

    return JSONResponse({"ok": True})


@app.delete("/api/admin/gebruikers/{manager_email:path}")
async def verwijder_manager(manager_email: str, request: Request):
    if not is_owner(request):
        raise HTTPException(status_code=403, detail="Geen toegang")
    if manager_email in EIGENAREN:
        raise HTTPException(status_code=400, detail="Eigenaren kunnen niet worden verwijderd")

    conn = get_conn()
    cur  = get_cur(conn)
    cur.execute("UPDATE users SET role = 'participant' WHERE email = %s AND role = 'manager'", (manager_email,))
    if cur.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="Beheerder niet gevonden")
    conn.commit()
    conn.close()

    actor = get_user(request)
    if actor:
        log_audit(actor["email"], "manager_verwijderd", target=manager_email, ip=get_client_ip(request))

    return JSONResponse({"ok": True})


# ── Admin: auditlog (eigenaren only) ─────────────────────────────────────────

@app.get("/admin/audit", response_class=HTMLResponse)
async def admin_audit(request: Request):
    user = get_user(request)
    if not user:
        return RedirectResponse(url="/?next=/admin/audit", status_code=303)
    conn = get_conn()
    cur  = get_cur(conn)
    if haal_rol(cur, user["email"]) != "owner":
        conn.close()
        return RedirectResponse(url="/?next=/admin/audit", status_code=303)
    cur.execute("SELECT * FROM admin_audit ORDER BY created_at DESC LIMIT 500")
    logs = [dict(r) for r in cur.fetchall()]
    conn.close()
    return templates.TemplateResponse(request, "admin_audit.html",
        {"logs": logs, "user": user, "is_owner": True})
