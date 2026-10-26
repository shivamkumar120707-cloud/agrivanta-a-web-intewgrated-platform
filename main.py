from __future__ import annotations

import os
import sqlite3
import base64
import hashlib
import hmac
import secrets
import time
import re
import json
import logging
from collections import defaultdict, deque
from contextlib import asynccontextmanager, closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")
DB_PATH = Path(os.getenv("AGRIVANTA_DB", str(BASE_DIR / "agrivanta.db")))
if not DB_PATH.is_absolute():
    DB_PATH = BASE_DIR / DB_PATH

logger = logging.getLogger("agrivanta")
_PLACEHOLDER_SECRETS = {"", "change-this-to-a-long-random-secret", "development-only-change-this-secret"}
SESSION_SECRET = os.getenv("AGRIVANTA_SECRET_KEY", "").strip()
if SESSION_SECRET in _PLACEHOLDER_SECRETS or len(SESSION_SECRET) < 16:
    # Never fall back to a publicly known secret: use a random one for this process.
    # Logins are lost on restart until a real AGRIVANTA_SECRET_KEY is configured.
    SESSION_SECRET = secrets.token_urlsafe(48)
    logger.warning("AGRIVANTA_SECRET_KEY is missing/placeholder/too short; using a temporary random secret. Set a long random value in .env.")
SESSION_COOKIE = "agrivanta_session"
SESSION_MAX_AGE = 60 * 60 * 24 * 7
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "0").strip() == "1"

@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="AgriVanta API",
    description="Bilingual agricultural decision-support mini-project API",
    version="1.0.0",
    lifespan=lifespan,
)
STATIC_DIR = Path(__file__).resolve().parent / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with closing(connect_db()) as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS soil_tests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            farmer_name TEXT NOT NULL,
            location TEXT NOT NULL,
            crop TEXT NOT NULL,
            ph REAL,
            nitrogen REAL,
            phosphorus REAL,
            potassium REAL,
            notes TEXT DEFAULT '',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS water_tests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            farmer_name TEXT NOT NULL,
            location TEXT NOT NULL,
            source TEXT NOT NULL,
            ph REAL,
            ec REAL,
            notes TEXT DEFAULT '',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS recommendations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            location TEXT NOT NULL,
            season TEXT NOT NULL,
            soil_type TEXT NOT NULL,
            water TEXT NOT NULL,
            farm_size REAL,
            budget REAL,
            result_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """)
        # Add owner columns safely when upgrading an older database.
        for table in ("soil_tests", "water_tests", "recommendations"):
            columns = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
            if "user_id" not in columns:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN user_id INTEGER NOT NULL DEFAULT 0")
        user_columns = {row["name"] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
        if "token_version" not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_soil_user ON soil_tests(user_id, id DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_water_user ON water_tests(user_id, id DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_recommendations_user ON recommendations(user_id, id DESC)")
        conn.commit()



class RegisterIn(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=8, max_length=128)


class LoginIn(BaseModel):
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=1, max_length=128)


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    rounds = 310_000
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds)
    return f"pbkdf2_sha256${rounds}${base64.urlsafe_b64encode(salt).decode()}${base64.urlsafe_b64encode(digest).decode()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, rounds, salt_b64, digest_b64 = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        salt = base64.urlsafe_b64decode(salt_b64.encode())
        expected = base64.urlsafe_b64decode(digest_b64.encode())
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(rounds))
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def create_session_token(user_id: int, version: int = 0) -> str:
    payload = f"{user_id}:{int(time.time()) + SESSION_MAX_AGE}:{version}"
    signature = hmac.new(SESSION_SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{payload}:{signature}".encode("utf-8")).decode("ascii").rstrip("=")


def session_user(token: str | None):
    if not token:
        return None
    try:
        padded = token + "=" * (-len(token) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
        user_id_text, expiry_text, version_text, signature = decoded.split(":", 3)
        payload = f"{user_id_text}:{expiry_text}:{version_text}"
        expected = hmac.new(SESSION_SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected) or int(expiry_text) < int(time.time()):
            return None
        user_id = int(user_id_text)
        with closing(connect_db()) as conn:
            row = conn.execute("SELECT id, name, email, token_version FROM users WHERE id=?", (user_id,)).fetchone()
        if not row or row["token_version"] != int(version_text):
            return None
        user = row_to_dict(row)
        user.pop("token_version", None)
        return user
    except (ValueError, UnicodeDecodeError, TypeError):
        return None


_AUTH_WINDOW = 15 * 60
_AUTH_MAX_ATTEMPTS = 10
_auth_attempts: dict[str, deque] = defaultdict(deque)


def check_rate_limit(request: Request, email: str) -> None:
    """Allow at most _AUTH_MAX_ATTEMPTS auth attempts per client+email per window (in-memory)."""
    client_ip = request.client.host if request.client else "unknown"
    key = f"{client_ip}|{email}"
    now = time.time()
    attempts = _auth_attempts[key]
    while attempts and now - attempts[0] > _AUTH_WINDOW:
        attempts.popleft()
    if len(attempts) >= _AUTH_MAX_ATTEMPTS:
        raise HTTPException(status_code=429, detail="Too many attempts. Please wait a few minutes and try again.")
    attempts.append(now)
    if len(_auth_attempts) > 5000:
        for k in [k for k, v in _auth_attempts.items() if not v or now - v[-1] > _AUTH_WINDOW]:
            _auth_attempts.pop(k, None)


@app.middleware("http")
async def require_login_for_api(request: Request, call_next):
    request.state.user = session_user(request.cookies.get(SESSION_COOKIE))
    path = request.url.path
    public_api = path == "/api/health" or path.startswith("/api/auth/")
    if path.startswith("/api/") and not public_api and request.state.user is None:
        return JSONResponse(status_code=401, content={"detail": "Please log in to continue."})
    return await call_next(request)


@app.post("/api/auth/register", status_code=201)
def register(data: RegisterIn, request: Request, response: Response):
    name = data.name.strip()
    email = data.email.strip().lower()
    check_rate_limit(request, email)
    if not name or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise HTTPException(status_code=422, detail="Enter a valid name and email address.")
    try:
        with closing(connect_db()) as conn:
            cur = conn.execute(
                "INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (name, email, hash_password(data.password), now_iso()),
            )
            conn.commit()
            user_id = cur.lastrowid
            # Preserve records created before login was introduced by assigning
            # unowned legacy rows to the first account only (never to later sign-ups).
            if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1:
                for table in ("soil_tests", "water_tests", "recommendations"):
                    conn.execute(f"UPDATE {table} SET user_id=? WHERE user_id=0", (user_id,))
                conn.commit()
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="An account with this email already exists. Please log in.") from exc
    response.set_cookie(SESSION_COOKIE, create_session_token(user_id, 0), httponly=True, secure=COOKIE_SECURE, samesite="lax", max_age=SESSION_MAX_AGE, path="/")
    return {"message": "Account created successfully.", "user": {"id": user_id, "name": name, "email": email}}


@app.post("/api/auth/login")
def login(data: LoginIn, request: Request, response: Response):
    email = data.email.strip().lower()
    check_rate_limit(request, email)
    with closing(connect_db()) as conn:
        user = conn.execute("SELECT id, name, email, password_hash, token_version FROM users WHERE email=? COLLATE NOCASE", (email,)).fetchone()
    if not user or not verify_password(data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Email or password is incorrect.")
    response.set_cookie(SESSION_COOKIE, create_session_token(user["id"], user["token_version"]), httponly=True, secure=COOKIE_SECURE, samesite="lax", max_age=SESSION_MAX_AGE, path="/")
    return {"message": "Logged in successfully.", "user": {"id": user["id"], "name": user["name"], "email": user["email"]}}


@app.post("/api/auth/logout")
def logout(request: Request, response: Response):
    user = getattr(request.state, "user", None)
    if user:
        # Invalidate every outstanding token for this account, not just the cookie.
        with closing(connect_db()) as conn:
            conn.execute("UPDATE users SET token_version = token_version + 1 WHERE id=?", (user["id"],))
            conn.commit()
    response.delete_cookie(SESSION_COOKIE, path="/", httponly=True, secure=COOKIE_SECURE, samesite="lax")
    return {"message": "Logged out."}


@app.get("/api/auth/me")
def auth_me(request: Request):
    user = getattr(request.state, "user", None)
    if not user:
        raise HTTPException(status_code=401, detail="Not logged in.")
    return {"user": user}


class SoilTestIn(BaseModel):
    farmer_name: str = Field(min_length=1, max_length=100)
    location: str = Field(min_length=1, max_length=160)
    crop: str = Field(min_length=1, max_length=100)
    ph: Optional[float] = Field(default=None, ge=0, le=14)
    nitrogen: Optional[float] = Field(default=None, ge=0, le=10000)
    phosphorus: Optional[float] = Field(default=None, ge=0, le=10000)
    potassium: Optional[float] = Field(default=None, ge=0, le=10000)
    notes: str = Field(default="", max_length=1000)


class WaterTestIn(BaseModel):
    farmer_name: str = Field(min_length=1, max_length=100)
    location: str = Field(min_length=1, max_length=160)
    source: str = Field(min_length=1, max_length=100)
    ph: Optional[float] = Field(default=None, ge=0, le=14)
    ec: Optional[float] = Field(default=None, ge=0, le=100000)
    notes: str = Field(default="", max_length=1000)


class CropAdvisorIn(BaseModel):
    location: str = Field(min_length=1, max_length=160)
    season: str = Field(min_length=1, max_length=40)
    soil_type: str = Field(min_length=1, max_length=80)
    water: str = Field(min_length=1, max_length=80)
    ph: Optional[float] = Field(default=None, ge=0, le=14)
    farm_size: Optional[float] = Field(default=None, ge=0)
    budget: Optional[float] = Field(default=None, ge=0)


class ChatIn(BaseModel):
    message: str = Field(min_length=1, max_length=4000)
    language: str = Field(default="en", pattern="^(en|hi)$")


def row_to_dict(row: sqlite3.Row) -> dict:
    return dict(row)


@app.get("/", include_in_schema=False)
def home(request: Request):
    if not getattr(request.state, "user", None):
        return RedirectResponse("/login", status_code=303)
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/login", include_in_schema=False)
def login_page(request: Request):
    if getattr(request.state, "user", None):
        return RedirectResponse("/", status_code=303)
    return FileResponse(STATIC_DIR / "login.html")


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "AgriVanta API", "ai_configured": bool(os.getenv("GEMINI_API_KEY"))}


@app.get("/api/dashboard")
def dashboard(request: Request):
    with closing(connect_db()) as conn:
        soil_count = conn.execute("SELECT COUNT(*) FROM soil_tests WHERE user_id=?", (request.state.user["id"],)).fetchone()[0]
        water_count = conn.execute("SELECT COUNT(*) FROM water_tests WHERE user_id=?", (request.state.user["id"],)).fetchone()[0]
        rec_count = conn.execute("SELECT COUNT(*) FROM recommendations WHERE user_id=?", (request.state.user["id"],)).fetchone()[0]
        recent_soil = conn.execute("SELECT id, farmer_name, location, crop, ph, created_at FROM soil_tests WHERE user_id=? ORDER BY id DESC LIMIT 3", (request.state.user["id"],)).fetchall()
        recent_water = conn.execute("SELECT id, farmer_name, location, source, ph, ec, created_at FROM water_tests WHERE user_id=? ORDER BY id DESC LIMIT 3", (request.state.user["id"],)).fetchall()
        recent_recommendations = conn.execute("SELECT id, location, season, soil_type, water, created_at FROM recommendations WHERE user_id=? ORDER BY id DESC LIMIT 3", (request.state.user["id"],)).fetchall()
    return {
        "counts": {"soil_tests": soil_count, "water_tests": water_count, "recommendations": rec_count},
        "recent_soil": [row_to_dict(r) for r in recent_soil],
        "recent_water": [row_to_dict(r) for r in recent_water],
        "recent_recommendations": [row_to_dict(r) for r in recent_recommendations],
    }


@app.post("/api/soil-tests", status_code=201)
def create_soil_test(data: SoilTestIn, request: Request):
    created = now_iso()
    with closing(connect_db()) as conn:
        cur = conn.execute(
            """INSERT INTO soil_tests
            (farmer_name, location, crop, ph, nitrogen, phosphorus, potassium, notes, created_at, user_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (data.farmer_name, data.location, data.crop, data.ph, data.nitrogen,
             data.phosphorus, data.potassium, data.notes, created, request.state.user["id"]),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM soil_tests WHERE id=?", (cur.lastrowid,)).fetchone()
    return {"message": "Soil report saved", "report": row_to_dict(row)}


@app.get("/api/soil-tests")
def list_soil_tests(request: Request):
    with closing(connect_db()) as conn:
        rows = conn.execute("SELECT * FROM soil_tests WHERE user_id=? ORDER BY id DESC LIMIT 100", (request.state.user["id"],)).fetchall()
    return {"items": [row_to_dict(r) for r in rows]}


@app.post("/api/water-tests", status_code=201)
def create_water_test(data: WaterTestIn, request: Request):
    created = now_iso()
    with closing(connect_db()) as conn:
        cur = conn.execute(
            """INSERT INTO water_tests
            (farmer_name, location, source, ph, ec, notes, created_at, user_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (data.farmer_name, data.location, data.source, data.ph, data.ec, data.notes, created, request.state.user["id"]),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM water_tests WHERE id=?", (cur.lastrowid,)).fetchone()
    return {"message": "Water report saved", "report": row_to_dict(row)}


@app.get("/api/water-tests")
def list_water_tests(request: Request):
    with closing(connect_db()) as conn:
        rows = conn.execute("SELECT * FROM water_tests WHERE user_id=? ORDER BY id DESC LIMIT 100", (request.state.user["id"],)).fetchall()
    return {"items": [row_to_dict(r) for r in rows]}


def crop_suggestions(data: CropAdvisorIn) -> list[dict]:
    # Transparent starter rules for educational use, not a validated agronomic model.
    season = data.season.lower()
    soil = data.soil_type.lower()
    water = data.water.lower()
    ph = data.ph
    suggestions = []
    if season in ("kharif", "monsoon", "खरीफ", "मानसून"):
        suggestions.extend([
            {"crop": "Rice (धान)", "reason": "Often grown in the monsoon season where water is sufficient.", "duration": "Usually around 100–150 days, depending on variety", "caution": "Needs suitable water management and locally appropriate variety."},
            {"crop": "Maize (मक्का)", "reason": "Can suit many monsoon farming systems with suitable drainage.", "duration": "Often around 80–110 days", "caution": "Variety, rainfall and local soil conditions matter."},
        ])
    elif season in ("rabi", "winter", "रबी", "सर्दी"):
        suggestions.extend([
            {"crop": "Wheat (गेहूँ)", "reason": "A common winter crop in many northern Indian farming regions.", "duration": "Often around 110–150 days", "caution": "Needs region-appropriate variety and irrigation planning."},
            {"crop": "Mustard (सरसों)", "reason": "A common winter oilseed option in suitable areas.", "duration": "Often around 100–140 days", "caution": "Check local climate and soil recommendations."},
        ])
    else:
        suggestions.extend([
            {"crop": "Green gram / Moong (मूंग)", "reason": "A short-duration pulse option in suitable local seasons.", "duration": "Often around 60–75 days", "caution": "Confirm the locally recommended sowing window."},
            {"crop": "Vegetables (सब्ज़ियाँ)", "reason": "A broad category that may fit small farms with a reliable market.", "duration": "Varies by crop", "caution": "Select a specific crop after checking local demand, water and season."},
        ])
    if "sandy" in soil or "बलुई" in soil:
        suggestions.append({"crop": "Pearl millet / Bajra (बाजरा)", "reason": "Can tolerate relatively dry conditions in suitable regions.", "duration": "Often around 75–100 days", "caution": "Confirm local suitability and seed variety."})
    if ph is not None and (ph < 5.5 or ph > 8.5):
        for item in suggestions:
            item["caution"] += " The entered soil pH is outside a commonly preferred range for many crops; obtain a lab interpretation before planting."
    if water in ("low", "limited", "कम", "सीमित"):
        suggestions = [s for s in suggestions if "Rice" not in s["crop"]]
        suggestions.append({"crop": "Millets / मोटे अनाज", "reason": "Some millet crops can be options where water is limited.", "duration": "Depends on crop and variety", "caution": "Choose only after checking local agronomy guidance."})
    if water in ("low", "limited", "कम", "सीमित"):
        # Keep the water-limited option inside the 4 returned items.
        suggestions = suggestions[:3] + [suggestions.pop()] if len(suggestions) > 4 else suggestions
    return suggestions[:4]


@app.post("/api/crop-advisor")
def crop_advisor(data: CropAdvisorIn, request: Request):
    suggestions = crop_suggestions(data)
    result = {
        "location": data.location,
        "season": data.season,
        "notice": "Educational starter recommendations based on simple rules. Confirm with local Krishi Vigyan Kendra/agriculture officer before investing.",
        "suggestions": suggestions,
        "inputs": data.model_dump(),
    }
    with closing(connect_db()) as conn:
        conn.execute(
            """INSERT INTO recommendations
            (location, season, soil_type, water, farm_size, budget, result_json, created_at, user_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (data.location, data.season, data.soil_type, data.water, data.farm_size, data.budget,
             json.dumps(result, ensure_ascii=False), now_iso(), request.state.user["id"]),
        )
        conn.commit()
    return result


@app.get("/api/weather")
async def weather(location: str, request: Request):
    location = location.strip()
    if not location or len(location) > 160:
        raise HTTPException(status_code=422, detail="Enter a valid city or village name.")
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            geo = await client.get(
                "https://geocoding-api.open-meteo.com/v1/search",
                params={"name": location, "count": 1, "language": "en", "format": "json"},
            )
            geo.raise_for_status()
            places = geo.json().get("results") or []
            if not places:
                raise HTTPException(status_code=404, detail="Location not found. Try a nearby city or district.")
            place = places[0]
            forecast = await client.get(
                "https://api.open-meteo.com/v1/forecast",
                params={
                    "latitude": place["latitude"], "longitude": place["longitude"],
                    "current": "temperature_2m,relative_humidity_2m,apparent_temperature,is_day,precipitation,weather_code,wind_speed_10m",
                    "daily": "temperature_2m_max,temperature_2m_min,precipitation_probability_max",
                    "forecast_days": 3, "timezone": "auto",
                },
            )
            forecast.raise_for_status()
            data = forecast.json()
        return {
            "source": "Open-Meteo",
            "place": f'{place.get("name", location)}, {place.get("admin1", "")}, {place.get("country", "")}'.strip(", "),
            "current": data.get("current", {}),
            "daily": data.get("daily", {}),
            "timezone": data.get("timezone"),
        }
    except HTTPException:
        raise
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        raise HTTPException(status_code=502, detail="Weather service is temporarily unavailable. Please try again later.") from exc


@app.post("/api/assistant")
async def assistant(data: ChatIn, request: Request):
    key = os.getenv("GEMINI_API_KEY", "").strip()
    model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash").strip()
    if not key:
        answer = (
            "AI is not configured yet. Add GEMINI_API_KEY to the .env file and restart the server. "
            "For now, please share your crop, location, season, soil report and water availability with a local agriculture officer."
            if data.language == "en" else
            "AI अभी कॉन्फ़िगर नहीं है। .env फ़ाइल में GEMINI_API_KEY जोड़ें और सर्वर दोबारा शुरू करें। "
            "फिलहाल अपनी फसल, स्थान, मौसम, मिट्टी की रिपोर्ट और पानी की उपलब्धता की जानकारी स्थानीय कृषि अधिकारी से साझा करें।"
        )
        return {"answer": answer, "mode": "setup_required", "provider": None}
    prompt = (
        "You are AgriVanta, a cautious agricultural information assistant for Indian farmers. "
        "Answer in " + ("Hindi" if data.language == "hi" else "English") + ". "
        "Be practical, clear, and concise. Do not guarantee yield or profit. Do not invent local weather, market prices, "
        "laboratory results, official recommendations, or citations. Ask for missing context when needed. "
        "For pesticide, fertilizer dosage, disease diagnosis, or high-risk decisions, advise following product labels "
        "and consulting a qualified local agricultural expert/KVK. State uncertainty clearly.\n\nFarmer question: " + data.message
    )
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    try:
        async with httpx.AsyncClient(timeout=25) as client:
            response = await client.post(
                url,
                params={"key": key},
                json={"contents": [{"parts": [{"text": prompt}]}], "generationConfig": {"temperature": 0.35, "maxOutputTokens": 700}},
            )
        if response.status_code >= 400:
            raise HTTPException(status_code=502, detail="AI provider rejected the request. Check the model name, API key and quota.")
        payload = response.json()
        answer = payload["candidates"][0]["content"]["parts"][0]["text"]
        return {"answer": answer, "mode": "live_ai", "provider": "Gemini"}
    except HTTPException:
        raise
    except (httpx.HTTPError, ValueError, KeyError, IndexError) as exc:
        raise HTTPException(status_code=502, detail="AI service is temporarily unavailable. Please try again later.") from exc


@app.get("/api/recommendations")
def recommendations(request: Request):
    with closing(connect_db()) as conn:
        rows = conn.execute("SELECT id, location, season, soil_type, water, created_at FROM recommendations WHERE user_id=? ORDER BY id DESC LIMIT 10", (request.state.user["id"],)).fetchall()
    return {"items": [row_to_dict(r) for r in rows]}


@app.get("/api/reports")
def reports(request: Request):
    with closing(connect_db()) as conn:
        soil = conn.execute("SELECT id, 'Soil' AS type, farmer_name AS name, location, crop AS detail, created_at FROM soil_tests WHERE user_id=? ORDER BY id DESC LIMIT 10", (request.state.user["id"],)).fetchall()
        water = conn.execute("SELECT id, 'Water' AS type, farmer_name AS name, location, source AS detail, created_at FROM water_tests WHERE user_id=? ORDER BY id DESC LIMIT 10", (request.state.user["id"],)).fetchall()
        plans = conn.execute("SELECT id, 'Crop plan' AS type, '—' AS name, location, season || ' · ' || soil_type || ' soil' AS detail, created_at FROM recommendations WHERE user_id=? ORDER BY id DESC LIMIT 10", (request.state.user["id"],)).fetchall()
    combined = [row_to_dict(r) for r in soil] + [row_to_dict(r) for r in water] + [row_to_dict(r) for r in plans]
    combined.sort(key=lambda x: x["created_at"], reverse=True)
    return {"items": combined[:25]}


