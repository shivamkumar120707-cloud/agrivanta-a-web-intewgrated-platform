# AgriVanta — From Soil to Sale

A runnable bilingual (English/Hindi) college mini-project for farmer support. It includes a responsive web UI, FastAPI backend, SQLite persistence, email/password registration and login, signed HttpOnly sessions, per-account soil/water/crop-plan records, crop recommendations, weather lookup, and an optional Gemini-powered farming assistant.

## Requirements
- Python 3.10+
- Internet access for installing dependencies and live weather / AI integrations (the website itself runs locally)
- A Gemini API key is optional; add it to `.env` to enable live AI responses.

## Run locally

### Windows (PowerShell)
```powershell
cd agrivanta
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
uvicorn app.main:app --reload
```
Open http://127.0.0.1:8000

### macOS / Linux
```bash
cd agrivanta
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload
```
Open http://127.0.0.1:8000

API docs: http://127.0.0.1:8000/docs

## AI setup (optional)
1. Obtain a Gemini API key from Google AI Studio.
2. Put it in `.env` as `GEMINI_API_KEY=your_key_here`.
3. Set `GEMINI_MODEL=gemini-2.5-flash` or another currently available model that supports text generation.
4. Restart the server.

Without a key, the assistant uses a clearly identified local demo response. It does not pretend that the response came from a live AI model.

## What works
- Bilingual English/Hindi UI toggle.
- Soil test entry and SQLite persistence.
- Water test entry and SQLite persistence.
- Rule-based crop suggestions from farm details and soil pH.
- Farming assistant with optional Gemini REST API integration.
- Current weather lookup through Open-Meteo using a searched city/place name.
- Recent reports shown in the dashboard.
- API documentation and health endpoint.
- Login/register page with password hashing, signed HttpOnly cookies, logout, and account-specific report visibility.

## Project limitations
- Soil and water values are farmer-entered/lab-reported; this app does not physically test samples.
- Crop suggestions are educational decision support, not a guarantee of yield or profit.
- Crop-health photo analysis, live market prices, and verified buyer discovery are not implemented as live integrations in this first runnable version. They are presented as future modules rather than fake live services.
- If `AGRIVANTA_SECRET_KEY` is missing or a placeholder, the app uses a temporary random secret (logins reset on restart). Login/register attempts are rate-limited in memory (10 per 15 min per IP+email); use a shared limiter if you run multiple workers.
- Weather geocoding and forecast require internet access.
- For public deployment, set a strong unique AGRIVANTA_SECRET_KEY, set COOKIE_SECURE=1 behind HTTPS, and add rate limiting, backup/restore procedures, monitoring, and a security review. The included authentication is suitable as a college-project starter, not a substitute for a professional security audit.

## Project structure
```text
agrivanta/
├── app/
│   ├── __init__.py
│   ├── main.py
│   └── static/
│       ├── index.html
│       ├── login.html
│       ├── styles.css
│       └── app.js
├── tests/
│   └── test_app.py
├── .env.example
├── requirements.txt
└── README.md
```


## Updated version notes
- Added a three-step getting-started panel with links to soil reports, crop planning, and local weather.
- Crop recommendations and their main explanations now display in Hindi when Hindi is selected.
- Recent dashboard activity includes crop plans as well as soil and water reports.
- Reports history now includes saved crop plans.
- The crop recommendation module is labelled honestly as a rule-based crop advisor; the separate assistant can use Gemini when configured.
