import os
import sys
import tempfile
from pathlib import Path
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Ensure tests use an isolated database before importing the app.
tmp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
tmp_db.close()
os.environ["AGRIVANTA_DB"] = tmp_db.name

from app.main import app, init_db  # noqa: E402

init_db()
client = TestClient(app)
# Keep the existing feature tests authenticated, as a real browser session would be.
register_response = client.post("/api/auth/register", json={
    "name": "Test Farmer",
    "email": "farmer@example.com",
    "password": "SecurePass123",
})
assert register_response.status_code == 201


def test_health():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_save_soil_report():
    response = client.post("/api/soil-tests", json={
        "farmer_name": "Test Farmer",
        "location": "Muzaffarpur, Bihar",
        "crop": "Wheat",
        "ph": 6.5,
        "nitrogen": None,
        "notes": "Sample test entry"
    })
    assert response.status_code == 201
    assert response.json()["report"]["crop"] == "Wheat"


def test_crop_advisor():
    response = client.post("/api/crop-advisor", json={
        "location": "Muzaffarpur, Bihar",
        "season": "Rabi",
        "soil_type": "Loamy",
        "water": "Moderate",
        "ph": 6.7
    })
    assert response.status_code == 200
    assert len(response.json()["suggestions"]) >= 1
    assert "notice" in response.json()


def test_invalid_ph_rejected():
    response = client.post("/api/soil-tests", json={
        "farmer_name": "Test Farmer",
        "location": "Test",
        "crop": "Wheat",
        "ph": 18
    })
    assert response.status_code == 422


def test_home_page():
    response = client.get("/")
    assert response.status_code == 200
    assert "AgriVanta" in response.text


def test_crop_plan_is_saved_in_dashboard_and_reports():
    response = client.post("/api/crop-advisor", json={
        "location": "Muzaffarpur, Bihar",
        "season": "Rabi",
        "soil_type": "Loamy",
        "water": "Moderate",
        "ph": 6.5,
        "farm_size": 1.5,
        "budget": 10000,
    })
    assert response.status_code == 200
    dashboard = client.get("/api/dashboard").json()
    assert dashboard["counts"]["recommendations"] >= 1
    assert dashboard["recent_recommendations"]
    reports = client.get("/api/reports").json()["items"]
    assert any(item["type"] == "Crop plan" for item in reports)



def test_login_page_redirects_when_logged_out():
    guest = TestClient(app)
    response = guest.get("/", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    login_page = guest.get("/login")
    assert login_page.status_code == 200
    assert "Create account" in login_page.text


def test_login_logout_and_protected_api():
    guest = TestClient(app)
    assert guest.get("/api/dashboard").status_code == 401
    response = guest.post("/api/auth/login", json={
        "email": "farmer@example.com",
        "password": "SecurePass123",
    })
    assert response.status_code == 200
    assert guest.get("/api/dashboard").status_code == 200
    guest.post("/api/auth/logout")
    assert guest.get("/api/dashboard").status_code == 401


def test_accounts_cannot_see_each_others_reports():
    other = TestClient(app)
    created = other.post("/api/auth/register", json={
        "name": "Other Farmer",
        "email": "other@example.com",
        "password": "OtherPass123",
    })
    assert created.status_code == 201
    assert other.get("/api/soil-tests").json()["items"] == []


def test_duplicate_registration_rejected():
    other = TestClient(app)
    response = other.post("/api/auth/register", json={
        "name": "Dup", "email": "FARMER@example.com", "password": "SecurePass123"})
    assert response.status_code == 409


def test_wrong_password_rejected():
    guest = TestClient(app)
    response = guest.post("/api/auth/login", json={
        "email": "farmer@example.com", "password": "WrongPass999"})
    assert response.status_code == 401


def test_logout_invalidates_old_token():
    session = TestClient(app)
    session.post("/api/auth/login", json={"email": "farmer@example.com", "password": "SecurePass123"})
    stolen = session.cookies.get("agrivanta_session")
    session.post("/api/auth/logout")
    replay = TestClient(app, cookies={"agrivanta_session": stolen})
    assert replay.get("/api/dashboard").status_code == 401


def test_tampered_token_rejected():
    forged = TestClient(app, cookies={"agrivanta_session": "MToxOTk5OTk5OTk5OjA6YWJj"})
    assert forged.get("/api/dashboard").status_code == 401
