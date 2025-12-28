import importlib
import os

import pyotp
from fastapi.testclient import TestClient


def setup_module(module):
    os.environ["DATABASE_URL"] = "sqlite:///./test_auth.db"
    os.environ["DOCKBACK_SECRET_KEY"] = "test-secret"


def test_login_and_mfa_flow():
    from api.app import db as db_module
    from api.app import main as main_module
    importlib.reload(db_module)
    importlib.reload(main_module)

    client = TestClient(main_module.app)

    from api.app.security import hash_password
    from api.app.models import User

    with db_module.SessionLocal() as session:
        user = User(
            email="user@example.com",
            password_hash=hash_password("password"),
            role="Admin",
            force_password_change=True,
            is_active=True,
        )
        session.add(user)
        session.commit()

    resp = client.post("/auth/login", json={"email": "user@example.com", "password": "password"})
    assert resp.status_code == 200
    assert resp.cookies.get("dockback_access")

    mfa_resp = client.post("/auth/mfa/setup")
    assert mfa_resp.status_code == 200
    otpauth = mfa_resp.json()["otpauth_url"]
    secret = otpauth.split("secret=")[1].split("&")[0]
    totp = pyotp.TOTP(secret).now()

    resp_fail = client.post("/auth/login", json={"email": "user@example.com", "password": "password"})
    assert resp_fail.status_code == 401

    resp_ok = client.post(
        "/auth/login",
        json={"email": "user@example.com", "password": "password", "totp": totp},
    )
    assert resp_ok.status_code == 200
