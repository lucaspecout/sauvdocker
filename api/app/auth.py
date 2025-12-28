from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, Request
from jose import JWTError
from sqlalchemy.orm import Session
import pyotp

from .db import get_db
from .models import User
from .security import decode_token

ROLE_PERMISSIONS = {
    "Admin": {"view", "backup", "restore", "manage_users", "manage_settings"},
    "Operator": {"view", "backup", "restore"},
    "ReadOnly": {"view"},
}

RATE_LIMIT = {}


def rate_limit_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def check_rate_limit(request: Request):
    key = rate_limit_key(request)
    now = datetime.utcnow()
    record = RATE_LIMIT.get(key, {"count": 0, "locked_until": None, "window_start": now})
    if record["locked_until"] and record["locked_until"] > now:
        raise HTTPException(status_code=429, detail="Too many attempts")
    if (now - record["window_start"]) > timedelta(minutes=5):
        record = {"count": 0, "locked_until": None, "window_start": now}
    record["count"] += 1
    if record["count"] > 5:
        record["locked_until"] = now + timedelta(minutes=5)
    RATE_LIMIT[key] = record


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    token = request.cookies.get("dockback_access")
    if not token:
        raise HTTPException(status_code=401, detail="Missing token")
    try:
        payload = decode_token(token)
        email = payload.get("sub")
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc
    user = db.query(User).filter(User.email == email).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Inactive user")
    return user


def require_permission(permission: str):
    def checker(user: User = Depends(get_current_user)) -> User:
        allowed = ROLE_PERMISSIONS.get(user.role, set())
        if permission not in allowed:
            raise HTTPException(status_code=403, detail="Forbidden")
        return user

    return checker


def verify_mfa(user: User, totp: Optional[str], recovery_code: Optional[str]) -> bool:
    if not user.mfa_enabled:
        return True
    if recovery_code and user.recovery_codes:
        if recovery_code in user.recovery_codes:
            user.recovery_codes.remove(recovery_code)
            return True
    if totp and user.mfa_secret:
        return pyotp.TOTP(user.mfa_secret).verify(totp)
    return False
