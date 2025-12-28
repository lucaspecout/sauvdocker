from fastapi import APIRouter, Depends, HTTPException, Response, Request
from sqlalchemy.orm import Session
import pyotp

from ..db import get_db
from ..models import User
from ..schemas import LoginRequest, UserOut, PasswordChange, MFASetupResponse
from ..security import hash_password, verify_password, create_access_token, create_refresh_token, generate_recovery_codes, decode_token
from ..auth import check_rate_limit, verify_mfa, get_current_user
from ..audit import log_event

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=UserOut)
def login(payload: LoginRequest, response: Response, request: Request, db: Session = Depends(get_db)):
    check_rate_limit(request)
    user = db.query(User).filter(User.email == payload.email).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not verify_mfa(user, payload.totp, payload.recovery_code):
        raise HTTPException(status_code=401, detail="MFA required")
    access = create_access_token(user.email, user.role)
    refresh = create_refresh_token(user.email)
    response.set_cookie("dockback_access", access, httponly=True, samesite="strict")
    response.set_cookie("dockback_refresh", refresh, httponly=True, samesite="strict")
    log_event(db, user.id, "login", "User logged in")
    return user


@router.post("/logout")
def logout(response: Response):
    response.delete_cookie("dockback_access")
    response.delete_cookie("dockback_refresh")
    return {"status": "ok"}


@router.post("/change-password")
def change_password(payload: PasswordChange, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    user.password_hash = hash_password(payload.new_password)
    user.force_password_change = False
    db.commit()
    log_event(db, user.id, "password_change", "Password updated")
    return {"status": "updated"}


@router.post("/mfa/setup", response_model=MFASetupResponse)
def setup_mfa(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    secret = pyotp.random_base32()
    user.mfa_secret = secret
    user.mfa_enabled = True
    recovery_codes = generate_recovery_codes()
    user.recovery_codes = recovery_codes
    db.commit()
    otpauth = pyotp.TOTP(secret).provisioning_uri(name=user.email, issuer_name="DockBack")
    log_event(db, user.id, "mfa_setup", "MFA configured")
    return MFASetupResponse(otpauth_url=otpauth, recovery_codes=recovery_codes)


@router.post("/refresh")
def refresh_token(request: Request, response: Response):
    refresh = request.cookies.get("dockback_refresh")
    if not refresh:
        raise HTTPException(status_code=401, detail="Missing refresh token")
    payload = decode_token(refresh)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    access = create_access_token(subject=payload.get("sub", "unknown"), role="ReadOnly")
    response.set_cookie("dockback_access", access, httponly=True, samesite="strict")
    return {"status": "refreshed"}
