from pydantic import BaseModel, EmailStr
from typing import Optional, Any


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    totp: Optional[str] = None
    recovery_code: Optional[str] = None


class UserOut(BaseModel):
    id: int
    email: EmailStr
    role: str
    force_password_change: bool
    mfa_enabled: bool

    class Config:
        from_attributes = True


class UserCreate(BaseModel):
    email: EmailStr
    password: str
    role: str


class PasswordChange(BaseModel):
    new_password: str


class MFASetupResponse(BaseModel):
    otpauth_url: str
    recovery_codes: list[str]


class AuditLogOut(BaseModel):
    id: int
    action: str
    detail: Optional[str]

    class Config:
        from_attributes = True


class BackupPlanIn(BaseModel):
    name: str
    cron: str
    target_type: str
    target_ref: str
    retention_policy: Optional[dict[str, Any]] = None


class BackupPlanOut(BackupPlanIn):
    id: int
    enabled: bool

    class Config:
        from_attributes = True
