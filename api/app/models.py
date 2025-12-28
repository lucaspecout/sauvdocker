from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, JSON
from sqlalchemy.sql import func
from .db import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(50), nullable=False, default="Admin")
    is_active = Column(Boolean, nullable=False, default=True)
    force_password_change = Column(Boolean, nullable=False, default=True)
    mfa_secret = Column(String(64), nullable=True)
    mfa_enabled = Column(Boolean, nullable=False, default=False)
    recovery_codes = Column(JSON, nullable=True)
    created_at = Column(DateTime, server_default=func.now())


class Setting(Base):
    __tablename__ = "settings"

    id = Column(Integer, primary_key=True)
    key = Column(String(128), unique=True, nullable=False)
    value = Column(Text, nullable=True)
    encrypted = Column(Boolean, nullable=False, default=False)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=True)
    action = Column(String(100), nullable=False)
    detail = Column(Text, nullable=True)
    created_at = Column(DateTime, server_default=func.now())


class BackupPlan(Base):
    __tablename__ = "backup_plans"

    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False)
    cron = Column(String(100), nullable=False)
    target_type = Column(String(50), nullable=False)
    target_ref = Column(String(200), nullable=False)
    retention_policy = Column(JSON, nullable=True)
    enabled = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, server_default=func.now())


class Job(Base):
    __tablename__ = "jobs"

    id = Column(Integer, primary_key=True)
    plan_id = Column(Integer, nullable=True)
    job_type = Column(String(50), nullable=False)
    status = Column(String(50), nullable=False)
    target_type = Column(String(50), nullable=False)
    target_ref = Column(String(200), nullable=False)
    backup_path = Column(String(500), nullable=True)
    checksum = Column(String(128), nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())


class Backup(Base):
    __tablename__ = "backups"

    id = Column(Integer, primary_key=True)
    job_id = Column(Integer, nullable=False)
    storage = Column(String(50), nullable=False)
    remote_path = Column(String(500), nullable=True)
    status = Column(String(50), nullable=False)
    error = Column(Text, nullable=True)
    created_at = Column(DateTime, server_default=func.now())
