from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..auth import require_permission
from ..db import get_db
from ..models import AuditLog

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("/")
def list_audit(user=Depends(require_permission("manage_settings")), db: Session = Depends(get_db)):
    return db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(200).all()
