from sqlalchemy.orm import Session
from .models import AuditLog


def log_event(db: Session, user_id: int | None, action: str, detail: str | None = None) -> None:
    entry = AuditLog(user_id=user_id, action=action, detail=detail)
    db.add(entry)
    db.commit()
