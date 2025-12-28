from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..auth import require_permission
from ..db import get_db
from ..settings_store import set_setting, get_setting
from ..audit import log_event

router = APIRouter(prefix="/settings", tags=["settings"])


@router.get("/{key}")
def read_setting(key: str, user=Depends(require_permission("manage_settings")), db: Session = Depends(get_db)):
    return {"key": key, "value": get_setting(db, key)}


@router.post("/{key}")
def write_setting(key: str, payload: dict, user=Depends(require_permission("manage_settings")), db: Session = Depends(get_db)):
    value = payload.get("value")
    encrypted = payload.get("encrypted", False)
    if value is None:
        return {"status": "no-op"}
    set_setting(db, key, value, encrypted=encrypted)
    log_event(db, user.id, "settings_update", key)
    return {"status": "updated"}
