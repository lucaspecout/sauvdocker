from sqlalchemy.orm import Session
from .models import Setting
from .security import encrypt_value, decrypt_value


def set_setting(db: Session, key: str, value: str, encrypted: bool = False) -> None:
    existing = db.query(Setting).filter(Setting.key == key).first()
    stored = encrypt_value(value) if encrypted else value
    if existing:
        existing.value = stored
        existing.encrypted = encrypted
    else:
        db.add(Setting(key=key, value=stored, encrypted=encrypted))
    db.commit()


def get_setting(db: Session, key: str) -> str | None:
    setting = db.query(Setting).filter(Setting.key == key).first()
    if not setting:
        return None
    if setting.encrypted and setting.value:
        return decrypt_value(setting.value)
    return setting.value
