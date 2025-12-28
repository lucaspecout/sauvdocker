from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..auth import require_permission
from ..db import get_db
from ..models import User
from ..schemas import UserOut, UserCreate
from ..security import hash_password
from ..audit import log_event

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/", response_model=list[UserOut])
def list_users(user=Depends(require_permission("manage_users")), db: Session = Depends(get_db)):
    return db.query(User).all()


@router.post("/", response_model=UserOut)
def create_user(payload: UserCreate, user=Depends(require_permission("manage_users")), db: Session = Depends(get_db)):
    new_user = User(
        email=payload.email,
        password_hash=hash_password(payload.password),
        role=payload.role,
        force_password_change=True,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    log_event(db, user.id, "user_create", payload.email)
    return new_user
