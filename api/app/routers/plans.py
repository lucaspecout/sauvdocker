from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..auth import require_permission
from ..db import get_db
from ..models import BackupPlan
from ..schemas import BackupPlanIn, BackupPlanOut
from ..audit import log_event

router = APIRouter(prefix="/plans", tags=["plans"])


@router.get("/", response_model=list[BackupPlanOut])
def list_plans(user=Depends(require_permission("view")), db: Session = Depends(get_db)):
    return db.query(BackupPlan).all()


@router.post("/", response_model=BackupPlanOut)
def create_plan(payload: BackupPlanIn, user=Depends(require_permission("manage_settings")), db: Session = Depends(get_db)):
    plan = BackupPlan(**payload.model_dump(), enabled=True)
    db.add(plan)
    db.commit()
    db.refresh(plan)
    log_event(db, user.id, "plan_create", f"Plan {plan.name}")
    return plan
