from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..auth import require_permission
from ..db import get_db
from ..models import Job
from ..audit import log_event

router = APIRouter(prefix="/jobs", tags=["jobs"])


@router.get("/")
def list_jobs(user=Depends(require_permission("view")), db: Session = Depends(get_db)):
    return db.query(Job).order_by(Job.created_at.desc()).all()


@router.post("/backup")
def trigger_backup(payload: dict, user=Depends(require_permission("backup")), db: Session = Depends(get_db)):
    job = Job(
        job_type="backup",
        status="queued",
        target_type=payload.get("target_type", "volume"),
        target_ref=payload.get("target_ref", ""),
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    log_event(db, user.id, "backup_trigger", f"Job {job.id}")
    return {"job_id": job.id}
