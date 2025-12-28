import hashlib
import os
from datetime import datetime

import boto3
import docker
from celery.utils.log import get_task_logger
from sqlalchemy import update, insert

from .celery_app import celery_app
from .config import settings
from .db import SessionLocal
from .models import jobs, backups

logger = get_task_logger(__name__)


def _update_job(job_id: int, **fields):
    with SessionLocal() as session:
        session.execute(update(jobs).where(jobs.c.id == job_id).values(**fields))
        session.commit()


def _create_backup_record(job_id: int, storage: str, status: str, remote_path: str | None = None, error: str | None = None):
    with SessionLocal() as session:
        session.execute(
            insert(backups).values(
                job_id=job_id,
                storage=storage,
                status=status,
                remote_path=remote_path,
                error=error,
                created_at=datetime.utcnow(),
            )
        )
        session.commit()


def _checksum(path: str) -> str:
    sha = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            sha.update(chunk)
    return sha.hexdigest()


@celery_app.task(name="app.tasks.backup_volume")
def backup_volume(job_id: int, volume_name: str):
    _update_job(job_id, status="running")
    client = docker.DockerClient(base_url="unix://var/run/docker.sock")
    backup_dir = os.path.join(settings.dockback_data_dir, f"job-{job_id}")
    os.makedirs(backup_dir, exist_ok=True)
    archive_path = os.path.join(backup_dir, f"{volume_name}.tar.gz")
    try:
        client.containers.run(
            image="alpine:3.20",
            command=f"sh -c 'tar -czf /output/{volume_name}.tar.gz -C /source .'",
            remove=True,
            volumes={
                volume_name: {"bind": "/source", "mode": "ro"},
                backup_dir: {"bind": "/output", "mode": "rw"},
            },
        )
        checksum = _checksum(archive_path)
        _update_job(job_id, status="completed", backup_path=archive_path, checksum=checksum)
        _create_backup_record(job_id, "local", "completed", remote_path=archive_path)
        return {"path": archive_path, "checksum": checksum}
    except Exception as exc:  # noqa: BLE001
        logger.exception("Backup failed")
        _update_job(job_id, status="failed")
        _create_backup_record(job_id, "local", "failed", error=str(exc))
        raise


@celery_app.task(name="app.tasks.upload_s3")
def upload_s3(job_id: int, file_path: str, bucket: str, key: str, endpoint: str | None = None):
    client = boto3.client(
        "s3",
        endpoint_url=endpoint,
    )
    try:
        client.upload_file(file_path, bucket, key)
        _create_backup_record(job_id, "s3", "completed", remote_path=key)
        return {"bucket": bucket, "key": key}
    except Exception as exc:  # noqa: BLE001
        logger.exception("S3 upload failed")
        _create_backup_record(job_id, "s3", "failed", error=str(exc))
        raise
