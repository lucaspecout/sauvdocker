import importlib
import os
import pathlib


def setup_module(module):
    os.environ["DATABASE_URL"] = "sqlite:///./test_backup.db"
    os.environ["REDIS_URL"] = "redis://localhost:6379/0"
    os.environ["DOCKBACK_DATA_DIR"] = "./backups-test"


def test_backup_volume_task(monkeypatch):
    from worker.app import db as db_module
    from worker.app import models as models_module
    importlib.reload(db_module)
    importlib.reload(models_module)

    models_module.metadata.create_all(db_module.engine)

    backup_root = pathlib.Path("./backups-test")
    backup_root.mkdir(exist_ok=True)

    with db_module.SessionLocal() as session:
        session.execute(
            models_module.jobs.insert().values(
                id=1,
                job_type="backup",
                status="queued",
                target_type="volume",
                target_ref="demo-volume",
            )
        )
        session.commit()

    class FakeContainers:
        def run(self, image, command, remove, volumes):
            output_dir = next(iter(volumes.values()))["bind"]
            archive_path = pathlib.Path(output_dir) / "demo-volume.tar.gz"
            archive_path.write_bytes(b"dummy")

    class FakeClient:
        containers = FakeContainers()

    monkeypatch.setattr("worker.app.tasks.docker.DockerClient", lambda base_url: FakeClient())

    from worker.app.tasks import backup_volume

    result = backup_volume(job_id=1, volume_name="demo-volume")
    assert result["checksum"]
    assert pathlib.Path(result["path"]).exists()
