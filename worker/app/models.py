from sqlalchemy import Table, Column, Integer, String, MetaData, DateTime
from sqlalchemy.sql import func

metadata = MetaData()

jobs = Table(
    "jobs",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("plan_id", Integer),
    Column("job_type", String(50)),
    Column("status", String(50)),
    Column("target_type", String(50)),
    Column("target_ref", String(200)),
    Column("backup_path", String(500)),
    Column("checksum", String(128)),
    Column("created_at", DateTime, server_default=func.now()),
    Column("updated_at", DateTime, server_default=func.now(), onupdate=func.now()),
)

backups = Table(
    "backups",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("job_id", Integer),
    Column("storage", String(50)),
    Column("remote_path", String(500)),
    Column("status", String(50)),
    Column("error", String(500)),
    Column("created_at", DateTime, server_default=func.now()),
)
