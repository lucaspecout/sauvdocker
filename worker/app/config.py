from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "postgresql+psycopg2://dockback:dockback@postgres:5432/dockback"
    redis_url: str = "redis://redis:6379/0"
    dockback_data_dir: str = "/data/backups"
    dockback_encryption_key_file: str = "/run/secrets/dockback_encryption_key"

    class Config:
        env_prefix = ""
        case_sensitive = False


settings = Settings()
