from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "postgresql+psycopg2://dockback:dockback@postgres:5432/dockback"
    redis_url: str = "redis://redis:6379/0"
    dockback_data_dir: str = "/data/backups"
    dockback_secret_key: str = "change-me"
    dockback_base_url: str = "http://localhost:8080"
    dockback_encryption_key_file: str = "/run/secrets/dockback_encryption_key"
    access_token_exp_minutes: int = 30
    refresh_token_exp_days: int = 7

    class Config:
        env_prefix = ""
        case_sensitive = False


settings = Settings()
