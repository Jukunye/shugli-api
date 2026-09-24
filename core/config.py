import os
from typing import Literal
from pydantic import Field
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file = ".env",
        env_file_encoding="utf-8"
    )

    # --- App ---
    debug: bool = False
    app_name: str = "Shugli API"

    # --- Security ---
    secret_key: str = BASE_DIR / Field(..., min_length=32)
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7


settings = Settings()