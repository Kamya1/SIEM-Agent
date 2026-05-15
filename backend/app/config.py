from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    groq_api_key: str | None = None
    groq_model: str = "llama-3.3-70b-versatile"

    stm_max_turns: int = 10
    stm_compress_batch: int = 5
    ltm_retrieval_k: int = 3
    ltm_similarity_threshold: float = 0.35
    hybrid_context_similarity_threshold: float = 0.6

    data_dir: str = "data"
    db_path: str = "data/ltm_store.db"

    @property
    def data_path(self) -> Path:
        p = Path(self.data_dir)
        return p.resolve() if p.is_absolute() else (Path.cwd() / p).resolve()

    @property
    def ltm_db_path(self) -> Path:
        p = Path(self.db_path)
        return p.resolve() if p.is_absolute() else (self.data_path / p.name).resolve()

    def resolved_groq(self) -> tuple[str | None, str]:
        return self.groq_api_key, self.groq_model


@lru_cache
def get_settings() -> Settings:
    return Settings()
