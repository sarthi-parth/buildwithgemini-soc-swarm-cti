import os
from pydantic_settings import BaseSettings
from typing import List

class Settings(BaseSettings):
    ENVIRONMENT: str = "development"
    DATABASE_URL: str = "sqlite+aiosqlite:///./cti_platform.db"
    VECTOR_DB_PATH: str = "./vector_store.db"
    PORT: int = 8000
    HOST: str = "0.0.0.0"
    CORS_ORIGINS: str = "http://localhost:5173,http://localhost:8000,http://127.0.0.1:5173,http://127.0.0.1:8000"

    # Google GenAI / Vertex AI
    GOOGLE_GENAI_USE_VERTEXAI: bool = True
    GOOGLE_CLOUD_PROJECT: str = "qwiklabs-gcp-03-fd05546dff54"
    GOOGLE_CLOUD_LOCATION: str = "global"
    GEMINI_MODEL: str = "gemini-3.8-flash"
    EMBEDDING_MODEL: str = "text-embedding-004"

    # Gmail
    GMAIL_CREDENTIALS_FILE: str = "./credentials.json"
    GMAIL_TOKEN_FILE: str = "./token.json"
    GMAIL_DEFAULT_RECIPIENT: str = "security-analyst@example.com"
    GMAIL_ENABLED: bool = False
    GMAIL_HIGH_SEVERITY_ONLY: bool = False

    # Scheduler & Pipeline
    POLLING_INTERVAL_MINUTES: int = 15
    AUTO_INVESTIGATE: bool = True
    MAX_PARALLEL_INVESTIGATIONS: int = 3
    MAX_VERIFICATION_RETRIES: int = 2

    @property
    def cors_origin_list(self) -> List[str]:
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()
