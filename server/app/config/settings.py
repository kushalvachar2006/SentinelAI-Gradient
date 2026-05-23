from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    # Service
    PORT: int = 8000
    DEBUG: bool = False
    WORKERS: int = 4
    NODE_SERVICE_URL: str = "http://localhost:3001"

    # AI — optional so service starts without a key (AI features degrade gracefully)
    GEMINI_API_KEY: Optional[str] = None

    # MongoDB
    MONGODB_URI: str = "mongodb://localhost:27017/sentinelai"
    MONGODB_DB: str = "sentinelai"

    # Enrichment APIs
    ABUSEIPDB_KEY: Optional[str] = None
    VIRUSTOTAL_KEY: Optional[str] = None
    MAXMIND_DB_PATH: Optional[str] = "/opt/maxmind/GeoLite2-City.mmdb"

    # Auth (shared JWT secret with Node) — default matches Node .env.example
    JWT_SECRET: str = "changeme_in_production"

    # Autonomous agent webhook
    JIRA_WEBHOOK_URL: Optional[str] = None

    class Config:
        env_file = ".env"
        case_sensitive = True
        extra = "ignore"


settings = Settings()