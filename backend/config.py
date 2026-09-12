from pydantic_settings import BaseSettings
from typing import List, Literal
import os


class Settings(BaseSettings):
    """Application configuration settings"""
    
    # Triage-6 integration settings
    MODEL_PATH: str = "model/lightgbm.txt"
    MODEL_MANIFEST: str = "model/manifest.json"
    HIGH_RISK_THRESHOLD: float = 0.85
    NARRATIVE_PROVIDER: Literal["auto", "template", "watsonx", "mistral"] = "auto"
    MISTRAL_API_KEY: str = ""
    MISTRAL_MODEL_ID: str = "mistral-large-latest"
    WATSONX_API_KEY: str = ""
    WATSONX_PROJECT_ID: str = ""
    WATSONX_URL: str = "https://us-south.ml.cloud.ibm.com"
    WATSONX_MODEL_ID: str = ""
    WATSONX_ENABLED: bool = False
    ADMIN_API_KEY: str = ""
    ANALYST_API_KEY: str = ""
    VIEWER_API_KEY: str = ""
    DEMO_ENABLED: bool = True

    # Application settings
    APP_NAME: str = "Security Operations Platform"
    VERSION: str = "1.0.0"
    DEBUG: bool = False
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    
    # Database settings
    DATABASE_URL: str = "sqlite:///./security_ops.db"
    
    # Security settings
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # CORS settings
    ALLOWED_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:8000"]
    
    # Logging settings
    LOG_LEVEL: str = "INFO"
    
    # CERT-In compliance settings
    CERT_IN_REPORTING_ENABLED: bool = True
    CERT_IN_REPORT_THRESHOLD_HOURS: int = 6
    
    # AI/ML settings
    AI_MODEL_ENABLED: bool = True
    AI_THREAT_ANALYSIS_ENABLED: bool = True
    
    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
