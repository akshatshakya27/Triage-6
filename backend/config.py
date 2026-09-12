from pydantic_settings import BaseSettings
from typing import List
import os


class Settings(BaseSettings):
    """Application configuration settings"""
    
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
