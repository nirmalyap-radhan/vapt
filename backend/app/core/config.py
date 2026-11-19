from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    APP_NAME: str = "VAPTProX"
    API_PREFIX: str = "/api/v1"
    SECRET_KEY: str = "dev-secret-key-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    DATABASE_URL: str = "sqlite:///./vaptprox.db"
    FRONTEND_ORIGIN: str = "http://localhost:5173"
    REQUEST_TIMEOUT_SECONDS: int = 15

    GEMINI_API_KEY: str = ""
    GROQ_API_KEY: str = ""

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()
