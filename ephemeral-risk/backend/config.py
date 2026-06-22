from pydantic_settings import BaseSettings, SettingsConfigDict

# IMPORTANT: All secrets are loaded from environment variables (or a local
# .env file). The defaults below are intentionally NON-FUNCTIONAL placeholders
# safe to commit. Set real values via environment variables or .env before run.
#
# Copy .env.example to .env and fill in your real credentials.

class Settings(BaseSettings):
    # GitHub webhook HMAC secret. Must match the secret configured on the
    # GitHub repository webhook. Override via GITHUB_WEBHOOK_SECRET env var.
    GITHUB_WEBHOOK_SECRET: str = "devsecret"

    # ngrok authtoken to expose the local server publicly for GitHub webhooks.
    # Leave empty to skip the ngrok tunnel (e.g. when running locally only).
    # Override via NGROK_AUTHTOKEN env var.
    NGROK_AUTHTOKEN: str = ""

    # ── Email / SMTP alert settings ──────────────────────────────────────────
    # SMTP host — leave empty to disable email alerts (local log only).
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""

    # Comma-separated list of recipient addresses for incident alerts.
    ALERT_RECIPIENT: str = ""

    # Ollama Cloud configuration loaded from .env
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_API_KEY: str = ""
    OLLAMA_MODEL: str = "gemma4"
    
    # Groq API Key loaded from env or .env
    GROQ_API_KEY: str = ""

    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()

GROQ_API_KEY = settings.GROQ_API_KEY
