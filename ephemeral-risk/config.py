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
    NGROK_AUTHTOKEN: str = "3FMaJoRSGOGoXl9LCfGJrQP78si_67ZfcWkzJxVm8V8aLmAEx"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()
