from pydantic import BaseModel, field_validator
from typing import Optional


class RunCreate(BaseModel):
    target_url: str
    target_repo: Optional[str] = None
    tools: list[str] = ["deepaudit", "hexstrike", "strix", "shannon"]
    llm_provider: Optional[str] = "openrouter"
    llm_model: Optional[str] = None
    nono_enabled: bool = True
    reset_between_stages: bool = True

    @field_validator("target_url")
    @classmethod
    def validate_url(cls, v):
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL должен начинаться с http:// или https://")
        return v.strip()


class ScheduleCreate(BaseModel):
    target_url: str
    target_repo: Optional[str] = None
    tools: list[str] = ["hexstrike", "strix", "shannon"]
    cron: str  # cron-выражение, например "0 2 * * 1"
    active: bool = True


class LLMProviderCreate(BaseModel):
    name: str
    provider_type: str  # openrouter | ollama | openai | custom
    endpoint: str
    api_key: Optional[str] = None
    default_model: Optional[str] = None


class SettingsUpdate(BaseModel):
    instance_name: Optional[str] = None
    timezone: Optional[str] = None
    results_dir: Optional[str] = None
    reset_script: Optional[str] = None
    retention_days: Optional[int] = None
    nono_enabled: Optional[bool] = None
    telegram_webhook: Optional[str] = None
    slack_webhook: Optional[str] = None
    notify_critical: Optional[bool] = None
    notify_done: Optional[bool] = None
    notify_error: Optional[bool] = None


class LLMTestRequest(BaseModel):
    provider_type: str
    endpoint: str
    api_key: Optional[str] = None
    model: Optional[str] = None


class LLMActiveConfig(BaseModel):
    """Единый активный LLM-провайдер для всего оркестратора."""
    provider_type: str    # openrouter | groq | ollama | openai | custom
    api_key: Optional[str] = None
    model: Optional[str] = None
    custom_url: Optional[str] = None  # только для provider_type=custom
