"""
Централизованный LLM-конфигуратор.

Логика простая:
  1. Пользователь задаёт ONE провайдер в настройках оркестратора.
  2. llm_config.py транслирует его в переменные окружения,
     которые понимает каждый конкретный инструмент.
  3. pipeline.py передаёт эти env-vars в subprocess при запуске каждого этапа.

Поддерживаемые провайдеры:
  openrouter  → https://openrouter.ai/api/v1
  groq        → https://api.groq.com/openai/v1
  ollama      → http://localhost:11434/v1
  openai      → https://api.openai.com/v1
  custom      → любой OpenAI-совместимый endpoint

Все четыре инструмента в итоге получают одни и те же три ключевые переменные:
  OPENAI_API_KEY   — ключ (для ollama можно "ollama")
  OPENAI_BASE_URL  — endpoint
  OPENAI_MODEL     — название модели

Плюс инструменто-специфичные алиасы (LLM_API_KEY, STRIX_LLM и т.д.),
которые некоторые инструменты требуют в дополнение к стандартным.
"""

import os
from . import db

# ── Предустановленные провайдеры ──
PRESETS: dict[str, dict] = {
    "openrouter": {
        "base_url": "https://openrouter.ai/api/v1",
        "free_models": [
            "deepseek/deepseek-r1:free",
            "meta-llama/llama-3.3-70b-instruct:free",
            "google/gemini-2.0-flash-exp:free",
            "mistralai/mistral-7b-instruct:free",
        ],
        "default_model": "deepseek/deepseek-r1:free",
        "extra_headers": {
            "HTTP-Referer": "https://github.com/your/strikenet",
            "X-Title": "StrikeNet Orchestrator",
        },
    },
    "groq": {
        "base_url": "https://api.groq.com/openai/v1",
        "free_models": [
            "llama-3.3-70b-versatile",
            "llama-3.1-8b-instant",
            "mixtral-8x7b-32768",
        ],
        "default_model": "llama-3.3-70b-versatile",
    },
    "ollama": {
        "base_url": "http://localhost:11434/v1",
        "free_models": [
            "llama3.3:70b",
            "deepseek-r1:32b",
            "qwen2.5:14b",
            "mistral:7b",
        ],
        "default_model": "qwen2.5:14b",
        "api_key": "ollama",   # ollama не требует реального ключа
    },
    "openai": {
        "base_url": "https://api.openai.com/v1",
        "free_models": [],
        "default_model": "gpt-4o-mini",
    },
}


def get_active_provider() -> dict | None:
    """Читает активный LLM-провайдер из настроек оркестратора."""
    settings = db.get_settings()
    provider_type = settings.get("llm_provider_type", "openrouter")
    api_key       = settings.get("llm_api_key", "")
    model         = settings.get("llm_model", "")
    custom_url    = settings.get("llm_custom_url", "")

    preset = PRESETS.get(provider_type, PRESETS["openrouter"])
    base_url = custom_url if provider_type == "custom" and custom_url else preset["base_url"]
    resolved_model = model or preset.get("default_model", "")
    resolved_key = api_key or preset.get("api_key", "")

    return {
        "provider_type": provider_type,
        "base_url": base_url,
        "api_key": resolved_key,
        "model": resolved_model,
        "preset": preset,
    }


def build_env_for_tool(tool: str, provider: dict | None = None) -> dict[str, str]:
    """
    Возвращает словарь env-переменных для конкретного инструмента.
    Берёт текущее окружение процесса как базу и добавляет/перезаписывает
    только LLM-специфичные переменные.
    """
    if provider is None:
        provider = get_active_provider()
    if not provider:
        return {}

    base_url  = provider["base_url"]
    api_key   = provider["api_key"]
    model     = provider["model"]
    p_type    = provider["provider_type"]

    # ── Базовые переменные (OpenAI-совместимый формат, понимают все) ──
    env = {
        "OPENAI_API_KEY":  api_key,
        "OPENAI_BASE_URL": base_url,
        "OPENAI_MODEL":    model,
        # некоторые инструменты читают старые имена
        "OPENAI_API_BASE": base_url,
        "LLM_API_KEY":     api_key,
        "LLM_API_BASE":    base_url,
        "LLM_MODEL":       model,
    }

    # ── Инструменто-специфичные переменные ──
    if tool == "strix":
        # Strix читает STRIX_LLM в формате "provider/model"
        strix_model = f"openai/{model}" if p_type not in ("openrouter",) else model
        env["STRIX_LLM"]      = strix_model
        env["LLM_API_KEY"]    = api_key
        env["DOCKER_LLM_KEY"] = api_key   # пробрасывается в strix-dind

    elif tool == "shannon":
        # Shannon читает KEYGRAPH_* или стандартные OPENAI_*
        env["KEYGRAPH_LLM_ENDPOINT"] = base_url
        env["KEYGRAPH_API_KEY"]      = api_key
        env["KEYGRAPH_MODEL"]        = model

    elif tool == "deepaudit":
        # DeepAudit поддерживает несколько форматов
        env["DEEPAUDIT_LLM_PROVIDER"] = p_type
        env["DEEPAUDIT_API_KEY"]      = api_key
        env["DEEPAUDIT_BASE_URL"]     = base_url
        env["DEEPAUDIT_MODEL"]        = model

    elif tool == "hexstrike":
        # HexStrike через opencode читает стандартные OPENAI_*
        # а также специфичные для opencode
        env["OPENCODE_API_KEY"]   = api_key
        env["OPENCODE_BASE_URL"]  = base_url
        env["OPENCODE_MODEL"]     = model

    # ── OpenRouter: дополнительные заголовки через переменные ──
    if p_type == "openrouter":
        env["OPENROUTER_API_KEY"] = api_key
        env["OR_SITE_URL"] = "https://github.com/your/strikenet"
        env["OR_APP_NAME"] = "StrikeNet Orchestrator"

    # ── Ollama: дополнительный хост на случай Docker-сети ──
    if p_type == "ollama":
        # если инструмент в Docker — localhost не достучится до хоста
        # используем host.docker.internal или явный IP
        docker_host = base_url.replace("localhost", "host.docker.internal")
        env["OLLAMA_HOST"]     = base_url
        env["OPENAI_BASE_URL"] = docker_host
        env["LLM_API_BASE"]    = docker_host

    return env


def merge_with_os_env(tool_env: dict[str, str]) -> dict[str, str]:
    """Мерджит LLM-переменные с текущим окружением процесса."""
    merged = dict(os.environ)
    merged.update(tool_env)
    return merged


def get_provider_info() -> dict:
    """Для API: возвращает текущий провайдер с замаскированным ключом."""
    p = get_active_provider()
    if not p:
        return {}
    return {
        "provider_type": p["provider_type"],
        "base_url":      p["base_url"],
        "model":         p["model"],
        "api_key_set":   bool(p["api_key"]),
        "api_key_hint":  (p["api_key"][:8] + "***") if p["api_key"] else "",
        "free_models":   p["preset"].get("free_models", []),
    }
