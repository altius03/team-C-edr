from __future__ import annotations

import os

from src.config import BASE_DIR as PROJECT_BASE_DIR


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_list(name: str, default: list[str]) -> list[str]:
    value = os.environ.get(name)
    if not value:
        return default
    return [item.strip() for item in value.split(",") if item.strip()]


# Local defaults keep the PoC runnable; deployed environments should override
# these values through environment variables.
SECRET_KEY = os.environ.get("LAYERTRACE_SECRET_KEY", "layertrace-local-development-key")
DEBUG = _env_bool("LAYERTRACE_DEBUG", True)
ALLOWED_HOSTS = _env_list("LAYERTRACE_ALLOWED_HOSTS", ["127.0.0.1", "localhost", "testserver"])
ROOT_URLCONF = "src.django_backend.urls"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
INSTALLED_APPS: list[str] = []
MIDDLEWARE: list[str] = []
USE_TZ = True
TIME_ZONE = "Asia/Seoul"
BASE_DIR = PROJECT_BASE_DIR
# Agent ingest is authenticated even in the local REST version so the contract
# already matches a customer/tenant separated deployment shape.
LAYERTRACE_REQUIRE_API_TOKEN = _env_bool("LAYERTRACE_REQUIRE_API_TOKEN", True)
LAYERTRACE_API_TOKEN = os.environ.get("LAYERTRACE_API_TOKEN", "local-dev-token")
