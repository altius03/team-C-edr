from __future__ import annotations

from src.config import BASE_DIR as PROJECT_BASE_DIR

SECRET_KEY = "layertrace-local-development-key"
DEBUG = True
ALLOWED_HOSTS = ["127.0.0.1", "localhost", "testserver"]
ROOT_URLCONF = "src.django_backend.urls"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
INSTALLED_APPS: list[str] = []
MIDDLEWARE: list[str] = []
USE_TZ = True
TIME_ZONE = "Asia/Seoul"
BASE_DIR = PROJECT_BASE_DIR
