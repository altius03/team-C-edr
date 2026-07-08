from __future__ import annotations

import os
from typing import Final

from celery import Celery

DEFAULT_CELERY_BROKER_URL: Final = "redis://localhost:6379/0"


def broker_url_from_env() -> str:
    return os.environ.get("CELERY_BROKER_URL") or os.environ.get("REDIS_URL") or DEFAULT_CELERY_BROKER_URL


def create_celery_app(broker_url: str | None = None) -> Celery:
    app = Celery("layertrace", broker=broker_url or broker_url_from_env(), backend="disabled://", include=["src.celery_tasks"])
    app.conf.update(
        accept_content=["json"],
        enable_utc=True,
        result_backend="disabled://",
        result_serializer="json",
        task_ignore_result=True,
        task_serializer="json",
        timezone="UTC",
    )
    return app


celery_app = create_celery_app()
