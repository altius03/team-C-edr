from __future__ import annotations

from fastapi import APIRouter

from .dashboard import router as dashboard_router
from .health import router as health_router
from .incidents import router as incidents_router
from .reports import router as reports_router
from .tasks import router as tasks_router
from .telemetry import router as telemetry_router

ROUTERS: tuple[APIRouter, ...] = (
    health_router,
    dashboard_router,
    reports_router,
    incidents_router,
    telemetry_router,
    tasks_router,
)
