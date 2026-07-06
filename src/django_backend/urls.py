from __future__ import annotations

from django.urls import path

from . import views

urlpatterns = [
    path("v1/health", views.health, name="health"),
    path("v1/dashboard/latest", views.dashboard_latest, name="dashboard_latest"),
    path("v1/incidents", views.incidents, name="incidents"),
    path("v1/reports/latest", views.reports_latest, name="reports_latest"),
    path("v1/telemetry/events", views.telemetry_events, name="telemetry_events"),
]
