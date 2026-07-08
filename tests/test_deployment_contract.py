"""Protect deployment files that keep local and split-service runs aligned."""

import json
import unittest
from pathlib import Path

from src.service_store import ServiceStore

PROJECT_DIR = Path(__file__).resolve().parents[1]


class DeploymentContractTests(unittest.TestCase):
    """Check storage selection, compose topology, and viewport-scope decisions."""

    def test_service_store_accepts_database_url_and_identifies_postgres(self) -> None:
        """Ensure PostgreSQL URLs select the deployment storage label."""
        store = ServiceStore(database_url="postgresql+psycopg://layertrace:layertrace@localhost:5432/layertrace")

        self.assertEqual(store.storage_label, "postgresql")

    def test_compose_env_and_dependencies_target_split_deployment(self) -> None:
        """Ensure compose, env, and package metadata describe the split stack."""
        compose_path = PROJECT_DIR / "docker-compose.yml"
        dockerfile = (PROJECT_DIR / "Dockerfile.api").read_text(encoding="utf-8")
        frontend_dockerfile = (PROJECT_DIR / "Dockerfile.frontend").read_text(encoding="utf-8")
        pyproject = (PROJECT_DIR / "pyproject.toml").read_text(encoding="utf-8")
        env_example = (PROJECT_DIR / ".env.example").read_text(encoding="utf-8")
        package = json.loads((PROJECT_DIR / "package.json").read_text(encoding="utf-8"))

        self.assertTrue(compose_path.exists(), "docker-compose.yml is required for local deployment parity")
        compose_text = compose_path.read_text(encoding="utf-8")
        for required in ("api:", "postgres:", "redis:", "worker:"):
            self.assertIn(required, compose_text)
        self.assertNotIn("redpanda:", compose_text)
        self.assertNotIn("rabbitmq:", compose_text.lower())
        self.assertNotIn("kafka:", compose_text.lower())
        self.assertNotIn("local-dev-token", compose_text)
        self.assertNotIn("POSTGRES_PASSWORD: layertrace", compose_text)
        self.assertNotIn(":layertrace@postgres", compose_text)
        self.assertNotIn("5432:5432", compose_text)
        self.assertIn("CELERY_BROKER_URL: &celery-broker-url redis://redis:6379/0", compose_text)
        self.assertIn("REDIS_URL: *celery-broker-url", compose_text)
        self.assertIn('command: ["uv", "run", "celery", "-A", "src.celery_app:celery_app", "worker"', compose_text)
        self.assertNotIn('scripts/run_worker.py", "--poll-interval"', compose_text)
        self.assertIn("condition: service_healthy", compose_text)
        self.assertNotIn("--seed-sample", dockerfile)
        self.assertIn('"--task-runner", "celery"', dockerfile)
        self.assertNotIn('"--task-runner", "external"', dockerfile)
        self.assertIn("VITE_LAYERTRACE_ALLOW_DEMO_FALLBACK", frontend_dockerfile)
        self.assertIn("VITE_LAYERTRACE_ALLOW_DEMO_FALLBACK: ${VITE_LAYERTRACE_ALLOW_DEMO_FALLBACK:-false}", compose_text)
        self.assertNotIn("outbox-publisher", compose_text)
        self.assertIn("celery", pyproject)
        self.assertIn("redis", pyproject)
        self.assertIn("psycopg", pyproject)
        self.assertIn("CELERY_BROKER_URL=", env_example)
        self.assertIn("REDIS_URL=", env_example)
        self.assertIn("DATABASE_URL=", env_example)
        self.assertIn("LAYERTRACE_API_TOKEN=", env_example)
        self.assertIn("POSTGRES_PASSWORD=", env_example)
        self.assertIn("VITE_LAYERTRACE_API_BASE_URL=", env_example)
        self.assertIn("VITE_LAYERTRACE_ALLOW_DEMO_FALLBACK=false", env_example)
        self.assertIn("local:up", package["scripts"])
        self.assertIn("local:down", package["scripts"])

    def test_lineage_schema_change_has_postgres_migration_artifact(self) -> None:
        migration_path = PROJECT_DIR / "migrations" / "20260707_deployment_lineage.sql"

        self.assertTrue(migration_path.exists(), "deployment lineage schema changes need a Postgres migration file")
        migration = migration_path.read_text(encoding="utf-8")
        for required in (
            "ALTER TABLE runs ADD COLUMN IF NOT EXISTS customer_id",
            "ALTER TABLE events ADD COLUMN IF NOT EXISTS tenant_id",
            "CREATE TABLE IF NOT EXISTS alert_events",
            "CREATE TABLE IF NOT EXISTS incident_alerts",
            "fk_alert_events_event",
            "fk_incident_alerts_alert",
        ):
            self.assertIn(required, migration)

    def test_small_viewport_specific_surface_is_removed(self) -> None:
        """Ensure responsive-specific wording and CSS branches stay out of this PoC."""
        css = (PROJECT_DIR / "web" / "src" / "styles.css").read_text(encoding="utf-8")
        readme = (PROJECT_DIR / "README.md").read_text(encoding="utf-8").lower()

        self.assertNotIn("@media (max-width: " + "720px)", css)
        self.assertNotIn("390" + "px", css)
        self.assertNotIn("mobi" + "le", readme)
        self.assertNotIn("모바" + "일", readme)


if __name__ == "__main__":
    unittest.main()
