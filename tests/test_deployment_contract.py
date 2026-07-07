import json
import unittest
from pathlib import Path

from src.service_store import ServiceStore

PROJECT_DIR = Path(__file__).resolve().parents[1]


class DeploymentContractTests(unittest.TestCase):
    def test_service_store_accepts_database_url_and_identifies_postgres(self) -> None:
        store = ServiceStore(database_url="postgresql+psycopg://layertrace:layertrace@localhost:5432/layertrace")

        self.assertEqual(store.storage_label, "postgresql")

    def test_compose_env_and_dependencies_target_split_deployment(self) -> None:
        compose_path = PROJECT_DIR / "docker-compose.yml"
        pyproject = (PROJECT_DIR / "pyproject.toml").read_text(encoding="utf-8")
        env_example = (PROJECT_DIR / ".env.example").read_text(encoding="utf-8")
        package = json.loads((PROJECT_DIR / "package.json").read_text(encoding="utf-8"))

        self.assertTrue(compose_path.exists(), "docker-compose.yml is required for local deployment parity")
        compose_text = compose_path.read_text(encoding="utf-8")
        for required in ("api:", "frontend:", "postgres:", "redpanda:", "worker:"):
            self.assertIn(required, compose_text)
        self.assertNotIn("outbox-publisher", compose_text)
        self.assertIn("psycopg", pyproject)
        self.assertIn("DATABASE_URL=", env_example)
        self.assertIn("LAYERTRACE_API_TOKEN=", env_example)
        self.assertIn("VITE_LAYERTRACE_API_BASE_URL=", env_example)
        self.assertIn("local:up", package["scripts"])
        self.assertIn("local:down", package["scripts"])

    def test_small_viewport_specific_surface_is_removed(self) -> None:
        css = (PROJECT_DIR / "web" / "src" / "styles.css").read_text(encoding="utf-8")
        readme = (PROJECT_DIR / "README.md").read_text(encoding="utf-8").lower()

        self.assertNotIn("@media (max-width: " + "720px)", css)
        self.assertNotIn("390" + "px", css)
        self.assertNotIn("mobi" + "le", readme)
        self.assertNotIn("모바" + "일", readme)


if __name__ == "__main__":
    unittest.main()
