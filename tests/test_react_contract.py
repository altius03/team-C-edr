"""Protect the React dashboard project contract and required EDR surfaces."""

import json
import subprocess
import textwrap
import unittest
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[1]


class ReactDashboardContractTests(unittest.TestCase):
    """Check Vite project files and dashboard text/adapter invariants."""

    def test_react_vite_project_contract_exists(self) -> None:
        """Ensure React build metadata and required source files are present."""
        package_json = PROJECT_DIR / "package.json"
        self.assertTrue(package_json.exists(), package_json)

        package = json.loads(package_json.read_text(encoding="utf-8"))
        self.assertIn("dev", package["scripts"])
        self.assertIn("build", package["scripts"])
        self.assertIn("preview", package["scripts"])
        self.assertIn("react", package["dependencies"])
        self.assertIn("vite", package["devDependencies"])
        self.assertIn("scripts/build_react.mjs", package["scripts"]["build"])

        for relative_path in (
            "tsconfig.json",
            "scripts/build_react.mjs",
            "web/index.html",
            "web/src/main.tsx",
            "web/src/App.tsx",
            "web/src/resultAdapter.ts",
            "web/src/dashboardReport.tsx",
            "web/src/styles.css",
        ):
            self.assertTrue((PROJECT_DIR / relative_path).exists(), relative_path)

    def test_react_dashboard_preserves_required_edr_surface(self) -> None:
        """Ensure the dashboard keeps operational panels and data-source fallbacks."""
        app = (PROJECT_DIR / "web" / "src" / "App.tsx").read_text(encoding="utf-8")
        adapter = "\n".join(
            (PROJECT_DIR / "web" / "src" / path).read_text(encoding="utf-8")
            for path in ("resultAdapter.ts", "resultNormalizer.ts", "resultPrimitives.ts", "resultRows.ts", "dashboardTypes.ts")
        )
        panels = "\n".join(
            (PROJECT_DIR / "web" / "src" / path).read_text(encoding="utf-8")
            for path in (
                "dashboardPanels.tsx",
                "dashboardPanelCore.tsx",
                "dashboardPanelUtils.ts",
                "dashboardTopology.tsx",
                "dashboardCharts.tsx",
                "dashboardQueues.tsx",
                "dashboardReport.tsx",
            )
        )

        for required in (
            "Endpoint fleet",
            "Protected tenant boundary",
            "External destinations",
            "last10m",
            "last1h",
            "last24h",
            "all",
            "ReportModal",
            "Report Center",
            "Endpoint Risk",
            "DLQ Monitor",
            "Process Tree",
            "SignalStrip",
            "severityFilter",
        ):
            self.assertIn(required, app)
        self.assertIn("/v1/dashboard/latest", adapter)
        self.assertIn("latest-result.json", adapter)
        self.assertIn("VITE_LAYERTRACE_API_BASE_URL", adapter)
        self.assertIn("VITE_LAYERTRACE_ALLOW_DEMO_FALLBACK", adapter)
        self.assertIn("demo-fallback", adapter)
        self.assertIn("api_error", adapter)
        self.assertIn("분석 report가 아직 없습니다", panels)
        self.assertIn("api_unavailable", panels)
        self.assertIn("Report unavailable", panels)
        self.assertIn("VITE_API_BASE_URL", adapter)
        self.assertIn("process_trees", adapter)
        self.assertIn("dlq_events", adapter)
        self.assertIn("value.toLowerCase()", adapter)
        self.assertNotIn("window.SIEM_RESULT", adapter)
        self.assertNotIn("result JSON", app)

    def test_dashboard_adapter_fallback_behavior_uses_explicit_runtime_flag(self) -> None:
        script = textwrap.dedent(
            """
            (async () => {
            const fs = require("fs");
            const os = require("os");
            const path = require("path");
            const ts = require("typescript");
            const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "layertrace-adapter-"));
            const compilerOptions = {
              module: ts.ModuleKind.CommonJS,
              target: ts.ScriptTarget.ES2022,
              esModuleInterop: true
            };
            for (const fileName of ["dashboardTypes.ts", "resultPrimitives.ts", "resultRows.ts", "resultNormalizer.ts", "resultAdapter.ts"]) {
              const source = fs.readFileSync(path.join("web", "src", fileName), "utf8").replaceAll("import.meta.env", "globalThis.__viteEnv");
              const output = ts.transpileModule(source, { compilerOptions }).outputText;
              fs.writeFileSync(path.join(tempDir, fileName.replace(".ts", ".js")), output);
            }
            const adapter = require(path.join(tempDir, "resultAdapter.js"));
            const results = {};

            async function runCase(allowDemoFallback) {
              const calls = [];
              const fetcher = async (input) => {
                calls.push(input);
                if (input.endsWith("/v1/dashboard/latest")) {
                  return { ok: false, json: async () => ({}) };
                }
                if (input === "/latest-result.json") {
                  return { ok: true, json: async () => ({}) };
                }
                throw new Error(`unexpected fetch ${input}`);
              };
              const result = await adapter.loadDashboardResultWithRuntime(
                new AbortController().signal,
                { apiBaseUrl: "http://api.test", allowDemoFallback },
                fetcher
              );
              return { calls, result };
            }

            results.production = await runCase(false);
            results.demo = await runCase(true);
            console.log(JSON.stringify(results));
            })().catch((error) => {
              console.error(error);
              process.exit(1);
            });
            """
        )

        completed = subprocess.run(
            ["node", "-e", script],
            check=True,
            cwd=PROJECT_DIR,
            capture_output=True,
            encoding="utf-8",
            text=True,
        )
        results = json.loads(completed.stdout)

        self.assertEqual(results["production"]["result"]["source"], "api_error")
        self.assertEqual(results["production"]["result"]["status"], "api_error")
        self.assertNotIn("/latest-result.json", results["production"]["calls"])
        self.assertEqual(results["demo"]["result"]["source"], "demo-fallback")
        self.assertIn("/latest-result.json", results["demo"]["calls"])
        self.assertGreaterEqual(len(results["demo"]["result"]["endpointRisk"]), 1)


if __name__ == "__main__":
    unittest.main()
