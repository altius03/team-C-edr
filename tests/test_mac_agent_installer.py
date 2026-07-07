from __future__ import annotations

import os
import shlex
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[1]


class MacAgentInstallerTests(unittest.TestCase):
    def test_launch_agent_collector_arguments_are_opt_in(self) -> None:
        configured_plist = _run_installer(
            {
                "COLLECTOR_URL": "http://127.0.0.1:8080/v1/telemetry/events",
                "LAYERTRACE_API_TOKEN": "local-dev-token",
            }
        )
        self.assertIn("<string>--collector-url</string>", configured_plist)
        self.assertIn("<string>http://127.0.0.1:8080/v1/telemetry/events</string>", configured_plist)
        self.assertIn("<string>--api-token</string>", configured_plist)
        self.assertIn("<string>local-dev-token</string>", configured_plist)
        self.assertIn("<integer>300</integer>", configured_plist)

        loopback_default_token_plist = _run_installer(
            {
                "COLLECTOR_URL": "http://127.0.0.1:8080/v1/telemetry/events",
            }
        )
        self.assertIn("<string>--collector-url</string>", loopback_default_token_plist)
        self.assertNotIn("--api-token", loopback_default_token_plist)
        self.assertIn("<integer>300</integer>", loopback_default_token_plist)

        local_only_plist = _run_installer({})
        self.assertNotIn("--collector-url", local_only_plist)
        self.assertNotIn("--api-token", local_only_plist)
        self.assertIn("<integer>300</integer>", local_only_plist)


def _run_installer(extra_env: dict[str, str]) -> str:
    bash = _find_bash()

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        home = temp_path / "home"
        fake_bin = temp_path / "bin"
        script_dir = temp_path / "repo" / "scripts"
        home.mkdir()
        fake_bin.mkdir()
        script_dir.mkdir(parents=True)
        script_file = script_dir / "install_mac_agent.sh"
        shutil.copy2(PROJECT_DIR / "scripts" / "install_mac_agent.sh", script_file)
        _write_fake_command(fake_bin / "plutil", "exit 0\n")
        _write_fake_command(
            fake_bin / "launchctl",
            "case \"${1:-}\" in\n  unload|load|list) exit 0 ;;\n  *) exit 0 ;;\nesac\n",
        )

        home_bash = _bash_path(bash, home)
        fake_bin_bash = _bash_path(bash, fake_bin)
        env = os.environ.copy()
        env.update(extra_env)

        script = _bash_path(bash, script_file)
        exports = " ".join(f"{key}={shlex.quote(value)}" for key, value in env.items() if key in extra_env)
        command = (
            f"export HOME={shlex.quote(home_bash)}; "
            f"export PATH={shlex.quote(fake_bin_bash)}:\"$PATH\"; "
            "export PYTHON_BIN=python3; "
            "export IFACE=en0; "
            "export SKIP_TCPDUMP_PREFLIGHT=1; "
            f"{'export ' + exports + '; ' if exports else ''}"
            f"\"$BASH\" {shlex.quote(script)}"
        )
        completed = subprocess.run(
            [bash, "-lc", command],
            cwd=PROJECT_DIR,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            check=False,
        )
        if completed.returncode != 0:
            raise AssertionError(
                f"install_mac_agent.sh failed with {completed.returncode}\n"
                f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
            )
        plist_path = home / "Library" / "LaunchAgents" / "com.security-edr-agent-parser.mac-agent.plist"
        return plist_path.read_text(encoding="utf-8")


def _write_fake_command(path: Path, body: str) -> None:
    path.write_text(f"#!/usr/bin/env bash\n{body}", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _bash_path(bash: str, path: Path) -> str:
    if os.name != "nt":
        return str(path)
    completed = subprocess.run(
        [bash, "-lc", "cygpath -u \"$1\"", "cygpath", str(path)],
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=True,
    )
    return completed.stdout.strip()


def _find_bash() -> str:
    if os.name != "nt":
        bash = shutil.which("bash")
        if bash is None:
            raise AssertionError("bash is required to exercise scripts/install_mac_agent.sh")
        return bash

    candidates = [
        os.environ.get("GIT_BASH"),
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files\Git\usr\bin\bash.exe",
        r"C:\Program Files (x86)\Git\bin\bash.exe",
        shutil.which("bash"),
    ]
    for candidate in candidates:
        if not candidate:
            continue
        candidate_path = Path(candidate)
        if not candidate_path.exists():
            continue
        completed = subprocess.run(
            [str(candidate_path), "-lc", "command -v cygpath >/dev/null"],
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            check=False,
        )
        if completed.returncode == 0:
            return str(candidate_path)
    raise AssertionError("Git Bash with cygpath is required to exercise scripts/install_mac_agent.sh on Windows")


if __name__ == "__main__":
    unittest.main()
