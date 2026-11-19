#!/usr/bin/env python3
"""Execute a schema-v1 project validation profile in a checked-out target.

Profile commands are trusted shell input. Do not run profiles from untrusted
repositories or pull requests in an environment containing credentials.
"""
from __future__ import annotations

import json
import os
import pathlib
import shlex
import shutil
import subprocess
import sys
import time
from typing import Any

PROFILE_ROOT = pathlib.Path(os.environ["PROFILE_SOURCE"]).resolve()
PROFILE_PATH = (PROFILE_ROOT / os.environ["PROFILE"]).resolve()
TARGET = pathlib.Path(os.environ["TARGET"]).resolve()
REPORT_PATH = pathlib.Path("PROJECT_VALIDATION_REPORT.txt")
SECRET_MARKERS = ("TOKEN", "PASSWORD", "SECRET", "CREDENTIAL", "AUTH", "COOKIE", "KEY")


def ensure_inside(root: pathlib.Path, candidate: pathlib.Path, label: str) -> None:
    if candidate == root or root in candidate.parents:
        return
    raise SystemExit(f"{label} must stay inside its configured root.")


ensure_inside(PROFILE_ROOT, PROFILE_PATH, "Profile path")
if not PROFILE_PATH.is_file():
    raise SystemExit(f"Profile not found: {PROFILE_PATH}")
if not TARGET.is_dir():
    raise SystemExit(f"Target directory does not exist: {TARGET}")

try:
    CFG: dict[str, Any] = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError) as exc:
    raise SystemExit(f"Could not load validation profile: {exc}") from exc

if CFG.get("schema_version") != 1:
    raise SystemExit("Unsupported profile schema_version; expected 1.")

SETUP = CFG.get("setup", [])
TESTS = CFG.get("tests", [])
if not isinstance(SETUP, list) or not isinstance(TESTS, list):
    raise SystemExit("Profile setup and tests must be arrays.")

TIMEOUT = int(CFG.get("test_timeout", 900))
if not 1 <= TIMEOUT <= 7200:
    raise SystemExit("test_timeout must be between 1 and 7200 seconds.")

CONTINUE_ON_ERROR = bool(CFG.get("continue_on_error", True))
LINES = [
    "PROJECT VALIDATION REPORT",
    f"Project: {CFG.get('project_name', 'Project')}",
    f"Target: {TARGET}",
    f"Profile: {PROFILE_PATH}",
    "",
]
COUNTS = {"passed": 0, "failed": 0, "skipped": 0}


def sanitized_environment() -> dict[str, str]:
    env = os.environ.copy()
    for key in list(env):
        if any(marker in key.upper() for marker in SECRET_MARKERS):
            env.pop(key, None)
    return env


def parse_needs(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [part.strip() for part in str(value or "").split(",") if part.strip()]


def run_step(name: str, command: str, needs: Any = "") -> bool:
    requirements = parse_needs(needs)
    missing = [tool for tool in requirements if shutil.which(tool) is None]
    if missing:
        COUNTS["skipped"] += 1
        message = f"SKIP: {name} (missing executable(s): {', '.join(missing)})"
        LINES.extend([message, ""])
        print(f"::notice::{message}")
        return True

    print(f"::group::{name}")
    started = time.monotonic()
    try:
        result = subprocess.run(
            command,
            shell=True,
            executable="/bin/bash",
            cwd=TARGET,
            env=sanitized_environment(),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=TIMEOUT,
            check=False,
        )
        output = result.stdout or ""
        status = "PASS" if result.returncode == 0 else "FAIL"
        COUNTS["passed" if result.returncode == 0 else "failed"] += 1
        LINES.extend([
            f"{status}: {name}",
            f"Command: {command}",
            f"Exit code: {result.returncode}",
            f"Duration: {time.monotonic() - started:.2f}s",
            output,
            "",
        ])
        if output:
            print(output)
        print(f"::endgroup::")
        return result.returncode == 0
    except subprocess.TimeoutExpired as exc:
        COUNTS["failed"] += 1
        output = exc.stdout or ""
        if isinstance(output, bytes):
            output = output.decode(errors="replace")
        LINES.extend([
            f"FAIL: {name} (timeout after {TIMEOUT}s)",
            f"Command: {command}",
            str(output),
            "",
        ])
        print(output)
        print(f"::error::{name} timed out after {TIMEOUT}s")
        print("::endgroup::")
        return False


for index, command_value in enumerate(SETUP, start=1):
    command = str(command_value).strip()
    if not command:
        COUNTS["skipped"] += 1
        LINES.extend([f"SKIP: Setup {index} (empty command)", ""])
        continue
    ok = run_step(f"Setup {index}", command)
    if not ok and not CONTINUE_ON_ERROR:
        break

for test in TESTS:
    if not isinstance(test, dict):
        COUNTS["skipped"] += 1
        LINES.extend(["SKIP: Invalid test definition (expected object)", ""])
        continue
    name = str(test.get("name", "Unnamed test"))
    command = str(test.get("command", "")).strip()
    if not command:
        COUNTS["skipped"] += 1
        LINES.extend([f"SKIP: {name} (empty command)", ""])
        continue
    if COUNTS["failed"] and not CONTINUE_ON_ERROR:
        COUNTS["skipped"] += 1
        LINES.extend([f"SKIP: {name} (previous failure)", ""])
        continue
    run_step(name, command, test.get("needs", ""))

LINES.extend([
    "",
    f"Summary: {COUNTS['passed']} passed, {COUNTS['failed']} failed, {COUNTS['skipped']} skipped",
])
REPORT_PATH.write_text("\n".join(LINES) + "\n", encoding="utf-8")
print(f"Report written: {REPORT_PATH.resolve()}")

if COUNTS["failed"]:
    sys.exit(1)
if COUNTS["skipped"]:
    print("::warning::Validation was partial because one or more tests were skipped.")
