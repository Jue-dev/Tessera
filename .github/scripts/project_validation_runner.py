#!/usr/bin/env python3
"""Execute a schema-v1 project validation profile in a checked-out target."""
import json, os, pathlib, shutil, subprocess, sys, time

profile_path = pathlib.Path(os.environ["PROFILE_SOURCE"]) / os.environ["PROFILE"]
target = pathlib.Path(os.environ["TARGET"])
report_path = pathlib.Path("PROJECT_VALIDATION_REPORT.txt")
cfg = json.loads(profile_path.read_text(encoding="utf-8"))
setup = cfg.get("setup", [])
tests = cfg.get("tests", [])
timeout = int(cfg.get("test_timeout", 900))
continue_on_error = bool(cfg.get("continue_on_error", True))
lines = [
    "PROJECT VALIDATION REPORT",
    f"Project: {cfg.get('project_name', 'Project')}",
    f"Target: {target}",
    f"Profile: {profile_path}",
    "",
]
passed = failed = skipped = 0

def run(name, command, needs=""):
    global passed, failed, skipped
    if needs and shutil.which(needs) is None:
        skipped += 1
        lines.extend([f"SKIP: {name} (missing executable: {needs})", ""])
        print(f"::notice::{name} skipped; missing {needs}")
        return True
    print(f"::group::{name}")
    started = time.time()
    try:
        result = subprocess.run(command, shell=True, cwd=target, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=timeout)
        output = result.stdout or ""
        status = "PASS" if result.returncode == 0 else "FAIL"
        if result.returncode == 0: passed += 1
        else: failed += 1
        lines.extend([f"{status}: {name}", f"Command: {command}",
                      f"Exit code: {result.returncode}", f"Duration: {time.time()-started:.2f}s", output, ""])
        print(output)
        print(f"::endgroup::")
        return result.returncode == 0
    except subprocess.TimeoutExpired as exc:
        failed += 1
        output = (exc.stdout or b"").decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        lines.extend([f"FAIL: {name} (timeout)", f"Command: {command}", output, ""])
        print(output)
        print(f"::error::{name} timed out after {timeout}s")
        print("::endgroup::")
        return False

for i, command in enumerate(setup, 1):
    if not run(f"Setup {i}", command):
        if not continue_on_error: break
for test in tests:
    name = str(test.get("name", "Unnamed test"))
    command = str(test.get("command", "")).strip()
    needs = str(test.get("needs", "")).strip()
    if not command:
        skipped += 1
        lines.extend([f"SKIP: {name} (empty command)", ""])
        continue
    if failed and not continue_on_error:
        skipped += 1
        lines.extend([f"SKIP: {name} (previous failure)", ""])
        continue
    run(name, command, needs)
lines.extend(["", f"Summary: {passed} passed, {failed} failed, {skipped} skipped"])
report_path.write_text("\n".join(lines), encoding="utf-8")
print(f"Report written: {report_path.resolve()}")
if failed:
    sys.exit(1)
if skipped:
    print("::warning::Validation was partial because one or more tests were skipped")
