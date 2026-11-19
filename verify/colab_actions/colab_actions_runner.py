#!/usr/bin/env python3
"""Colab-side GitHub Actions compatibility runner; not a security sandbox."""
from __future__ import annotations
import ast, fnmatch, glob, html, itertools, signal, json, os, pathlib, re, shutil, subprocess, sys, tempfile, threading, time, zipfile
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import yaml

def s(v):
    if v is None: return ""
    if isinstance(v, (dict, list)): return str(v)
    return str(v).strip()
def truth(v): return s(v).lower() in {"1", "true", "yes", "on"}
def mp(v): return v if isinstance(v, dict) else {}
def seq(v): return v if isinstance(v, list) else []
def load_yaml(p): return mp(yaml.load(p.read_text(encoding="utf-8"), Loader=yaml.BaseLoader))
def safe_path(root, value):
    raw = pathlib.PurePosixPath(str(value).replace("\\", "/"))
    if raw.is_absolute() or ".." in raw.parts: raise ValueError("Path must stay inside the workspace.")
    base = pathlib.Path(root).resolve()
    result = (base / pathlib.Path(*raw.parts)).resolve()
    if result != base and base not in result.parents: raise ValueError("Path escapes workspace.")
    return result
def normalize_repo(value):
    value = str(value).strip()
    if value.startswith("https://github.com/"): value = value.removeprefix("https://github.com/").removesuffix(".git").strip("/")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value) or ".." in value: raise ValueError("Repository must be owner/name or GitHub HTTPS URL.")
    return value
def ref_parts(ref):
    ref = ref or "main"
    if ref.startswith("refs/heads/"): return ref, ref.split("/", 2)[2]
    if ref.startswith("refs/tags/"): return ref, ref.split("/", 2)[2]
    if ref.startswith("refs/"): return ref, ref.rsplit("/", 1)[-1]
    return "refs/heads/" + ref, ref

@dataclass
class StepResult:
    name: str
    status: str
    duration: float = 0.0
    exit_code: int | None = None
    detail: str = ""
@dataclass
class JobResult:
    job_id: str
    name: str
    status: str
    steps: list
    detail: str = ""

class ColabActionsRunner:
    def __init__(self, workspace, token="", step_timeout=1800, log=None, cancel_event=None):
        self.workspace = pathlib.Path(workspace).resolve()
        self.token = token or ""
        self.step_timeout = max(1, min(int(step_timeout), 7200))
        self.log = log or (lambda m: print(m, flush=True))
        self.cancel_event = cancel_event or threading.Event()
        self.artifact_dir = self.workspace.parent / "colab-actions-artifacts"
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        self.workflow_path = None; self.workflow = {}; self.event_name = "workflow_dispatch"
        self.inputs = {}; self.event_ref = "refs/heads/main"; self.event_sha = ""; self.repo_full_name = ""
        self.job_results = []; self.warnings = []; self.env_global = {}; self.step_outputs = {}; self.job_outputs = {}
        self._run_failed = False; self._report_data = {}
    def emit(self, m): self.log(str(m))
    def clone_repository(self, repo, ref="", depth=1, destination=None):
        full = normalize_repo(repo); url = "https://github.com/" + full + ".git"
        dest = pathlib.Path(destination or self.workspace).resolve()
        if dest.exists(): shutil.rmtree(dest)
        dest.parent.mkdir(parents=True, exist_ok=True); depth = max(0, min(int(depth), 1000))
        askpass = None; env = os.environ.copy(); env["GIT_TERMINAL_PROMPT"] = "0"
        if self.token:
            fd, askpass = tempfile.mkstemp(prefix="colab-git-askpass-"); os.close(fd)
            pathlib.Path(askpass).write_text('#!/bin/sh\ncase "$1" in\n *sername*) echo x-access-token ;;\n *assword*) printf "%s" "$COLAB_GIT_TOKEN" ;;\n *) echo x-access-token ;;\nesac\n', encoding="utf-8")
            os.chmod(askpass, 0o700); env["GIT_ASKPASS"] = askpass; env["COLAB_GIT_TOKEN"] = self.token
        cmd = ["git", "clone", "--no-tags"] + (["--depth", str(depth)] if depth else [])
        if ref and not re.fullmatch(r"[0-9a-fA-F]{7,40}", ref): cmd += ["--branch", ref]
        cmd += [url, str(dest)]
        try:
            self.emit("Cloning " + full + " (" + (ref or "default") + ")")
            proc = subprocess.run(cmd, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
            if proc.returncode == 0 and ref and re.fullmatch(r"[0-9a-fA-F]{7,40}", ref):
                proc = subprocess.run(["git", "fetch", "--depth", "1", "origin", ref], cwd=dest, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
                if proc.returncode == 0:
                    proc = subprocess.run(["git", "checkout", "--detach", "FETCH_HEAD"], cwd=dest, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
            if proc.returncode and ref and re.fullmatch(r"[0-9a-fA-F]{7,40}", ref):
                shutil.rmtree(dest, ignore_errors=True)
                base = ["git", "clone", "--no-tags"] + (["--depth", str(depth)] if depth else []) + [url, str(dest)]
                proc = subprocess.run(base, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
                if proc.returncode == 0:
                    proc = subprocess.run(["git", "fetch", "--depth", "1", "origin", ref], cwd=dest, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
                    if proc.returncode == 0: proc = subprocess.run(["git", "checkout", "--detach", "FETCH_HEAD"], cwd=dest, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
            if proc.returncode: raise RuntimeError("Git clone failed:\n" + (proc.stdout or "")[-12000:])
        finally:
            if askpass and os.path.exists(askpass):
                try: os.remove(askpass)
                except OSError: pass
        self.workspace = dest; self.repo_full_name = full; self.artifact_dir = dest.parent / "colab-actions-artifacts"; self.artifact_dir.mkdir(parents=True, exist_ok=True)
        return dest
    def default_branch(self):
        try:
            branch = subprocess.check_output(["git", "branch", "--show-current"], cwd=self.workspace,
                                             text=True, stderr=subprocess.DEVNULL).strip()
            return branch or "main"
        except Exception:
            return "main"
    def discover_workflows(self):
        folder = self.workspace / ".github" / "workflows"
        if not folder.is_dir(): return []
        return sorted(str(p.relative_to(self.workspace)).replace("\\", "/") for p in folder.rglob("*") if p.is_file() and p.suffix.lower() in {".yml", ".yaml"})
    def read_workflow(self, relative):
        path = safe_path(self.workspace, relative)
        if path.suffix.lower() not in {".yml", ".yaml"} or ".github/workflows" not in str(path): raise ValueError("Select YAML inside .github/workflows.")
        self.workflow_path = path; self.workflow = load_yaml(path); return self.workflow
    def declared_events(self, workflow=None):
        obj = workflow or self.workflow; on = obj.get("on", obj.get(True, {}))
        if isinstance(on, str): return [on]
        if isinstance(on, list): return [s(x) for x in on]
        return list(mp(on).keys())
    def dispatch_inputs(self, workflow=None):
        obj = workflow or self.workflow
        return mp(mp(mp(obj.get("on", obj.get(True, {}))).get("workflow_dispatch")).get("inputs"))
    def matrix_variants(self, job):
        matrix = mp(mp(job.get("strategy")).get("matrix")); axes = {k: seq(v) for k, v in matrix.items() if k not in {"include", "exclude"}}
        if axes:
            keys = list(axes); variants = [dict(zip(keys, vals)) for vals in itertools.product(*(axes[k] or [""] for k in keys))]
        else: variants = [{}]
        variants = [v for v in variants if not any(all(v.get(k) == val for k, val in mp(ex).items()) for ex in seq(matrix.get("exclude")))]
        for extra in seq(matrix.get("include")):
            if mp(extra): variants.append({**(variants[0] if variants else {}), **mp(extra)})
        return variants or [{}]
    def platform_state(self, runs_on):
        labels = [s(x).lower() for x in runs_on] if isinstance(runs_on, list) else [s(runs_on).lower()]; label = " ".join(labels)
        if not label: return "UNSUPPORTED", "Job has no runs-on value."
        if any(x in label for x in ("windows", "windows-latest", "windows-2022", "windows-2019")): return "BLOCKED_PLATFORM", "Requires Windows; Colab is Linux."
        if "macos" in label: return "BLOCKED_PLATFORM", "Requires macOS; Colab is Linux."
        if any(x in label for x in ("ubuntu", "linux", "debian")): return "READY", "Linux-compatible."
        if "self-hosted" in label: return "UNSUPPORTED", "Self-hosted runner cannot be reproduced."
        return "UNSUPPORTED", "Unknown runner label: " + label
    def preview(self):
        rows = []
        for jid, raw in mp(self.workflow.get("jobs")).items():
            job = mp(raw); state, reason = self.platform_state(job.get("runs-on", ""))
            for matrix in self.matrix_variants(job):
                rows.append({"job_id": jid, "name": s(job.get("name")) or jid, "matrix": matrix,
                             "runs_on": s(job.get("runs-on")), "compatibility": state, "reason": reason,
                             "step_count": len(seq(job.get("steps")))})
        return rows
    def git_sha(self):
        try: return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=self.workspace, text=True, stderr=subprocess.DEVNULL).strip()
        except Exception: return ""
    def context(self, matrix=None, job_id="", env=None):
        ref, name = ref_parts(self.event_ref)
        return {"github": {"workspace": str(self.workspace), "repository": self.repo_full_name, "event_name": self.event_name, "ref": ref, "ref_name": name, "sha": self.event_sha or self.git_sha(), "actor": "colab-user"},
                "runner": {"os": "Linux", "name": "Colab", "temp": tempfile.gettempdir()},
                "matrix": mp(matrix), "inputs": self.inputs, "env": env or {}, "job": {"id": job_id},
                "steps": self.step_outputs, "needs": self.job_outputs}
    def lookup(self, expr, ctx):
        value = ctx
        for part in expr.strip().split("."): value = value.get(part, "") if isinstance(value, dict) else ""
        return value
    def interpolate(self, value, ctx):
        raw = s(value)
        def replace(m):
            expr = m.group(1).strip()
            if "secrets." in expr: raise ValueError("secrets.* is blocked; Colab runner never injects secrets into workflow commands.")
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*", expr): return s(self.lookup(expr, ctx))
            if expr in {"true", "false", "null"}: return {"true": "true", "false": "false", "null": ""}[expr]
            raise ValueError("Unsupported GitHub expression: " + expr)
        return re.sub(r"\$\{\{\s*(.*?)\s*\}\}", replace, raw)
    def evaluate_condition(self, condition, ctx, previous_failed=False):
        expr = s(condition)
        if not expr: return True
        expr = re.sub(r"^\$\{\{\s*|\s*\}\}$", "", expr).strip()
        if "secrets." in expr: return False
        expr = expr.replace("&&", " and ").replace("||", " or ")
        expr = re.sub(r"(?<![=!<>])!(?!=)", " not ", expr)
        for fn, result in (("always", True), ("success", not previous_failed), ("failure", previous_failed), ("cancelled", False)):
            expr = re.sub(r"\b" + fn + r"\s*\(\s*\)", str(result), expr)
        for fn in ("startsWith", "contains"):
            pattern = re.compile(r"\b" + fn + r"\(([^()]*)\)")
            while True:
                m = pattern.search(expr)
                if not m: break
                args = [x.strip().strip("'\\\"") for x in m.group(1).split(",", 1)]
                if len(args) != 2: return False
                left = s(self.lookup(args[0], ctx)) if re.fullmatch(r"[A-Za-z_][\w.]*", args[0]) else args[0]
                right = s(self.lookup(args[1], ctx)) if re.fullmatch(r"[A-Za-z_][\w.]*", args[1]) else args[1]
                result = left.startswith(right) if fn == "startsWith" else right in left
                expr = expr[:m.start()] + str(result) + expr[m.end():]
        expr = re.sub(r"\b(?:github|runner|matrix|inputs|env|job|needs|steps)\.[A-Za-z_][A-Za-z0-9_.]*", lambda m: repr(self.lookup(m.group(0), ctx)), expr)
        try:
            tree = ast.parse(expr, mode="eval")
            allowed = (ast.Expression, ast.BoolOp, ast.And, ast.Or, ast.UnaryOp, ast.Not, ast.Compare, ast.Eq, ast.NotEq, ast.In, ast.NotIn, ast.Constant, ast.Load)
            if any(not isinstance(n, allowed) for n in ast.walk(tree)): return False
            return bool(eval(compile(tree, "<workflow-if>", "eval"), {"__builtins__": {}}, {}))
        except Exception:
            self.warnings.append("Unrecognized condition treated as false: " + s(condition)); return False
    def make_env(self, extra, ctx):
        env = {k: v for k, v in os.environ.items() if not re.search(r"TOKEN|PASSWORD|SECRET|CREDENTIAL|AUTH|COOKIE|KEY", k, re.I)}
        env.update(self.env_global)
        for key, value in mp(extra).items():
            if re.search(r"TOKEN|PASSWORD|SECRET|CREDENTIAL|AUTH|COOKIE|KEY", str(key), re.I): raise ValueError("Credential-like environment variable blocked: " + str(key))
            env[str(key)] = self.interpolate(value, ctx)
        env.update({"GITHUB_WORKSPACE": str(self.workspace), "GITHUB_EVENT_NAME": self.event_name, "GITHUB_REF": self.event_ref,
                    "GITHUB_REF_NAME": ref_parts(self.event_ref)[1], "GITHUB_SHA": self.event_sha or self.git_sha(),
                    "RUNNER_OS": "Linux", "RUNNER_NAME": "Colab", "RUNNER_TEMP": tempfile.gettempdir(), "GITHUB_ACTIONS": "true"})
        for key in ("GITHUB_ENV", "GITHUB_PATH", "GITHUB_OUTPUT", "GITHUB_STEP_SUMMARY"):
            fd, path = tempfile.mkstemp(prefix="colab-actions-"); os.close(fd); env[key] = path
        return env
    def update_env(self, env):
        path = env.get("GITHUB_ENV", "")
        if os.path.isfile(path):
            for line in pathlib.Path(path).read_text(errors="replace").splitlines():
                if "=" in line:
                    key, val = line.split("=", 1)
                    if not re.search(r"TOKEN|PASSWORD|SECRET|CREDENTIAL|AUTH|COOKIE|KEY", key, re.I): self.env_global[key] = val
        path = env.get("GITHUB_PATH", "")
        if os.path.isfile(path):
            entries = pathlib.Path(path).read_text(errors="replace").splitlines()
            if entries: self.env_global["PATH"] = os.pathsep.join(entries) + os.pathsep + os.environ.get("PATH", "")
    def read_step_outputs(self, env, step):
        step_id = s(step.get("id"))
        path = env.get("GITHUB_OUTPUT", "")
        if step_id and path and os.path.isfile(path):
            outputs = {}
            for line in pathlib.Path(path).read_text(errors="replace").splitlines():
                if "=" in line:
                    key, value = line.split("=", 1)
                    outputs[key] = value
            self.step_outputs[step_id] = {"outputs": outputs}
    def cleanup_env(self, env):
        for key in ("GITHUB_ENV", "GITHUB_PATH", "GITHUB_OUTPUT", "GITHUB_STEP_SUMMARY"):
            try: pathlib.Path(env.get(key, "")).unlink(missing_ok=True)
            except Exception: pass
    def run_command(self, name, command, shell, cwd, env, timeout):
        started = time.monotonic()
        shell = shell.lower()
        if shell in {"pwsh", "powershell", "powershell.exe"}:
            return StepResult(name, "UNSUPPORTED", 0, None, "PowerShell is not available in standard Colab Linux.")
        if shell.startswith("bash"):
            args = [shutil.which("bash") or "bash", "--noprofile", "--norc", "-e", "-o", "pipefail"]
            script, suffix = "set -euo pipefail\n" + command, ".sh"
        elif shell.startswith("sh"):
            args = [shutil.which("sh") or "sh", "-e"]
            script, suffix = "set -e\n" + command, ".sh"
        elif shell in {"python", "python3"}:
            args = [sys.executable]
            script, suffix = command, ".py"
        else:
            return StepResult(name, "UNSUPPORTED", 0, None, "Unsupported shell: " + shell)
        fd, path = tempfile.mkstemp(prefix="colab-actions-step-", suffix=suffix)
        os.close(fd)
        try:
            pathlib.Path(path).write_text(script, encoding="utf-8")
            proc = subprocess.Popen(args + [path], cwd=cwd, env=env,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, errors="replace", bufsize=1,
                                    start_new_session=True)
            deadline = time.monotonic() + max(1, int(timeout))
            output = ""
            while True:
                if self.cancel_event.is_set():
                    try:
                        os.killpg(proc.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    try:
                        output, _ = proc.communicate(timeout=5)
                    except subprocess.TimeoutExpired:
                        try:
                            os.killpg(proc.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        output, _ = proc.communicate()
                    return StepResult(name, "CANCELLED", time.monotonic() - started,
                                      proc.returncode, (output or "")[-100000:])
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    output, _ = proc.communicate()
                    return StepResult(name, "TIMEOUT", time.monotonic() - started,
                                      proc.returncode, (output or "")[-100000:])
                try:
                    output, _ = proc.communicate(timeout=min(1.0, remaining))
                    break
                except subprocess.TimeoutExpired:
                    continue
            output = (output or "")[-250000:]
            if output:
                self.emit(output)
            return StepResult(name, "PASS" if proc.returncode == 0 else "FAIL",
                              time.monotonic() - started, proc.returncode, output)
        finally:
            pathlib.Path(path).unlink(missing_ok=True)

    def upload_artifact(self, step, cwd):
        cfg = mp(step.get("with")); name = s(cfg.get("name")) or "artifact"
        files = sorted({p for pat in s(cfg.get("path")).splitlines() if pat.strip() for p in glob.glob(str(cwd / pat.strip()), recursive=True)})
        files = [pathlib.Path(p) for p in files if pathlib.Path(p).exists()]
        if not files:
            mode = s(cfg.get("if-no-files-found")) or "warn"
            return StepResult(s(step.get("name")) or "Upload artifact", "FAIL" if mode == "error" else "PASS", 0, 1 if mode == "error" else 0, "No matching files: " + s(cfg.get("path")))
        dest = self.artifact_dir / (re.sub(r"[^A-Za-z0-9_.-]+", "-", name) + ".zip")
        with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
            for p in files:
                if p.is_file(): z.write(p, str(p.relative_to(cwd)) if cwd in p.parents else p.name)
                else:
                    for child in p.rglob("*"):
                        if child.is_file(): z.write(child, str(child.relative_to(cwd)))
        return StepResult(s(step.get("name")) or "Upload artifact", "PASS", 0, 0, "Saved locally: " + str(dest))
    def download_artifact(self, step):
        cfg = mp(step.get("with")); name = s(cfg.get("name"))
        matches = list(self.artifact_dir.glob(name if name.endswith(".zip") else (name + ".zip" if name else "*.zip")))
        if not matches: return StepResult(s(step.get("name")) or "Download artifact", "FAIL", 0, 1, "Artifact not found: " + name)
        dest = safe_path(self.workspace, s(cfg.get("path")) or "."); dest.mkdir(parents=True, exist_ok=True)
        for path in matches:
            with zipfile.ZipFile(path) as z:
                for entry in z.namelist(): safe_path(dest, entry)
                z.extractall(dest)
        return StepResult(s(step.get("name")) or "Download artifact", "PASS", 0, 0, "Restored " + str(len(matches)) + " local artifact(s).")
    def checkout(self, step, ctx):
        cfg = mp(step.get("with"))
        repo = self.interpolate(cfg.get("repository"), ctx) if cfg.get("repository") else ""
        if not repo: return StepResult(s(step.get("name")) or "Checkout", "PASS", 0, 0, "Primary workspace already checked out.")
        try:
            dest = safe_path(self.workspace, self.interpolate(cfg.get("path"), ctx) if cfg.get("path") else "external/" + normalize_repo(repo).replace("/", "-"))
            nested = ColabActionsRunner(dest, self.token, self.step_timeout, self.log, self.cancel_event)
            nested.clone_repository(repo, self.interpolate(cfg.get("ref"), ctx) if cfg.get("ref") else "main", 1, dest)
            return StepResult(s(step.get("name")) or "Checkout", "PASS", 0, 0, "Checked out " + repo)
        except Exception as exc: return StepResult(s(step.get("name")) or "Checkout", "FAIL", 0, 1, str(exc))
    def local_action(self, uses, step, ctx, cwd, env_base, depth):
        if depth > 4: return [StepResult(s(step.get("name")) or uses, "UNSUPPORTED", 0, None, "Composite action nesting limit exceeded.")]
        folder = safe_path(self.workspace, uses[2:])
        meta = next((p for p in (folder/"action.yml", folder/"action.yaml") if p.is_file()), None)
        if not meta: return [StepResult(uses, "FAIL", 0, 1, "Local action metadata missing.")]
        action = load_yaml(meta); runs = mp(action.get("runs"))
        if s(runs.get("using")) != "composite": return [StepResult(uses, "UNSUPPORTED", 0, None, "Only local composite actions are supported.")]
        supplied = mp(step.get("with")); local_inputs = {k: supplied.get(k, mp(v).get("default", "")) for k, v in mp(action.get("inputs")).items()}
        action_ctx = dict(ctx)
        action_ctx["inputs"] = local_inputs
        for child_raw in seq(runs.get("steps")):
            child = dict(mp(child_raw)); child_env = {}
            for key, val in mp(child.get("env")).items():
                child_env[key] = re.sub(r"\$\{\{\s*inputs\.([A-Za-z0-9_-]+)\s*\}\}", lambda m: s(local_inputs.get(m.group(1), "")), s(val))
            child["env"] = child_env
            result = self.run_step(child, action_ctx, cwd, env_base, depth+1)
            if result[0].status not in {"PASS", "SKIP"} and not truth(child.get("continue-on-error")): return result
        return [StepResult(s(step.get("name")) or uses, "PASS", 0, 0, "Composite action completed.")]
    def run_step(self, step, ctx, cwd, env_base, depth=0):
        name = s(step.get("name")) or s(step.get("id")) or "Unnamed step"
        if self.cancel_event.is_set(): return [StepResult(name, "CANCELLED", 0, None, "Run cancelled.")]
        step_condition = s(step.get("if"))
        if (not step_condition and self._run_failed) or (step_condition and not self.evaluate_condition(step_condition, ctx, self._run_failed)):
            self.emit(name + ": skipped by default success() / if condition")
            return [StepResult(name, "SKIP", 0, None, "Default success() or explicit if condition evaluated to false.")]
        uses = s(step.get("uses"))
        if uses:
            low = uses.lower()
            if uses.startswith("./"): results = self.local_action(uses, step, ctx, cwd, env_base, depth)
            elif low.startswith("actions/checkout@"): results = [self.checkout(step, ctx)]
            elif low.startswith("actions/upload-artifact@"): results = [self.upload_artifact(step, cwd)]
            elif low.startswith("actions/download-artifact@"): results = [self.download_artifact(step)]
            elif low.startswith("actions/cache@"): results = [StepResult(name, "PASS", 0, 0, "Cache treated as no-op in ephemeral Colab.")]
            elif low.startswith("actions/setup-python@"):
                wanted = s(mp(step.get("with")).get("python-version")); current = ".".join(map(str, sys.version_info[:2]))
                wanted_mm = ".".join(wanted.split(".")[:2]) if wanted and wanted[0].isdigit() else ""
                ok = not wanted_mm or wanted_mm == current
                results = [StepResult(name, "PASS" if ok else "UNSUPPORTED", 0, 0 if ok else None, "Colab Python " + current + (" matches" if ok else "; requested " + wanted_mm + ". No replacement attempted."))]
            elif low.startswith("actions/setup-node@"):
                node = shutil.which("node"); results = [StepResult(name, "PASS" if node else "UNSUPPORTED", 0, 0 if node else None, "Node available: " + node if node else "Node runtime missing; setup-node is not emulated.")]
            else: results = [StepResult(name, "UNSUPPORTED", 0, None, "Unsupported Marketplace action: " + uses)]
            for r in results: self.emit(r.name + ": " + r.status + " — " + r.detail)
            return results
        command = s(step.get("run"))
        if not command: return [StepResult(name, "UNSUPPORTED", 0, None, "Step has neither run nor supported uses.")]
        try:
            folder = safe_path(self.workspace, s(step.get("working-directory")) or ".")
            if not folder.is_dir(): raise ValueError("Working directory does not exist: " + str(folder))
            env = self.make_env({**mp(env_base), **mp(step.get("env"))}, ctx)
            expanded = self.interpolate(command, ctx)
            result = self.run_command(name, expanded, s(step.get("shell")) or "bash", folder, env, self.step_timeout)
            self.update_env(env); self.read_step_outputs(env, step); self.cleanup_env(env); return [result]
        except Exception as exc: return [StepResult(name, "FAIL", 0, 1, str(exc))]
    def execute(self, workflow_path, event_name="workflow_dispatch", inputs=None, ref="main"):
        self.read_workflow(workflow_path); self.event_name = event_name; self.inputs = mp(inputs)
        self.event_ref = ref if str(ref).startswith("refs/") else "refs/heads/" + str(ref); self.event_sha = self.git_sha()
        self.job_results = []; self.warnings = []; self.env_global = {}; self._run_failed = False
        if self.workflow.get("concurrency"): self.warnings.append("Concurrency groups are not emulated.")
        if mp(self.workflow.get("permissions")): self.warnings.append("GitHub token permissions are not issued; no token is passed to jobs.")
        on = self.workflow.get("on", self.workflow.get(True, {})); event_cfg = mp(on).get(event_name)
        if event_name not in self.declared_events(): self.warnings.append("Selected event is not declared in this workflow.")
        if mp(event_cfg).get("paths") or mp(event_cfg).get("paths-ignore"): self.warnings.append("Path filters not evaluated; changed-file metadata is unavailable.")
        trigger_reason = ""
        if event_name not in self.declared_events():
            trigger_reason = "Selected event is not declared by this workflow."
        elif event_name == "push" and isinstance(event_cfg, dict):
            ref_name = ref_parts(self.event_ref)[1]
            is_tag = self.event_ref.startswith("refs/tags/")
            branch_patterns = seq(event_cfg.get("branches"))
            tag_patterns = seq(event_cfg.get("tags"))
            if is_tag:
                if branch_patterns and not tag_patterns:
                    trigger_reason = "This workflow filters branch pushes and has no tag trigger."
                elif tag_patterns and not any(fnmatch.fnmatchcase(ref_name, s(p)) for p in tag_patterns):
                    trigger_reason = "Push tag does not match this workflow's tags filter."
                if any(fnmatch.fnmatchcase(ref_name, s(p)) for p in seq(event_cfg.get("tags-ignore"))):
                    trigger_reason = "Push tag is excluded by tags-ignore."
            else:
                if tag_patterns and not branch_patterns:
                    trigger_reason = "This workflow filters tag pushes and has no branch trigger."
                elif branch_patterns and not any(fnmatch.fnmatchcase(ref_name, s(p)) for p in branch_patterns):
                    trigger_reason = "Push branch does not match this workflow's branches filter."
                if any(fnmatch.fnmatchcase(ref_name, s(p)) for p in seq(event_cfg.get("branches-ignore"))):
                    trigger_reason = "Push branch is excluded by branches-ignore."
                if event_cfg.get("paths") or event_cfg.get("paths-ignore"):
                    trigger_reason = "This branch push has path filters; changed-file metadata is not supplied by the Colab UI."
        if trigger_reason:
            for jid, raw_job in mp(self.workflow.get("jobs")).items():
                self.job_results.append(JobResult(jid, s(mp(raw_job).get("name")) or jid, "SKIP", [], trigger_reason))
            self._report_data = self.build_report()
            self.emit("Workflow not started: " + trigger_reason)
            return self._report_data
        self.emit("Workflow: " + (s(self.workflow.get("name")) or workflow_path))
        self.emit("Event: " + event_name + " | Ref: " + self.event_ref)
        jobs = mp(self.workflow.get("jobs")); pending = list(jobs); completed = {}
        while pending:
            progressed = False
            for jid in list(pending):
                job = mp(jobs[jid]); needs = job.get("needs", [])
                needs = [needs] if isinstance(needs, str) else seq(needs)
                if any(dep not in completed for dep in needs): continue
                pending.remove(jid); progressed = True
                failed_deps = [dep for dep in needs if completed.get(dep) != "PASS"]
                ctx = self.context(job_id=jid)
                job_condition = s(job.get("if"))
                if failed_deps and not job_condition:
                    detail = "Dependency failed or was not fully validated: " + ", ".join(failed_deps)
                    self.job_results.append(JobResult(jid, s(job.get("name")) or jid, "SKIP", [], detail)); completed[jid] = "SKIP"; continue
                if not job_condition and self._run_failed:
                    self.job_results.append(JobResult(jid, s(job.get("name")) or jid, "SKIP", [], "Default success() condition blocked this job after a previous failure.")); completed[jid] = "SKIP"; continue
                if job_condition and not self.evaluate_condition(job_condition, ctx, self._run_failed):
                    self.job_results.append(JobResult(jid, s(job.get("name")) or jid, "SKIP", [], "Job if condition evaluated to false.")); completed[jid] = "SKIP"; continue
                platform, reason = self.platform_state(job.get("runs-on", ""))
                if platform != "READY":
                    self.emit(jid + ": " + platform + " — " + reason)
                    self.job_results.append(JobResult(jid, s(job.get("name")) or jid, platform, [], reason)); completed[jid] = platform; continue
                statuses, all_steps = [], []
                workflow_failed_before_job = self._run_failed
                original_timeout = self.step_timeout; minutes = int(s(job.get("timeout-minutes")) or "0")
                if minutes: self.step_timeout = min(original_timeout, minutes*60)
                for matrix in self.matrix_variants(job):
                    if self.cancel_event.is_set(): statuses.append("CANCELLED"); break
                    self._run_failed = False
                    self.env_global = {}
                    self.step_outputs = {}
                    label = ", ".join(k + "=" + s(v) for k,v in matrix.items())
                    self.emit("\n========== JOB " + jid + ((" [" + label + "]") if label else "") + " ==========")
                    workflow_env, job_env = mp(self.workflow.get("env")), mp(job.get("env"))
                    env_base = {**workflow_env, **job_env}
                    ctx = self.context(matrix, jid, env_base)
                    resolved_env = {}
                    for env_key, env_value in env_base.items():
                        resolved_env[env_key] = self.interpolate(env_value, ctx)
                    ctx["env"] = resolved_env
                    env_base = resolved_env
                    failed, unsupported = False, False
                    for raw_step in seq(job.get("steps")):
                        step = mp(raw_step); results = self.run_step(step, ctx, self.workspace, env_base)
                        all_steps.extend(asdict(x) for x in results)
                        for r in results:
                            if r.status in {"FAIL", "TIMEOUT"}:
                                if truth(step.get("continue-on-error")):
                                    self.warnings.append("Step failure ignored by continue-on-error: " + r.name)
                                else:
                                    failed = True; self._run_failed = True
                            if r.status == "UNSUPPORTED":
                                if truth(step.get("continue-on-error")):
                                    self.warnings.append("Unsupported step ignored: " + r.name)
                                else:
                                    unsupported = True; self._run_failed = True
                        if self.cancel_event.is_set(): break
                    statuses.append("FAIL" if failed else ("PARTIAL" if unsupported else ("CANCELLED" if self.cancel_event.is_set() else "PASS")))
                self.step_timeout = original_timeout
                state = "FAIL" if "FAIL" in statuses else ("CANCELLED" if "CANCELLED" in statuses else ("PARTIAL" if "PARTIAL" in statuses else "PASS"))
                self._run_failed = workflow_failed_before_job or state in {"FAIL", "PARTIAL"}
                self.job_results.append(JobResult(jid, s(job.get("name")) or jid, state, all_steps, reason)); completed[jid] = state
            if not progressed:
                for jid in pending:
                    self.job_results.append(JobResult(jid, s(mp(jobs[jid]).get("name")) or jid, "UNSUPPORTED", [], "Circular or unresolved needs dependency.")); completed[jid] = "UNSUPPORTED"
                break
        self._report_data = self.build_report(); return self._report_data
    def build_report(self):
        jobs, steps = {}, {}
        for job in self.job_results:
            jobs[job.status] = jobs.get(job.status, 0) + 1
            for step in job.steps:
                status = step.get("status", "UNKNOWN"); steps[status] = steps.get(status, 0) + 1
        blocked = jobs.get("BLOCKED_PLATFORM", 0) + jobs.get("UNSUPPORTED", 0)
        status = "FAIL" if jobs.get("FAIL", 0) else ("PARTIAL" if blocked or jobs.get("PARTIAL", 0) or jobs.get("SKIP", 0) else ("CANCELLED" if jobs.get("CANCELLED", 0) else "PASS"))
        return {"schema_version": 1, "status": status, "created_at": datetime.now(timezone.utc).isoformat(),
                "workflow": s(self.workflow.get("name")) or str(self.workflow_path),
                "workflow_path": str(self.workflow_path.relative_to(self.workspace)) if self.workflow_path else "",
                "repository": self.workspace.name, "event": self.event_name, "ref": self.event_ref,
                "commit": self.event_sha or self.git_sha(), "runner": "Google Colab Linux", "job_counts": jobs, "step_counts": steps,
                "jobs": [asdict(j) for j in self.job_results], "warnings": self.warnings,
                "artifacts": [p.name for p in self.artifact_dir.glob("*.zip")],
                "limitations": ["Not a GitHub-hosted runner or security sandbox.", "Windows/macOS runners, most Marketplace actions and unavailable toolchains are not emulated.", "Colab CPU/RAM/disk/runtime quotas may interrupt builds.", "No GitHub checks, statuses, releases or PR changes are published."]}
    def save_report(self, output_dir=None):
        report = self._report_data or self.build_report()
        out = pathlib.Path(output_dir or (self.workspace.parent / "colab-actions-reports")); out.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S"); jp = out / ("colab-actions-" + stamp + ".json"); md = out / ("colab-actions-" + stamp + ".md")
        jp.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        lines = ["# Colab Actions Run Report", "", "- **Status:** " + report["status"], "- **Workflow:** " + report["workflow"],
                 "- **Path:** " + report["workflow_path"], "- **Event:** " + report["event"], "- **Ref:** " + report["ref"],
                 "- **Commit:** " + report["commit"], "- **Runner:** " + report["runner"], "", "## Jobs", "",
                 "| Job | Status | Details |", "|---|---|---|"]
        lines += ["| " + j["name"].replace("|","/") + " | " + j["status"] + " | " + j["detail"].replace("|","/") + " |" for j in report["jobs"]]
        lines += ["", "## Warnings", ""] + (["- " + x for x in report["warnings"]] or ["- None"])
        lines += ["", "## Limitations", ""] + ["- " + x for x in report["limitations"]]
        md.write_text("\n".join(lines) + "\n", encoding="utf-8"); return jp, md

def github_api(path, token=""):
    import urllib.request
    headers = {"Accept":"application/vnd.github+json", "X-GitHub-Api-Version":"2022-11-28"}
    if token: headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request("https://api.github.com" + path, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as response: return json.loads(response.read().decode("utf-8"))

def launch_ui():
    import ipywidgets as w
    from IPython.display import display, Markdown, clear_output
    import traceback
    try:
        from google.colab import userdata, files
        in_colab = True
    except Exception: userdata, files, in_colab = None, None, False
    title = w.HTML("<h2>Colab Actions Workbench</h2><p>Workflow YAML dosyalarını keşfeder; desteklenen işleri Colab Linux üzerinde çalıştırır.</p>")
    repo = w.Text(value="", description="Repository", placeholder="owner/repository", layout=w.Layout(width="75%"))
    ref = w.Text(value="", description="Branch / tag / SHA (blank = default branch)", placeholder="default branch", layout=w.Layout(width="75%"))
    secret = w.Text(value="GH_TOKEN", description="Colab Secret", layout=w.Layout(width="55%"))
    depth = w.IntSlider(value=1, min=0, max=50, description="Clone depth", continuous_update=False)
    timeout = w.IntSlider(value=1800, min=60, max=7200, step=60, description="Step timeout", continuous_update=False)
    repos_btn = w.Button(description="Depolarımı listele"); branches_btn = w.Button(description="Branch'leri getir")
    repos = w.Dropdown(options=[], description="Depo", layout=w.Layout(width="75%")); branches = w.Dropdown(options=[], description="Branch", layout=w.Layout(width="75%"))
    scan = w.Button(description="Depoyu indir ve workflow'ları tara", button_style="primary", icon="download")
    workflow = w.Dropdown(options=[], description="Workflow", layout=w.Layout(width="95%")); event = w.Dropdown(options=[], description="Event", layout=w.Layout(width="75%"))
    inputs_box = w.VBox([]); analyze = w.Button(description="Workflow planını analiz et", button_style="info", disabled=True)
    trust = w.Checkbox(value=False, description="Workflow dosyalarını inceledim ve komutlarına güveniyorum.")
    run = w.Button(description="Colab'da çalıştır", button_style="success", disabled=True); cancel = w.Button(description="Durdur", button_style="danger", disabled=True)
    keep = w.Checkbox(value=True, description="Çalışma alanını koru")
    status = w.HTML("<b>Durum:</b> Hazır"); plan_out = w.Output(); logs = w.Output(layout=w.Layout(height="350px", overflow="auto")); report_out = w.Output()
    download = w.Button(description="Raporları indir", icon="download", disabled=True)
    state = {"runner":None,"workspace":None,"input_widgets":{},"cancel":None,"paths":None}
    def say(msg, color="#d4a017"): status.value = "<b>Durum:</b> <span style='color:"+color+"'>"+html.escape(str(msg))+"</span>"
    def get_token():
        if not in_colab: return ""
        try: return userdata.get(secret.value.strip() or "GH_TOKEN") or ""
        except Exception: return ""
    def list_repos(_=None):
        token = get_token()
        if not token:
            with plan_out: print("Depo listesi için Colab Secrets'e token ekle. Public depolar elle de seçilebilir.")
            return
        try:
            found=[]
            for page in range(1,6):
                batch=github_api("/user/repos?per_page=100&page="+str(page)+"&sort=updated",token); found.extend(batch)
                if len(batch)<100: break
            repos.options=[(x["full_name"],x["full_name"]) for x in found]
            with plan_out: print("Depo sayısı:",len(found))
        except Exception as exc:
            with plan_out: print("GitHub API:",exc)
    def repo_changed(ch):
        if ch.get("new"): repo.value=ch["new"]
    repos.observe(repo_changed,names="value")
    def list_branches(_=None):
        try:
            full=normalize_repo(repo.value); token=get_token(); found=[]
            for page in range(1,6):
                batch=github_api("/repos/"+full+"/branches?per_page=100&page="+str(page),token); found.extend(batch)
                if len(batch)<100: break
            branches.options=[(x["name"],x["name"]) for x in found]
            with plan_out: print("Branch sayısı:",len(found))
        except Exception as exc:
            with plan_out: print("Branch listesi:",exc)
    def branch_changed(ch):
        if ch.get("new"): ref.value=ch["new"]
    branches.observe(branch_changed,names="value")
    def make_inputs(_=None):
        runner=state["runner"]
        if not runner or not workflow.value: return
        runner.read_workflow(workflow.value); spec=runner.dispatch_inputs(); controls=[]; by_name={}
        if event.value!="workflow_dispatch":
            inputs_box.children=[w.HTML("<i>Bu event için workflow_dispatch girdisi yok.</i>")]; state["input_widgets"]={}; return
        for key,raw in spec.items():
            cfg=mp(raw); desc=s(cfg.get("description")) or key; default=s(cfg.get("default")); kind=s(cfg.get("type")) or "string"
            if kind=="choice":
                opts=[s(x) for x in seq(cfg.get("options"))]; control=w.Dropdown(options=opts,value=default if default in opts else (opts[0] if opts else None),description=key)
            elif kind=="boolean": control=w.Checkbox(value=truth(default),description=key)
            else: control=w.Text(value=default,description=key,layout=w.Layout(width="85%"))
            control.tooltip=desc; by_name[key]=control
            controls.append(w.VBox([w.Label(desc + (" (required)" if truth(cfg.get("required")) else "")),control]))
        inputs_box.children=controls or [w.HTML("<i>Workflow input tanımlanmamış.</i>")]; state["input_widgets"]=by_name
    def selected_workflow(ch):
        runner=state["runner"]
        if not runner or not ch.get("new"): return
        try:
            runner.read_workflow(ch["new"]); ev=runner.declared_events()
            event.options=ev; event.value="workflow_dispatch" if "workflow_dispatch" in ev else (ev[0] if ev else None); make_inputs()
        except Exception as exc: say("Workflow okunamadı: "+str(exc),"#cc4444")
    def discover(_=None):
        try:
            say("Repository indiriliyor…"); token=get_token()
            workspace=pathlib.Path("/content/colab-actions-workspace")/re.sub(r"[^A-Za-z0-9_.-]+","-",repo.value)
            runner=ColabActionsRunner(workspace,token,timeout.value,lambda m:logs.append_stdout(str(m)+"\n"))
            runner.clone_repository(repo.value,ref.value,depth.value,workspace)
            if not ref.value:
                ref.value = runner.default_branch()
            files = runner.discover_workflows()
            if not files: raise RuntimeError(".github/workflows altında YAML bulunamadı.")
            state["runner"],state["workspace"]=runner,workspace; workflow.options=files; workflow.value=files[0]
            analyze.disabled=False; run.disabled=False; selected_workflow({"new":files[0]})
            say(str(len(files))+" workflow bulundu.","#2e9d63")
            with plan_out:
                clear_output(); print("Bulunan workflow dosyaları:")
                for f in files: print(" •",f)
        except Exception as exc:
            say("Keşif başarısız: "+str(exc),"#cc4444")
            with logs: print(traceback.format_exc())
    def analyze_plan(_=None):
        try:
            runner=state["runner"]; runner.read_workflow(workflow.value); runner.event_name=event.value; runner.event_ref=ref_parts(ref.value or "main")[0]
            rows=runner.preview()
            with plan_out:
                clear_output(); display(Markdown("### Workflow planı")); display(Markdown("Event: **"+str(event.value)+"** · Ref: **"+ref.value+"**"))
                table=["| Job | Matrix | Runs-on | Colab durumu | Steps |","|---|---|---|---|---|"]
                for row in rows: table.append("| "+row["name"]+" | "+json.dumps(row["matrix"],ensure_ascii=False)+" | "+row["runs_on"]+" | **"+row["compatibility"]+"** — "+row["reason"]+" | "+str(row["step_count"])+" |")
                display(Markdown("\n".join(table)))
                if any(x["compatibility"]=="BLOCKED_PLATFORM" for x in rows): display(Markdown("> Windows/macOS job'ları Colab'da çalıştırılmayacak."))
            say("Plan hazır.","#2e9d63")
        except Exception as exc:
            say("Plan hatası: "+str(exc),"#cc4444")
            with plan_out: print(traceback.format_exc())
    def start(_=None):
        if not trust.value: say("Önce güven onayını işaretle.","#cc4444"); return
        runner=state["runner"]
        if not runner: say("Önce repository taraması yap.","#cc4444"); return
        values={k:c.value for k,c in state["input_widgets"].items()}; runner.step_timeout=timeout.value; runner.cancel_event=threading.Event(); state["cancel"]=runner.cancel_event
        run.disabled=True; analyze.disabled=True; cancel.disabled=False; say("Workflow çalışıyor…")
        with logs: clear_output(); print("Colab workflow run started.")
        def worker():
            try:
                report=runner.execute(workflow.value,event.value,values,ref.value or runner.default_branch()); state["paths"]=runner.save_report()
                color="#2e9d63" if report["status"]=="PASS" else ("#d4a017" if report["status"]=="PARTIAL" else "#cc4444")
                say("Bitti: "+report["status"],color)
                with report_out:
                    clear_output(); display(Markdown("### Sonuç: **"+report["status"]+"**"))
                    display(Markdown("Jobs: "+json.dumps(report["job_counts"])+" · Steps: "+json.dumps(report["step_counts"])))
                    for job in report["jobs"]: display(Markdown("- **"+job["name"]+"** — Status: **"+job["status"]+"** "+job["detail"]))
                    if report["warnings"]: display(Markdown("**Uyarılar**\n"+"\n".join("- "+x for x in report["warnings"])))
                    display(Markdown("Raporlar kaydedildi: "+str(state["paths"][0])+" · "+str(state["paths"][1])))
                download.disabled=False
                if not keep.value: shutil.rmtree(state["workspace"],ignore_errors=True)
            except Exception as exc:
                say("Çalıştırma hatası: "+str(exc),"#cc4444")
                with logs: print(traceback.format_exc())
            finally:
                run.disabled=False; analyze.disabled=False; cancel.disabled=True
        threading.Thread(target=worker,daemon=True).start()
    def stop(_=None):
        if state["cancel"]: state["cancel"].set(); say("Durdurma istendi…")
    def get_reports(_=None):
        if files and state["paths"]:
            for p in state["paths"]: files.download(str(p))
    repos_btn.on_click(list_repos); branches_btn.on_click(list_branches); scan.on_click(discover)
    workflow.observe(selected_workflow,names="value"); event.observe(make_inputs,names="value")
    analyze.on_click(analyze_plan); run.on_click(start); cancel.on_click(stop); download.on_click(get_reports)
    display(title); display(w.HTML("<h3>1 · Repository ve branch</h3>"))
    display(repo,ref,secret,w.HBox([repos_btn,branches_btn]),repos,branches,depth)
    display(w.HTML("<h3>2 · Workflow ve event</h3>")); display(scan,workflow,event,inputs_box)
    display(w.HTML("<h3>3 · Analiz ve çalıştırma</h3>")); display(timeout,keep,analyze,trust,w.HBox([run,cancel]))
    display(status,w.HTML("<h3>Plan</h3>"),plan_out,w.HTML("<h3>Loglar</h3>"),logs,w.HTML("<h3>Rapor</h3>"),report_out,download)
    display(w.HTML("<hr><small>Güvenlik: Colab sandbox değildir. Workflow komutları runtime üzerinde kod çalıştırır. "
                   "Yalnızca güvendiğin depolarda kullan. Token job adımlarına aktarılmaz. Windows/MSVC native davranışı emüle edilmez.</small>"))

def run_self_tests():
    """Quick smoke tests for shell execution, GITHUB_ENV and platform gating."""
    with tempfile.TemporaryDirectory(prefix="colab-actions-selftest-") as temporary:
        root = pathlib.Path(temporary)
        workflow_dir = root / ".github" / "workflows"
        workflow_dir.mkdir(parents=True, exist_ok=True)
        workflow_text = "\n".join([
            "name: Colab runner self-test",
            "on:",
            "  workflow_dispatch:",
            "jobs:",
            "  smoke:",
            "    runs-on: ubuntu-latest",
            "    steps:",
            "      - name: Write environment file",
            "        run: echo COLAB_ACTIONS_SMOKE=passed >> \"$GITHUB_ENV\"",
            "      - name: Verify environment is passed between steps",
            "        run: test \"$COLAB_ACTIONS_SMOKE\" = \"passed\"",
        ])
        (workflow_dir / "smoke.yml").write_text(workflow_text, encoding="utf-8")
        runner = ColabActionsRunner(root, step_timeout=20, log=lambda _message: None)
        result = runner.execute(".github/workflows/smoke.yml", "workflow_dispatch", {}, "main")
        if result.get("status") != "PASS":
            raise RuntimeError("Runner shell/environment self-test failed: " +
                               json.dumps(result, ensure_ascii=False))
        if runner.platform_state("windows-latest")[0] != "BLOCKED_PLATFORM":
            raise RuntimeError("Runner must block Windows jobs on the Colab Linux platform.")
        if len(runner.matrix_variants({"strategy": {"matrix": {"arch": ["x86", "x64"]}}})) != 2:
            raise RuntimeError("Runner matrix expansion self-test failed.")
    print("Colab Actions runner self-tests: PASS (Linux shell, GITHUB_ENV, matrix, platform gate).")


if __name__ == "__main__":
    run_self_tests()
    launch_ui()
