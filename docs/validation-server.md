# Secure Server-Based Validation Console

The Colab notebook is no longer the preferred interface. The planned validation console is a responsive web application for phone and desktop, backed by a server-side job runner.

## Security architecture

- The browser never receives the GitHub access token.
- GitHub access is provided to the server through a deployment secret, not a UI field, URL, saved test profile, or job log.
- Prefer a GitHub App installation token. If using a fine-grained PAT, restrict it to the Tessera repository and grant only Contents: Read.
- Authenticate console users; require HTTPS; use secure, HttpOnly, SameSite cookies; protect state-changing endpoints against CSRF; rate-limit login and job creation.
- Validate repository URLs against an allowlist (initially github.com) and refs/inputs before starting jobs.
- Clone with a short-lived credential helper/askpass process; remove credential material immediately after clone; never persist it in Git config.
- Run commands in disposable containers as a non-root user. No host filesystem access, Docker socket, secrets, or network access in the test container. Enforce CPU, memory, PID, output-size and wall-clock limits.
- Keep the runner separate from the web process. The web UI/API must not have access to the container runtime socket.
- Use a bounded queue and one or a small number of workers; clean up workspace and containers after each job.
- Keep only redacted, size-limited reports. Provide a configurable retention policy.

## Responsive console requirements

- Mobile-first layout with no horizontal scrolling.
- Dynamic setup-command rows and dynamic test rows (add/remove).
- Repository/ref and server-side credential status; never display token contents.
- Run, cancel, and refresh job status.
- Progress stages: queued, clone, setup, tests, report, finished.
- Summary cards for PASS/FAIL/SKIP and duration.
- Expandable per-test logs, copyable report, and downloadable text report.
- Clear warnings that portable Linux tests do not prove Windows/MSVC or native hook correctness.

## Default Tessera profile

1. GCC strict mock: `bash verify/windows_mock/run_windows_mock_tests.sh`
2. Clang/libc++ strict mock (when the runner image has the toolchain): `EXTRA_CXXFLAGS='-stdlib=libc++' CXX=clang++ bash verify/windows_mock/run_windows_mock_tests.sh`
3. GCC ASan/UBSan: `EXTRA_CXXFLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer' ASAN_OPTIONS='detect_leaks=1:halt_on_error=1' UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1' bash verify/windows_mock/run_windows_mock_tests.sh`

The test profile is editable in the console. Tests must run against a pinned commit SHA, and the report must include that SHA.

## Deployment target

The intended first deployment is a self-hosted Ubuntu server/VPS using Docker Compose, HTTPS through a reverse proxy, and secrets injected at deployment. Do not deploy the Docker socket to the web/API container. A dedicated runner service is required for container execution.

## Acceptance checklist

- [ ] Server-side secret setup; token absent from browser/network responses and logs.
- [ ] Authentication, HTTPS, CSRF protection, rate limits.
- [ ] Repository/ref validation and pinned commit.
- [ ] Isolated runner with resource/time/output limits and no secrets.
- [ ] Dynamic setup/test rows.
- [ ] Mobile and desktop layout verified.
- [ ] PASS/FAIL/SKIP, detailed logs, report copy/download.
- [ ] Cancel job and cleanup workspace/container.
- [ ] Security review and deployment smoke test.
- [ ] Native Windows/MSVC validation remains a separate required gate.
