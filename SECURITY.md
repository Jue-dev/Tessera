# Security Policy

## Supported versions

Security fixes are developed against the latest commit on `main`. Until a stable 1.0 release is published, no older release line is guaranteed to receive security updates. The supported patch line will be documented when 1.0 is released.

## Reporting a vulnerability

Do not open a public issue for an exploitable vulnerability. Use GitHub's **Report a vulnerability** action in the repository Security tab to submit a private report. Include the affected commit or release, platform and architecture, a minimal reproduction, impact, and known mitigations. Do not attach secrets or real process-memory dumps.

Maintainers will acknowledge reports as soon as practical, investigate privately, coordinate a fix and disclosure timeline with the reporter, and publish an advisory when a fix is available.

## Threat model and trust boundaries

Tessera is a native C++ library that may inspect another process's memory and manipulate executable code. These capabilities are privileged operations.

- **PE inputs are untrusted.** Validate offsets, lengths, directory bounds, integer arithmetic, section mappings and alignment before dereferencing data. Malformed files must fail safely without out-of-bounds reads or integer wrap-around.
- **JSON and profile inputs are untrusted.** Apply schema validation, bounded parsing, safe handling of references and secrets, and never log secret values.
- **Remote process memory is volatile and untrusted.** Reads may be partial or fail between region queries. Handle inaccessible pages, process exit, address-space changes and architecture mismatches.
- **Inline hooks and patching are privileged.** They alter executable memory. Validate instruction boundaries, relocation operands, page protections, transaction rollback and lifetime. Never execute arbitrary bytes supplied by a parser or fuzz corpus.
- **Fuzzing inputs are hostile by design.** Keep harnesses deterministic, bounded and isolated. Do not check in crash artifacts, raw logs or oversized corpora.

## Secure-use guidance

Use the least privilege required, validate process identity and architecture, avoid hooking processes you do not own or administer, and treat all external binary/profile data as attacker-controlled. Tessera is not a sandbox and does not make untrusted code safe to execute.
