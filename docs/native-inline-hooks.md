The Windows validation workflows run at multiple stages:
`.github/workflows/ci.yml` runs the x86/x64 Debug and Release matrix, the
`/GR-` quality gate (including fuzz/benchmark smoke targets), Detours
integration, MSVC static analysis, and SDK packaging. It runs on relevant
pushes to `main`, manual dispatch, and version-tag pushes; manual dispatch
against a PR branch runs validation but skips release packaging. There is no PR
or scheduled validation trigger, to avoid consuming Actions quota on every
iteration.

The separate `.github/workflows/native-hook-fuzz.yml` workflow is manual-only
and supports bounded 60-, 300-, or 900-second Windows x64 Clang libFuzzer
campaigns with coverage, ASan/UBSan, checked-in binary seeds, and uploaded
corpus/crash artifacts. Review the artifacts and verify the exact tested commit
before treating a campaign as validated. Actions results from older commits do
not validate the current head.

## Current Issue #6 evidence

The current PR head
`f4cc4d1715cef026585cf14650659981f891ace4` passed the complete Windows CI
matrix and quality gates in
[run #44561390158](https://github.com/Jue-dev/Tessera/actions/runs/44561390158):
x86/x64 Debug/Release, CTest, Detours x86/x64, `/GR-`, MSVC `/analyze`,
and SDK packaging. Release publication was skipped as expected.

Still outstanding:
- Current-head bounded five-minute Clang libFuzzer + ASan/UBSan campaign and
  corpus/crash artifact review.
- Real host integration proving admission/drain of every direct target call,
  detour callback, and raw/escaped trampoline pointer before detach/unload.
- Independent final failure-path audit.

A passing test fixture demonstrates the controlled admission/drain/unload
sequence; it does not establish that a production host gates every call path.
See `docs/issue-6-ci-validation-checklist.md` for the evidence ledger.
