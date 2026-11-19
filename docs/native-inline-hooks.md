The Windows validation workflows run at multiple stages:
`.github/workflows/ci.yml` runs the x86/x64 Debug and Release matrix, the
`/GR-` quality gate (including fuzz/benchmark smoke targets), Detours
integration, and MSVC static analysis. It runs on relevant pushes to `main`,
manual dispatch, and version-tag pushes; manual dispatch against a PR branch
runs validation but skips release packaging. There is no PR or scheduled
validation trigger, to avoid consuming Actions quota on every iteration.
The separate `.github/workflows/native-hook-fuzz.yml` workflow is manual-only
and supports bounded 60-, 300-, or 900-second Windows x64 Clang libFuzzer
campaigns with coverage, ASan/UBSan, checked-in binary seeds, and uploaded
corpus/crash artifacts. Review the artifacts and verify the exact tested commit
before treating a campaign as validated. Actions results from older commits do
not validate the current head. The full Windows matrix, sustained fuzz,
Detours, static-analysis, packaging, and real host integration checks remain
separate acceptance gates.