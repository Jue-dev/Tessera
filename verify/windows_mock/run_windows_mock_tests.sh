#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$ROOT/verify/windows_mock/build"
LOG="${LOG:-$ROOT/verify/windows_mock/windows_mock_tests.log}"
CXX="${CXX:-g++}"
read -r -a EXTRA_CXXFLAGS_ARRAY <<< "${EXTRA_CXXFLAGS:-}"
mkdir -p "$OUT" "$(dirname "$LOG")"
rm -f "$OUT"/*
COMMON=(
  -std=c++23 -O0 -Wall -Wextra -Wpedantic -Werror -Wno-missing-field-initializers
  -DWIN32_LEAN_AND_MEAN -DNOMINMAX -DUNICODE -D_UNICODE -D_WIN32_WINNT=0x0A00
  -DTESSERA_WITH_DETOURS_ENABLED=1
  -I"$ROOT/verify/windows_mock/sdk" -I"$ROOT/include" -I"$ROOT/src"
  "${EXTRA_CXXFLAGS_ARRAY[@]}"
)
SOURCES=(
  src/platform/windows/process_backend.cpp
  src/memory/memory.cpp
  src/platform/windows/memory_backend.cpp
  src/platform/windows/module_backend.cpp
  src/platform/windows/thread_backend.cpp
  src/hook/backends/detours_backend.cpp
)
idx=0
OBJECTS=()
for src in "${SOURCES[@]}"; do
  obj="$OUT/backend_${idx}.o"
  echo "[CXX MOCK-WIN32] $src"
  "$CXX" "${COMMON[@]}" -c "$ROOT/$src" -o "$obj"
  OBJECTS+=("$obj")
  ((idx+=1))
done

echo "[CXX MOCK-WIN32] verify/windows_mock/src/api_stubs.cpp"
"$CXX" "${COMMON[@]}" -c "$ROOT/verify/windows_mock/src/api_stubs.cpp" -o "$OUT/api_stubs.o"
echo "[CXX MOCK-WIN32] verify/windows_mock/src/test_windows_backends.cpp"
"$CXX" "${COMMON[@]}" -c "$ROOT/verify/windows_mock/src/test_windows_backends.cpp" -o "$OUT/test_windows_backends.o"
echo "[LINK] windows_mock_backends"
"$CXX" "${EXTRA_CXXFLAGS_ARRAY[@]}" -pthread "${OBJECTS[@]}" "$OUT/api_stubs.o" "$OUT/test_windows_backends.o" -o "$OUT/windows_mock_backends"
"$OUT/windows_mock_backends" | tee "$LOG"
echo "WINDOWS_MOCK_VALIDATION_COMPLETE"
