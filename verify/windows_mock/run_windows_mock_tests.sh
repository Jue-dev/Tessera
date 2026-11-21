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
  src/hook/backends/native_thread_suspension.cpp
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
TEST_SOURCES=(
  verify/windows_mock/src/test_windows_backends.cpp
  verify/windows_mock/src/test_windows_memory_module.cpp
  verify/windows_mock/src/test_windows_process_thread.cpp
  verify/windows_mock/src/test_windows_detours_hook.cpp
)
TEST_OBJECTS=()
for src in "${TEST_SOURCES[@]}"; do
  name="$(basename "${src%.cpp}")"
  obj="$OUT/${name}.o"
  echo "[CXX MOCK-WIN32] $src"
  "$CXX" "${COMMON[@]}" -c "$ROOT/$src" -o "$obj"
  TEST_OBJECTS+=("$obj")
done

echo "[LINK] windows_mock_backends"
"$CXX" "${EXTRA_CXXFLAGS_ARRAY[@]}" -pthread "${OBJECTS[@]}" "$OUT/api_stubs.o" "${TEST_OBJECTS[@]}" -o "$OUT/windows_mock_backends"
"$OUT/windows_mock_backends" | tee "$LOG"

# Build the concurrency test against the same portable Windows backend stubs.
# This runs in the normal, ASan/UBSan and TSan invocations of this script.
CONCURRENCY_COMMON=(
  "${COMMON[@]}"
  -I"$ROOT/verify/tests/support"
  -I"$ROOT/verify/tests/support/catch2_shim"
)
CONCURRENCY_SOURCES=(
  src/core/core.cpp
  src/diagnostics/diagnostics.cpp
  src/logging/logging.cpp
  src/pattern/pattern.cpp
  src/pattern/pattern_simd.cpp
  src/pattern/pattern_simd_avx2.cpp
  src/disasm/x86_instruction_decoder.cpp
  src/module/pe_image.cpp
  src/module/pe_image_detail.cpp
  src/module/pe_image_memory.cpp
  src/module/pe_image_raw.cpp
  src/scanner/scanner.cpp
  src/scanner/scanner_batch.cpp
  src/scanner/xref.cpp
  src/patch/patch.cpp
  verify/tests/support/test_main.cpp
  verify/tests/concurrency/test_concurrency.cpp
)
CONCURRENCY_OBJECTS=()
idx=0
for src in "${CONCURRENCY_SOURCES[@]}"; do
  obj="$OUT/concurrency_${idx}.o"
  echo "[CXX CONCURRENCY] $src"
  "$CXX" "${CONCURRENCY_COMMON[@]}" -c "$ROOT/$src" -o "$obj"
  CONCURRENCY_OBJECTS+=("$obj")
  ((idx+=1))
done

echo "[LINK] tessera_test_concurrency"
"$CXX" "${EXTRA_CXXFLAGS_ARRAY[@]}" -pthread "${OBJECTS[@]}" "$OUT/api_stubs.o" \
  "${CONCURRENCY_OBJECTS[@]}" -o "$OUT/tessera_test_concurrency"
"$OUT/tessera_test_concurrency" | tee -a "$LOG"
"$OUT/tessera_test_concurrency" --shuffle --seed 20261121 | tee -a "$LOG"
echo "CONCURRENCY_VALIDATION_COMPLETE"
echo "WINDOWS_MOCK_VALIDATION_COMPLETE"
