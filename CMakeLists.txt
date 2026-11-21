cmake_minimum_required(VERSION 3.28)
project(Tessera VERSION 0.1.0 LANGUAGES C CXX)

option(TESSERA_BUILD_TESTS       "Build tests"                         ON)
option(TESSERA_BUILD_EXAMPLES    "Build examples"                      ON)
option(TESSERA_BUILD_BENCH       "Build benchmarks"                    OFF)
option(TESSERA_BUILD_FUZZ        "Build parser fuzz harnesses"         OFF)
option(TESSERA_ENABLE_LIBFUZZER  "Use LLVM libFuzzer with ASan/UBSan instrumentation" OFF)
option(TESSERA_BUILD_PROFILE     "Build Settings Profile component"    ON)
option(TESSERA_BUILD_TARGETS     "Build Target Profile component"      ON)
option(TESSERA_BUILD_LOGGING     "Build logging component"             ON)
option(TESSERA_WITH_DETOURS      "Enable Microsoft Detours backend"    OFF)
option(TESSERA_STATIC_RUNTIME    "Use /MT instead of /MD"              OFF)
if(TESSERA_ENABLE_LIBFUZZER AND NOT TESSERA_STATIC_RUNTIME)
    message(FATAL_ERROR "TESSERA_ENABLE_LIBFUZZER requires TESSERA_STATIC_RUNTIME=ON (/MT). LLVM libFuzzer on Windows does not support the dynamic /MD runtime.")
endif()
option(TESSERA_WARNINGS_AS_ERRORS "Treat warnings as errors"           ON)
option(TESSERA_ENABLE_ASAN       "Enable AddressSanitizer"             OFF)
option(TESSERA_ENABLE_MSVC_FUZZER "Use MSVC's experimental coverage-guided fuzzer" OFF)

if(TESSERA_ENABLE_MSVC_FUZZER)
    if(NOT MSVC OR NOT CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
        message(FATAL_ERROR "TESSERA_ENABLE_MSVC_FUZZER requires the native MSVC compiler.")
    endif()
    if(NOT TESSERA_ENABLE_ASAN)
        message(FATAL_ERROR "TESSERA_ENABLE_MSVC_FUZZER requires TESSERA_ENABLE_ASAN=ON.")
    endif()
    if(NOT TESSERA_STATIC_RUNTIME)
        message(FATAL_ERROR "TESSERA_ENABLE_MSVC_FUZZER requires TESSERA_STATIC_RUNTIME=ON (/MT).")
    endif()
    if(TESSERA_ENABLE_LIBFUZZER)
        message(FATAL_ERROR "Select either LLVM libFuzzer or the MSVC fuzzer, not both.")
    endif()
endif()
option(TESSERA_ENABLE_ANALYZE    "Enable MSVC /analyze"                OFF)
option(TESSERA_ENABLE_COVERAGE    "Enable GCC/Clang line and branch coverage" OFF)
option(TESSERA_PATTERN_FORCE_SCALAR "Disable pattern SIMD dispatch for scalar-fallback validation" OFF)

if(TESSERA_ENABLE_COVERAGE)
    if((MSVC AND NOT (CMAKE_CXX_COMPILER_ID STREQUAL "Clang" AND
                      CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC")) OR
       NOT CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        message(FATAL_ERROR "TESSERA_ENABLE_COVERAGE requires GCC or Clang on a supported host.")
    endif()
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        add_compile_options(--coverage -O0 -g)
        add_link_options(--coverage)
    else()
        add_compile_options(-fprofile-instr-generate -fcoverage-mapping)
        add_link_options(-fprofile-instr-generate -fcoverage-mapping)
        if(CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC")
            add_compile_options(/Od /Zi)
        else()
            add_compile_options(-O0 -g)
        endif()
    endif()
endif()

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/TesseraCompilerOptions.cmake")
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/TesseraAddModule.cmake")

tessera_verify_cpp23_toolchain()

# ------------------------------------------------------------------------------
# L0: core
# ------------------------------------------------------------------------------
tessera_add_module(
    NAME core
    SOURCES
        src/core/core.cpp
    PUBLIC_HEADERS
        include/tessera/version.hpp
        include/tessera/core/assert.hpp
        include/tessera/core/checked_math.hpp
        include/tessera/core/enum_flags.hpp
        include/tessera/core/error.hpp
        include/tessera/core/function_ref.hpp
        include/tessera/core/result.hpp
        include/tessera/core/types.hpp
        include/tessera/core/core.hpp
    PUBLIC_DEFS
        TESSERA_CMAKE_VERSION_MAJOR=${PROJECT_VERSION_MAJOR}
        TESSERA_CMAKE_VERSION_MINOR=${PROJECT_VERSION_MINOR}
        TESSERA_CMAKE_VERSION_PATCH=${PROJECT_VERSION_PATCH}
)

# ------------------------------------------------------------------------------
# L0.5: diagnostics & reflection (depend only on core)
# ------------------------------------------------------------------------------
tessera_add_module(
    NAME diagnostics
    SOURCES
        src/diagnostics/diagnostics.cpp
    PUBLIC_HEADERS
        include/tessera/diagnostics/diagnostic_observer.hpp
        include/tessera/diagnostics/error_format.hpp
        include/tessera/diagnostics/diagnostics.hpp
    PUBLIC_DEPS
        tessera::core
)

tessera_add_module(
    NAME reflection
    SOURCES
        src/reflection/reflection.cpp
    PUBLIC_HEADERS
        include/tessera/reflection/reflection.hpp
    PUBLIC_DEPS
        tessera::core
)

# ------------------------------------------------------------------------------
# Internal low-level x86/x64 instruction decoder shared by hook, scanner and resolver
# ------------------------------------------------------------------------------
tessera_add_module(
    NAME disasm
    SOURCES
        src/disasm/x86_instruction_decoder.cpp
)

# ------------------------------------------------------------------------------
# L1 (Process/Memory independent): pattern, utility, filesystem, json, logging, profiling
# ------------------------------------------------------------------------------
if(MSVC AND NOT CMAKE_SYSTEM_PROCESSOR MATCHES "ARM|arm")
    if(CMAKE_SIZEOF_VOID_P EQUAL 4)
        set_source_files_properties(src/pattern/pattern_simd.cpp PROPERTIES COMPILE_OPTIONS "/arch:SSE2")
    endif()
    set_source_files_properties(src/pattern/pattern_simd_avx2.cpp PROPERTIES COMPILE_OPTIONS "/arch:AVX2")
endif()

tessera_add_module(
    NAME pattern
    SOURCES
        src/pattern/pattern.cpp
        src/pattern/pattern_simd.cpp
        src/pattern/pattern_simd_avx2.cpp
    PUBLIC_HEADERS
        include/tessera/pattern/pattern.hpp
    PUBLIC_DEPS
        tessera::core
)

if(TESSERA_PATTERN_FORCE_SCALAR)
    target_compile_definitions(tessera_pattern PRIVATE TESSERA_PATTERN_FORCE_SCALAR=1)
endif()

tessera_add_module(
    NAME utility
    SOURCES
        src/utility/utility.cpp
    PUBLIC_HEADERS
        include/tessera/utility/scope_guard.hpp
        include/tessera/utility/string.hpp
        include/tessera/utility/bytes.hpp
        include/tessera/utility/hex.hpp
        include/tessera/utility/encoding.hpp
        include/tessera/utility/path.hpp
        include/tessera/utility/utility.hpp
    PUBLIC_DEPS
        tessera::core
    SYSTEM_LIBS
        Shell32.lib
        Ole32.lib
)

tessera_add_module(
    NAME filesystem
    SOURCES
        src/filesystem/filesystem.cpp
    PUBLIC_HEADERS
        include/tessera/filesystem/filesystem.hpp
    PUBLIC_DEPS
        tessera::core
        tessera::utility
)

tessera_add_module(
    NAME json
    SOURCES
        src/json/json.cpp
    PUBLIC_HEADERS
        include/tessera/json/json.hpp
    PUBLIC_DEPS
        tessera::core
        tessera::utility
)

if(TESSERA_BUILD_LOGGING)
    tessera_add_module(
        NAME logging
        SOURCES
            src/logging/logging.cpp
        PUBLIC_HEADERS
            include/tessera/logging/logging.hpp
        PUBLIC_DEPS
            tessera::core
            tessera::diagnostics
        PRIVATE_DEPS
            tessera::utility
    )
endif()

tessera_add_module(
    NAME profiling
    SOURCES
        src/profiling/profiling.cpp
    PUBLIC_HEADERS
        include/tessera/profiling/profiling.hpp
    PUBLIC_DEPS
        tessera::core
)

# ------------------------------------------------------------------------------
# L1 (Process/Memory layer): process, memory
# ------------------------------------------------------------------------------
tessera_add_module(
    NAME process
    SOURCES
        src/platform/windows/process_backend.cpp
    PUBLIC_HEADERS
        include/tessera/process/process.hpp
        include/tessera/platform/windows/native.hpp
    PUBLIC_DEPS
        tessera::core
        tessera::diagnostics
)

tessera_add_module(
    NAME memory
    SOURCES
        src/platform/windows/memory_backend.cpp
        src/memory/memory.cpp
    PUBLIC_HEADERS
        include/tessera/memory/memory_region.hpp
        include/tessera/memory/memory_backend.hpp
        include/tessera/memory/protection_scope.hpp
        include/tessera/memory/memory_reader.hpp
        include/tessera/memory/memory_writer.hpp
        include/tessera/memory/process_address.hpp
        include/tessera/memory/memory.hpp
    PUBLIC_DEPS
        tessera::core
        tessera::diagnostics
        tessera::process
)

# ------------------------------------------------------------------------------
# L2: scanner, module, resolver, patch, hook, profile
# ------------------------------------------------------------------------------
tessera_add_module(
    NAME scanner
    SOURCES
        src/scanner/scanner.cpp
    PUBLIC_HEADERS
        include/tessera/scanner/scanner.hpp
        include/tessera/scanner/xref.hpp
    PUBLIC_DEPS
        tessera::core
        tessera::diagnostics
        tessera::process
        tessera::memory
        tessera::pattern
        tessera::disasm
    PRIVATE_DEPS
        tessera::disasm
)

tessera_add_module(
    NAME module
    SOURCES
        src/module/pe_image.cpp
        src/module/pe_image_detail.cpp
        src/module/pe_image_memory.cpp
        src/module/pe_image_raw.cpp
        src/platform/windows/module_backend.cpp
    PUBLIC_HEADERS
        include/tessera/module/pe_image.hpp
        include/tessera/module/module.hpp
    PUBLIC_DEPS
        tessera::core
        tessera::process
        tessera::memory
    SYSTEM_LIBS
        Psapi.lib
)

tessera_add_module(
    NAME resolver
    SOURCES
        src/resolver/resolver.cpp
    PUBLIC_HEADERS
        include/tessera/resolver/resolver.hpp
        include/tessera/resolver/address_cursor.hpp
    PUBLIC_DEPS
        tessera::core
        tessera::process
        tessera::memory
        tessera::scanner
        tessera::disasm
    PRIVATE_DEPS
        tessera::disasm
)

tessera_add_module(
    NAME rtti
    SOURCES
        src/rtti/rtti.cpp
        src/rtti/discovery.cpp
        src/rtti/python_bridge.cpp
        src/rtti/python_bridge_tables.cpp
        src/rtti/python_bridge_link.cpp
        src/rtti/python_bridge_types.cpp
        src/rtti/python_environment.cpp
    PUBLIC_HEADERS
        include/tessera/rtti/rtti.hpp
        include/tessera/rtti/discovery.hpp
        include/tessera/rtti/python_bridge.hpp
        include/tessera/rtti/object_view.hpp
    PUBLIC_DEPS
        tessera::core
        tessera::reflection
        tessera::process
        tessera::memory
        tessera::pattern
        tessera::scanner
        tessera::module
        tessera::utility
)

tessera_add_module(
    NAME patch
    SOURCES
        src/patch/patch.cpp
    PUBLIC_HEADERS
        include/tessera/patch/patch.hpp
    PUBLIC_DEPS
        tessera::core
        tessera::diagnostics
        tessera::process
        tessera::memory
        tessera::pattern
)

set(TESSERA_HOOK_PRIVATE_DEFS "")
set(TESSERA_HOOK_SYSTEM_LIBS "")
if(TESSERA_WITH_DETOURS)
    find_path(DETOURS_INCLUDE_DIRS NAMES "detours/detours.h" "detours.h")
    find_library(DETOURS_LIBRARY NAMES detours)
    if(NOT DETOURS_INCLUDE_DIRS OR NOT DETOURS_LIBRARY)
        message(FATAL_ERROR
            "TESSERA_WITH_DETOURS=ON requires Microsoft Detours headers and library, "
            "but they were not found.")
    endif()
    list(APPEND TESSERA_HOOK_PRIVATE_DEFS "TESSERA_WITH_DETOURS_ENABLED=1")
    list(APPEND TESSERA_HOOK_SYSTEM_LIBS "${DETOURS_LIBRARY}")
endif()

tessera_add_module(
    NAME hook
    SOURCES
        src/platform/windows/thread_backend.cpp
        src/hook/backends/detours_backend.cpp
        src/hook/backends/native_inline_backend.cpp
        src/hook/backends/native_thread_suspension.cpp
        src/hook/backends/native_trampoline.cpp
        src/hook/backends/native_relocation.cpp
        src/hook/backends/native_unwind.cpp
    PUBLIC_HEADERS
        include/tessera/hook/hook.hpp
    PUBLIC_DEPS
        tessera::core
        tessera::diagnostics
    PRIVATE_DEPS
        tessera::process
        tessera::memory
        tessera::disasm
    PRIVATE_DEFS
        ${TESSERA_HOOK_PRIVATE_DEFS}
    SYSTEM_LIBS
        ${TESSERA_HOOK_SYSTEM_LIBS}
)

if(TESSERA_WITH_DETOURS AND DETOURS_INCLUDE_DIRS)
    target_include_directories(tessera_hook PRIVATE "${DETOURS_INCLUDE_DIRS}")
endif()

if(TESSERA_BUILD_PROFILE)
    tessera_add_module(
        NAME profile
        SOURCES
            src/profile/profile.cpp
        PUBLIC_HEADERS
            include/tessera/profile/profile.hpp
        PUBLIC_DEPS
            tessera::core
    )

    tessera_add_module(
        NAME profile_json
        SOURCES
            src/profile/profile_json.cpp
        PUBLIC_HEADERS
            include/tessera/profile/profile_json.hpp
        PUBLIC_DEPS
            tessera::core
            tessera::profile
            tessera::json
            tessera::filesystem
    )
endif()

# ------------------------------------------------------------------------------
# L3: targets (split into target_profiles, target_profiles_json, target_runtime, targets)
# ------------------------------------------------------------------------------
if(TESSERA_BUILD_TARGETS)
    tessera_add_module(
        NAME target_profiles
        SOURCES
            src/targets/target_profile.cpp
        PUBLIC_HEADERS
            include/tessera/targets/target_profile.hpp
        PUBLIC_DEPS
            tessera::core
            tessera::utility
    )

    tessera_add_module(
        NAME target_profiles_json
        SOURCES
            src/targets/target_profile_json_read.cpp
            src/targets/target_profile_json_write.cpp
            src/targets/target_profile_json_common.cpp
        PUBLIC_HEADERS
            include/tessera/targets/target_profile_json.hpp
        PUBLIC_DEPS
            tessera::core
            tessera::target_profiles
            tessera::json
            tessera::filesystem
            tessera::utility
    )

    tessera_add_module(
        NAME target_runtime
        SOURCES
            src/targets/target_runtime.cpp
            src/targets/target_fingerprinter.cpp
            src/targets/discovery_session.cpp
        PUBLIC_HEADERS
            include/tessera/targets/target_runtime.hpp
        PUBLIC_DEPS
            tessera::core
            tessera::target_profiles
            tessera::process
            tessera::memory
            tessera::pattern
            tessera::scanner
            tessera::module
            tessera::resolver
            tessera::rtti
            tessera::filesystem
            tessera::utility
    )

    add_library(tessera_targets INTERFACE)
    add_library(tessera::targets ALIAS tessera_targets)
    set_target_properties(tessera_targets PROPERTIES EXPORT_NAME targets)
    target_include_directories(tessera_targets INTERFACE
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    )
    target_link_libraries(tessera_targets INTERFACE
        tessera::target_profiles
        tessera::target_profiles_json
        tessera::target_runtime
    )
endif()

# ------------------------------------------------------------------------------
# Unified single static library output: tessera.lib (tessera::tessera)
# ------------------------------------------------------------------------------
get_property(ALL_TESSERA_OBJECTS GLOBAL PROPERTY TESSERA_MODULE_OBJECTS)
get_property(ALL_TESSERA_SYS_LIBS GLOBAL PROPERTY TESSERA_MODULE_SYSTEM_LIBS)
if(ALL_TESSERA_SYS_LIBS)
    list(REMOVE_DUPLICATES ALL_TESSERA_SYS_LIBS)
endif()

add_library(tessera_static STATIC ${ALL_TESSERA_OBJECTS})
add_library(tessera::tessera ALIAS tessera_static)
set_target_properties(tessera_static PROPERTIES
    EXPORT_NAME tessera
    OUTPUT_NAME tessera
)
target_include_directories(tessera_static PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
target_compile_definitions(tessera_static PUBLIC
    TESSERA_CMAKE_VERSION_MAJOR=${PROJECT_VERSION_MAJOR}
    TESSERA_CMAKE_VERSION_MINOR=${PROJECT_VERSION_MINOR}
    TESSERA_CMAKE_VERSION_PATCH=${PROJECT_VERSION_PATCH}
)
tessera_apply_target_options(tessera_static)
if(ALL_TESSERA_SYS_LIBS)
    target_link_libraries(tessera_static PUBLIC ${ALL_TESSERA_SYS_LIBS})
endif()
if(TESSERA_WITH_DETOURS AND DETOURS_LIBRARY)
    target_link_libraries(tessera_static PUBLIC "${DETOURS_LIBRARY}")
endif()

install(TARGETS tessera_static
    EXPORT TesseraTargets
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
)

# ------------------------------------------------------------------------------
# Install / SDK Packaging
# ------------------------------------------------------------------------------
install(DIRECTORY "${PROJECT_SOURCE_DIR}/include/tessera"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)

install(EXPORT TesseraTargets
    FILE TesseraTargets.cmake
    NAMESPACE tessera::
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/Tessera"
)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/TesseraConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

configure_package_config_file(
    "${PROJECT_SOURCE_DIR}/cmake/tessera-config.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/TesseraConfig.cmake"
    INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/Tessera"
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/TesseraConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/TesseraConfigVersion.cmake"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/Tessera"
)


# ------------------------------------------------------------------------------
# Subdirectories: Verify (tests, bench, fuzz) and Examples
# ------------------------------------------------------------------------------
if(TESSERA_BUILD_TESTS OR TESSERA_BUILD_BENCH OR TESSERA_BUILD_FUZZ)
    enable_testing()
    add_subdirectory(verify)
endif()

if(TESSERA_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()
