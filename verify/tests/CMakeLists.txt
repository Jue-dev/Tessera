find_package(Catch2 3 CONFIG QUIET)

if(NOT Catch2_FOUND)
    add_library(tessera_test_main STATIC
        "${CMAKE_CURRENT_SOURCE_DIR}/support/test_main.cpp"
    )
    target_include_directories(tessera_test_main PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/support/catch2_shim"
        "${CMAKE_CURRENT_SOURCE_DIR}/support"
    )
    tessera_apply_target_options(tessera_test_main)
endif()

function(tessera_add_test test_name)
    set(options "")
    set(oneValueArgs "")
    set(multiValueArgs SOURCES LIBS)
    cmake_parse_arguments(TST "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    add_executable(${test_name} ${TST_SOURCES})
    tessera_apply_target_options(${test_name})
    target_include_directories(${test_name} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/support")
    target_link_libraries(${test_name} PRIVATE ${TST_LIBS})

    if(Catch2_FOUND)
        target_link_libraries(${test_name} PRIVATE Catch2::Catch2WithMain)
    else()
        target_link_libraries(${test_name} PRIVATE tessera_test_main)
    endif()

    add_test(NAME ${test_name} COMMAND ${test_name})
endfunction()

# ------------------------------------------------------------------------------
# Integration test host process (tessera_test_host)
# ------------------------------------------------------------------------------
add_executable(tessera_test_host host/main.cpp)
tessera_apply_target_options(tessera_test_host)

# ------------------------------------------------------------------------------
# Header self-containment & Windows.h leak verification
# ------------------------------------------------------------------------------
get_property(PUBLIC_HEADERS GLOBAL PROPERTY TESSERA_PUBLIC_HEADERS)
list(APPEND PUBLIC_HEADERS "${PROJECT_SOURCE_DIR}/include/tessera/tessera.hpp")

set(SELF_CONTAINMENT_SOURCES "")
set(HEADER_INDEX 0)
foreach(HDR_PATH IN LISTS PUBLIC_HEADERS)
    if(NOT IS_ABSOLUTE "${HDR_PATH}")
        set(HDR_PATH "${PROJECT_SOURCE_DIR}/${HDR_PATH}")
    endif()
    file(RELATIVE_PATH REL_HDR "${PROJECT_SOURCE_DIR}/include" "${HDR_PATH}")
    set(GEN_CPP "${CMAKE_CURRENT_BINARY_DIR}/header_checks/check_${HEADER_INDEX}.cpp")
    file(WRITE "${GEN_CPP}"
"#include \"${REL_HDR}\"

#if defined(_WINDOWS_) || defined(_INC_WINDOWS) || defined(MEM_COMMIT) || defined(PAGE_READWRITE)
#error \"Public header ${REL_HDR} leaked Windows.h definitions!\"
#endif

namespace tessera::header_check_${HEADER_INDEX} {
    inline int anchor() noexcept { return ${HEADER_INDEX}; }
}
")
    list(APPEND SELF_CONTAINMENT_SOURCES "${GEN_CPP}")
    math(EXPR HEADER_INDEX "${HEADER_INDEX} + 1")
endforeach()

add_library(tessera_header_self_containment OBJECT ${SELF_CONTAINMENT_SOURCES})
tessera_apply_target_options(tessera_header_self_containment)
target_link_libraries(tessera_header_self_containment PRIVATE tessera::tessera)

# ------------------------------------------------------------------------------
# Standalone link test (verifies infra/profile/targets data models link WITHOUT process/memory)
# ------------------------------------------------------------------------------
tessera_add_test(tessera_test_standalone_consumers
    SOURCES
        consumers/standalone_consumer.cpp
    LIBS
        tessera::core
        tessera::diagnostics
        tessera::pattern
        tessera::utility
        tessera::filesystem
        tessera::json
        tessera::logging
        tessera::profiling
        tessera::profile
        tessera::profile_json
        tessera::target_profiles
        tessera::target_profiles_json
        tessera::reflection
)

# ------------------------------------------------------------------------------
# Module unit & integration test suites
# ------------------------------------------------------------------------------
tessera_add_test(tessera_test_core
    SOURCES
        core/test_core.cpp
    LIBS
        tessera::core
        tessera::diagnostics
)

tessera_add_test(tessera_test_process_memory
    SOURCES
        process_memory/test_process_memory.cpp
    LIBS
        tessera::core
        tessera::diagnostics
        tessera::process
        tessera::memory
)
add_dependencies(tessera_test_process_memory tessera_test_host)
target_compile_definitions(tessera_test_process_memory PRIVATE
    TESSERA_TEST_HOST_PATH="$<TARGET_FILE:tessera_test_host>"
)

tessera_add_test(tessera_test_pattern_scanner
    SOURCES
        pattern_scanner/test_pattern_scanner.cpp
    LIBS
        tessera::core
        tessera::diagnostics
        tessera::process
        tessera::memory
        tessera::pattern
        tessera::scanner
)

tessera_add_test(tessera_test_module_resolver
    SOURCES
        module_resolver/test_module_resolver.cpp
    LIBS
        tessera::core
        tessera::diagnostics
        tessera::process
        tessera::memory
        tessera::pattern
        tessera::scanner
        tessera::module
        tessera::resolver
)

tessera_add_test(tessera_test_patch_hook
    SOURCES
        patch_hook/test_patch_hook_core.cpp
        patch_hook/test_native_hook_unwind.cpp
        patch_hook/test_native_hook_relocation.cpp
        patch_hook/test_native_hook_backend.cpp
        patch_hook/test_native_hook_lifecycle.cpp
        patch_hook/test_patch_transactions.cpp
    LIBS
        tessera::core
        tessera::diagnostics
        tessera::process
        tessera::memory
        tessera::pattern
        tessera::patch
        tessera::hook
)
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    target_sources(tessera_test_patch_hook PRIVATE patch_hook/test_patch_hook_x86.cpp)
endif()
target_include_directories(tessera_test_patch_hook PRIVATE
    ${PROJECT_SOURCE_DIR}/src
)
if(TESSERA_WITH_DETOURS)
    target_compile_definitions(tessera_test_patch_hook PRIVATE TESSERA_TEST_WITH_DETOURS=1)
endif()

# Separate DLL fixture used to prove that host admission/drain and successful
# detach happen before the module containing the detour is unloaded.
add_library(tessera_hook_module_fixture SHARED
    patch_hook/native_hook_module_fixture.cpp
)
tessera_apply_target_options(tessera_hook_module_fixture)
set_target_properties(tessera_hook_module_fixture PROPERTIES
    PREFIX ""
    OUTPUT_NAME "tessera_hook_module_fixture"
)
add_dependencies(tessera_test_patch_hook tessera_hook_module_fixture)
target_compile_definitions(tessera_test_patch_hook PRIVATE
    TESSERA_HOOK_MODULE_FIXTURE_PATH=\"$<TARGET_FILE:tessera_hook_module_fixture>\"
)

tessera_add_test(tessera_test_utility
    SOURCES infra/test_utility.cpp
    LIBS tessera::core tessera::diagnostics tessera::utility
)

tessera_add_test(tessera_test_filesystem
    SOURCES infra/test_filesystem.cpp
    LIBS tessera::core tessera::diagnostics tessera::utility tessera::filesystem
)

tessera_add_test(tessera_test_json
    SOURCES infra/test_json.cpp
    LIBS tessera::core tessera::diagnostics tessera::utility tessera::json
)

tessera_add_test(tessera_test_reflection
    SOURCES infra/test_reflection.cpp
    LIBS tessera::core tessera::diagnostics tessera::utility tessera::reflection
)

tessera_add_test(tessera_test_logging_diagnostics
    SOURCES infra/test_logging_diagnostics.cpp
    LIBS tessera::core tessera::diagnostics tessera::logging tessera::profiling tessera::utility
)

tessera_add_test(tessera_test_profile_targets
    SOURCES
        profile_targets/test_profile_targets.cpp
    LIBS
        tessera::tessera
)

tessera_add_test(tessera_test_rtti
    SOURCES
        rtti/test_rtti.cpp
    LIBS
        tessera::tessera
)


# Deterministic property/fuzz regression suite with checked-in PE32/PE32+ fixtures.
tessera_add_test(tessera_test_deep_validation
    SOURCES
        deep_validation/test_deep_validation.cpp
    LIBS
        tessera::tessera
)
target_compile_definitions(tessera_test_deep_validation PRIVATE
    TESSERA_TEST_FIXTURE_DIR=\"${CMAKE_CURRENT_SOURCE_DIR}/fixtures\"
)


# Optional independent decoder differential oracle. The dependency is test-only
# and is installed by the dedicated CI job; it never enters the SDK/runtime.
option(TESSERA_ENABLE_DECODER_ORACLE "Enable the optional iced-x86 differential decoder test" OFF)
if(TESSERA_ENABLE_DECODER_ORACLE)
    find_package(Python3 COMPONENTS Interpreter REQUIRED)
    add_executable(tessera_decoder_probe
        decoder_oracle/decoder_probe.cpp
        ${PROJECT_SOURCE_DIR}/src/hook/backends/x86_instruction_decoder.cpp
    )
    target_include_directories(tessera_decoder_probe PRIVATE
        ${PROJECT_SOURCE_DIR}/src
    )
    tessera_apply_target_options(tessera_decoder_probe)
    add_test(
        NAME tessera_decoder_differential
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/decoder_oracle/compare_iced.py
            $<TARGET_FILE:tessera_decoder_probe>
    )
endif()
