cmake_minimum_required(VERSION 3.28)

add_executable(tessera_fuzz_pattern fuzz_pattern.cpp)
target_link_libraries(tessera_fuzz_pattern PRIVATE tessera::pattern)
tessera_apply_target_options(tessera_fuzz_pattern)

add_executable(tessera_fuzz_pe fuzz_pe.cpp)
target_link_libraries(tessera_fuzz_pe PRIVATE tessera::tessera)
tessera_apply_target_options(tessera_fuzz_pe)

add_executable(tessera_fuzz_json fuzz_json.cpp)
target_link_libraries(tessera_fuzz_json PRIVATE tessera::tessera)
tessera_apply_target_options(tessera_fuzz_json)

add_executable(tessera_fuzz_profile_json fuzz_profile_json.cpp)
target_link_libraries(tessera_fuzz_profile_json PRIVATE tessera::tessera)
tessera_apply_target_options(tessera_fuzz_profile_json)

add_executable(tessera_fuzz_python_bridge fuzz_python_bridge.cpp)
target_link_libraries(tessera_fuzz_python_bridge PRIVATE tessera::tessera)
target_include_directories(tessera_fuzz_python_bridge PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../tests/support)
tessera_apply_target_options(tessera_fuzz_python_bridge)

add_executable(tessera_fuzz_scanner fuzz_scanner.cpp)
target_link_libraries(tessera_fuzz_scanner PRIVATE tessera::tessera)
target_include_directories(tessera_fuzz_scanner PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../tests/support)
tessera_apply_target_options(tessera_fuzz_scanner)

add_executable(tessera_fuzz_rtti_discovery fuzz_rtti_discovery.cpp)
target_link_libraries(tessera_fuzz_rtti_discovery PRIVATE tessera::tessera)
target_include_directories(tessera_fuzz_rtti_discovery PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../tests/support
)
tessera_apply_target_options(tessera_fuzz_rtti_discovery)

# The native relocator is Windows-only. This harness maps fuzz bytes into an
# isolated executable page, asks the real backend to attach/detach, and never
# executes the supplied bytes or generated trampoline.
if(WIN32)
    add_executable(tessera_fuzz_native_hook fuzz_native_hook.cpp)
    target_link_libraries(tessera_fuzz_native_hook PRIVATE tessera::tessera)
    tessera_apply_target_options(tessera_fuzz_native_hook)
endif()

# Visual Studio's experimental /fsanitize=fuzzer runtime supports both x86
# and x64. Use it for native MSVC x86 validation because the distributed LLVM
# Windows toolchain does not ship a 32-bit libFuzzer archive.
if(TESSERA_ENABLE_MSVC_FUZZER)
    if(NOT MSVC OR NOT CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
        message(FATAL_ERROR "TESSERA_ENABLE_MSVC_FUZZER requires native MSVC.")
    endif()

    get_property(TESSERA_FUZZ_MODULE_TARGETS GLOBAL PROPERTY TESSERA_MODULE_TARGETS)
    foreach(module_target IN LISTS TESSERA_FUZZ_MODULE_TARGETS)
        target_compile_options(${module_target} PRIVATE /fsanitize=fuzzer)
    endforeach()

    set(TESSERA_MSVC_FUZZ_TARGETS
        tessera_fuzz_pattern
        tessera_fuzz_pe
        tessera_fuzz_json
        tessera_fuzz_profile_json
        tessera_fuzz_python_bridge
        tessera_fuzz_scanner
        tessera_fuzz_rtti_discovery
    )
    if(TARGET tessera_fuzz_native_hook)
        list(APPEND TESSERA_MSVC_FUZZ_TARGETS tessera_fuzz_native_hook)
    endif()

    foreach(fuzz_target IN LISTS TESSERA_MSVC_FUZZ_TARGETS)
        target_compile_definitions(${fuzz_target} PRIVATE TESSERA_LIBFUZZER=1)
        target_compile_options(${fuzz_target} PRIVATE /fsanitize=fuzzer)
        target_link_options(${fuzz_target} PRIVATE /INCREMENTAL:NO)
    endforeach()
endif()


if(TESSERA_ENABLE_LIBFUZZER)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "TESSERA_ENABLE_LIBFUZZER requires Clang with the LLVM libFuzzer runtime.")
    endif()

    # Use the option spelling for the active Clang driver frontend. clang-cl
    # treats the GNU -fno-omit-frame-pointer spelling as an ignored argument,
    # and /WX turns that warning into a hard build failure.
    if(CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC")
        set(TESSERA_FUZZ_FRAME_POINTER_OPTION /Oy-)

        # CMake's MSVC-style linker rule invokes lld-link directly for clang-cl.
        # That bypasses clang-cl's sanitizer runtime injection, so provide the
        # compiler-rt search path and the same whole-archive runtimes explicitly.
        execute_process(
            COMMAND "${CMAKE_CXX_COMPILER}" -print-resource-dir
            RESULT_VARIABLE TESSERA_CLANG_RESOURCE_RESULT
            OUTPUT_VARIABLE TESSERA_CLANG_RESOURCE_DIR
            ERROR_VARIABLE TESSERA_CLANG_RESOURCE_ERROR
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
        if(NOT TESSERA_CLANG_RESOURCE_RESULT EQUAL 0 OR
           TESSERA_CLANG_RESOURCE_DIR STREQUAL "")
            message(FATAL_ERROR
                "Unable to locate the clang-cl compiler-rt resource directory: "
                "${TESSERA_CLANG_RESOURCE_ERROR}")
        endif()

        set(TESSERA_CLANG_WINDOWS_RUNTIME_DIR
            "${TESSERA_CLANG_RESOURCE_DIR}/lib/windows")
        if(CMAKE_SIZEOF_VOID_P EQUAL 8)
            set(TESSERA_CLANG_RUNTIME_ARCH x86_64)
        else()
            set(TESSERA_CLANG_RUNTIME_ARCH i386)
        endif()

        set(TESSERA_CLANG_FUZZER_RUNTIME
            "${TESSERA_CLANG_WINDOWS_RUNTIME_DIR}/clang_rt.fuzzer-${TESSERA_CLANG_RUNTIME_ARCH}.lib")
        set(TESSERA_CLANG_ASAN_RUNTIME
            "${TESSERA_CLANG_WINDOWS_RUNTIME_DIR}/clang_rt.asan_dynamic-${TESSERA_CLANG_RUNTIME_ARCH}.lib")
        set(TESSERA_CLANG_ASAN_STATIC_THUNK
            "${TESSERA_CLANG_WINDOWS_RUNTIME_DIR}/clang_rt.asan_static_runtime_thunk-${TESSERA_CLANG_RUNTIME_ARCH}.lib")
        set(TESSERA_CLANG_ASAN_RUNTIME_DLL
            "${TESSERA_CLANG_WINDOWS_RUNTIME_DIR}/clang_rt.asan_dynamic-${TESSERA_CLANG_RUNTIME_ARCH}.dll")

        foreach(runtime_file IN ITEMS
                "${TESSERA_CLANG_FUZZER_RUNTIME}"
                "${TESSERA_CLANG_ASAN_RUNTIME}"
                "${TESSERA_CLANG_ASAN_STATIC_THUNK}"
                "${TESSERA_CLANG_ASAN_RUNTIME_DLL}")
            if(NOT EXISTS "${runtime_file}")
                message(FATAL_ERROR "Required clang-cl sanitizer runtime is missing: ${runtime_file}")
            endif()
        endforeach()
    else()
        set(TESSERA_FUZZ_FRAME_POINTER_OPTION -fno-omit-frame-pointer)
    endif()

    # Instrument the production object-library code, not just the tiny fuzz entry points.
    get_property(TESSERA_FUZZ_MODULE_TARGETS GLOBAL PROPERTY TESSERA_MODULE_TARGETS)
    foreach(module_target IN LISTS TESSERA_FUZZ_MODULE_TARGETS)
        # The bundled libFuzzer runtime is built without MSVC STL string annotations.
        # Disable that annotation consistently to avoid linker detect_mismatch conflicts.
        if(CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC")
            target_compile_definitions(${module_target} PRIVATE _DISABLE_STRING_ANNOTATION _DISABLE_VECTOR_ANNOTATION)
        endif()
        target_compile_options(${module_target} PRIVATE
            -fsanitize=fuzzer-no-link,address,undefined
            ${TESSERA_FUZZ_FRAME_POINTER_OPTION}
        )
        # Direct lld-link has no clang driver to translate these options.
        if(NOT CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC")
            target_link_options(${module_target} INTERFACE -fsanitize=address,undefined)
        endif()
    endforeach()
    if(NOT CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC")
        target_link_options(tessera_static INTERFACE -fsanitize=address,undefined)
    endif()

    set(TESSERA_FUZZ_TARGETS
        tessera_fuzz_pattern
        tessera_fuzz_pe
        tessera_fuzz_json
        tessera_fuzz_profile_json
        tessera_fuzz_python_bridge
        tessera_fuzz_scanner
        tessera_fuzz_rtti_discovery
    )
    if(TARGET tessera_fuzz_native_hook)
        list(APPEND TESSERA_FUZZ_TARGETS tessera_fuzz_native_hook)
    endif()

    foreach(fuzz_target IN LISTS TESSERA_FUZZ_TARGETS)
        target_compile_definitions(${fuzz_target} PRIVATE TESSERA_LIBFUZZER=1)
        if(CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC")
            target_compile_definitions(${fuzz_target} PRIVATE _DISABLE_STRING_ANNOTATION _DISABLE_VECTOR_ANNOTATION)
        endif()
        target_compile_options(${fuzz_target} PRIVATE
            -fsanitize=fuzzer-no-link,address,undefined
            ${TESSERA_FUZZ_FRAME_POINTER_OPTION}
        )
        if(CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC")
            # UBSan auto-link directives need the compiler-rt library path.
            # libFuzzer and ASan use whole-archive runtimes on Windows.
            target_link_options(${fuzz_target} PRIVATE
                "/LIBPATH:${TESSERA_CLANG_WINDOWS_RUNTIME_DIR}"
                "/WHOLEARCHIVE:${TESSERA_CLANG_FUZZER_RUNTIME}"
                "/WHOLEARCHIVE:${TESSERA_CLANG_ASAN_STATIC_THUNK}"
                "/INCREMENTAL:NO"
            )
            target_link_libraries(${fuzz_target} PRIVATE
                "${TESSERA_CLANG_ASAN_RUNTIME}")
        else()
            target_link_options(${fuzz_target} PRIVATE -fsanitize=fuzzer,address,undefined)
        endif()
    endforeach()
endif()


# Standalone smoke builds replay every checked-in seed through the same
# LLVMFuzzerTestOneInput entry point. Coverage-guided runtimes own their
# corpus scheduling and therefore do not register these deterministic tests.
if(TESSERA_BUILD_TESTS AND NOT TESSERA_ENABLE_MSVC_FUZZER AND NOT TESSERA_ENABLE_LIBFUZZER)
    function(tessera_add_fuzz_corpus_test target corpus)
        if(TARGET ${target})
            add_test(
                NAME ${target}_corpus_replay
                COMMAND $<TARGET_FILE:${target}>
                        "${CMAKE_CURRENT_SOURCE_DIR}/corpus/${corpus}"
                        "-runs=100"
            )
        endif()
    endfunction()

    tessera_add_fuzz_corpus_test(tessera_fuzz_pattern pattern)
    tessera_add_fuzz_corpus_test(tessera_fuzz_pe pe)
    tessera_add_fuzz_corpus_test(tessera_fuzz_json json)
    tessera_add_fuzz_corpus_test(tessera_fuzz_profile_json profile_json)
    tessera_add_fuzz_corpus_test(tessera_fuzz_python_bridge python_bridge)
    tessera_add_fuzz_corpus_test(tessera_fuzz_scanner scanner)
    tessera_add_fuzz_corpus_test(tessera_fuzz_rtti_discovery rtti_discovery)
    tessera_add_fuzz_corpus_test(tessera_fuzz_native_hook native_hook)
endif()
