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

# The native relocator is Windows-only. This harness maps fuzz bytes into an
# isolated executable page, asks the real backend to attach/detach, and never
# executes the supplied bytes or generated trampoline.
if(WIN32)
    add_executable(tessera_fuzz_native_hook fuzz_native_hook.cpp)
    target_link_libraries(tessera_fuzz_native_hook PRIVATE tessera::tessera)
    tessera_apply_target_options(tessera_fuzz_native_hook)
endif()

if(TESSERA_ENABLE_LIBFUZZER)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "TESSERA_ENABLE_LIBFUZZER requires Clang with the LLVM libFuzzer runtime.")
    endif()

    # Instrument the production object-library code, not just the tiny fuzz entry points.
    get_property(TESSERA_FUZZ_MODULE_TARGETS GLOBAL PROPERTY TESSERA_MODULE_TARGETS)
    foreach(module_target IN LISTS TESSERA_FUZZ_MODULE_TARGETS)
        target_compile_options(${module_target} PRIVATE
            -fsanitize=fuzzer-no-link,address,undefined
            -fno-omit-frame-pointer
        )
        # Tests/examples that also consume these modules need the sanitizer runtimes.
        target_link_options(${module_target} INTERFACE -fsanitize=address,undefined)
    endforeach()
    target_link_options(tessera_static INTERFACE -fsanitize=address,undefined)

    set(TESSERA_FUZZ_TARGETS
        tessera_fuzz_pattern
        tessera_fuzz_pe
        tessera_fuzz_json
    )
    if(TARGET tessera_fuzz_native_hook)
        list(APPEND TESSERA_FUZZ_TARGETS tessera_fuzz_native_hook)
    endif()

    foreach(fuzz_target IN LISTS TESSERA_FUZZ_TARGETS)
        target_compile_definitions(${fuzz_target} PRIVATE TESSERA_LIBFUZZER=1)
        target_compile_options(${fuzz_target} PRIVATE
            -fsanitize=fuzzer-no-link,address,undefined
            -fno-omit-frame-pointer
        )
        target_link_options(${fuzz_target} PRIVATE -fsanitize=fuzzer,address,undefined)
        if(MSVC)
            # LLVM's Windows libFuzzer does not support incremental linking.
            target_link_options(${fuzz_target} PRIVATE /INCREMENTAL:NO)
        endif()
    endforeach()
endif()
