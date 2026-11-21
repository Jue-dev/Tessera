include_guard(GLOBAL)

include(CheckCXXSourceCompiles)

function(tessera_verify_cpp23_toolchain)
    if(NOT WIN32)
        message(FATAL_ERROR "Tessera v0.1 only supports Windows (x86 and x64).")
    endif()

    if(NOT (CMAKE_SIZEOF_VOID_P EQUAL 4 OR CMAKE_SIZEOF_VOID_P EQUAL 8))
        message(FATAL_ERROR "Unsupported pointer size: ${CMAKE_SIZEOF_VOID_P}.")
    endif()

    # CheckCXXSourceCompiles does not inherit target compile_features.
    # Native MSVC and GNU/Clang receive an explicit language-mode probe.
    # clang-cl's MSVC STL probe is skipped below because CMake's try-compile
    # does not consistently expose its C++23 feature macros.
    if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang" AND
       CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC")
        # clang-cl uses the MSVC STL, which gates C++23 facilities on
        # _MSVC_LANG; use the MSVC language-mode switch for the probe.
        set(CMAKE_REQUIRED_FLAGS "/std:c++latest /Zc:__cplusplus")
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        set(CMAKE_REQUIRED_FLAGS "-std=c++23")
    elseif(MSVC)
        set(CMAKE_REQUIRED_FLAGS "/std:c++latest /Zc:__cplusplus")
    else()
        set(CMAKE_REQUIRED_FLAGS "-std=c++23")
    endif()

    message(STATUS
        "C++23 library probe: ${CMAKE_CXX_COMPILER_ID} "
        "${CMAKE_CXX_COMPILER_VERSION} (${CMAKE_CXX_COMPILER_FRONTEND_VARIANT}); "
        "flags: ${CMAKE_REQUIRED_FLAGS}")
    unset(TESSERA_HAS_CPP23_FEATURES CACHE)

    if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang" AND
       CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC")
        # clang-cl's CMake try-compile does not consistently expose the MSVC
        # STL's C++23 feature macros even with /std:c++latest. The Windows
        # MSVC build matrix validates these standard-library facilities, and
        # the clang-cl coverage/tidy jobs still compile the actual project.
        set(TESSERA_HAS_CPP23_FEATURES TRUE)
        message(STATUS "Skipping C++23 library probe for clang-cl; MSVC build matrix is authoritative")
    else()
        check_cxx_source_compiles("
            #include <expected>
            #include <functional>
            #include <utility>
            #include <bit>
            #if !defined(__cpp_lib_expected) || __cpp_lib_expected < 202202L
            #error \"std::expected is required\"
            #endif
            #if !defined(__cpp_lib_move_only_function) || __cpp_lib_move_only_function < 202110L
            #error \"std::move_only_function is required\"
            #endif
            #if !defined(__cpp_lib_byteswap) || __cpp_lib_byteswap < 202110L
            #error \"std::byteswap is required\"
            #endif
            int main() {
                std::expected<int, int> e = 42;
                std::move_only_function<int()> f = [] { return 42; };
                return e.value_or(0) == 42 && f() == 42 && std::byteswap(0x01020304u) == 0x04030201u ? 0 : 1;
            }
        " TESSERA_HAS_CPP23_FEATURES)
    endif()

    if(NOT TESSERA_HAS_CPP23_FEATURES)
        message(FATAL_ERROR
            "Compiler does not support required C++23 library features "
            "(std::expected, std::move_only_function, std::byteswap). "
            "Compiler: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}; "
            "frontend: ${CMAKE_CXX_COMPILER_FRONTEND_VARIANT}; "
            "probe flags: ${CMAKE_REQUIRED_FLAGS}. "
            "Inspect CMakeFiles/CMakeConfigureLog.yaml for the failing compile command.")
    endif()
endfunction()

function(tessera_apply_target_options target_name)
    target_compile_features(${target_name} PUBLIC cxx_std_23)
    set_target_properties(${target_name} PROPERTIES
        CXX_EXTENSIONS OFF
        CXX_STANDARD_REQUIRED ON
    )

    if(TESSERA_STATIC_RUNTIME)
        set_property(TARGET ${target_name} PROPERTY
            MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    else()
        set_property(TARGET ${target_name} PROPERTY
            MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
    endif()

    if(MSVC)
        target_compile_options(${target_name} PRIVATE
            "$<$<COMPILE_LANGUAGE:CXX>:/W4>"
            "$<$<COMPILE_LANGUAGE:CXX>:/permissive->"
            "$<$<COMPILE_LANGUAGE:CXX>:/Zc:__cplusplus>"
            "$<$<COMPILE_LANGUAGE:CXX>:/Zc:inline>"
            /utf-8
            "$<$<COMPILE_LANGUAGE:CXX>:/EHsc>"
            /GS
            /sdl
            "$<$<COMPILE_LANGUAGE:CXX>:/wd4324>" # structure was padded due to alignment specifier
        )

        # This switch is specific to cl.exe; clang-cl diagnoses it as an
        # unused driver option, and warnings are errors in the fuzz build.
        if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
            target_compile_options(${target_name} PRIVATE
                "$<$<COMPILE_LANGUAGE:CXX>:/Zc:preprocessor>"
            )
        endif()

        # /guard:cf requires both compile and link flags
        if(NOT TESSERA_ENABLE_ASAN)
            target_compile_options(${target_name} PRIVATE /guard:cf)
            target_link_options(${target_name} PRIVATE /guard:cf)
        endif()

        if(TESSERA_WARNINGS_AS_ERRORS)
            target_compile_options(${target_name} PRIVATE "$<$<COMPILE_LANGUAGE:CXX>:/WX>")
        endif()

        if(TESSERA_ENABLE_ASAN)
            target_compile_options(${target_name} PRIVATE /fsanitize=address)
        endif()

        if(TESSERA_ENABLE_ANALYZE)
            target_compile_options(${target_name} PRIVATE "$<$<COMPILE_LANGUAGE:CXX>:/analyze>")
        endif()

        target_compile_definitions(${target_name} PRIVATE
            WIN32_LEAN_AND_MEAN
            NOMINMAX
            UNICODE
            _UNICODE
            _WIN32_WINNT=0x0A00
        )
    endif()
endfunction()
