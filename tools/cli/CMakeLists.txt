if(NOT TESSERA_BUILD_TARGETS)
    message(FATAL_ERROR "TESSERA_BUILD_CLI requires TESSERA_BUILD_TARGETS=ON")
endif()
add_executable(tessera_cli main.cpp)
set_target_properties(tessera_cli PROPERTIES OUTPUT_NAME tessera)
target_link_libraries(tessera_cli PRIVATE tessera::tessera)
if(TESSERA_BUILD_TESTS)
    add_test(NAME tessera_cli_smoke
        COMMAND pwsh -NoProfile -ExecutionPolicy Bypass
            -File "${PROJECT_SOURCE_DIR}/tools/cli/cli_smoke.ps1"
            -CliPath "$<TARGET_FILE:tessera_cli>"
            -FixturePath "${PROJECT_SOURCE_DIR}/verify/tests/fixtures/rtti_virtual_branch_x64.dll"
            -ProfilePath "${PROJECT_SOURCE_DIR}/verify/tests/fixtures/cli_profile.json")
    set_tests_properties(tessera_cli_smoke PROPERTIES LABELS "cli;integration")
endif()
