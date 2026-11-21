cmake_minimum_required(VERSION 3.28)

add_executable(tessera_bench scanner_bench.cpp)
target_include_directories(tessera_bench PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../tests/support"
    "${PROJECT_SOURCE_DIR}/src"
)
target_link_libraries(tessera_bench PRIVATE tessera::tessera)
tessera_apply_target_options(tessera_bench)

add_executable(tessera_decoder_bench decoder_bench.cpp)
target_include_directories(tessera_decoder_bench PRIVATE "${PROJECT_SOURCE_DIR}/src")
target_link_libraries(tessera_decoder_bench PRIVATE tessera::tessera)
tessera_apply_target_options(tessera_decoder_bench)

add_executable(tessera_pe_bench pe_bench.cpp)
target_link_libraries(tessera_pe_bench PRIVATE tessera::tessera)
tessera_apply_target_options(tessera_pe_bench)


add_executable(tessera_json_bench json_bench.cpp)
target_link_libraries(tessera_json_bench PRIVATE tessera::tessera)
tessera_apply_target_options(tessera_json_bench)

add_executable(tessera_rtti_discovery_bench rtti_discovery_bench.cpp)
target_link_libraries(tessera_rtti_discovery_bench PRIVATE tessera::tessera)
target_include_directories(tessera_rtti_discovery_bench PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../tests/support
)
tessera_apply_target_options(tessera_rtti_discovery_bench)

if(TESSERA_BUILD_TESTS)
    add_test(NAME tessera_bench_scanner_smoke COMMAND tessera_bench)
    add_test(NAME tessera_bench_decoder_smoke COMMAND tessera_decoder_bench)
    add_test(NAME tessera_bench_pe_smoke COMMAND tessera_pe_bench)
    add_test(NAME tessera_bench_json_smoke COMMAND tessera_json_bench)
    add_test(NAME tessera_bench_rtti_discovery_smoke COMMAND tessera_rtti_discovery_bench)
endif()
