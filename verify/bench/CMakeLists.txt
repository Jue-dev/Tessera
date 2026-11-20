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
