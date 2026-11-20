cmake_minimum_required(VERSION 3.28)

add_executable(tessera_bench scanner_bench.cpp)
target_include_directories(tessera_bench PRIVATE\n    "${CMAKE_CURRENT_SOURCE_DIR}/../tests/support"\n    "${PROJECT_SOURCE_DIR}/src"\n)
target_link_libraries(tessera_bench PRIVATE tessera::tessera)
tessera_apply_target_options(tessera_bench)
