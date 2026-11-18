cmake_minimum_required(VERSION 3.28)

if(TESSERA_BUILD_TESTS)
    add_subdirectory(tests)
endif()

if(TESSERA_BUILD_BENCH)
    add_subdirectory(bench)
endif()

if(TESSERA_BUILD_FUZZ)
    add_subdirectory(fuzz)
endif()
