cmake_minimum_required(VERSION 3.28)
project(TesseraInstalledConsumer LANGUAGES CXX)

find_package(Tessera CONFIG REQUIRED)
add_executable(tessera_installed_consumer ../standalone_consumer.cpp)
target_link_libraries(tessera_installed_consumer PRIVATE tessera::tessera)
target_compile_definitions(tessera_installed_consumer PRIVATE
    TESSERA_STANDALONE_SDK_CONSUMER=1
    TESSERA_CONSUMER_WITH_PROFILE=1
    TESSERA_CONSUMER_WITH_TARGETS=1
)
