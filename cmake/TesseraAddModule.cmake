include_guard(GLOBAL)

include(GNUInstallDirs)
include("${CMAKE_CURRENT_LIST_DIR}/TesseraCompilerOptions.cmake")

# Global property tracking all enabled Tessera module targets, object files, and system libs
set_property(GLOBAL PROPERTY TESSERA_MODULE_TARGETS "")
set_property(GLOBAL PROPERTY TESSERA_MODULE_OBJECTS "")
set_property(GLOBAL PROPERTY TESSERA_MODULE_SYSTEM_LIBS "")
set_property(GLOBAL PROPERTY TESSERA_PUBLIC_HEADERS "")

function(tessera_add_module)
    set(options "")
    set(oneValueArgs NAME EXPORT_NAME)
    set(multiValueArgs SOURCES PUBLIC_HEADERS PUBLIC_DEPS PRIVATE_DEPS SYSTEM_LIBS PRIVATE_DEFS PUBLIC_DEFS)
    cmake_parse_arguments(MOD "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    if(NOT MOD_NAME)
        message(FATAL_ERROR "tessera_add_module requires NAME")
    endif()

    set(target_name "tessera_${MOD_NAME}")
    if(MOD_EXPORT_NAME)
        set(export_name "${MOD_EXPORT_NAME}")
    else()
        set(export_name "${MOD_NAME}")
    endif()

    add_library(${target_name} OBJECT ${MOD_SOURCES} ${MOD_PUBLIC_HEADERS})
    add_library(tessera::${export_name} ALIAS ${target_name})

    set_target_properties(${target_name} PROPERTIES
        EXPORT_NAME "${export_name}"
    )

    target_include_directories(${target_name}
        PUBLIC
            $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        PRIVATE
            ${PROJECT_SOURCE_DIR}/src
    )

    tessera_apply_target_options(${target_name})

    if(MOD_PUBLIC_DEPS)
        target_link_libraries(${target_name} PUBLIC ${MOD_PUBLIC_DEPS})
    endif()

    if(MOD_PRIVATE_DEPS)
        target_link_libraries(${target_name} PRIVATE ${MOD_PRIVATE_DEPS})
    endif()

    if(MOD_SYSTEM_LIBS)
        target_link_libraries(${target_name} PUBLIC ${MOD_SYSTEM_LIBS})
        set_property(GLOBAL APPEND PROPERTY TESSERA_MODULE_SYSTEM_LIBS ${MOD_SYSTEM_LIBS})
    endif()

    if(MOD_PRIVATE_DEFS)
        target_compile_definitions(${target_name} PRIVATE ${MOD_PRIVATE_DEFS})
    endif()

    if(MOD_PUBLIC_DEFS)
        target_compile_definitions(${target_name} PUBLIC ${MOD_PUBLIC_DEFS})
    endif()

    set_property(GLOBAL APPEND PROPERTY TESSERA_MODULE_TARGETS "${target_name}")
    set_property(GLOBAL APPEND PROPERTY TESSERA_MODULE_OBJECTS "$<TARGET_OBJECTS:${target_name}>")
    if(MOD_PUBLIC_HEADERS)
        set_property(GLOBAL APPEND PROPERTY TESSERA_PUBLIC_HEADERS ${MOD_PUBLIC_HEADERS})
    endif()
endfunction()
