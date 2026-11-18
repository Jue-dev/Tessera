cmake_minimum_required(VERSION 3.28)

function(tessera_add_example target_name source_file)
    add_executable(${target_name} ${source_file})
    target_link_libraries(${target_name} PRIVATE tessera::tessera)
    tessera_apply_target_options(${target_name})
endfunction()

tessera_add_example(tessera_example_01_scan_and_pe          basic_scan_and_resolve.cpp)
tessera_add_example(tessera_example_02_patch_and_hook       memory_patch_and_hook.cpp)
tessera_add_example(tessera_example_03_rtti_and_reflection  rtti_and_object_view.cpp)
tessera_add_example(tessera_example_04_blind_discovery      blind_binary_discovery.cpp)
tessera_add_example(tessera_example_05_python_bridge        python_bridge_discovery.cpp)
tessera_add_example(tessera_example_06_profiles_and_targets profiles_and_targets_workflow.cpp)
