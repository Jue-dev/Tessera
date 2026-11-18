#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "tessera/core/result.hpp"
#include "tessera/core/types.hpp"
#include "tessera/module/pe_image.hpp"
#include "tessera/process/process.hpp"
#include "tessera/reflection/reflection.hpp"

namespace tessera::rtti {

enum class PythonDeployment : std::uint8_t {
    None,            // Deployment mode is not established (not equivalent to no Python API)
    SharedLibrary,  // External pythonXX.dll imported or loaded
    StaticEmbedded, // CPython compiled statically directly into the .exe (no python*.dll)
};

enum class PythonFramework : std::uint8_t {
    Unknown,
    CPythonCAPI,
    PyBind11,
    BoostPython,
    Cython,
};

struct PythonEnvironmentInfo {
    PythonDeployment deployment = PythonDeployment::None;
    PythonFramework framework = PythonFramework::Unknown;
    std::string version_hint{};     // e.g. "2.7", "3.11", "3.x"
    std::string python_dll_name{};  // Empty when StaticEmbedded
    Address static_init_module_address{}; // Resolved Py_InitModule4 / PyModule_Create2 in .text
    std::vector<std::string> detected_fingerprints{};

    [[nodiscard]] constexpr bool is_present() const noexcept {
        // A framework can be structurally identified even when deployment
        // mode cannot be inferred (for example, when PE import metadata is absent).
        return deployment != PythonDeployment::None || framework != PythonFramework::Unknown;
    }
};

struct PyInittabEntry {
    std::string module_name{};
    Address init_function_address{};
    Rva init_function_rva{};
    Address entry_address{};
};

struct PyMethodEntry {
    std::string name{};
    Address cpp_function_address{};
    Rva cpp_function_rva{};
    std::uint32_t flags = 0; // METH_VARARGS (0x1), METH_KEYWORDS (0x2), METH_NOARGS (0x4), METH_O (0x8), etc.
    std::string doc{};
    Address entry_address{};
};

struct PyMethodTable {
    Address table_address{};
    Rva table_rva{};
    std::string inferred_module_name{};
    Address init_function_address{};
    Address register_call_target{}; // Callee in init function (e.g. static Py_InitModule4 / PyModule_Create2)
    std::vector<PyMethodEntry> methods{};
};

struct PyMemberEntry {
    std::string name{};
    std::int32_t type = 0; // CPython T_INT (1), T_FLOAT (3), T_OBJECT (6), etc.
    std::size_t offset = 0;
    std::int32_t flags = 0;
    std::string doc{};
    Address entry_address{};

    [[nodiscard]] std::size_t inferred_field_size(std::uint8_t ptr_size) const noexcept;
};

struct PyGetSetEntry {
    std::string name{};
    Address getter_address{};
    Address setter_address{};
    std::string doc{};
    Address closure{};
    Address entry_address{};
};

struct PyDiscoveredTypeObject {
    std::string type_name{};
    std::size_t basic_size = 0; // sizeof(C++ struct) from tp_basicsize
    std::size_t item_size = 0;
    Address type_object_address{};
    Address methods_table_address{};
    Address members_table_address{};
    Address getset_table_address{};
};

struct PythonBridgeCatalog {
    PythonEnvironmentInfo environment{};
    std::vector<PyInittabEntry> inittab_entries{};
    std::vector<PyMethodTable> method_tables{};
    std::vector<PyMemberEntry> member_entries{};
    std::vector<PyGetSetEntry> getset_entries{};
    std::vector<PyDiscoveredTypeObject> type_objects{};

    // Finds a Python-exposed C++ function by "module.func" or unqualified "func" name.
    [[nodiscard]] Result<PyMethodEntry> find_method(std::string_view name_or_qualified) const;

    // Exports all discovered Python modules, methods, and C++ struct layouts into TypeRegistry.
    [[nodiscard]] Status export_to_registry(reflection::TypeRegistry& registry) const;
};

// Discovers C++/Python bindings (CPython C-API, PyBind11, Boost.Python, Cython) in both
// DLL-based and Statically-Embedded (.exe without python.dll) C++ binaries.
class PythonBridgeScanner {
public:
    [[nodiscard]] static Result<PythonEnvironmentInfo> detect_environment(
        const Process& process,
        AddressRange module_range,
        const PeImage* pe = nullptr);

    [[nodiscard]] static Result<std::vector<PyInittabEntry>> scan_inittab(
        const Process& process,
        AddressRange module_range);

    [[nodiscard]] static Result<std::vector<PyMethodTable>> scan_method_tables(
        const Process& process,
        AddressRange module_range);

    // Links unnamed PyMethodDef tables to their Python module name and static init functions via .text xrefs.
    static void link_tables_to_modules(const Process& process,
                                       AddressRange module_range,
                                       std::span<PyMethodTable> tables,
                                       std::span<const PyInittabEntry> inittab = {},
                                       Address* out_static_init_module = nullptr);

    [[nodiscard]] static Result<std::vector<PyMemberEntry>> scan_member_tables(
        const Process& process,
        AddressRange module_range);

    [[nodiscard]] static Result<std::vector<PyGetSetEntry>> scan_getset_tables(
        const Process& process,
        AddressRange module_range);

    [[nodiscard]] static Result<std::vector<PyDiscoveredTypeObject>> scan_type_objects(
        const Process& process,
        AddressRange module_range);

    [[nodiscard]] static Result<PythonBridgeCatalog> discover_all(
        const Process& process,
        AddressRange module_range,
        const PeImage* pe = nullptr);
};

} // namespace tessera::rtti
