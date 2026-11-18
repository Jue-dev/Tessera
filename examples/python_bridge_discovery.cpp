#include "tessera/tessera.hpp"

#include <cstdint>
#include <iostream>

namespace {

// Sample C++ callbacks that would be exposed to an embedded Python interpreter
void* py_net_SendChatPacket(void*, void*) { return nullptr; }
void* py_net_GetServerInfo(void*, void*) { return nullptr; }

struct PyMethodDefLayout {
    const char* ml_name;
    void* (*ml_meth)(void*, void*);
    std::uint32_t ml_flags;
    std::uint32_t ml_pad;
    const char* ml_doc;
};

struct PyMemberDefLayout {
    const char* name;
    std::int32_t type;
    std::int32_t pad0;
    std::size_t offset;
    std::int32_t flags;
    std::int32_t pad1;
    const char* doc;
};

// Static CPython fingerprint + embedded tables right inside our .rdata/.data sections
// (demonstrating discovery when Python is compiled directly into the .exe without pythonXX.dll!)
alignas(16) const char kStaticPyFingerprint[] = "builtin_function_or_method";

alignas(16) const PyMethodDefLayout kEmbeddedNetMethods[] = {
    {"SendChatPacket", &py_net_SendChatPacket, 0x0001u /* METH_VARARGS */, 0u, "Send chat packet"},
    {"GetServerInfo", &py_net_GetServerInfo, 0x0004u /* METH_NOARGS */, 0u, "Get server info"},
    {nullptr, nullptr, 0u, 0u, nullptr},
};

alignas(16) const PyMemberDefLayout kEmbeddedActorMembers[] = {
    {"health", 1 /* T_INT */, 0, 0x24, 0, 0, "Actor health"},
    {"move_speed", 3 /* T_FLOAT */, 0, 0x28, 0, 0, "Movement speed"},
    {nullptr, 0, 0, 0, 0, 0, nullptr},
};

} // namespace

int main() {
    using namespace tessera;
    using namespace tessera::rtti;

    // Reference static data so the linker keeps it in the binary
    (void)kStaticPyFingerprint[0];
    (void)kEmbeddedNetMethods[0].ml_name;
    (void)kEmbeddedActorMembers[0].name;

    std::cout << "=== Tessera Example 05: Static/Embedded & DLL C++/Python Bridge Discovery ===\n\n";

    const Process proc = Process::current();
    auto main_mod = ModuleCatalog::main_module(proc);
    if (!main_mod.has_value()) {
        return 1;
    }

    auto py_cat = PythonBridgeScanner::discover_all(proc, main_mod->range());
    if (!py_cat.has_value()) {
        std::cout << "Python scan failed.\n";
        return 1;
    }

    std::cout << "[Python Env]  Deployment: "
              << (py_cat->environment.deployment == PythonDeployment::StaticEmbedded
                      ? "StaticEmbedded (No pythonXX.dll required!)"
                  : py_cat->environment.deployment == PythonDeployment::SharedLibrary
                      ? "SharedLibrary (DLL)"
                      : "None")
              << "\n";

    std::cout << "[MethodDef]   Discovered " << py_cat->method_tables.size()
              << " PyMethodDef table(s):\n";
    for (const auto& tbl : py_cat->method_tables) {
        for (const auto& m : tbl.methods) {
            std::cout << "              - " << m.name << " -> C++ Function @ "
                      << hex::format_u64(m.cpp_function_address.value()) << " (RVA "
                      << hex::format_u64(m.cpp_function_rva.value()) << ")\n";
        }
    }

    std::cout << "[MemberDef]   Discovered " << py_cat->member_entries.size()
              << " non-virtual C++ struct field binding(s):\n";
    for (const auto& mem : py_cat->member_entries) {
        std::cout << "              - field '" << mem.name << "' at struct offset +0x" << std::hex
                  << mem.offset << std::dec << "\n";
    }

    // Export discovered Python bindings into Tessera's unified TypeRegistry
    reflection::TypeRegistry reg{};
    (void)py_cat->export_to_registry(reg);
    std::cout << "[Registry]    Exported " << reg.all_types().size()
              << " Python module/struct type(s) to TypeRegistry.\n";

    return 0;
}
