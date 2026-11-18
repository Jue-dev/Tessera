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
#include "tessera/rtti/rtti.hpp"

namespace tessera::rtti {

enum class DiscoveredTypeKind : std::uint8_t {
    Class,  // .?AV
    Struct, // .?AU
    Enum,   // .?AW4
    Union,  // .?AT
};

struct DiscoveredTypeDescriptor {
    std::string mangled_name{};
    std::string demangled_name{};
    DiscoveredTypeKind kind = DiscoveredTypeKind::Class;
    reflection::TypeId type_id{};
    Address descriptor_address{};
    Rva descriptor_rva{};
    bool has_vtable = false;
};

struct DiscoveredString {
    std::string value{};
    Address address{};
    Rva rva{};
    bool is_utf16 = false;
    bool is_source_path = false;
    std::vector<Address> code_xrefs{};
};

struct DiscoveredFunction {
    Address address{};
    Rva rva{};
    std::uint32_t size = 0;
    bool from_pdata = false;
    std::vector<Address> callees{};
    std::vector<Address> callers{};
    std::vector<std::string> referenced_strings{};
    std::string associated_class{};
};

enum class InferredFieldKind : std::uint8_t {
    Unknown,
    UInt8,
    Int32,
    Float32,
    UInt64OrPointer,
    VTablePointer,
};

struct InferredField {
    std::size_t offset = 0;
    std::size_t size = 4;
    InferredFieldKind kind = InferredFieldKind::Int32;
    std::size_t access_count = 1;
    bool is_read = false;
    bool is_written = false;
};

struct ReconstructedStruct {
    std::string name_hint{};
    std::size_t estimated_size = 0;
    std::vector<InferredField> fields{};

    [[nodiscard]] reflection::TypeInfo to_type_info() const;
};

struct DiscoveredInstance {
    Address instance_address{};
    Address vftable_address{};
    std::string class_name{};
    reflection::TypeId type_id{};
};

enum class MemorySlotKind : std::uint8_t {
    Zero,
    Integer32,
    Float32,
    PointerToCode,
    PointerToData,
    PointerToAsciiString,
    VTableInstance,
};

struct DissectedSlot {
    std::size_t offset = 0;
    std::uint64_t raw_u64 = 0;
    std::int32_t i32_value = 0;
    float f32_value = 0.0f;
    MemorySlotKind kind = MemorySlotKind::Zero;
    std::string resolved_class_name{};
    std::string string_preview{};
};

// Blind / Exploratory Discovery Engine for analyzing unknown C++ binaries (both virtual and non-virtual).
class BinaryExplorer {
public:
    // Finds all MSVC TypeDescriptors (.?AV, .?AU, .?AW4, .?AT), including non-virtual structs/enums without vtables.
    [[nodiscard]] static Result<std::vector<DiscoveredTypeDescriptor>> scan_all_type_descriptors(
        const Process& process,
        AddressRange module_range,
        const RttiCatalog* known_vtable_catalog = nullptr);

    // Catalogs ASCII and UTF-16 strings, detects source path hints (.cpp/.h), and optionally finds code xrefs.
    [[nodiscard]] static Result<std::vector<DiscoveredString>> scan_strings(
        const Process& process,
        AddressRange module_range,
        std::size_t min_length = 4,
        bool resolve_code_xrefs = false);

    // Discovers non-virtual and virtual functions using .pdata (PE32+) and E8 rel32 call target analysis.
    [[nodiscard]] static Result<std::vector<DiscoveredFunction>> discover_functions(
        const Process& process,
        AddressRange module_range,
        const PeImage* pe = nullptr);

    // Reconstructs a non-virtual/virtual struct layout by analyzing [rcx/ecx + disp] instructions in a function.
    [[nodiscard]] static Result<ReconstructedStruct> reconstruct_struct(
        const Process& process,
        AddressRange function_range,
        std::string_view name_hint = "InferredStruct");

    // Scans memory for live object instances whose vtable pointer matches a class in RttiCatalog.
    [[nodiscard]] static Result<std::vector<DiscoveredInstance>> find_instances(
        const Process& process,
        AddressRange search_range,
        const RttiCatalog& catalog,
        std::string_view class_filter = {});

    // ReClass-style memory dissection classifying pointers, vtables, strings, floats, and integers.
    [[nodiscard]] static Result<std::vector<DissectedSlot>> dissect_memory(
        const Process& process,
        AddressRange module_range,
        Address object_address,
        std::size_t byte_count = 128,
        const RttiCatalog* catalog = nullptr);
};

} // namespace tessera::rtti
