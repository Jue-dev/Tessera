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

// Demangles MSVC RTTI type names (e.g. ".?AVPlayer@Game@@" -> "Game::Player").
[[nodiscard]] std::string demangle_msvc_symbol(std::string_view mangled);

// MSVC Pointer-to-Member Data (PMD) displacement descriptor used for base sub-object casting.
struct MsvcPmd {
    std::int32_t mdisp = 0;  // Member displacement (static byte offset)
    std::int32_t pdisp = -1; // Vbtable displacement (-1 if not a virtual base)
    std::int32_t vdisp = 0;  // Displacement inside vbtable
};

struct RttiBaseEntry {
    std::string mangled_name{};
    std::string demangled_name{};
    reflection::TypeId type_id{};
    MsvcPmd pmd{};
    std::uint32_t num_contained_bases = 0;
    std::uint32_t attributes = 0;
    Address type_descriptor_address{};

    [[nodiscard]] constexpr bool is_virtual_base() const noexcept { return pmd.pdisp >= 0; }
};

struct RttiClassDescriptor {
    std::string mangled_name{};
    std::string demangled_name{};
    reflection::TypeId type_id{};
    Address vftable_address{};
    Rva vftable_rva{};
    Address col_address{};
    Address type_descriptor_address{};
    Address chd_address{};
    std::uint32_t offset = 0;    // Sub-object offset of this vftable inside the complete object
    std::uint32_t cd_offset = 0; // Construction displacement offset
    std::uint32_t chd_attributes = 0;
    std::vector<Address> virtual_methods{};
    std::vector<RttiBaseEntry> base_classes{};

    [[nodiscard]] constexpr bool is_multiple_inheritance() const noexcept {
        return (chd_attributes & 0x01u) != 0;
    }

    // CHD_VIRTINH (0x02) describes virtual inheritance in a branching hierarchy;
    // it is not set by every MSVC-ABI producer for a simple single virtual base.
    [[nodiscard]] constexpr bool has_virtual_branching_hierarchy() const noexcept {
        return (chd_attributes & 0x02u) != 0;
    }

    // PMD.pdisp is -1 for non-virtual bases and identifies the vbptr displacement
    // for virtual bases. Prefer this concrete per-base metadata when answering
    // whether this class has any virtual base, while preserving the CHD flag as
    // a fallback for partially available hierarchy metadata.
    [[nodiscard]] constexpr bool has_virtual_base_classes() const noexcept {
        for (const auto& base : base_classes) {
            if (base.is_virtual_base()) {
                return true;
            }
        }
        return false;
    }

    [[nodiscard]] constexpr bool is_virtual_inheritance() const noexcept {
        return has_virtual_branching_hierarchy() || has_virtual_base_classes();
    }
};

// Discovers and indexes all polymorphic C++ classes, vtables, and inheritance trees in a module.
class RttiCatalog {
public:
    RttiCatalog() = default;

    [[nodiscard]] static Result<RttiCatalog> discover_all(const Process& process,
                                                          AddressRange module_range,
                                                          const PeImage* pe = nullptr);

    [[nodiscard]] static Result<RttiClassDescriptor> inspect_vftable(const Process& process,
                                                                     AddressRange module_range,
                                                                     Address vftable_address);

    [[nodiscard]] std::span<const RttiClassDescriptor> classes() const noexcept {
        return classes_;
    }

    [[nodiscard]] Result<RttiClassDescriptor> find_class(std::string_view name_or_mangled) const;

    [[nodiscard]] std::vector<RttiClassDescriptor> find_all_vftables(
        std::string_view name_or_mangled) const;

    [[nodiscard]] std::vector<RttiClassDescriptor> search_classes(std::string_view query) const;

    [[nodiscard]] std::vector<RttiClassDescriptor> root_classes() const;

    [[nodiscard]] std::vector<RttiClassDescriptor> derived_from(
        std::string_view base_name_or_mangled) const;

    [[nodiscard]] Result<RttiClassDescriptor> identify_instance(const Process& process,
                                                                Address instance_addr) const;

    // Safely adjusts an instance pointer to a base or complete class using MSVC PMD rules.
    [[nodiscard]] Result<Address> cast_to(const Process& process,
                                          Address instance_addr,
                                          std::string_view target_class_name) const;

    // Exports all discovered RTTI classes, base hierarchies, and virtual methods into TypeRegistry.
    [[nodiscard]] Status export_to_registry(reflection::TypeRegistry& registry) const;

private:
    Address module_base_{};
    std::vector<RttiClassDescriptor> classes_{};
};

} // namespace tessera::rtti
