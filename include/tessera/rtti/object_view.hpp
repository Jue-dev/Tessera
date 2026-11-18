#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

#include "tessera/core/result.hpp"
#include "tessera/core/types.hpp"
#include "tessera/memory/memory_reader.hpp"
#include "tessera/memory/memory_writer.hpp"
#include "tessera/process/process.hpp"
#include "tessera/reflection/reflection.hpp"

namespace tessera::rtti {

// Unified view over a C++ object in process memory (supports both non-virtual structs and polymorphic classes).
class ObjectView {
public:
    ObjectView(const Process& process, Address base_address, reflection::TypeInfo type_info) noexcept
        : process_(&process), base_(base_address), type_(std::move(type_info)) {}

    [[nodiscard]] Address address() const noexcept { return base_; }
    [[nodiscard]] const reflection::TypeInfo& type() const noexcept { return type_; }

    [[nodiscard]] Result<Address> field_address(std::string_view field_name) const noexcept {
        const auto* f = type_.find_field(field_name);
        if (f == nullptr) {
            return fail(ErrorCode::NotFound, "ObjectView::field_address", 0, "Field not found in TypeInfo");
        }
        return base_.offset(static_cast<std::int64_t>(f->offset));
    }

    template <TriviallyReadable T>
    [[nodiscard]] Result<T> read_field(std::string_view field_name) const noexcept {
        const auto* f = type_.find_field(field_name);
        if (f == nullptr) {
            return fail(ErrorCode::NotFound, "ObjectView::read_field", 0, "Field not found in TypeInfo");
        }
        if (sizeof(T) > f->size && f->size != 0) {
            return fail(ErrorCode::InvalidArgument,
                        "ObjectView::read_field",
                        0,
                        "Requested type size exceeds reflected field size");
        }
        auto addr = base_.offset(static_cast<std::int64_t>(f->offset));
        if (!addr) {
            return std::unexpected(addr.error());
        }
        MemoryReader reader{*process_};
        return reader.read<T>(*addr);
    }

    template <TriviallyReadable T>
    [[nodiscard]] Status write_field(std::string_view field_name, const T& value) const noexcept {
        const auto* f = type_.find_field(field_name);
        if (f == nullptr) {
            return fail(ErrorCode::NotFound, "ObjectView::write_field", 0, "Field not found in TypeInfo");
        }
        if (sizeof(T) > f->size && f->size != 0) {
            return fail(ErrorCode::InvalidArgument,
                        "ObjectView::write_field",
                        0,
                        "Written type size exceeds reflected field size");
        }
        auto addr = base_.offset(static_cast<std::int64_t>(f->offset));
        if (!addr) {
            return std::unexpected(addr.error());
        }
        MemoryWriter writer{*process_};
        return writer.write_value<T>(*addr, value);
    }

    [[nodiscard]] Result<std::uint64_t> read_bitfield(std::string_view field_name) const noexcept {
        const auto* f = type_.find_field(field_name);
        if (f == nullptr || !has_flag(f->flags, reflection::FieldFlags::Bitfield) ||
            f->bit_width == 0 || f->bit_width > 64) {
            return fail(ErrorCode::InvalidArgument, "ObjectView::read_bitfield");
        }
        auto addr = base_.offset(static_cast<std::int64_t>(f->offset));
        if (!addr) {
            return std::unexpected(addr.error());
        }
        MemoryReader reader{*process_};
        std::uint64_t raw = 0;
        if (f->size == 1) {
            auto v = reader.read<std::uint8_t>(*addr);
            if (!v) return std::unexpected(v.error());
            raw = *v;
        } else if (f->size == 2) {
            auto v = reader.read<std::uint16_t>(*addr);
            if (!v) return std::unexpected(v.error());
            raw = *v;
        } else if (f->size == 4) {
            auto v = reader.read<std::uint32_t>(*addr);
            if (!v) return std::unexpected(v.error());
            raw = *v;
        } else if (f->size == 8) {
            auto v = reader.read<std::uint64_t>(*addr);
            if (!v) return std::unexpected(v.error());
            raw = *v;
        } else {
            return fail(ErrorCode::InvalidArgument, "ObjectView::read_bitfield");
        }
        const std::uint64_t mask =
            (f->bit_width == 64) ? ~0ULL : ((1ULL << f->bit_width) - 1ULL);
        return (raw >> f->bit_offset) & mask;
    }

    // Resolves a sub-object view for a base class (supports both static and virtual base offsets).
    [[nodiscard]] Result<ObjectView> base_subobject(const reflection::TypeRegistry& registry,
                                                    std::string_view base_name) const {
        const auto base_id = reflection::TypeId::from_name(base_name);
        const auto* b = type_.find_base(base_id);
        if (b == nullptr) {
            return fail(ErrorCode::NotFound, "ObjectView::base_subobject", 0, "Base class not found");
        }
        auto base_type_res = registry.find(base_id);
        if (!base_type_res) {
            return std::unexpected(base_type_res.error());
        }

        Address sub_addr{};
        if (!b->is_virtual && b->pdisp < 0) {
            auto a = base_.offset(b->offset);
            if (!a) return std::unexpected(a.error());
            sub_addr = *a;
        } else {
            // MSVC virtual base PMD resolution: *(*(int32_t**)((char*)this + pdisp) + vdisp) + mdisp
            MemoryReader reader{*process_};
            auto vbptr_loc = base_.offset(b->pdisp);
            if (!vbptr_loc) return std::unexpected(vbptr_loc.error());
            auto vbtable_addr = reader.read_pointer(*vbptr_loc);
            if (!vbtable_addr) return std::unexpected(vbtable_addr.error());
            auto vdisp_loc = vbtable_addr->offset(b->vdisp);
            if (!vdisp_loc) return std::unexpected(vdisp_loc.error());
            auto vbase_delta = reader.read<std::int32_t>(*vdisp_loc);
            if (!vbase_delta) return std::unexpected(vbase_delta.error());
            auto final_addr = vbptr_loc->offset(static_cast<std::int64_t>(*vbase_delta) + b->mdisp);
            if (!final_addr) return std::unexpected(final_addr.error());
            sub_addr = *final_addr;
        }
        return ObjectView{*process_, sub_addr, std::move(*base_type_res)};
    }

    // Resolves either a virtual method (by reading the live vptr + vtable_index) or a non-virtual/Python method.
    [[nodiscard]] Result<Address> resolve_method(std::string_view method_name,
                                                 Address module_base = {}) const noexcept {
        const auto* m = type_.find_method(method_name);
        if (m == nullptr) {
            return fail(ErrorCode::NotFound, "ObjectView::resolve_method", 0, "Method not found");
        }
        if (m->kind == reflection::MethodKind::Virtual && m->vtable_index.has_value()) {
            MemoryReader reader{*process_};
            auto vptr = reader.read_pointer(base_);
            if (!vptr || vptr->is_null()) {
                return fail(ErrorCode::NullAddress, "ObjectView::resolve_method", 0, "Null vptr");
            }
            const std::size_t slot_off = (*m->vtable_index) * process_->pointer_size();
            auto slot_addr = vptr->offset(static_cast<std::int64_t>(slot_off));
            if (!slot_addr) {
                return std::unexpected(slot_addr.error());
            }
            return reader.read_pointer(*slot_addr);
        }
        if (!m->address.is_null()) {
            return m->address;
        }
        if (m->rva.value() != 0 && !module_base.is_null()) {
            return module_base.add_rva(m->rva);
        }
        return fail(ErrorCode::NotFound, "ObjectView::resolve_method", 0, "Method has no resolved address");
    }

private:
    const Process* process_ = nullptr;
    Address base_{};
    reflection::TypeInfo type_{};
};

} // namespace tessera::rtti
