#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string_view>
#include <utility>

#include "tessera/core/checked_math.hpp"
#include "tessera/core/result.hpp"
#include "tessera/core/types.hpp"
#include "tessera/memory/memory_reader.hpp"
#include "tessera/memory/memory_writer.hpp"
#include "tessera/process/process.hpp"
#include "tessera/reflection/reflection.hpp"

namespace tessera::rtti {

// Unified view over an object in process memory. The Process is retained by value
// so the view does not depend on the lifetime of the caller's Process variable.
class ObjectView {
public:
    ObjectView(const Process& process, Address base_address, reflection::TypeInfo type_info) noexcept
        : process_(process), base_(base_address), type_(std::move(type_info)) {}

    [[nodiscard]] Address address() const noexcept { return base_; }
    [[nodiscard]] const reflection::TypeInfo& type() const noexcept { return type_; }

    [[nodiscard]] Result<Address> field_address(std::string_view field_name) const noexcept {
        const auto* f = type_.find_field(field_name);
        if (f == nullptr) {
            return fail(ErrorCode::NotFound, "ObjectView::field_address", 0, "Field not found in TypeInfo");
        }
        if (!field_in_bounds(*f)) {
            return fail(ErrorCode::OutOfRange, "ObjectView::field_address", 0,
                        "Reflected field lies outside the object size");
        }
        auto offset = checked_offset<std::uint64_t>(base_.value(), static_cast<std::int64_t>(f->offset));
        if (!offset) {
            return std::unexpected(offset.error());
        }
        return Address{*offset};
    }

    template <TriviallyReadable T>
    [[nodiscard]] Result<T> read_field(std::string_view field_name) const noexcept {
        const auto* f = type_.find_field(field_name);
        if (f == nullptr) {
            return fail(ErrorCode::NotFound, "ObjectView::read_field", 0, "Field not found in TypeInfo");
        }
        if (!field_in_bounds(*f) || sizeof(T) > f->size) {
            return fail(ErrorCode::InvalidArgument,
                        "ObjectView::read_field",
                        0,
                        "Requested type size exceeds reflected field or object bounds");
        }
        auto addr = field_address(field_name);
        if (!addr) {
            return std::unexpected(addr.error());
        }
        return MemoryReader{process_}.read<T>(*addr);
    }

    template <TriviallyReadable T>
    [[nodiscard]] Status write_field(std::string_view field_name, const T& value) const noexcept {
        const auto* f = type_.find_field(field_name);
        if (f == nullptr) {
            return fail(ErrorCode::NotFound, "ObjectView::write_field", 0, "Field not found in TypeInfo");
        }
        if (!field_in_bounds(*f) || sizeof(T) > f->size) {
            return fail(ErrorCode::InvalidArgument,
                        "ObjectView::write_field",
                        0,
                        "Written type size exceeds reflected field or object bounds");
        }
        auto addr = field_address(field_name);
        if (!addr) {
            return std::unexpected(addr.error());
        }
        return MemoryWriter{process_}.write_value<T>(*addr, value);
    }

    [[nodiscard]] Result<std::uint64_t> read_bitfield(std::string_view field_name) const noexcept {
        const auto* f = type_.find_field(field_name);
        if (f == nullptr || !has_flag(f->flags, reflection::FieldFlags::Bitfield) ||
            f->bit_width == 0 || f->bit_width > 64 ||
            (f->size != 1 && f->size != 2 && f->size != 4 && f->size != 8) ||
            f->bit_offset >= f->size * 8 || f->bit_width > f->size * 8 - f->bit_offset ||
            !field_in_bounds(*f)) {
            return fail(ErrorCode::InvalidArgument,
                        "ObjectView::read_bitfield",
                        0,
                        "Invalid bitfield metadata or bit range");
        }
        auto addr = field_address(field_name);
        if (!addr) {
            return std::unexpected(addr.error());
        }

        MemoryReader reader{process_};
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
        } else {
            auto v = reader.read<std::uint64_t>(*addr);
            if (!v) return std::unexpected(v.error());
            raw = *v;
        }
        const std::uint64_t mask =
            (f->bit_width == 64) ? ~0ULL : ((1ULL << f->bit_width) - 1ULL);
        return (raw >> f->bit_offset) & mask;
    }

    // Resolves a sub-object view for a base class (supports static and MSVC virtual base offsets).
    [[nodiscard]] Result<ObjectView> base_subobject(const reflection::TypeRegistry& registry,
                                                    std::string_view base_name) const {
        const auto requested_id = reflection::TypeId::from_name(base_name);
        const auto* b = type_.find_base(requested_id);
        if (b == nullptr) {
            return fail(ErrorCode::NotFound, "ObjectView::base_subobject", 0, "Base class not found");
        }
        const reflection::TypeId base_id = b->base_type.valid() ? b->base_type : requested_id;
        auto base_type_res = registry.find(base_id);
        if (!base_type_res) {
            return std::unexpected(base_type_res.error());
        }

        Address sub_addr{};
        if (!b->is_virtual) {
            auto a = base_.offset(static_cast<std::int64_t>(b->offset));
            if (!a) return std::unexpected(a.error());
            sub_addr = *a;
        } else {
            // MSVC PMD: this + mdisp + *(vbtable + vdisp).
            // pdisp locates the vbptr and is not part of the final base address.
            if (b->pdisp < 0 || b->vdisp < 0) {
                return fail(ErrorCode::InvalidArgument,
                            "ObjectView::base_subobject",
                            0,
                            "Virtual-base PMD is missing a valid vbptr or vbtable offset");
            }
            MemoryReader reader{process_};
            auto vbptr_loc = base_.offset(b->pdisp);
            if (!vbptr_loc) return std::unexpected(vbptr_loc.error());
            auto vbtable_addr = reader.read_pointer(*vbptr_loc);
            if (!vbtable_addr) return std::unexpected(vbtable_addr.error());
            auto vdisp_loc = vbtable_addr->offset(b->vdisp);
            if (!vdisp_loc) return std::unexpected(vdisp_loc.error());
            auto vbase_delta = reader.read<std::int32_t>(*vdisp_loc);
            if (!vbase_delta) return std::unexpected(vbase_delta.error());
            const std::int64_t final_delta =
                static_cast<std::int64_t>(*vbase_delta) + static_cast<std::int64_t>(b->mdisp);
            auto final_addr = base_.offset(final_delta);
            if (!final_addr) return std::unexpected(final_addr.error());
            sub_addr = *final_addr;
        }
        return ObjectView{process_, sub_addr, std::move(*base_type_res)};
    }

    // Resolves either a virtual method (live vptr + slot) or a recorded method address/RVA.
    [[nodiscard]] Result<Address> resolve_method(std::string_view method_name,
                                                 Address module_base = {}) const noexcept {
        const auto* m = type_.find_method(method_name);
        if (m == nullptr) {
            return fail(ErrorCode::NotFound, "ObjectView::resolve_method", 0, "Method not found");
        }
        if (m->kind == reflection::MethodKind::Virtual && m->vtable_index.has_value()) {
            MemoryReader reader{process_};
            auto vptr = reader.read_pointer(base_);
            if (!vptr || vptr->is_null()) {
                return fail(ErrorCode::NullAddress, "ObjectView::resolve_method", 0, "Null vptr");
            }
            auto slot_off = checked_mul<std::size_t>(*m->vtable_index, process_.pointer_size());
            if (!slot_off ||
                *slot_off > static_cast<std::size_t>((std::numeric_limits<std::int64_t>::max)())) {
                return fail(ErrorCode::OutOfRange, "ObjectView::resolve_method", 0,
                            "Vtable slot offset overflowed");
            }
            auto slot_addr = vptr->offset(static_cast<std::int64_t>(*slot_off));
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
    [[nodiscard]] bool field_in_bounds(const reflection::FieldInfo& field) const noexcept {
        return type_.size != 0 && field.size != 0 &&
               field.offset <= type_.size && field.size <= type_.size - field.offset &&
               field.offset <= static_cast<std::size_t>((std::numeric_limits<std::int64_t>::max)());
    }

    Process process_;
    Address base_{};
    reflection::TypeInfo type_{};
};

} // namespace tessera::rtti
