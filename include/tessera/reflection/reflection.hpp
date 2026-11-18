#pragma once

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#include "tessera/core/enum_flags.hpp"
#include "tessera/core/result.hpp"
#include "tessera/core/types.hpp"

namespace tessera::reflection {

// Stable, RTTI-independent 64-bit type identifier (FNV-1a hash of canonical type name).
class [[nodiscard]] TypeId {
public:
    constexpr TypeId() noexcept = default;
    constexpr explicit TypeId(std::uint64_t value) noexcept : value_(value) {}

    [[nodiscard]] static constexpr TypeId from_name(std::string_view canonical_name) noexcept {
        std::uint64_t hash = 14695981039346656037ULL;
        for (const char c : canonical_name) {
            hash ^= static_cast<std::uint64_t>(static_cast<unsigned char>(c));
            hash *= 1099511628211ULL;
        }
        return TypeId{hash};
    }

    [[nodiscard]] constexpr std::uint64_t value() const noexcept { return value_; }
    [[nodiscard]] constexpr bool valid() const noexcept { return value_ != 0; }
    constexpr explicit operator bool() const noexcept { return valid(); }

    [[nodiscard]] constexpr auto operator<=>(const TypeId&) const noexcept = default;

private:
    std::uint64_t value_ = 0;
};

enum class TypeKind : std::uint8_t {
    Primitive,
    Struct,
    Class,
    Enum,
    Union,
    PythonModule,
    PythonType,
};

enum class FieldFlags : std::uint16_t {
    None = 0,
    Pointer = 1u << 0,
    Array = 1u << 1,
    Bitfield = 1u << 2,
    Const = 1u << 3,
    Static = 1u << 4,
    Inferred = 1u << 5,
    PythonExposed = 1u << 6,
};

} // namespace tessera::reflection

TESSERA_ENABLE_ENUM_FLAGS(tessera::reflection::FieldFlags);

namespace tessera::reflection {

struct FieldInfo {
    std::string name{};
    TypeId type_id{};
    std::size_t offset = 0;
    std::size_t size = 0;
    std::uint8_t bit_offset = 0;
    std::uint8_t bit_width = 0;
    TypeId pointee_type{};
    std::size_t array_count = 0;
    FieldFlags flags = FieldFlags::None;
};

using MemberInfo = FieldInfo;

struct BaseClassInfo {
    TypeId base_type{};
    std::string base_name{};
    std::ptrdiff_t offset = 0;
    bool is_virtual = false;
    std::int32_t mdisp = 0;
    std::int32_t pdisp = -1;
    std::int32_t vdisp = 0;
};

enum class MethodKind : std::uint8_t {
    NonVirtual,
    Virtual,
    Static,
    PythonCFunction,
    PythonGetter,
    PythonSetter,
};

struct MethodInfo {
    std::string name{};
    MethodKind kind = MethodKind::NonVirtual;
    std::optional<std::size_t> vtable_index{};
    Rva rva{};
    Address address{};
    std::string signature_hint{};
    std::string python_doc{};
    std::uint32_t python_flags = 0;
};

struct EnumEnumerator {
    std::string name{};
    std::int64_t value = 0;
};

struct EnumInfo {
    TypeId underlying_type{};
    bool is_scoped = true;
    std::vector<EnumEnumerator> enumerators{};

    [[nodiscard]] const EnumEnumerator* find_by_name(std::string_view enum_name) const noexcept {
        for (const auto& e : enumerators) {
            if (e.name == enum_name) {
                return &e;
            }
        }
        return nullptr;
    }

    [[nodiscard]] const EnumEnumerator* find_by_value(std::int64_t val) const noexcept {
        for (const auto& e : enumerators) {
            if (e.value == val) {
                return &e;
            }
        }
        return nullptr;
    }
};

struct TypeInfo {
    TypeId id{};
    std::string name{};
    std::string mangled_name{};
    TypeKind kind = TypeKind::Struct;
    std::size_t size = 0;
    std::size_t alignment = 0;
    bool is_trivially_copyable = false;
    bool is_standard_layout = false;
    bool is_polymorphic = false;
    Rva vtable_rva{};
    Address vtable_address{};
    std::vector<BaseClassInfo> bases{};
    std::vector<FieldInfo> members{};
    std::vector<MethodInfo> methods{};
    std::optional<EnumInfo> enum_info{};

    [[nodiscard]] const FieldInfo* find_member(std::string_view member_name) const noexcept {
        for (const auto& m : members) {
            if (m.name == member_name) {
                return &m;
            }
        }
        return nullptr;
    }

    [[nodiscard]] const FieldInfo* find_field(std::string_view field_name) const noexcept {
        return find_member(field_name);
    }

    [[nodiscard]] const FieldInfo* find_field_at_offset(std::size_t byte_offset) const noexcept {
        for (const auto& m : members) {
            if (m.offset == byte_offset) {
                return &m;
            }
        }
        return nullptr;
    }

    [[nodiscard]] const MethodInfo* find_method(std::string_view method_name) const noexcept {
        for (const auto& fn : methods) {
            if (fn.name == method_name) {
                return &fn;
            }
        }
        return nullptr;
    }

    [[nodiscard]] const BaseClassInfo* find_base(TypeId base_id) const noexcept {
        for (const auto& b : bases) {
            if (b.base_type == base_id) {
                return &b;
            }
        }
        return nullptr;
    }
};

template <class T>
class TypeBuilder {
public:
    explicit TypeBuilder(std::string_view canonical_name) {
        info_.id = TypeId::from_name(canonical_name);
        info_.name = std::string(canonical_name);
        info_.kind = std::is_enum_v<T> ? TypeKind::Enum
                                       : (std::is_polymorphic_v<T> ? TypeKind::Class : TypeKind::Struct);
        info_.size = sizeof(T);
        info_.alignment = alignof(T);
        info_.is_trivially_copyable = std::is_trivially_copyable_v<T>;
        info_.is_standard_layout = std::is_standard_layout_v<T>;
        info_.is_polymorphic = std::is_polymorphic_v<T>;
    }

    TypeBuilder& member(std::string name,
                        TypeId member_type,
                        std::size_t offset,
                        std::size_t size,
                        FieldFlags flags = FieldFlags::None) {
        info_.members.push_back(FieldInfo{
            .name = std::move(name),
            .type_id = member_type,
            .offset = offset,
            .size = size,
            .flags = flags,
        });
        return *this;
    }

    TypeBuilder& field(std::string name,
                       TypeId field_type,
                       std::size_t offset,
                       std::size_t size,
                       FieldFlags flags = FieldFlags::None) {
        return member(std::move(name), field_type, offset, size, flags);
    }

    TypeBuilder& pointer_field(std::string name,
                               TypeId pointee,
                               std::size_t offset,
                               std::size_t ptr_size = sizeof(void*)) {
        info_.members.push_back(FieldInfo{
            .name = std::move(name),
            .type_id = TypeId::from_name("pointer"),
            .offset = offset,
            .size = ptr_size,
            .pointee_type = pointee,
            .flags = FieldFlags::Pointer,
        });
        return *this;
    }

    TypeBuilder& array_field(std::string name,
                             TypeId elem_type,
                             std::size_t offset,
                             std::size_t elem_size,
                             std::size_t count) {
        info_.members.push_back(FieldInfo{
            .name = std::move(name),
            .type_id = elem_type,
            .offset = offset,
            .size = elem_size * count,
            .array_count = count,
            .flags = FieldFlags::Array,
        });
        return *this;
    }

    TypeBuilder& bitfield(std::string name,
                          TypeId storage_type,
                          std::size_t byte_offset,
                          std::size_t storage_size,
                          std::uint8_t bit_offset,
                          std::uint8_t bit_width) {
        info_.members.push_back(FieldInfo{
            .name = std::move(name),
            .type_id = storage_type,
            .offset = byte_offset,
            .size = storage_size,
            .bit_offset = bit_offset,
            .bit_width = bit_width,
            .flags = FieldFlags::Bitfield,
        });
        return *this;
    }

    template <class BaseT>
        requires std::is_base_of_v<BaseT, T>
    TypeBuilder& base(std::string_view base_canonical_name, bool is_virtual_base = false) {
        std::ptrdiff_t off = 0;
        if constexpr (!std::is_polymorphic_v<T> || !std::is_polymorphic_v<BaseT>) {
            alignas(T) std::byte storage[sizeof(T)]{};
            const auto* derived_ptr = reinterpret_cast<const T*>(storage);
            const auto* base_ptr = static_cast<const BaseT*>(derived_ptr);
            off = reinterpret_cast<const std::byte*>(base_ptr) -
                  reinterpret_cast<const std::byte*>(derived_ptr);
        }
        info_.bases.push_back(BaseClassInfo{
            .base_type = TypeId::from_name(base_canonical_name),
            .base_name = std::string(base_canonical_name),
            .offset = off,
            .is_virtual = is_virtual_base,
            .mdisp = static_cast<std::int32_t>(off),
        });
        return *this;
    }

    TypeBuilder& base_raw(BaseClassInfo b) {
        info_.bases.push_back(std::move(b));
        return *this;
    }

    TypeBuilder& method(MethodInfo m) {
        info_.methods.push_back(std::move(m));
        return *this;
    }

    TypeBuilder& non_virtual_method(std::string name,
                                    Rva rva,
                                    std::string signature_hint = {},
                                    Address address = {}) {
        info_.methods.push_back(MethodInfo{
            .name = std::move(name),
            .kind = MethodKind::NonVirtual,
            .rva = rva,
            .address = address,
            .signature_hint = std::move(signature_hint),
        });
        return *this;
    }

    TypeBuilder& virtual_method(std::string name,
                                std::size_t vtable_index,
                                Rva rva = {},
                                std::string signature_hint = {},
                                Address address = {}) {
        info_.is_polymorphic = true;
        info_.methods.push_back(MethodInfo{
            .name = std::move(name),
            .kind = MethodKind::Virtual,
            .vtable_index = vtable_index,
            .rva = rva,
            .address = address,
            .signature_hint = std::move(signature_hint),
        });
        return *this;
    }

    [[nodiscard]] TypeInfo build() noexcept { return std::move(info_); }

private:
    TypeInfo info_{};
};

// Runtime builder for non-virtual structs, RTTI-discovered classes, and Python-exposed types.
class DynamicTypeBuilder {
public:
    explicit DynamicTypeBuilder(std::string_view canonical_name,
                                TypeKind kind = TypeKind::Struct,
                                std::size_t size = 0,
                                std::size_t alignment = 0) {
        info_.id = TypeId::from_name(canonical_name);
        info_.name = std::string(canonical_name);
        info_.kind = kind;
        info_.size = size;
        info_.alignment = alignment;
        info_.is_polymorphic = (kind == TypeKind::Class);
    }

    DynamicTypeBuilder& mangled_name(std::string mangled) {
        info_.mangled_name = std::move(mangled);
        return *this;
    }

    DynamicTypeBuilder& size(std::size_t sz, std::size_t align = 0) noexcept {
        info_.size = sz;
        if (align != 0) {
            info_.alignment = align;
        }
        return *this;
    }

    DynamicTypeBuilder& polymorphic(bool poly, Rva vtbl_rva = {}, Address vtbl_va = {}) noexcept {
        info_.is_polymorphic = poly;
        info_.vtable_rva = vtbl_rva;
        info_.vtable_address = vtbl_va;
        return *this;
    }

    DynamicTypeBuilder& field(FieldInfo f) {
        info_.members.push_back(std::move(f));
        return *this;
    }

    DynamicTypeBuilder& base(BaseClassInfo b) {
        info_.bases.push_back(std::move(b));
        return *this;
    }

    DynamicTypeBuilder& method(MethodInfo m) {
        info_.methods.push_back(std::move(m));
        return *this;
    }

    [[nodiscard]] TypeInfo build() noexcept { return std::move(info_); }

private:
    TypeInfo info_{};
};

template <class E>
    requires std::is_enum_v<E>
class EnumBuilder {
public:
    explicit EnumBuilder(std::string_view canonical_name) {
        info_.id = TypeId::from_name(canonical_name);
        info_.name = std::string(canonical_name);
        info_.kind = TypeKind::Enum;
        info_.size = sizeof(E);
        info_.alignment = alignof(E);
        info_.is_trivially_copyable = true;
        info_.is_standard_layout = true;
        EnumInfo ei{};
        ei.underlying_type = TypeId::from_name("enum_underlying");
        ei.is_scoped = !std::is_convertible_v<E, std::underlying_type_t<E>>;
        info_.enum_info = std::move(ei);
    }

    EnumBuilder& value(std::string name, E enumerator_val) {
        info_.enum_info->enumerators.push_back(EnumEnumerator{
            .name = std::move(name),
            .value = static_cast<std::int64_t>(static_cast<std::underlying_type_t<E>>(enumerator_val)),
        });
        return *this;
    }

    [[nodiscard]] TypeInfo build() noexcept { return std::move(info_); }

private:
    TypeInfo info_{};
};

// Thread-safe runtime type metadata registry independent of native C++ RTTI.
class TypeRegistry {
public:
    TypeRegistry() = default;

    [[nodiscard]] static TypeRegistry& instance() noexcept;

    [[nodiscard]] Status register_type(TypeInfo info);
    [[nodiscard]] Status upsert_type(TypeInfo info);

    [[nodiscard]] Result<TypeInfo> find(TypeId id) const;
    [[nodiscard]] Result<TypeInfo> find_by_name(std::string_view name) const;

    [[nodiscard]] std::vector<TypeInfo> all_types() const;
    [[nodiscard]] std::vector<TypeInfo> search(std::string_view query) const;
    [[nodiscard]] std::vector<TypeInfo> derived_from(TypeId base_id) const;

    [[nodiscard]] std::size_t size() const noexcept;
    void clear() noexcept;

private:
    mutable std::mutex mutex_{};
    std::vector<TypeInfo> types_{};
};

} // namespace tessera::reflection
