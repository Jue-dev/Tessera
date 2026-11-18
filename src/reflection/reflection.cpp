#include "tessera/reflection/reflection.hpp"

#include <algorithm>
#include <format>
#include <new>

namespace tessera::reflection {

namespace {

[[nodiscard]] bool icontains_ascii(std::string_view haystack, std::string_view needle) noexcept {
    if (needle.empty()) {
        return true;
    }
    if (haystack.size() < needle.size()) {
        return false;
    }
    auto to_lower = [](char c) noexcept -> unsigned char {
        const auto uc = static_cast<unsigned char>(c);
        return (uc >= 'A' && uc <= 'Z') ? static_cast<unsigned char>(uc + 32u) : uc;
    };
    for (std::size_t i = 0; i <= haystack.size() - needle.size(); ++i) {
        bool match = true;
        for (std::size_t j = 0; j < needle.size(); ++j) {
            if (to_lower(haystack[i + j]) != to_lower(needle[j])) {
                match = false;
                break;
            }
        }
        if (match) {
            return true;
        }
    }
    return false;
}

} // namespace

TypeRegistry& TypeRegistry::instance() noexcept {
    static TypeRegistry kGlobalRegistry{};
    return kGlobalRegistry;
}

Status TypeRegistry::register_type(TypeInfo info) {
    if (!info.id.valid() || info.name.empty()) {
        return fail(ErrorCode::InvalidArgument,
                    "TypeRegistry::register_type",
                    0,
                    "TypeInfo id and name must be non-empty");
    }

    try {
        const std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& existing : types_) {
            if (existing.id == info.id || existing.name == info.name) {
                return fail(ErrorCode::Conflict,
                            "TypeRegistry::register_type",
                            0,
                            std::format("Type '{}' is already registered", info.name));
            }
        }
        types_.push_back(std::move(info));
        return ok();
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "TypeRegistry::register_type");
    }
}

Status TypeRegistry::upsert_type(TypeInfo info) {
    if (!info.id.valid() || info.name.empty()) {
        return fail(ErrorCode::InvalidArgument,
                    "TypeRegistry::upsert_type",
                    0,
                    "TypeInfo id and name must be non-empty");
    }

    try {
        const std::lock_guard<std::mutex> lock(mutex_);
        for (auto& existing : types_) {
            if (existing.id == info.id || existing.name == info.name) {
                if (info.size > existing.size) {
                    existing.size = info.size;
                }
                if (info.alignment > existing.alignment) {
                    existing.alignment = info.alignment;
                }
                if (info.is_polymorphic) {
                    existing.is_polymorphic = true;
                    if (info.vtable_rva.value() != 0) {
                        existing.vtable_rva = info.vtable_rva;
                    }
                    if (!info.vtable_address.is_null()) {
                        existing.vtable_address = info.vtable_address;
                    }
                }
                if (!info.mangled_name.empty()) {
                    existing.mangled_name = std::move(info.mangled_name);
                }
                for (auto& b : info.bases) {
                    if (existing.find_base(b.base_type) == nullptr) {
                        existing.bases.push_back(std::move(b));
                    }
                }
                for (auto& m : info.members) {
                    if (existing.find_member(m.name) == nullptr) {
                        existing.members.push_back(std::move(m));
                    }
                }
                for (auto& fn : info.methods) {
                    if (existing.find_method(fn.name) == nullptr) {
                        existing.methods.push_back(std::move(fn));
                    }
                }
                if (info.enum_info.has_value()) {
                    existing.enum_info = std::move(info.enum_info);
                }
                return ok();
            }
        }
        types_.push_back(std::move(info));
        return ok();
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "TypeRegistry::upsert_type");
    }
}

Result<TypeInfo> TypeRegistry::find(TypeId id) const {
    const std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& t : types_) {
        if (t.id == id) {
            return t;
        }
    }
    return fail(ErrorCode::NotFound, "TypeRegistry::find");
}

Result<TypeInfo> TypeRegistry::find_by_name(std::string_view name) const {
    const std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& t : types_) {
        if (t.name == name) {
            return t;
        }
    }
    return fail(ErrorCode::NotFound, "TypeRegistry::find_by_name");
}

std::vector<TypeInfo> TypeRegistry::all_types() const {
    const std::lock_guard<std::mutex> lock(mutex_);
    return types_;
}

std::vector<TypeInfo> TypeRegistry::search(std::string_view query) const {
    const std::lock_guard<std::mutex> lock(mutex_);
    std::vector<TypeInfo> results;
    for (const auto& t : types_) {
        if (icontains_ascii(t.name, query) || icontains_ascii(t.mangled_name, query)) {
            results.push_back(t);
        }
    }
    return results;
}

std::vector<TypeInfo> TypeRegistry::derived_from(TypeId base_id) const {
    const std::lock_guard<std::mutex> lock(mutex_);
    std::vector<TypeInfo> results;
    for (const auto& t : types_) {
        if (t.find_base(base_id) != nullptr) {
            results.push_back(t);
        }
    }
    return results;
}

std::size_t TypeRegistry::size() const noexcept {
    const std::lock_guard<std::mutex> lock(mutex_);
    return types_.size();
}

void TypeRegistry::clear() noexcept {
    const std::lock_guard<std::mutex> lock(mutex_);
    types_.clear();
}

} // namespace tessera::reflection
