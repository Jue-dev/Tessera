#include "targets/detail/target_profile_json_common.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "tessera/utility/hex.hpp"
#include "tessera/utility/string.hpp"
#include "json/detail/field_access.hpp"


namespace tessera::targets::target_profile_json_detail {


[[nodiscard]] std::string_view arch_to_str(TargetArch a) noexcept {
    return a == TargetArch::X64 ? "x64" : "x86";
}

[[nodiscard]] Result<TargetArch> str_to_arch(std::string_view s) noexcept {
    if (utility::ascii_iequals(s, "x64")) {
        return TargetArch::X64;
    }
    if (utility::ascii_iequals(s, "x86")) {
        return TargetArch::X86;
    }
    return fail(ErrorCode::ParseError, "str_to_arch", 0, "Invalid architecture string");
}

[[nodiscard]] std::string_view kind_to_str(AddressKind k) noexcept {
    switch (k) {
        case AddressKind::Function: return "function";
        case AddressKind::Global:   return "global";
        case AddressKind::Object:   return "object";
        case AddressKind::Field:    return "field";
        case AddressKind::VTable:   return "vtable";
        case AddressKind::Pointer:  return "pointer";
        case AddressKind::Data:     return "data";
        case AddressKind::Export:   return "export";
    }
    return "global";
}

[[nodiscard]] Result<AddressKind> str_to_kind(std::string_view s) noexcept {
    if (utility::ascii_iequals(s, "function")) return AddressKind::Function;
    if (utility::ascii_iequals(s, "global"))   return AddressKind::Global;
    if (utility::ascii_iequals(s, "object"))   return AddressKind::Object;
    if (utility::ascii_iequals(s, "field"))    return AddressKind::Field;
    if (utility::ascii_iequals(s, "vtable"))   return AddressKind::VTable;
    if (utility::ascii_iequals(s, "pointer"))  return AddressKind::Pointer;
    if (utility::ascii_iequals(s, "data"))     return AddressKind::Data;
    if (utility::ascii_iequals(s, "export"))   return AddressKind::Export;
    return fail(ErrorCode::ParseError, "str_to_kind", 0, "Unknown AddressKind");
}

[[nodiscard]] std::string_view val_type_to_str(ValueType vt) noexcept {
    switch (vt) {
        case ValueType::UInt8:   return "uint8";
        case ValueType::Int32:   return "int32";
        case ValueType::UInt32:  return "uint32";
        case ValueType::Int64:   return "int64";
        case ValueType::UInt64:  return "uint64";
        case ValueType::Float:   return "float";
        case ValueType::Double:  return "double";
        case ValueType::Pointer: return "pointer";
        case ValueType::Bytes:   return "bytes";
    }
    return "uint32";
}

[[nodiscard]] Result<ValueType> str_to_val_type(std::string_view s) noexcept {
    if (utility::ascii_iequals(s, "uint8"))   return ValueType::UInt8;
    if (utility::ascii_iequals(s, "int32"))   return ValueType::Int32;
    if (utility::ascii_iequals(s, "uint32"))  return ValueType::UInt32;
    if (utility::ascii_iequals(s, "int64"))   return ValueType::Int64;
    if (utility::ascii_iequals(s, "uint64"))  return ValueType::UInt64;
    if (utility::ascii_iequals(s, "float"))   return ValueType::Float;
    if (utility::ascii_iequals(s, "double"))  return ValueType::Double;
    if (utility::ascii_iequals(s, "pointer")) return ValueType::Pointer;
    if (utility::ascii_iequals(s, "bytes"))   return ValueType::Bytes;
    return fail(ErrorCode::ParseError, "str_to_val_type", 0, "Unknown ValueType");
}

[[nodiscard]] std::string_view strategy_to_str(ResolutionStrategy st) noexcept {
    switch (st) {
        case ResolutionStrategy::Rva:          return "rva";
        case ResolutionStrategy::Export:       return "export";
        case ResolutionStrategy::Pattern:      return "pattern";
        case ResolutionStrategy::PointerChain: return "pointer_chain";
        case ResolutionStrategy::Relative:     return "relative";
        case ResolutionStrategy::Field:        return "field";
        case ResolutionStrategy::RttiVTable:   return "rtti_vtable";
        case ResolutionStrategy::StringXref:   return "string_xref";
        case ResolutionStrategy::PythonMethod: return "python_method";
    }
    return "rva";
}

[[nodiscard]] Result<ResolutionStrategy> str_to_strategy(std::string_view s) noexcept {
    if (utility::ascii_iequals(s, "rva"))           return ResolutionStrategy::Rva;
    if (utility::ascii_iequals(s, "export"))        return ResolutionStrategy::Export;
    if (utility::ascii_iequals(s, "pattern"))       return ResolutionStrategy::Pattern;
    if (utility::ascii_iequals(s, "pointer_chain")) return ResolutionStrategy::PointerChain;
    if (utility::ascii_iequals(s, "relative"))      return ResolutionStrategy::Relative;
    if (utility::ascii_iequals(s, "field"))         return ResolutionStrategy::Field;
    if (utility::ascii_iequals(s, "rtti_vtable"))   return ResolutionStrategy::RttiVTable;
    if (utility::ascii_iequals(s, "string_xref"))   return ResolutionStrategy::StringXref;
    if (utility::ascii_iequals(s, "python_method")) return ResolutionStrategy::PythonMethod;
    return fail(ErrorCode::ParseError, "str_to_strategy", 0, "Unknown ResolutionStrategy");
}

[[nodiscard]] std::string_view rule_to_str(ValidationRuleKind rk) noexcept {
    switch (rk) {
        case ValidationRuleKind::ModuleRange:        return "module_range";
        case ValidationRuleKind::Section:            return "section";
        case ValidationRuleKind::MemoryReadable:     return "memory_readable";
        case ValidationRuleKind::MemoryWritable:     return "memory_writable";
        case ValidationRuleKind::MemoryExecutable:   return "memory_executable";
        case ValidationRuleKind::ExpectedBytes:      return "expected_bytes";
        case ValidationRuleKind::SecondarySignature: return "secondary_signature";
        case ValidationRuleKind::PointerSanity:      return "pointer_sanity";
        case ValidationRuleKind::ValueRange:         return "value_range";
        case ValidationRuleKind::InstructionShape:   return "instruction_shape";
    }
    return "module_range";
}

[[nodiscard]] Result<ValidationRuleKind> str_to_rule(std::string_view s) noexcept {
    if (utility::ascii_iequals(s, "module_range"))        return ValidationRuleKind::ModuleRange;
    if (utility::ascii_iequals(s, "section"))             return ValidationRuleKind::Section;
    if (utility::ascii_iequals(s, "memory_readable"))     return ValidationRuleKind::MemoryReadable;
    if (utility::ascii_iequals(s, "memory_writable"))     return ValidationRuleKind::MemoryWritable;
    if (utility::ascii_iequals(s, "memory_executable"))   return ValidationRuleKind::MemoryExecutable;
    if (utility::ascii_iequals(s, "expected_bytes"))      return ValidationRuleKind::ExpectedBytes;
    if (utility::ascii_iequals(s, "secondary_signature")) return ValidationRuleKind::SecondarySignature;
    if (utility::ascii_iequals(s, "pointer_sanity"))      return ValidationRuleKind::PointerSanity;
    if (utility::ascii_iequals(s, "value_range"))         return ValidationRuleKind::ValueRange;
    if (utility::ascii_iequals(s, "instruction_shape"))   return ValidationRuleKind::InstructionShape;
    return fail(ErrorCode::ParseError, "str_to_rule", 0, "Unknown ValidationRuleKind");
}

[[nodiscard]] json::JsonValue recipe_to_json(const ResolutionRecipe& r) {
    json::JsonValue obj = json::JsonValue::make_object();
    obj.set("strategy", strategy_to_str(r.strategy));
    switch (r.strategy) {
        case ResolutionStrategy::Rva:
            obj.set("rva", hex::format_u64(r.rva.value(), 8));
            break;
        case ResolutionStrategy::Export:
            if (!r.export_name.empty()) {
                obj.set("exportName", r.export_name);
            } else {
                obj.set("ordinal", static_cast<std::int64_t>(r.export_ordinal));
            }
            break;
        case ResolutionStrategy::Pattern:
        case ResolutionStrategy::Relative:
            obj.set("pattern", r.pattern);
            if (!r.section.empty()) {
                obj.set("section", r.section);
            }
            obj.set("matchCount", static_cast<std::int64_t>(r.match_count));
            obj.set("resultOffset", r.result_offset);
            if (r.strategy == ResolutionStrategy::Relative) {
                obj.set("dispOffset", static_cast<std::int64_t>(r.rel_disp_offset));
                obj.set("instrLen", static_cast<std::int64_t>(r.rel_instr_len));
            }
            break;
        case ResolutionStrategy::PointerChain: {
            obj.set("rva", hex::format_u64(r.rva.value(), 8));
            obj.set("offsets", json::JsonValue{json::detail::serialize_array(
                r.pointer_offsets,
                [](std::int64_t offset) { return json::JsonValue{offset}; })});
            break;
        }
        case ResolutionStrategy::Field:
            obj.set("rva", hex::format_u64(r.rva.value(), 8));
            obj.set("resultOffset", r.result_offset);
            break;
        case ResolutionStrategy::RttiVTable:
            obj.set("className", r.class_name);
            if (r.vtable_index.has_value()) {
                obj.set("vtableIndex", static_cast<std::int64_t>(*r.vtable_index));
            }
            if (r.result_offset != 0) {
                obj.set("resultOffset", r.result_offset);
            }
            break;
        case ResolutionStrategy::StringXref:
            obj.set("stringLiteral", r.string_literal);
            if (r.result_offset != 0) {
                obj.set("resultOffset", r.result_offset);
            }
            break;
        case ResolutionStrategy::PythonMethod:
            obj.set("pythonMethod", r.python_method);
            if (r.result_offset != 0) {
                obj.set("resultOffset", r.result_offset);
            }
            break;
    }
    return obj;
}

[[nodiscard]] Result<ResolutionRecipe> json_to_recipe(const json::JsonValue& jv) {
    if (!jv.is_object()) {
        return fail(ErrorCode::ParseError, "json_to_recipe", 0, "Recipe must be an object");
    }
    auto strategy_name = json::detail::required_field<std::string_view>(
        jv,
        "strategy",
        "json_to_recipe",
        "Missing recipe strategy",
        "Missing recipe strategy",
        [](const json::JsonValue& value) { return value.as_string(); });
    if (!strategy_name) {
        return std::unexpected(strategy_name.error());
    }
    auto st = str_to_strategy(*strategy_name);
    if (!st) {
        return std::unexpected(st.error());
    }

    ResolutionRecipe r{};
    r.strategy = *st;
    if (const auto* rva_v = jv.find("rva")) {
        auto s = rva_v->as_string();
        if (!s) {
            return fail(ErrorCode::ParseError, "json_to_recipe", 0, "rva must be a hex string");
        }
        auto u = hex::parse_u64(*s);
        if (!u || *u > 0xFFFFFFFFULL) {
            return fail(ErrorCode::ParseError, "json_to_recipe", 0, "Invalid 32-bit RVA hex string");
        }
        r.rva = Rva{static_cast<std::uint32_t>(*u)};
    }
    if (const auto* en = jv.find("exportName"); en && en->as_string()) {
        r.export_name = std::string(*en->as_string());
    }
    if (const auto* eo = jv.find("ordinal"); eo && eo->as_uint64()) {
        r.export_ordinal = static_cast<std::uint16_t>(*eo->as_uint64());
    }
    if (const auto* pat = jv.find("pattern"); pat && pat->as_string()) {
        r.pattern = std::string(*pat->as_string());
    }
    if (const auto* sec = jv.find("section"); sec && sec->as_string()) {
        r.section = std::string(*sec->as_string());
    }
    if (const auto* mc = jv.find("matchCount"); mc && mc->as_uint64()) {
        r.match_count = static_cast<std::size_t>(*mc->as_uint64());
    }
    if (const auto* ro = jv.find("resultOffset"); ro && ro->as_int64()) {
        r.result_offset = *ro->as_int64();
    }
    if (const auto* doff = jv.find("dispOffset"); doff && doff->as_uint64()) {
        r.rel_disp_offset = static_cast<std::size_t>(*doff->as_uint64());
    }
    if (const auto* ilen = jv.find("instrLen"); ilen && ilen->as_uint64()) {
        r.rel_instr_len = static_cast<std::size_t>(*ilen->as_uint64());
    }
    if (const auto* cn = jv.find("className"); cn && cn->as_string()) {
        r.class_name = std::string(*cn->as_string());
    }
    if (const auto* vi = jv.find("vtableIndex"); vi && vi->as_uint64()) {
        r.vtable_index = static_cast<std::size_t>(*vi->as_uint64());
    }
    if (const auto* sl = jv.find("stringLiteral"); sl && sl->as_string()) {
        r.string_literal = std::string(*sl->as_string());
    }
    if (const auto* pm = jv.find("pythonMethod"); pm && pm->as_string()) {
        r.python_method = std::string(*pm->as_string());
    }
    if (const auto* offs = jv.find("offsets"); offs && offs->is_array()) {
        for (const auto& item : *offs->as_array()) {
            if (auto iv = item.as_int64()) {
                r.pointer_offsets.push_back(*iv);
            } else if (auto sv = item.as_string()) {
                auto u = hex::parse_u64(*sv);
                if (!u) {
                    return std::unexpected(u.error());
                }
                r.pointer_offsets.push_back(static_cast<std::int64_t>(*u));
            }
        }
    }
    return r;
}



} // namespace tessera::targets::target_profile_json_detail
