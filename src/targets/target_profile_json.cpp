#include "tessera/targets/target_profile_json.hpp"

#include <format>
#include <new>

#include "tessera/filesystem/filesystem.hpp"
#include "tessera/utility/hex.hpp"
#include "tessera/utility/string.hpp"
#include "json/detail/field_access.hpp"

namespace tessera::targets {

namespace {

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
            json::JsonValue::Array offs;
            for (const std::int64_t off : r.pointer_offsets) {
                offs.emplace_back(off);
            }
            obj.set("offsets", json::JsonValue{std::move(offs)});
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

} // namespace

Result<json::JsonValue> serialize_target_profile_to_json(const TargetProfile& profile) {
    auto schema_st = validate_target_profile_schema(profile);
    if (!schema_st) {
        return std::unexpected(schema_st.error());
    }

    try {
        json::JsonValue root = json::JsonValue::make_object();
        root.set("formatVersion", static_cast<std::int64_t>(profile.format_version));
        root.set("profileVersion", static_cast<std::int64_t>(profile.profile_version));
        root.set("revision", static_cast<std::int64_t>(profile.revision));

        json::JsonValue app = json::JsonValue::make_object();
        app.set("applicationId", profile.application.application_id);
        app.set("displayName", profile.application.display_name);
        app.set("publisher", profile.application.publisher);
        json::JsonValue::Array exes;
        for (const auto& exe : profile.application.executables) {
            exes.emplace_back(exe);
        }
        app.set("executables", json::JsonValue{std::move(exes)});
        root.set("application", std::move(app));

        json::JsonValue::Array builds_arr;
        for (const auto& b : profile.builds) {
            json::JsonValue b_obj = json::JsonValue::make_object();
            b_obj.set("buildId", b.build_id);
            b_obj.set("architecture", arch_to_str(b.architecture));

            json::JsonValue fp_obj = json::JsonValue::make_object();
            fp_obj.set("fileVersion", b.fingerprint.file_version);
            fp_obj.set("sizeOfImage", hex::format_u64(b.fingerprint.size_of_image, 8));
            fp_obj.set("timestamp", hex::format_u64(b.fingerprint.timestamp, 8));
            fp_obj.set("checksum", hex::format_u64(b.fingerprint.checksum, 8));
            fp_obj.set("codeViewGuid", b.fingerprint.codeview_guid);
            fp_obj.set("codeViewAge", static_cast<std::int64_t>(b.fingerprint.codeview_age));
            fp_obj.set("sha256", b.fingerprint.sha256);
            b_obj.set("fingerprint", std::move(fp_obj));

            json::JsonValue::Array mods_arr;
            for (const auto& m : b.modules) {
                json::JsonValue m_obj = json::JsonValue::make_object();
                m_obj.set("moduleId", m.module_id);
                m_obj.set("fileName", m.file_name);
                m_obj.set("sizeOfImage", hex::format_u64(m.size_of_image, 8));
                m_obj.set("timestamp", hex::format_u64(m.timestamp, 8));
                m_obj.set("checksum", hex::format_u64(m.checksum, 8));
                m_obj.set("codeViewGuid", m.codeview_guid);
                m_obj.set("codeViewAge", static_cast<std::int64_t>(m.codeview_age));
                m_obj.set("sha256", m.sha256);
                mods_arr.push_back(std::move(m_obj));
            }
            b_obj.set("modules", json::JsonValue{std::move(mods_arr)});

            json::JsonValue::Array addrs_arr;
            for (const auto& a : b.addresses) {
                json::JsonValue a_obj = json::JsonValue::make_object();
                a_obj.set("id", a.id);
                a_obj.set("name", a.name);
                a_obj.set("description", a.description);
                a_obj.set("category", a.category);
                a_obj.set("kind", kind_to_str(a.kind));
                a_obj.set("moduleId", a.module_id);

                json::JsonValue val_obj = json::JsonValue::make_object();
                val_obj.set("type", val_type_to_str(a.value.type));
                val_obj.set("size", static_cast<std::int64_t>(a.value.size));
                a_obj.set("value", std::move(val_obj));

                json::JsonValue res_obj = json::JsonValue::make_object();
                res_obj.set("primary", recipe_to_json(a.primary));
                if (a.fallback.has_value()) {
                    res_obj.set("fallback", recipe_to_json(*a.fallback));
                }
                a_obj.set("resolution", std::move(res_obj));

                json::JsonValue val_pol = json::JsonValue::make_object();
                json::JsonValue::Array req_rules;
                for (const auto& r : a.validation.rules) {
                    json::JsonValue r_obj = json::JsonValue::make_object();
                    r_obj.set("rule", rule_to_str(r.kind));
                    r_obj.set("required", r.required);
                    if (!r.value.empty()) {
                        r_obj.set("value", r.value);
                    }
                    if (r.relative_offset != 0) {
                        r_obj.set("relativeOffset", r.relative_offset);
                    }
                    req_rules.push_back(std::move(r_obj));
                }
                val_pol.set("required", json::JsonValue{std::move(req_rules)});
                val_pol.set("minimumUniqueCandidates",
                            static_cast<std::int64_t>(a.validation.minimum_unique_candidates));
                a_obj.set("validation", std::move(val_pol));

                if (a.audit.has_value()) {
                    json::JsonValue aud = json::JsonValue::make_object();
                    aud.set("timestampUtc", a.audit->timestamp_utc);
                    aud.set("sourceBuildId", a.audit->source_build_id);
                    aud.set("strategyUsed", a.audit->strategy_used);
                    aud.set("summary", a.audit->summary);
                    a_obj.set("audit", std::move(aud));
                }
                addrs_arr.push_back(std::move(a_obj));
            }
            b_obj.set("addresses", json::JsonValue{std::move(addrs_arr)});
            builds_arr.push_back(std::move(b_obj));
        }
        root.set("builds", json::JsonValue{std::move(builds_arr)});
        return root;
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "serialize_target_profile_to_json");
    }
}

Result<TargetProfile> deserialize_target_profile_from_json(const json::JsonValue& root) {
    if (!root.is_object()) {
        return fail(ErrorCode::ParseError,
                    "deserialize_target_profile_from_json",
                    0,
                    "Root JSON value must be an object");
    }

    try {
        TargetProfile p{};
        if (const auto* fv = root.find("formatVersion"); fv && fv->as_uint64()) {
            p.format_version = static_cast<std::uint32_t>(*fv->as_uint64());
        }
        if (const auto* pv = root.find("profileVersion"); pv && pv->as_uint64()) {
            p.profile_version = static_cast<std::uint32_t>(*pv->as_uint64());
        }
        if (const auto* rev = root.find("revision"); rev && rev->as_uint64()) {
            p.revision = *rev->as_uint64();
        }

        auto app_field = json::detail::required_field<const json::JsonValue*>(
            root,
            "application",
            "deserialize_target_profile_from_json",
            "Missing 'application' object",
            "Missing 'application' object",
            [](const json::JsonValue& value) -> std::optional<const json::JsonValue*> {
                return value.is_object() ? std::optional<const json::JsonValue*>{&value} : std::nullopt;
            });
        if (!app_field) {
            return std::unexpected(app_field.error());
        }
        const auto* app = *app_field;
        if (auto application_id = json::detail::optional_field<std::string_view>(
                *app, "applicationId", [](const json::JsonValue& value) { return value.as_string(); })) {
            p.application.application_id = std::string(*application_id);
        }
        if (auto display_name = json::detail::optional_field<std::string_view>(
                *app, "displayName", [](const json::JsonValue& value) { return value.as_string(); })) {
            p.application.display_name = std::string(*display_name);
        }
        if (auto publisher = json::detail::optional_field<std::string_view>(
                *app, "publisher", [](const json::JsonValue& value) { return value.as_string(); })) {
            p.application.publisher = std::string(*publisher);
        }
        if (const auto* exes = app->find("executables"); exes && exes->is_array()) {
            for (const auto& e : *exes->as_array()) {
                if (auto s = e.as_string()) {
                    p.application.executables.emplace_back(*s);
                }
            }
        }

        if (const auto* builds = root.find("builds"); builds && builds->is_array()) {
            for (const auto& b_jv : *builds->as_array()) {
                if (!b_jv.is_object()) {
                    return fail(ErrorCode::ParseError, "deserialize_target_profile_from_json");
                }
                TargetBuild b{};
                if (const auto* bid = b_jv.find("buildId"); bid && bid->as_string()) {
                    b.build_id = std::string(*bid->as_string());
                }
                if (const auto* arch_v = b_jv.find("architecture"); arch_v && arch_v->as_string()) {
                    auto arch_res = str_to_arch(*arch_v->as_string());
                    if (!arch_res) {
                        return std::unexpected(arch_res.error());
                    }
                    b.architecture = *arch_res;
                }

                if (const auto* fp = b_jv.find("fingerprint"); fp && fp->is_object()) {
                    if (const auto* fv = fp->find("fileVersion"); fv && fv->as_string()) {
                        b.fingerprint.file_version = std::string(*fv->as_string());
                    }
                    if (const auto* soi = fp->find("sizeOfImage"); soi && soi->as_string()) {
                        if (auto u = hex::parse_u64(*soi->as_string())) {
                            b.fingerprint.size_of_image = static_cast<std::uint32_t>(*u);
                        }
                    }
                    if (const auto* ts = fp->find("timestamp"); ts && ts->as_string()) {
                        if (auto u = hex::parse_u64(*ts->as_string())) {
                            b.fingerprint.timestamp = static_cast<std::uint32_t>(*u);
                        }
                    }
                    if (const auto* cs = fp->find("checksum"); cs && cs->as_string()) {
                        if (auto u = hex::parse_u64(*cs->as_string())) {
                            b.fingerprint.checksum = static_cast<std::uint32_t>(*u);
                        }
                    }
                    if (const auto* cvg = fp->find("codeViewGuid"); cvg && cvg->as_string()) {
                        b.fingerprint.codeview_guid = std::string(*cvg->as_string());
                    }
                    if (const auto* cva = fp->find("codeViewAge"); cva && cva->as_uint64()) {
                        b.fingerprint.codeview_age = static_cast<std::uint32_t>(*cva->as_uint64());
                    }
                    if (const auto* sha = fp->find("sha256"); sha && sha->as_string()) {
                        b.fingerprint.sha256 = std::string(*sha->as_string());
                    }
                }

                if (const auto* mods = b_jv.find("modules"); mods && mods->is_array()) {
                    for (const auto& m_jv : *mods->as_array()) {
                        if (!m_jv.is_object()) {
                            continue;
                        }
                        ModuleFingerprint mf{};
                        mf.architecture = b.architecture;
                        if (const auto* mid = m_jv.find("moduleId"); mid && mid->as_string()) {
                            mf.module_id = std::string(*mid->as_string());
                        }
                        if (const auto* fn = m_jv.find("fileName"); fn && fn->as_string()) {
                            mf.file_name = std::string(*fn->as_string());
                        }
                        if (const auto* soi = m_jv.find("sizeOfImage"); soi && soi->as_string()) {
                            if (auto u = hex::parse_u64(*soi->as_string())) {
                                mf.size_of_image = static_cast<std::uint32_t>(*u);
                            }
                        }
                        if (const auto* ts = m_jv.find("timestamp"); ts && ts->as_string()) {
                            if (auto u = hex::parse_u64(*ts->as_string())) {
                                mf.timestamp = static_cast<std::uint32_t>(*u);
                            }
                        }
                        if (const auto* cs = m_jv.find("checksum"); cs && cs->as_string()) {
                            if (auto u = hex::parse_u64(*cs->as_string())) {
                                mf.checksum = static_cast<std::uint32_t>(*u);
                            }
                        }
                        if (const auto* cvg = m_jv.find("codeViewGuid"); cvg && cvg->as_string()) {
                            mf.codeview_guid = std::string(*cvg->as_string());
                        }
                        if (const auto* cva = m_jv.find("codeViewAge"); cva && cva->as_uint64()) {
                            mf.codeview_age = static_cast<std::uint32_t>(*cva->as_uint64());
                        }
                        if (const auto* sha = m_jv.find("sha256"); sha && sha->as_string()) {
                            mf.sha256 = std::string(*sha->as_string());
                        }
                        b.modules.push_back(std::move(mf));
                    }
                }

                if (const auto* addrs = b_jv.find("addresses"); addrs && addrs->is_array()) {
                    for (const auto& a_jv : *addrs->as_array()) {
                        if (!a_jv.is_object()) {
                            continue;
                        }
                        AddressEntry ae{};
                        if (const auto* id_v = a_jv.find("id"); id_v && id_v->as_string()) {
                            ae.id = std::string(*id_v->as_string());
                        }
                        if (const auto* nm = a_jv.find("name"); nm && nm->as_string()) {
                            ae.name = std::string(*nm->as_string());
                        }
                        if (const auto* k_v = a_jv.find("kind"); k_v && k_v->as_string()) {
                            auto kr = str_to_kind(*k_v->as_string());
                            if (!kr) {
                                return std::unexpected(kr.error());
                            }
                            ae.kind = *kr;
                        }
                        if (const auto* mid = a_jv.find("moduleId"); mid && mid->as_string()) {
                            ae.module_id = std::string(*mid->as_string());
                        }
                        if (const auto* val = a_jv.find("value"); val && val->is_object()) {
                            if (const auto* vt = val->find("type"); vt && vt->as_string()) {
                                if (auto vtr = str_to_val_type(*vt->as_string())) {
                                    ae.value.type = *vtr;
                                }
                            }
                            if (const auto* vs = val->find("size"); vs && vs->as_uint64()) {
                                ae.value.size = static_cast<std::uint32_t>(*vs->as_uint64());
                            }
                        }

                        if (const auto* res = a_jv.find("resolution"); res && res->is_object()) {
                            if (const auto* prim = res->find("primary")) {
                                auto pr = json_to_recipe(*prim);
                                if (!pr) {
                                    return std::unexpected(pr.error());
                                }
                                ae.primary = std::move(*pr);
                            }
                            if (const auto* fb = res->find("fallback")) {
                                auto fbr = json_to_recipe(*fb);
                                if (!fbr) {
                                    return std::unexpected(fbr.error());
                                }
                                ae.fallback = std::move(*fbr);
                            }
                        }

                        if (const auto* val_pol = a_jv.find("validation");
                            val_pol && val_pol->is_object()) {
                            if (const auto* req = val_pol->find("required"); req && req->is_array()) {
                                for (const auto& r_jv : *req->as_array()) {
                                    if (!r_jv.is_object()) {
                                        continue;
                                    }
                                    ValidationRule vr{};
                                    if (const auto* rn = r_jv.find("rule"); rn && rn->as_string()) {
                                        auto rk = str_to_rule(*rn->as_string());
                                        if (!rk) {
                                            return std::unexpected(rk.error());
                                        }
                                        vr.kind = *rk;
                                    }
                                    if (const auto* req_b = r_jv.find("required");
                                        req_b && req_b->as_bool()) {
                                        vr.required = *req_b->as_bool();
                                    }
                                    if (const auto* rv = r_jv.find("value"); rv && rv->as_string()) {
                                        vr.value = std::string(*rv->as_string());
                                    }
                                    if (const auto* ro = r_jv.find("relativeOffset");
                                        ro && ro->as_int64()) {
                                        vr.relative_offset = *ro->as_int64();
                                    }
                                    ae.validation.rules.push_back(std::move(vr));
                                }
                            }
                            if (const auto* muc = val_pol->find("minimumUniqueCandidates");
                                muc && muc->as_uint64()) {
                                ae.validation.minimum_unique_candidates =
                                    static_cast<std::size_t>(*muc->as_uint64());
                            }
                        }
                        b.addresses.push_back(std::move(ae));
                    }
                }
                p.builds.push_back(std::move(b));
            }
        }

        auto schema_st = validate_target_profile_schema(p);
        if (!schema_st) {
            return std::unexpected(schema_st.error());
        }
        return p;
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "deserialize_target_profile_from_json");
    }
}

std::filesystem::path JsonTargetProfileStore::path_for(std::string_view application_id) const {
    return directory_ / std::format("{}.target.json", application_id);
}

Result<TargetProfile> JsonTargetProfileStore::load(std::string_view application_id) const {
    if (application_id.empty()) {
        return fail(ErrorCode::InvalidArgument, "JsonTargetProfileStore::load");
    }
    auto text = filesystem::read_file_utf8(path_for(application_id));
    if (!text) {
        return std::unexpected(text.error());
    }
    auto jv = json::parse(*text);
    if (!jv) {
        return std::unexpected(jv.error());
    }
    return deserialize_target_profile_from_json(*jv);
}

Status JsonTargetProfileStore::save(TargetProfile& profile) {
    auto schema_st = validate_target_profile_schema(profile);
    if (!schema_st) {
        return schema_st;
    }

    const auto file_path = path_for(profile.application.application_id);
    std::error_code ec;
    if (std::filesystem::exists(file_path, ec)) {
        auto on_disk = load(profile.application.application_id);
        if (on_disk) {
            if (on_disk->revision != profile.revision) {
                return fail(ErrorCode::Conflict,
                            "JsonTargetProfileStore::save",
                            0,
                            std::format("TargetProfile revision conflict: expected {}, found {} on disk",
                                        profile.revision,
                                        on_disk->revision));
            }
            ++profile.revision;
        }
    } else if (profile.revision == 0) {
        profile.revision = 1;
    }

    auto jv = serialize_target_profile_to_json(profile);
    if (!jv) {
        return std::unexpected(jv.error());
    }
    auto text = json::write(*jv);
    if (!text) {
        return std::unexpected(text.error());
    }

    return filesystem::AtomicFileWriter::write_utf8(
        file_path, *text, {.create_backup = true, .write_through = true});
}

Result<std::vector<std::string>> JsonTargetProfileStore::list() const {
    try {
        std::vector<std::string> ids;
        std::error_code ec;
        if (!std::filesystem::exists(directory_, ec)) {
            return ids;
        }
        constexpr std::string_view kSuffix = ".target.json";
        for (const auto& entry : std::filesystem::directory_iterator(directory_, ec)) {
            if (!entry.is_regular_file()) {
                continue;
            }
            const std::string fname = entry.path().filename().string();
            if (fname.size() > kSuffix.size() && fname.ends_with(kSuffix)) {
                ids.push_back(fname.substr(0, fname.size() - kSuffix.size()));
            }
        }
        return ids;
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "JsonTargetProfileStore::list");
    }
}

} // namespace tessera::targets
