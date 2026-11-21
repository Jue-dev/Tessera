#include "detail/target_profile_json_common.hpp"
#include "tessera/filesystem/filesystem.hpp"
#include "tessera/targets/target_profile_json.hpp"
#include "tessera/utility/hex.hpp"

#include "json/detail/field_access.hpp"
#include <format>
#include <new>

namespace tessera::targets {

using namespace target_profile_json_detail;

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
        app.set("executables", json::JsonValue{json::detail::serialize_array(
                                   profile.application.executables, [](const std::string& executable) {
                                       return json::JsonValue{executable};
                                   })});
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
                return fail(ErrorCode::Conflict, "JsonTargetProfileStore::save", 0,
                            std::format("TargetProfile revision conflict: expected {}, found {} on disk",
                                        profile.revision, on_disk->revision));
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

    return filesystem::AtomicFileWriter::write_utf8(file_path, *text,
                                                    {.create_backup = true, .write_through = true});
}

} // namespace tessera::targets
