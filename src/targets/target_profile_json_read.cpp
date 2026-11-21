#include "detail/target_profile_json_common.hpp"
#include "json/detail/field_access.hpp"
#include "tessera/utility/hex.hpp"
#include "tessera/filesystem/filesystem.hpp"
#include "tessera/targets/target_profile_json.hpp"

#include <format>
#include <new>
#include <optional>

namespace tessera::targets {

using namespace target_profile_json_detail;

Result<TargetProfile> deserialize_target_profile_from_json(const json::JsonValue& root) {
    if (!root.is_object()) {
        return fail(ErrorCode::ParseError, "deserialize_target_profile_from_json", 0,
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
            root, "application", "deserialize_target_profile_from_json", "Missing 'application' object",
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
        if (const auto* exes = app->find("executables")) {
            json::detail::append_array(*exes, p.application.executables,
                                       [](const json::JsonValue& value) -> std::optional<std::string> {
                                           auto text = value.as_string();
                                           if (!text) {
                                               return std::nullopt;
                                           }
                                           return std::string(*text);
                                       });
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

                        if (const auto* val_pol = a_jv.find("validation"); val_pol && val_pol->is_object()) {
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
                                    if (const auto* ro = r_jv.find("relativeOffset"); ro && ro->as_int64()) {
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
