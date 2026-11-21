#include "tessera/profile/profile_json.hpp"

#include <format>
#include <new>

#include "tessera/filesystem/filesystem.hpp"
#include "json/detail/field_access.hpp"

namespace tessera::profile {

namespace {

[[nodiscard]] json::JsonValue setting_to_json(const SettingValue& val) {
    return std::visit(
        [](const auto& v) -> json::JsonValue {
            using T = std::decay_t<decltype(v)>;
            if constexpr (std::same_as<T, StringList>) {
                return json::JsonValue{json::detail::serialize_array(
                    v, [](const std::string& text) { return json::JsonValue{text}; })};
            } else {
                return json::JsonValue{v};
            }
        },
        val);
}

[[nodiscard]] Result<SettingValue> json_to_setting(const json::JsonValue& jv) {
    switch (jv.type()) {
        case json::JsonType::Bool:
            return SettingValue{*jv.as_bool()};
        case json::JsonType::Int64:
            return SettingValue{*jv.as_int64()};
        case json::JsonType::UInt64:
            return SettingValue{*jv.as_uint64()};
        case json::JsonType::Double:
            return SettingValue{*jv.as_double()};
        case json::JsonType::String:
            return SettingValue{std::string(*jv.as_string())};
        case json::JsonType::Array: {
            auto list = json::detail::parse_array<std::string>(
                jv,
                "deserialize_profile_from_json",
                "Settings array elements must be strings",
                [](const json::JsonValue& value) -> std::optional<std::string> {
                    auto text = value.as_string();
                    if (!text) {
                        return std::nullopt;
                    }
                    return std::string(*text);
                });
            if (!list) {
                return std::unexpected(list.error());
            }
            return SettingValue{std::move(*list)};
        }
        default:
            return fail(ErrorCode::ParseError,
                        "deserialize_profile_from_json",
                        0,
                        "Unsupported JSON value type in profile values");
    }
}

} // namespace

Result<json::JsonValue> serialize_profile_to_json(const Profile& profile,
                                                  const SettingsSchema* schema,
                                                  ISecretStore* secret_store) {
    try {
        json::JsonValue root = json::JsonValue::make_object();
        root.set("formatVersion", static_cast<std::int64_t>(profile.format_version));
        root.set("schemaVersion", static_cast<std::int64_t>(profile.schema_version));
        root.set("revision", static_cast<std::int64_t>(profile.revision));
        root.set("id", profile.id);
        root.set("name", profile.name);
        root.set("description", profile.description);

        root.set("tags", json::JsonValue{json::detail::serialize_array(
            profile.tags, [](const std::string& tag) { return json::JsonValue{tag}; })});

        json::JsonValue vals_obj = json::JsonValue::make_object();
        for (const auto& [k, v] : profile.values) {
            const SettingDefinition* def = schema ? schema->find_definition(k) : nullptr;
            if (def != nullptr && def->is_secret) {
                if (secret_store == nullptr) {
                    return fail(ErrorCode::ValidationFailed,
                                "serialize_profile_to_json",
                                0,
                                std::format("Secret key '{}' cannot be saved without an ISecretStore", k));
                }
                const auto* s_val = std::get_if<std::string>(&v);
                if (s_val == nullptr) {
                    return fail(ErrorCode::ValidationFailed,
                                "serialize_profile_to_json",
                                0,
                                "Secret setting must be a string");
                }
                auto ref_res = secret_store->store_secret(std::format("{}:{}", profile.id, k), *s_val);
                if (!ref_res) {
                    return std::unexpected(ref_res.error());
                }
                json::JsonValue sec_obj = json::JsonValue::make_object();
                sec_obj.set("$secretRef", *ref_res);
                vals_obj.set(k, std::move(sec_obj));
            } else {
                vals_obj.set(k, setting_to_json(v));
            }
        }
        root.set("values", std::move(vals_obj));
        return root;
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "serialize_profile_to_json");
    }
}

Result<Profile> deserialize_profile_from_json(const json::JsonValue& root,
                                              const SettingsSchema* schema,
                                              const ISecretStore* secret_store) {
    if (!root.is_object()) {
        return fail(ErrorCode::ParseError,
                    "deserialize_profile_from_json",
                    0,
                    "Root JSON value must be an object");
    }

    try {
        Profile p{};
        if (const auto* fv = root.find("formatVersion")) {
            auto v = json::detail::checked_unsigned<std::uint32_t>(
                *fv, "deserialize_profile_from_json", "Invalid formatVersion");
            if (!v || *v == 0) {
                return fail(ErrorCode::ParseError,
                            "deserialize_profile_from_json",
                            0,
                            "Invalid formatVersion");
            }
            p.format_version = *v;
        }
        if (const auto* sv = root.find("schemaVersion")) {
            auto v = json::detail::checked_unsigned<std::uint32_t>(
                *sv, "deserialize_profile_from_json", "Invalid schemaVersion");
            if (!v || *v == 0) {
                return fail(ErrorCode::ParseError,
                            "deserialize_profile_from_json",
                            0,
                            "Invalid schemaVersion");
            }
            p.schema_version = *v;
        }
        if (const auto* rev = root.find("revision")) {
            auto v = rev->as_uint64();
            if (!v) {
                return fail(ErrorCode::ParseError, "deserialize_profile_from_json", 0, "Invalid revision");
            }
            p.revision = *v;
        }
        auto id = json::detail::required_field<std::string_view>(
            root,
            "id",
            "deserialize_profile_from_json",
            "Missing profile id",
            "Invalid profile id",
            [](const json::JsonValue& value) -> std::optional<std::string_view> {
                auto text = value.as_string();
                if (!text || text->empty()) {
                    return std::nullopt;
                }
                return *text;
            });
        if (!id) {
            return std::unexpected(id.error());
        }
        p.id = std::string(*id);

        if (auto name = json::detail::optional_field<std::string_view>(
                root, "name", [](const json::JsonValue& value) { return value.as_string(); })) {
            p.name = std::string(*name);
        }
        if (auto description = json::detail::optional_field<std::string_view>(
                root, "description", [](const json::JsonValue& value) { return value.as_string(); })) {
            p.description = std::string(*description);
        }
        if (const auto* tags = root.find("tags")) {
            json::detail::append_array(
                *tags,
                p.tags,
                [](const json::JsonValue& value) -> std::optional<std::string> {
                    auto text = value.as_string();
                    if (!text) {
                        return std::nullopt;
                    }
                    return std::string(*text);
                });
        }

        if (const auto* vals = root.find("values")) {
            if (!vals->is_object()) {
                return fail(ErrorCode::ParseError,
                            "deserialize_profile_from_json",
                            0,
                            "'values' field must be an object");
            }
            for (const auto& [k, jv] : *vals->as_object()) {
                const SettingDefinition* def = schema ? schema->find_definition(k) : nullptr;
                if (jv.is_object()) {
                    if (const auto* sref = jv.find("$secretRef")) {
                        auto ref_str = sref->as_string();
                        if (!ref_str || secret_store == nullptr) {
                            return fail(ErrorCode::ValidationFailed,
                                        "deserialize_profile_from_json",
                                        0,
                                        "Cannot resolve $secretRef without an ISecretStore");
                        }
                        auto resolved = secret_store->load_secret(*ref_str);
                        if (!resolved) {
                            return std::unexpected(resolved.error());
                        }
                        p.set(k, SettingValue{std::move(*resolved)});
                        continue;
                    }
                }
                if (def != nullptr && def->is_secret) {
                    return fail(ErrorCode::ValidationFailed,
                                "deserialize_profile_from_json",
                                0,
                                std::format("Secret key '{}' must not be stored in plaintext", k));
                }
                auto sv = json_to_setting(jv);
                if (!sv) {
                    return std::unexpected(sv.error());
                }
                p.set(k, std::move(*sv));
            }
        }

        return p;
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "deserialize_profile_from_json");
    }
}

std::filesystem::path JsonProfileStore::path_for(std::string_view profile_id) const {
    return directory_ / std::format("{}.profile.json", profile_id);
}

Result<Profile> JsonProfileStore::load(std::string_view profile_id) const {
    if (profile_id.empty()) {
        return fail(ErrorCode::InvalidArgument, "JsonProfileStore::load");
    }
    auto text = filesystem::read_file_utf8(path_for(profile_id));
    if (!text) {
        return std::unexpected(text.error());
    }
    auto jv = json::parse(*text);
    if (!jv) {
        return std::unexpected(jv.error());
    }
    return deserialize_profile_from_json(*jv, schema_, secret_store_);
}

Status JsonProfileStore::save(Profile& profile) {
    if (profile.id.empty()) {
        return fail(ErrorCode::InvalidArgument, "JsonProfileStore::save", 0, "Profile id is empty");
    }

    const auto file_path = path_for(profile.id);
    std::error_code ec;
    if (std::filesystem::exists(file_path, ec)) {
        auto on_disk = load(profile.id);
        if (on_disk) {
            if (on_disk->revision != profile.revision) {
                return fail(ErrorCode::Conflict,
                            "JsonProfileStore::save",
                            0,
                            std::format("Profile revision conflict: expected {}, found {} on disk",
                                        profile.revision,
                                        on_disk->revision));
            }
            ++profile.revision;
        }
    } else if (profile.revision == 0) {
        profile.revision = 1;
    }

    auto jv = serialize_profile_to_json(profile, schema_, secret_store_);
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

Status JsonProfileStore::remove(std::string_view profile_id) {
    if (profile_id.empty()) {
        return fail(ErrorCode::InvalidArgument, "JsonProfileStore::remove");
    }
    std::error_code ec;
    const auto p = path_for(profile_id);
    if (!std::filesystem::exists(p, ec)) {
        return fail(ErrorCode::NotFound, "JsonProfileStore::remove");
    }
    if (!std::filesystem::remove(p, ec) || ec) {
        return fail(ErrorCode::IoError,
                    "std::filesystem::remove",
                    static_cast<std::uint32_t>(ec.value()));
    }
    return ok();
}

Result<std::vector<std::string>> JsonProfileStore::list() const {
    try {
        std::vector<std::string> ids;
        std::error_code ec;
        if (!std::filesystem::exists(directory_, ec)) {
            return ids;
        }
        constexpr std::string_view kSuffix = ".profile.json";
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
        return fail(ErrorCode::OutOfMemory, "JsonProfileStore::list");
    }
}

} // namespace tessera::profile
