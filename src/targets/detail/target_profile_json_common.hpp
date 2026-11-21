#pragma once

#include <string_view>

#include "tessera/json/json.hpp"
#include "tessera/targets/target_profile.hpp"

namespace tessera::targets::target_profile_json_detail {

[[nodiscard]] std::string_view arch_to_str(TargetArch a) noexcept;
[[nodiscard]] Result<TargetArch> str_to_arch(std::string_view s) noexcept;
[[nodiscard]] std::string_view kind_to_str(AddressKind k) noexcept;
[[nodiscard]] Result<AddressKind> str_to_kind(std::string_view s) noexcept;
[[nodiscard]] std::string_view val_type_to_str(ValueType vt) noexcept;
[[nodiscard]] Result<ValueType> str_to_val_type(std::string_view s) noexcept;
[[nodiscard]] std::string_view strategy_to_str(ResolutionStrategy st) noexcept;
[[nodiscard]] Result<ResolutionStrategy> str_to_strategy(std::string_view s) noexcept;
[[nodiscard]] std::string_view rule_to_str(ValidationRuleKind rk) noexcept;
[[nodiscard]] Result<ValidationRuleKind> str_to_rule(std::string_view s) noexcept;
[[nodiscard]] json::JsonValue recipe_to_json(const ResolutionRecipe& recipe);
[[nodiscard]] Result<ResolutionRecipe> json_to_recipe(const json::JsonValue& value);

} // namespace tessera::targets::target_profile_json_detail
