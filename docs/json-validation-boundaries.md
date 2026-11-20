# JSON validation and ownership boundaries

This note records the review of the profile and target-profile JSON paths. It intentionally does not introduce a generic deserialization framework: the overlap is mostly syntactic, while the validation and ownership rules are different.

## Shared responsibilities already centralized

- Both modules consume the same `tessera::json::JsonValue` tree and rely on the common `tessera::json::parse` implementation for RFC 8259 syntax, UTF-8 validity, nesting limits, duplicate-key policy, and input-size limits.
- Both persistence paths use the shared filesystem layer (`read_file_utf8` and `AtomicFileWriter`) rather than maintaining independent file I/O implementations.

## Profile JSON owns

- `profile_json.cpp` maps the `SettingValue` variant to/from JSON values.
- It owns schema-aware settings normalization, renamed/deprecated keys, secret references, and `ISecretStore` interactions.
- Arrays in settings have the specific meaning `StringList`; unsupported value kinds are rejected with profile-specific parse/validation errors.

## Target-profile JSON owns

- `target_profile_json.cpp` maps target-specific enums, resolution recipes, validation rules, module/build fingerprints, and audit records.
- Hexadecimal RVA/fingerprint fields and enum spellings are target-profile wire-format concerns.
- Structural invariants are enforced by `validate_target_profile_schema` (application identity, executable list, unique build/address IDs, module references, and required validation rules).

## RTTI shared traversal extraction

`python_bridge.cpp` and `discovery.cpp` contained byte-for-byte identical `for_each_readable_chunk` templates. They now share the private `src/rtti/readable_chunks.hpp` implementation. This helper owns only the common mechanics (query committed readable regions, clip to the requested range, chunk reads with overlap, and report executable protection); Python and MSVC RTTI consumers retain their own interpretation and validation rules.

## Refactoring decision

The two modules do not share a stable field schema, error taxonomy, or normalization policy. A generic typed-field helper would either erase useful field-specific error context or become a thin wrapper around the existing `JsonValue::find` / `as_*` operations. Secret handling is unique to settings profiles, while enum/hex/recipe handling is unique to target profiles. Keep these conversions local.

The safe common boundary remains the existing JSON parser/writer and filesystem APIs. New helpers should be introduced only when a repeated operation has the same accepted input types, defaulting behavior, and error semantics in both modules.

## Validation follow-up

Keep parser-level malformed UTF-8/depth/size tests in the JSON module suite, profile-specific secret/schema tests in profile tests, and target-profile structural/wire-format tests in target tests. Do not infer that a successful generic JSON parse means either domain schema is valid.
