#if !defined(TESSERA_STANDALONE_SDK_CONSUMER)
#include <catch2/catch_test_macros.hpp>
#endif

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <vector>
#include <span>
#include <string_view>

#include "tessera/core/core.hpp"
#include "tessera/hook/hook.hpp"
#include "tessera/json/json.hpp"
#include "tessera/memory/memory_reader.hpp"
#include "tessera/module/module.hpp"
#include "tessera/module/pe_image.hpp"
#include "tessera/patch/patch.hpp"
#include "tessera/pattern/pattern.hpp"
#include "tessera/process/process.hpp"
#include "tessera/resolver/resolver.hpp"
#include "tessera/rtti/python_bridge.hpp"
#include "tessera/rtti/rtti.hpp"
#include "tessera/scanner/scanner.hpp"
#include "tessera/scanner/xref.hpp"

#ifndef TESSERA_CONSUMER_WITH_PROFILE
#define TESSERA_CONSUMER_WITH_PROFILE 1
#endif

#ifndef TESSERA_CONSUMER_WITH_TARGETS
#define TESSERA_CONSUMER_WITH_TARGETS 1
#endif

#if TESSERA_CONSUMER_WITH_PROFILE
#include "tessera/profile/profile.hpp"
#include "tessera/profile/profile_json.hpp"
#endif

#if TESSERA_CONSUMER_WITH_TARGETS
#include "tessera/targets/target_profile.hpp"
#include "tessera/targets/target_profile_json.hpp"
#endif

namespace {

using HookFn = void (*)();
void consumer_noop() {}

using MemoryReadFn = tessera::Status (tessera::MemoryReader::*)(tessera::Address, std::span<std::byte>) const noexcept;
using ModuleSnapshotFn = tessera::Result<std::vector<tessera::Module>> (*)(const tessera::Process&);
using ScanFn = tessera::Result<tessera::ScanResult> (tessera::Scanner::*)(tessera::AddressRange, const tessera::Pattern&, const tessera::ScanOptions&) const;
using ScanBatchFn = tessera::Result<std::vector<tessera::ScanResult>> (tessera::Scanner::*)(
    tessera::AddressRange, std::span<const tessera::Pattern>, const tessera::ScanOptions&) const;
using XrefCallsFn = tessera::Result<std::vector<tessera::Address>> (*)(
    const tessera::Process&, tessera::AddressRange, tessera::Address, const tessera::ScanOptions&);
using XrefBatchFn = tessera::Result<std::vector<std::vector<tessera::Address>>> (*)(
    const tessera::Process&, tessera::AddressRange, std::span<const tessera::Address>,
    const tessera::ScanOptions&);
using CursorOffsetFn = tessera::AddressCursor (tessera::AddressCursor::*)(std::int64_t) const noexcept;
using PatchNopFn = tessera::Result<tessera::Patch> (*)(tessera::ProcessAddress, std::size_t, tessera::PatchOptions);
using HookCreateFn = tessera::Result<tessera::Hook<HookFn>> (*)(tessera::Address, HookFn, tessera::HookBackend*) noexcept;
using NativeBackendFn = tessera::HookBackend& (*)() noexcept;
using PeMemoryFn = tessera::Result<tessera::PeImage> (*)(const tessera::Process&, tessera::Address);
using PeFileFn = tessera::Result<tessera::PeImage> (*)(const std::filesystem::path&);
using PeRawFn = tessera::Result<tessera::PeImage> (*)(std::span<const std::byte>, tessera::Address);
using PatternParseFn = tessera::Result<tessera::Pattern> (*)(std::string_view, tessera::PatternError*);
using JsonParseFn = tessera::Result<tessera::json::JsonValue> (*)(std::string_view, const tessera::json::JsonParseOptions&, tessera::json::JsonParseError*);
using Rel32Fn = tessera::Result<tessera::Rva> (*)(const tessera::ProcessAddress&, std::size_t, std::uint64_t) noexcept;
using RttiDiscoverFn = tessera::Result<tessera::rtti::RttiCatalog> (*)(const tessera::Process&, tessera::AddressRange, const tessera::PeImage*);
using PythonDetectFn = tessera::Result<tessera::rtti::PythonEnvironmentInfo> (*)(const tessera::Process&, tessera::AddressRange, const tessera::PeImage*);
using PythonInittabFn = tessera::Result<std::vector<tessera::rtti::PyInittabEntry>> (*)(const tessera::Process&, tessera::AddressRange);
using PythonMethodsFn = tessera::Result<std::vector<tessera::rtti::PyMethodTable>> (*)(const tessera::Process&, tessera::AddressRange);
using PythonLinkFn = void (*)(const tessera::Process&, tessera::AddressRange, std::span<tessera::rtti::PyMethodTable>, std::span<const tessera::rtti::PyInittabEntry>, tessera::Address*);
using PythonMembersFn = tessera::Result<std::vector<tessera::rtti::PyMemberEntry>> (*)(const tessera::Process&, tessera::AddressRange);
using PythonGetSetFn = tessera::Result<std::vector<tessera::rtti::PyGetSetEntry>> (*)(const tessera::Process&, tessera::AddressRange);
using PythonTypesFn = tessera::Result<std::vector<tessera::rtti::PyDiscoveredTypeObject>> (*)(const tessera::Process&, tessera::AddressRange);
using PythonDiscoverFn = tessera::Result<tessera::rtti::PythonBridgeCatalog> (*)(const tessera::Process&, tessera::AddressRange, const tessera::PeImage*);
using PythonFindFn = tessera::Result<tessera::rtti::PyMethodEntry> (tessera::rtti::PythonBridgeCatalog::*)(std::string_view) const;
using PythonExportFn = tessera::Status (tessera::rtti::PythonBridgeCatalog::*)(tessera::reflection::TypeRegistry&) const;

[[maybe_unused]] MemoryReadFn volatile g_memory_read = &tessera::MemoryReader::read_exact;
[[maybe_unused]] ModuleSnapshotFn volatile g_module_snapshot = &tessera::ModuleCatalog::snapshot;
[[maybe_unused]] ScanFn volatile g_scan = &tessera::Scanner::scan;
[[maybe_unused]] ScanBatchFn volatile g_scan_batch = &tessera::Scanner::scan_batch;
[[maybe_unused]] XrefCallsFn volatile g_xref_calls = &tessera::xref::find_calls;
[[maybe_unused]] XrefBatchFn volatile g_xref_batch = &tessera::xref::find_pointer_refs_batch;
[[maybe_unused]] CursorOffsetFn volatile g_cursor_offset = &tessera::AddressCursor::offset;
[[maybe_unused]] PatchNopFn volatile g_patch_nop = &tessera::Patch::nop;
[[maybe_unused]] HookCreateFn volatile g_hook_create =
    static_cast<HookCreateFn>(&tessera::Hook<HookFn>::create);
[[maybe_unused]] NativeBackendFn volatile g_native_backend = &tessera::native_inline_hook_backend;
[[maybe_unused]] PeMemoryFn volatile g_pe_memory = &tessera::PeImage::from_memory;
[[maybe_unused]] PeFileFn volatile g_pe_file = &tessera::PeImage::from_file;
[[maybe_unused]] PeRawFn volatile g_pe_raw = &tessera::PeImage::from_raw_bytes;
[[maybe_unused]] PatternParseFn volatile g_pattern_parse = &tessera::Pattern::parse;
[[maybe_unused]] JsonParseFn volatile g_json_parse = &tessera::json::parse;
[[maybe_unused]] Rel32Fn volatile g_resolver_abs32_to_rva = &tessera::resolve::abs32_to_rva;
[[maybe_unused]] RttiDiscoverFn volatile g_rtti_discover = &tessera::rtti::RttiCatalog::discover_all;
[[maybe_unused]] PythonDetectFn volatile g_python_detect = &tessera::rtti::PythonBridgeScanner::detect_environment;
[[maybe_unused]] PythonInittabFn volatile g_python_inittab = &tessera::rtti::PythonBridgeScanner::scan_inittab;
[[maybe_unused]] PythonMethodsFn volatile g_python_methods = &tessera::rtti::PythonBridgeScanner::scan_method_tables;
[[maybe_unused]] PythonLinkFn volatile g_python_link = &tessera::rtti::PythonBridgeScanner::link_tables_to_modules;
[[maybe_unused]] PythonMembersFn volatile g_python_members = &tessera::rtti::PythonBridgeScanner::scan_member_tables;
[[maybe_unused]] PythonGetSetFn volatile g_python_getset = &tessera::rtti::PythonBridgeScanner::scan_getset_tables;
[[maybe_unused]] PythonTypesFn volatile g_python_types = &tessera::rtti::PythonBridgeScanner::scan_type_objects;
[[maybe_unused]] PythonDiscoverFn volatile g_python_discover = &tessera::rtti::PythonBridgeScanner::discover_all;
[[maybe_unused]] PythonFindFn volatile g_python_find = &tessera::rtti::PythonBridgeCatalog::find_method;
[[maybe_unused]] PythonExportFn volatile g_python_export = &tessera::rtti::PythonBridgeCatalog::export_to_registry;

static_assert(sizeof(tessera::Process) > 0);
static_assert(sizeof(tessera::MemoryReader) > 0);
static_assert(sizeof(tessera::PeImage) > 0);
static_assert(sizeof(tessera::Scanner) > 0);
static_assert(sizeof(tessera::AddressCursor) > 0);
static_assert(sizeof(tessera::Patch) > 0);
static_assert(sizeof(tessera::Hook<HookFn>) > 0);
static_assert(sizeof(tessera::rtti::RttiCatalog) > 0);
static_assert(sizeof(tessera::rtti::PythonBridgeScanner) > 0);

[[nodiscard]] int run_consumer() {
    const auto pattern = tessera::Pattern::parse("90");
    const auto pe = tessera::PeImage::from_raw_bytes(std::span<const std::byte>{});
    const auto json = tessera::json::parse("null");
    const auto python = tessera::rtti::PythonBridgeCatalog{}.find_method("missing");
    if (!pattern || pe || !json || python) {
        return 1;
    }

    auto& backend = tessera::native_inline_hook_backend();
    if (!backend.available()) {
        return 2;
    }
    auto invalid_hook = tessera::Hook<HookFn>::create(
        tessera::Address{}, &consumer_noop, &backend);
    if (invalid_hook) {
        return 3;
    }

#if TESSERA_CONSUMER_WITH_PROFILE
    tessera::profile::Profile profile{};
    profile.id = "standalone.consumer";
    profile.name = "Standalone consumer";
    auto profile_json = tessera::profile::serialize_profile_to_json(profile);
    if (!profile_json || !tessera::profile::deserialize_profile_from_json(*profile_json)) {
        return 4;
    }
#endif

#if TESSERA_CONSUMER_WITH_TARGETS
    tessera::targets::TargetProfile target{};
    target.application.application_id = "standalone.consumer";
    target.application.executables = {"consumer.exe"};
    if (!tessera::targets::validate_target_profile_schema(target)) {
        return 5;
    }
    auto target_json = tessera::targets::serialize_target_profile_to_json(target);
    if (!target_json || !tessera::targets::deserialize_target_profile_from_json(*target_json)) {
        return 6;
    }
#endif

    return 0;
}

} // namespace

#if defined(TESSERA_STANDALONE_SDK_CONSUMER)
int main() {
    return run_consumer();
}
#else
TEST_CASE("Installed SDK public modules compile, link, and execute", "[standalone][sdk]") {
    REQUIRE(run_consumer() == 0);
}
#endif
