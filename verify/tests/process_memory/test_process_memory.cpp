#include <catch2/catch_test_macros.hpp>

#include <Windows.h>

#include <array>
#include <cstring>
#include <cstdio>
#include <memory>
#include <string>

#include "FakeMemoryBackend.hpp"
#include "tessera/memory/memory.hpp"
#include "tessera/memory/protection_scope.hpp"
#include "tessera/platform/windows/native.hpp"
#include "tessera/process/process.hpp"

TEST_CASE("Process::current and Process::open contracts", "[process]") {
    using namespace tessera;

    Process cur = Process::current();
    REQUIRE(cur.is_local());
    REQUIRE(cur.pid().valid());
    REQUIRE(cur.pointer_size() == sizeof(void*));
    REQUIRE(cur.is_alive().value_or(false));

    // Invalid PID 0 is rejected
    auto bad0 = Process::open(ProcessId{0});
    REQUIRE_FALSE(bad0.has_value());
    REQUIRE(bad0.error().code == ErrorCode::InvalidArgument);

    // Non-existent PID fails with ProcessNotFound or AccessDenied
    auto bad_pid = Process::open(ProcessId{0xFFFFFFFCu});
    REQUIRE_FALSE(bad_pid.has_value());

    // Opening current PID with explicit Read-only access honors the access parameter
    auto self_ro = Process::open(cur.pid(), ProcessAccess::Read | ProcessAccess::Query);
    REQUIRE(self_ro.has_value());
    REQUIRE(self_ro->is_local());
    REQUIRE(self_ro->info().granted_access == (ProcessAccess::Read | ProcessAccess::Query));

    int local_var = 42;
    const Address var_addr{
        static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(&local_var))};
    MemoryReader ro_reader{*self_ro};
    REQUIRE(ro_reader.read<int>(var_addr).value() == 42);

    // Writing through a Read-only handle must fail!
    MemoryWriter ro_writer{*self_ro};
    auto write_fail = ro_writer.write_value<int>(var_addr, 99);
    REQUIRE_FALSE(write_fail.has_value());
    REQUIRE(local_var == 42);
}


TEST_CASE("Execute-only regions are not readable", "[memory][protection]") {
    using namespace tessera;
    using namespace tessera::testing;

    auto backend = std::make_shared<FakeMemoryBackend>();
    backend->map_region(Address{0x12000}, 0x1000, MemoryProtection::Execute);
    Process process = FakeMemoryBackend::make_process(backend, Architecture::X64);
    MemoryReader reader{process};

    const AddressRange range{Address{0x12000}, 16};
    REQUIRE_FALSE(reader.is_readable(range).value());
    REQUIRE(reader.is_executable(range).value());
    REQUIRE_FALSE(matches_region_filter(
        tessera::MemoryRegionInfo{
            .base = Address{0x12000},
            .allocation_base = Address{0x12000},
            .size = 0x1000,
            .state = MemoryState::Committed,
            .protection = MemoryProtection::Execute,
            .allocation_protection = MemoryProtection::Execute,
            .type = MemoryType::Private,
        },
        RegionFilter{}));
    REQUIRE_FALSE(reader.read<std::uint8_t>(Address{0x12000}).has_value());
}

TEST_CASE("Unbounded region enumeration stops at the address-space boundary", "[memory][regions]") {
    using namespace tessera;
    using namespace tessera::testing;

    auto backend = std::make_shared<FakeMemoryBackend>();
    backend->map_region(Address{0x10000}, 0x1000, MemoryProtection::Read);
    backend->map_region(Address{0x30000}, 0x2000, MemoryProtection::Read);

    Process process = FakeMemoryBackend::make_process(backend, Architecture::X86);
    const auto regions = enumerate_regions(process);

    REQUIRE(regions.has_value());
    REQUIRE(regions->size() == 2);
    REQUIRE((*regions)[0].base == Address{0x10000});
    REQUIRE((*regions)[1].base == Address{0x30000});

    // A caller-supplied bounded range is explicit; do not silently truncate it.
    const auto bounded = enumerate_regions(
        process, AddressRange{Address{0x10000}, 0x100000});
    REQUIRE_FALSE(bounded.has_value());
    REQUIRE(bounded.error().code == ErrorCode::OutOfRange);
}

TEST_CASE("FakeMemoryBackend reader, writer, rollback, and protection warnings", "[memory]") {
    using namespace tessera;
    using namespace tessera::testing;

    auto backend = std::make_shared<FakeMemoryBackend>();
    auto& r1 = backend->map_region(Address{0x10000}, 0x1000, MemoryProtection::Read);
    auto& r2 = backend->map_region(Address{0x11000}, 0x1000, MemoryProtection::ReadWrite);

    backend->poke_value<std::uint32_t>(Address{0x10000}, 0x11223344u);
    backend->poke_value<std::uint32_t>(Address{0x11000}, 0x55667788u);

    const char* cstr = "Hello Tessera";
    backend->poke_bytes(
        Address{0x10100},
        std::as_bytes(std::span<const char>(cstr, std::strlen(cstr) + 1)));

    const std::u16string_view u16str = u"WideText";
    backend->poke_bytes(
        Address{0x10200},
        std::as_bytes(std::span<const char16_t>(u16str.data(), u16str.size() + 1)));

    Process proc = FakeMemoryBackend::make_process(backend, Architecture::X64);
    MemoryReader reader{proc};
    MemoryWriter writer{proc};

    REQUIRE(reader.read<std::uint32_t>(Address{0x10000}).value() == 0x11223344u);
    REQUIRE(reader.read_cstring(Address{0x10100}).value() == "Hello Tessera");
    REQUIRE(reader.read_utf16(Address{0x10200}).value() == u"WideText");

    // Multi-region write across r1 (Read-only, requires temporary protection elevation) and r2
    std::array<std::byte, 8> cross_data{
        std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4},
        std::byte{5}, std::byte{6}, std::byte{7}, std::byte{8}};
    auto rep = writer.write_with_report(Address{0x10FFC}, cross_data);
    REQUIRE(rep.has_value());
    REQUIRE(rep->succeeded());
    REQUIRE(rep->bytes_written == 8);
    REQUIRE(rep->regions_touched == 2);
    // r1 protection was restored back to Read
    REQUIRE(r1.protection == MemoryProtection::Read);

    // Simulate mid-write failure in r2 and verify rollback restores r1's original bytes!
    const auto orig_b0 = *backend->peek_byte(Address{0x10FFC});
    r2.writable_prefix_limit = 2; // Fail after 2 bytes inside r2
    std::array<std::byte, 8> bad_write{
        std::byte{0xAA}, std::byte{0xAA}, std::byte{0xAA}, std::byte{0xAA},
        std::byte{0xBB}, std::byte{0xBB}, std::byte{0xBB}, std::byte{0xBB}};
    auto fail_rep = writer.write_with_report(Address{0x10FFC}, bad_write);
    REQUIRE(fail_rep.has_value());
    REQUIRE_FALSE(fail_rep->succeeded());
    REQUIRE(fail_rep->rolled_back);
    REQUIRE_FALSE(fail_rep->rollback_error.has_value());
    REQUIRE(*backend->peek_byte(Address{0x10FFC}) == orig_b0);
    r2.writable_prefix_limit.reset();

    // A failed protection restore remains explicitly owned by WriteReport.
    // The caller can retry after the transient OS/backend failure is resolved.
    r1.restore_failures_remaining = 2;
    auto warn_rep = writer.write_with_report(
        Address{0x10000}, std::span<const std::byte>(cross_data.data(), 4));
    REQUIRE(warn_rep.has_value());
    REQUIRE_FALSE(warn_rep->succeeded());
    REQUIRE(warn_rep->protection_restore_warning.has_value());
    REQUIRE(warn_rep->protection_restore_warning->code == ErrorCode::ProtectionRestoreFailed);
    REQUIRE(warn_rep->pending_protection_restores.size() == 1);
    REQUIRE(r1.protection == MemoryProtection::ReadWrite);

    // A repeated failure must preserve the same retry ticket and keep the
    // report unsuccessful until a later restoration actually succeeds.
    auto repeated_failure = writer.restore_pending_protections(*warn_rep);
    REQUIRE_FALSE(repeated_failure.has_value());
    REQUIRE(warn_rep->pending_protection_restores.size() == 1);
    REQUIRE_FALSE(warn_rep->succeeded());

    REQUIRE(writer.restore_pending_protections(*warn_rep).has_value());
    REQUIRE(warn_rep->pending_protection_restores.empty());
    REQUIRE_FALSE(warn_rep->protection_restore_warning.has_value());
    REQUIRE(warn_rep->succeeded());
    REQUIRE(r1.protection == MemoryProtection::Read);
}

#if !defined(TESSERA_PORTABLE_VALIDATION)
TEST_CASE("Remote process integration with tessera_test_host", "[process][integration]") {
    using namespace tessera;

#if defined(TESSERA_TEST_HOST_PATH)
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::wstring cmd = std::wstring(L"\"") + std::wstring(TEXT(TESSERA_TEST_HOST_PATH)) + L"\" --wait";

    const BOOL launched = ::CreateProcessW(
        nullptr, cmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    REQUIRE(launched != FALSE);

    // Give the host process a moment to initialize g_payload
    ::Sleep(50);

    auto remote_proc = Process::open(ProcessId{pi.dwProcessId});
    REQUIRE(remote_proc.has_value());
    REQUIRE_FALSE(remote_proc->is_local());
    REQUIRE(remote_proc->is_alive().value_or(false));

    auto regions = enumerate_regions(*remote_proc);
    if (!regions) {
        std::fprintf(stderr, "Remote region enumeration failed: %s (native=%u, operation=%.*s, detail=%s)\n",
                     error_code_name(regions.error().code).data(),
                     regions.error().native,
                     static_cast<int>(regions.error().operation.size()),
                     regions.error().operation.data(),
                     regions.error().detail.c_str());
    }
    REQUIRE(regions.has_value());
    REQUIRE_FALSE(regions->empty());

    ::TerminateProcess(pi.hProcess, 0);
    ::WaitForSingleObject(pi.hProcess, 2000);
    ::CloseHandle(pi.hThread);
    ::CloseHandle(pi.hProcess);
#endif
}

#endif // !TESSERA_PORTABLE_VALIDATION

TEST_CASE("MemoryWriter status convenience retries a transient protection restore failure",
           "[memory][protection]") {
    using namespace tessera;
    using namespace tessera::testing;

    auto backend = std::make_shared<FakeMemoryBackend>();
    auto& region = backend->map_region(
        Address{0x28000}, 0x1000, MemoryProtection::Read);
    region.restore_failures_remaining = 1;
    Process process = FakeMemoryBackend::make_process(backend);
    MemoryWriter writer{process};
    const std::array<std::byte, 4> bytes{
        std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}};

    REQUIRE(writer.write(Address{0x28000}, bytes).has_value());
    REQUIRE(region.protection == MemoryProtection::Read);
}

TEST_CASE("MemoryWriter rollback retains the first original protection restore ticket",
           "[memory][protection][rollback]") {
    using namespace tessera;
    using namespace tessera::testing;

    auto backend = std::make_shared<FakeMemoryBackend>();
    auto& read_only = backend->map_region(
        Address{0x30000}, 0x1000, MemoryProtection::Read);
    auto& writable = backend->map_region(
        Address{0x31000}, 0x1000, MemoryProtection::ReadWrite);
    std::array<std::byte, 8> original{
        std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4},
        std::byte{5}, std::byte{6}, std::byte{7}, std::byte{8}};
    backend->poke_bytes(Address{0x30FFC}, original);

    Process process = FakeMemoryBackend::make_process(backend);
    MemoryWriter writer{process};

    // The first region writes, but its first protection restore fails. The
    // second region then partially writes and forces rollback of the first.
    read_only.restore_failures_remaining = 1;
    writable.writable_prefix_limit = 2;
    const std::array<std::byte, 8> replacement{
        std::byte{0xA1}, std::byte{0xA2}, std::byte{0xA3}, std::byte{0xA4},
        std::byte{0xB1}, std::byte{0xB2}, std::byte{0xB3}, std::byte{0xB4}};

    auto report = writer.write_with_report(Address{0x30FFC}, replacement);
    REQUIRE(report.has_value());
    REQUIRE(report->rolled_back);
    REQUIRE_FALSE(report->rollback_error.has_value());
    REQUIRE(report->pending_protection_restores.size() == 1);
    REQUIRE(read_only.protection == MemoryProtection::ReadWrite);
    for (std::size_t index = 0; index < original.size(); ++index) {
        REQUIRE(backend->peek_byte(Address{0x30FFC + index}) == original[index]);
    }

    // The rollback pass must not replace the ticket's true original Read
    // protection with the temporary ReadWrite protection.
    REQUIRE(writer.restore_pending_protections(*report).has_value());
    REQUIRE(report->pending_protection_restores.empty());
    REQUIRE_FALSE(report->protection_restore_warning.has_value());
    REQUIRE(read_only.protection == MemoryProtection::Read);
    // The bytes/protection are recovered, but the original write operation
    // still failed and remains visible in write_error.
    REQUIRE(report->write_error.has_value());
    REQUIRE_FALSE(report->succeeded());
}

TEST_CASE("ProtectionScope retains restoration ownership after a failed restore", "[memory][protection]") {
    using namespace tessera;
    using namespace tessera::testing;

    auto backend = std::make_shared<FakeMemoryBackend>();
    auto& region = backend->map_region(Address{0x20000}, 0x1000, MemoryProtection::Read);
    Process process = FakeMemoryBackend::make_process(backend);

    auto scope_result = ProtectionScope::create(
        process, AddressRange{Address{0x20000}, 16}, MemoryProtection::ReadWrite);
    REQUIRE(scope_result.has_value());
    auto scope = std::move(*scope_result);
    REQUIRE(scope.active());
    REQUIRE(region.protection == MemoryProtection::ReadWrite);

    region.fail_restore_protect = true;
    auto failed_restore = scope.restore();
    REQUIRE_FALSE(failed_restore.has_value());
    REQUIRE(failed_restore.error().code == ErrorCode::ProtectionRestoreFailed);
    REQUIRE(scope.active());
    REQUIRE(region.protection == MemoryProtection::ReadWrite);

    // Explicitly retry after the injected API failure is removed. The failed
    // attempt must not have consumed the scope's restoration responsibility.
    region.fail_restore_protect = false;
    REQUIRE(scope.restore().has_value());
    REQUIRE_FALSE(scope.active());
    REQUIRE(region.protection == MemoryProtection::Read);
}

TEST_CASE("MemoryWriter reports rollback protection restoration failures to the observer",
           "[memory][protection][rollback][diagnostics]") {
    using namespace tessera;
    using namespace tessera::testing;

    struct CapturingObserver final : DiagnosticObserver {
        std::size_t warning_count = 0;
        std::string_view last_category{};
        std::string_view last_message{};
        void on_diagnostic(const DiagnosticEvent& event) noexcept override {
            if (event.severity == DiagnosticSeverity::Warning) {
                ++warning_count;
                last_category = event.category;
                last_message = event.message;
            }
        }
    } observer;

    auto backend = std::make_shared<FakeMemoryBackend>();
    auto& read_only = backend->map_region(
        Address{0x32000}, 0x1000, MemoryProtection::Read);
    auto& writable = backend->map_region(
        Address{0x33000}, 0x1000, MemoryProtection::ReadWrite);
    std::array<std::byte, 8> original{
        std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4},
        std::byte{5}, std::byte{6}, std::byte{7}, std::byte{8}};
    backend->poke_bytes(Address{0x32FFC}, original);

    // Per-region protect attempts: initial elevation=0, initial restore=1,
    // rollback elevation=2, rollback restore=3. Fail only the final step.
    read_only.fail_protect_on_attempt = 3u;
    writable.writable_prefix_limit = 2;
    Process process = FakeMemoryBackend::make_process(
        backend, Architecture::X64, ProcessId{4242}, &observer);
    MemoryWriter writer{process};
    const std::array<std::byte, 8> replacement{
        std::byte{0xA1}, std::byte{0xA2}, std::byte{0xA3}, std::byte{0xA4},
        std::byte{0xB1}, std::byte{0xB2}, std::byte{0xB3}, std::byte{0xB4}};

    auto report = writer.write_with_report(Address{0x32FFC}, replacement);
    REQUIRE(report.has_value());
    REQUIRE(report->rolled_back);
    REQUIRE_FALSE(report->rollback_error.has_value());
    REQUIRE(report->protection_restore_warning.has_value());
    REQUIRE(report->pending_protection_restores.size() == 1);
    REQUIRE(observer.warning_count == 1);
    REQUIRE(observer.last_category == "MemoryWriter");
    REQUIRE(observer.last_message.find("during rollback") != std::string_view::npos);
    REQUIRE(read_only.protection == MemoryProtection::ReadWrite);

    REQUIRE(writer.restore_pending_protections(*report).has_value());
    REQUIRE(read_only.protection == MemoryProtection::Read);
}
