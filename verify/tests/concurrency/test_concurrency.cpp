#include <catch2/catch_test_macros.hpp>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_set>
#include <utility>
#include <vector>

#include "FakeMemoryBackend.hpp"
#include "tessera/hook/hook.hpp"
#include "tessera/logging/logging.hpp"
#include "tessera/memory/protection_scope.hpp"
#include "tessera/memory/process_address.hpp"
#include "tessera/patch/patch.hpp"
#include "tessera/pattern/pattern.hpp"
#include "tessera/scanner/scanner.hpp"

namespace {

class ConcurrentHookBackend final : public tessera::HookBackend {
public:
    [[nodiscard]] bool available() const noexcept override { return true; }

    [[nodiscard]] tessera::Result<tessera::HookToken> attach(
        tessera::Address target, void* detour, const tessera::HookOptions& options) override {
        if (target.is_null() || detour == nullptr) {
            return tessera::fail(tessera::ErrorCode::InvalidArgument, "ConcurrentHookBackend::attach");
        }
        {
            const std::lock_guard lock(mutex_);
            if (!active_targets_.insert(target.value()).second) {
                return tessera::fail(tessera::ErrorCode::Conflict, "ConcurrentHookBackend::attach");
            }
        }
        attached_.fetch_add(1, std::memory_order_relaxed);
        return tessera::HookToken{
            .target = reinterpret_cast<void*>(static_cast<std::uintptr_t>(target.value())),
            .detour = detour,
            .trampoline = detour,
            .threads = options.threads,
            .observer = options.observer,
            .backend_data = this,
        };
    }

    [[nodiscard]] tessera::Status detach(tessera::HookToken& token) override {
        if (token.backend_data != this || token.target == nullptr) {
            return tessera::fail(tessera::ErrorCode::InvalidArgument, "ConcurrentHookBackend::detach");
        }
        const auto target = reinterpret_cast<std::uintptr_t>(token.target);
        {
            const std::lock_guard lock(mutex_);
            if (active_targets_.erase(static_cast<std::uint64_t>(target)) != 1u) {
                return tessera::fail(tessera::ErrorCode::NotFound, "ConcurrentHookBackend::detach");
            }
        }
        detached_.fetch_add(1, std::memory_order_relaxed);
        token = {};
        return tessera::ok();
    }

    [[nodiscard]] std::size_t active_count() const {
        const std::lock_guard lock(mutex_);
        return active_targets_.size();
    }

    [[nodiscard]] std::uint32_t attached_count() const noexcept {
        return attached_.load(std::memory_order_relaxed);
    }

    [[nodiscard]] std::uint32_t detached_count() const noexcept {
        return detached_.load(std::memory_order_relaxed);
    }

private:
    mutable std::mutex mutex_{};
    std::unordered_set<std::uint64_t> active_targets_{};
    std::atomic<std::uint32_t> attached_{0};
    std::atomic<std::uint32_t> detached_{0};
};

} // namespace

TEST_CASE("Concurrent logger, scanner, patch, hook and protection operations remain race-free",
          "[concurrency][stress]") {
    using namespace tessera;
    using namespace tessera::testing;
    using namespace tessera::logging;

    constexpr std::size_t kWorkers = 8;
    constexpr std::size_t kIterations = 24;
    constexpr std::uint64_t kScanBase = 0x100000ULL;
    constexpr std::uint64_t kWorkerBase = 0x200000ULL;
    constexpr std::uint64_t kWorkerStride = 0x3000ULL;

    auto backend = std::make_shared<FakeMemoryBackend>();
    backend->map_region(Address{kScanBase}, 0x8000, MemoryProtection::ReadWrite);
    std::vector<std::byte> scan_bytes(0x8000, std::byte{0x11});
    for (std::size_t i = 0; i + 4 <= scan_bytes.size(); i += 257) {
        scan_bytes[i] = std::byte{0xAA};
        scan_bytes[i + 1] = std::byte{0xBB};
        scan_bytes[i + 2] = std::byte{0xCC};
        scan_bytes[i + 3] = std::byte{0xDD};
    }
    backend->poke_bytes(Address{kScanBase}, scan_bytes);

    for (std::size_t worker = 0; worker < kWorkers; ++worker) {
        backend->map_region(Address{kWorkerBase + worker * kWorkerStride},
                             0x2000, MemoryProtection::ExecuteReadWrite);
    }
    Process process = FakeMemoryBackend::make_process(
        backend, sizeof(void*) == 8 ? Architecture::X64 : Architecture::X86);

    auto scan_pattern = Pattern::parse("AA BB CC DD");
    auto batch_pattern = Pattern::parse("BB CC DD");
    REQUIRE(scan_pattern.has_value());
    REQUIRE(batch_pattern.has_value());
    const std::array<Pattern, 2> batch_patterns{*scan_pattern, *batch_pattern};
    const AddressRange scan_range{Address{kScanBase}, 0x8000};
    Scanner scanner{process};

    auto logger = std::make_shared<Logger>("concurrency", LogLevel::Trace);
    auto primary_sink = std::make_shared<MemorySink>();
    auto alternate_sink = std::make_shared<MemorySink>();
    logger->add_sink(primary_sink);

    ConcurrentHookBackend hook_backend;
    int detour_storage = 0;
    auto hook_result = detail::HookCore::create(Address{0x40000000ULL}, &detour_storage, &hook_backend);
    REQUIRE(hook_result.has_value());
    detail::HookCore shared_hook = std::move(*hook_result);
    std::atomic<bool> failed{false};
    std::vector<std::thread> workers;
    workers.reserve(kWorkers);

    for (std::size_t worker = 0; worker < kWorkers; ++worker) {
        workers.emplace_back([&, worker] {
            const std::uint64_t region_base = kWorkerBase + worker * kWorkerStride;
            for (std::size_t iteration = 0; iteration < kIterations; ++iteration) {
                logger->set_min_level((iteration % 2u) == 0u ? LogLevel::Trace : LogLevel::Warn);
                logger->add_sink((iteration % 2u) == 0u ? primary_sink : alternate_sink);
                logger->warn("worker={} iteration={}", worker, iteration);
                logger->clear_sinks();
                logger->add_sink(primary_sink);
                primary_sink->set_enabled((iteration % 3u) != 0u);

                auto scanned = scanner.scan(scan_range, *scan_pattern);
                if (!scanned || scanned->hits.empty()) {
                    failed.store(true, std::memory_order_relaxed);
                }
                auto batch = scanner.scan_batch(scan_range, batch_patterns);
                if (!batch || batch->size() != batch_patterns.size() ||
                    batch->front().hits.empty() || batch->back().hits.empty()) {
                    failed.store(true, std::memory_order_relaxed);
                }

                auto patch = Patch::create(
                    ProcessAddress{process, Address{region_base}},
                    std::vector<std::byte>{std::byte{0x90}, std::byte{0x90}, std::byte{0x90}});
                if (!patch || !patch->apply() || !patch->restore()) {
                    failed.store(true, std::memory_order_relaxed);
                }

                auto protection = ProtectionScope::create(
                    process, AddressRange{Address{region_base + 0x100}, 0x80},
                    MemoryProtection::ReadWrite);
                if (!protection) {
                    failed.store(true, std::memory_order_relaxed);
                } else {
                    std::array<std::byte, 4> probe{};
                    MemoryReader reader{process};
                    MemoryWriter writer{process};
                    if (!reader.read_exact(Address{region_base + 0x100}, probe) ||
                        !writer.write(Address{region_base + 0x100}, probe) ||
                        !protection->restore()) {
                        failed.store(true, std::memory_order_relaxed);
                    }
                }

                if (!shared_hook.install(HookOptions{.threads = ThreadPolicy::None})) {
                    failed.store(true, std::memory_order_relaxed);
                }
                (void)shared_hook.installed();
                if (!shared_hook.remove()) {
                    failed.store(true, std::memory_order_relaxed);
                }
            }
        });
    }

    for (auto& worker : workers) {
        worker.join();
    }

    REQUIRE_FALSE(failed.load(std::memory_order_relaxed));
    REQUIRE_FALSE(shared_hook.installed());
    REQUIRE(hook_backend.active_count() == 0);
    REQUIRE(hook_backend.attached_count() == hook_backend.detached_count());
    REQUIRE_FALSE(primary_sink->records().empty());
    REQUIRE_FALSE(alternate_sink->records().empty());
}
