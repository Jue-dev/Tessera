#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "tessera/core/result.hpp"
#include "tessera/core/types.hpp"
#include "tessera/memory/memory_reader.hpp"
#include "tessera/memory/memory_writer.hpp"
#include "tessera/process/process.hpp"

namespace tessera {

class AddressCursor;

class [[nodiscard]] ProcessAddress {
public:
    ProcessAddress(Process process, Address address) noexcept
        : process_(std::move(process)), address_(address) {}

    [[nodiscard]] const Process& process() const noexcept { return process_; }
    [[nodiscard]] Address address() const noexcept { return address_; }
    [[nodiscard]] std::uint64_t value() const noexcept { return address_.value(); }
    [[nodiscard]] bool is_null() const noexcept { return address_.is_null(); }
    explicit operator bool() const noexcept { return !address_.is_null(); }

    [[nodiscard]] Result<ProcessAddress> offset(std::int64_t delta) const noexcept {
        auto next = address_.offset(delta);
        if (!next) {
            return std::unexpected(next.error());
        }
        return ProcessAddress{process_, *next};
    }

    [[nodiscard]] Result<ProcessAddress> deref() const noexcept {
        MemoryReader reader{process_};
        auto ptr = reader.read_pointer(address_);
        if (!ptr) {
            return std::unexpected(ptr.error());
        }
        if (ptr->is_null()) {
            return fail(ErrorCode::NullAddress, "ProcessAddress::deref", 0, "Dereferenced pointer is null");
        }
        return ProcessAddress{process_, *ptr};
    }

    template <TriviallyReadable T>
    [[nodiscard]] Result<T> read() const noexcept {
        return MemoryReader{process_}.read<T>(address_);
    }

    [[nodiscard]] Result<std::vector<std::byte>> read_bytes(std::size_t count,
                                                            ReadLimits limits = {}) const {
        return MemoryReader{process_}.read_bytes(address_, count, limits);
    }

    [[nodiscard]] Result<std::string> read_cstring(std::size_t max_chars = 256) const {
        return MemoryReader{process_}.read_cstring(address_, max_chars);
    }

    [[nodiscard]] Result<std::u16string> read_utf16(std::size_t max_chars = 256) const {
        return MemoryReader{process_}.read_utf16(address_, max_chars);
    }

    [[nodiscard]] Status write(std::span<const std::byte> data, WriteOptions options = {}) const {
        return MemoryWriter{process_}.write(address_, data, options);
    }

    template <TriviallyReadable T>
    [[nodiscard]] Status write_value(const T& val, WriteOptions options = {}) const {
        return MemoryWriter{process_}.write_value<T>(address_, val, options);
    }

    // Defined in tessera/resolver/address_cursor.hpp
    [[nodiscard]] AddressCursor cursor() const noexcept;

    [[nodiscard]] friend bool operator==(const ProcessAddress& lhs,
                                         const ProcessAddress& rhs) noexcept {
        return lhs.address_ == rhs.address_ && lhs.process_ == rhs.process_;
    }

private:
    Process process_;
    Address address_{};
};

namespace detail {

struct BindProcessAdapter {
    Process process;

    [[nodiscard]] ProcessAddress operator()(Address addr) const noexcept {
        return ProcessAddress{process, addr};
    }
};

template <TriviallyReadable T>
struct ReadAdapter {
    [[nodiscard]] Result<T> operator()(const ProcessAddress& pa) const noexcept {
        return pa.read<T>();
    }
};

} // namespace detail

[[nodiscard]] inline detail::BindProcessAdapter bind_process(Process process) noexcept {
    return detail::BindProcessAdapter{std::move(process)};
}

template <TriviallyReadable T>
inline constexpr detail::ReadAdapter<T> read{};

namespace local {

template <class F>
concept FunctionPointer = std::is_pointer_v<F> && std::is_function_v<std::remove_pointer_t<F>>;

// Unsafe local-process pointer conversion.
// Only succeeds if pa belongs to the current process and is non-null.
template <class T = void>
[[nodiscard]] Result<T*> ptr(const ProcessAddress& pa) noexcept {
    if (!pa.process().is_local()) {
        return fail(ErrorCode::InvalidArgument, "local::ptr", 0, "ProcessAddress is not local");
    }
    if (pa.is_null()) {
        return fail(ErrorCode::NullAddress, "local::ptr");
    }
    return reinterpret_cast<T*>(static_cast<std::uintptr_t>(pa.value()));
}

// Unsafe local-process function pointer conversion.
// Verifies that the target is in the current process and resides in executable memory.
template <FunctionPointer Fn>
[[nodiscard]] Result<Fn> function(const ProcessAddress& pa) noexcept {
    if (!pa.process().is_local()) {
        return fail(ErrorCode::InvalidArgument, "local::function", 0, "ProcessAddress is not local");
    }
    if (pa.is_null()) {
        return fail(ErrorCode::NullAddress, "local::function");
    }
    auto exec = MemoryReader{pa.process()}.is_executable(AddressRange{pa.address(), 1});
    if (!exec) {
        return std::unexpected(exec.error());
    }
    if (!*exec) {
        return fail(ErrorCode::AccessDenied, "local::function", 0, "Target address is not executable");
    }
    return reinterpret_cast<Fn>(static_cast<std::uintptr_t>(pa.value()));
}

// Invokes a function in the current process. SEH and C++ exceptions from the target are NOT caught.
template <FunctionPointer Fn, class... Args>
    requires std::invocable<Fn, Args...>
[[nodiscard]] auto call(const ProcessAddress& pa, Args&&... args)
    -> Result<std::invoke_result_t<Fn, Args...>> {
    using R = std::invoke_result_t<Fn, Args...>;
    auto fn_res = function<Fn>(pa);
    if (!fn_res) {
        return std::unexpected(fn_res.error());
    }
    if constexpr (std::is_void_v<R>) {
        (*fn_res)(std::forward<Args>(args)...);
        return ok();
    } else {
        return (*fn_res)(std::forward<Args>(args)...);
    }
}

} // namespace local

} // namespace tessera
