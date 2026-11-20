#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>

#include "tessera/memory/memory_reader.hpp"

namespace tessera::rtti::detail {

template <class Fn>
void for_each_readable_chunk(const MemoryReader& reader,
                             AddressRange range,
                             std::size_t overlap,
                             Fn&& fn) {
    const std::uint64_t mod_begin = range.begin().value();
    const std::uint64_t mod_end = mod_begin + range.size();
    constexpr std::size_t kChunk = 64 * 1024;

    std::uint64_t cur = mod_begin;
    while (cur < mod_end) {
        auto q = reader.query(Address{cur});
        if (!q || q->size == 0) {
            break;
        }
        const std::uint64_t reg_end = q->base.value() + q->size;
        if (reg_end <= cur) {
            break;
        }
        const std::uint64_t clip_begin = (std::max)(cur, q->base.value());
        const std::uint64_t clip_end = (std::min)(reg_end, mod_end);
        if (clip_begin < clip_end && q->state == MemoryState::Committed &&
            !has_flag(q->protection, MemoryProtection::NoAccess) &&
            !has_flag(q->protection, MemoryProtection::Guard)) {
            const bool is_exec = has_flag(q->protection, MemoryProtection::Execute);
            for (std::uint64_t pos = clip_begin; pos < clip_end; pos += kChunk) {
                const std::size_t read_len = static_cast<std::size_t>(
                    (std::min)(static_cast<std::uint64_t>(kChunk + overlap), clip_end - pos));
                if (auto got = reader.read_bytes(Address{pos}, read_len)) {
                    fn(Address{pos}, *got, is_exec);
                }
            }
        }
        cur = reg_end;
    }
}

} // namespace tessera::rtti::detail
