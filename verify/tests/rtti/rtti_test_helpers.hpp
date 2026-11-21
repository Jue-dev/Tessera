#pragma once

#include <cstring>
#include <string_view>
#include <vector>

namespace rtti_test_support {

using namespace tessera;

inline void write_u32(std::vector<std::byte>& buf, std::size_t off, std::uint32_t val) {
    std::memcpy(buf.data() + off, &val, 4);
}

inline void write_i32(std::vector<std::byte>& buf, std::size_t off, std::int32_t val) {
    std::memcpy(buf.data() + off, &val, 4);
}

inline void write_u64(std::vector<std::byte>& buf, std::size_t off, std::uint64_t val) {
    std::memcpy(buf.data() + off, &val, 8);
}

inline void write_f32(std::vector<std::byte>& buf, std::size_t off, float val) {
    std::memcpy(buf.data() + off, &val, 4);
}

inline void write_cstr(std::vector<std::byte>& buf, std::size_t off, std::string_view s) {
    std::memcpy(buf.data() + off, s.data(), s.size());
    buf[off + s.size()] = std::byte{0};
}

} // namespace rtti_test_support
