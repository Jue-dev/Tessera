#include "tessera/utility/encoding.hpp"

#include <cstdint>

namespace tessera::encoding {

// The portable Windows-backend mock links the logger without compiling the
// Win32 shell/utility translation unit. Its test messages are ASCII; reject
// non-ASCII input rather than pretending this shim is the production codec.
Result<std::u16string> utf8_to_utf16(std::string_view utf8) {
    std::u16string result;
    result.reserve(utf8.size());
    for (const unsigned char ch : utf8) {
        if (ch > 0x7Fu) {
            return fail(ErrorCode::ParseError, "encoding::utf8_to_utf16",
                        0, "Portable Windows mock codec accepts ASCII test messages only");
        }
        result.push_back(static_cast<char16_t>(ch));
    }
    return result;
}

} // namespace tessera::encoding
