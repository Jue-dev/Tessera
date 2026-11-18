#pragma once

#include <utility>

#if !defined(NDEBUG)
    #if defined(_MSC_VER)
        #define TESSERA_ASSERT(expr)                                                               \
            do {                                                                                   \
                if (!(expr)) [[unlikely]] {                                                        \
                    __debugbreak();                                                                \
                }                                                                                  \
            } while (false)
    #else
        #define TESSERA_ASSERT(expr)                                                               \
            do {                                                                                   \
                if (!(expr)) [[unlikely]] {                                                        \
                    __builtin_trap();                                                              \
                }                                                                                  \
            } while (false)
    #endif
#else
    #define TESSERA_ASSERT(expr) ((void)sizeof(bool(expr)))
#endif

#define TESSERA_ASSERT_MSG(expr, msg) TESSERA_ASSERT((expr) && (msg))

namespace tessera {

[[noreturn]] inline void unreachable() noexcept {
    TESSERA_ASSERT_MSG(false, "Reached unreachable code path");
    std::unreachable();
}

} // namespace tessera
