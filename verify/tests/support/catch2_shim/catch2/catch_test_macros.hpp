#pragma once

#include <cstdio>
#include <exception>
#include <source_location>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace tessera::test_runner {

struct FailureException : std::exception {
    std::string message;
    explicit FailureException(std::string msg) : message(std::move(msg)) {}
    const char* what() const noexcept override { return message.c_str(); }
};

struct TestCaseEntry {
    const char* name;
    const char* tags;
    void (*fn)();
};

inline std::vector<TestCaseEntry>& registry() {
    static std::vector<TestCaseEntry> kTests;
    return kTests;
}

inline int& assertion_counter() noexcept {
    static int kCount = 0;
    return kCount;
}

inline int& check_failure_counter() noexcept {
    static int kFailures = 0;
    return kFailures;
}

struct AutoReg {
    AutoReg(const char* name, const char* tags, void (*fn)()) {
        registry().push_back(TestCaseEntry{name, tags, fn});
    }
};

inline void fail_require(const char* expr, const char* file, int line) {
    throw FailureException(
        std::string(file) + "(" + std::to_string(line) + "): REQUIRE(" + expr + ") failed");
}

inline void fail_check(const char* expr, const char* file, int line) {
    std::fprintf(stderr, "%s(%d): CHECK(%s) failed\n", file, line, expr);
    ++check_failure_counter();
}

} // namespace tessera::test_runner

#define TESSERA_TEST_CONCAT_INNER(a, b) a##b
#define TESSERA_TEST_CONCAT(a, b) TESSERA_TEST_CONCAT_INNER(a, b)

#define TEST_CASE(name, ...)                                                                       \
    static void TESSERA_TEST_CONCAT(tessera_test_fn_, __LINE__)();                                 \
    namespace {                                                                                    \
    const ::tessera::test_runner::AutoReg TESSERA_TEST_CONCAT(tessera_test_reg_, __LINE__)(        \
        name, "" __VA_ARGS__, &TESSERA_TEST_CONCAT(tessera_test_fn_, __LINE__));                   \
    }                                                                                              \
    static void TESSERA_TEST_CONCAT(tessera_test_fn_, __LINE__)()

#define SECTION(name) if (true)

#define REQUIRE(expr)                                                                              \
    do {                                                                                           \
        ++::tessera::test_runner::assertion_counter();                                             \
        if (!(expr)) {                                                                             \
            ::tessera::test_runner::fail_require(#expr, __FILE__, __LINE__);                       \
        }                                                                                          \
    } while (false)

#define REQUIRE_FALSE(expr)                                                                        \
    do {                                                                                           \
        ++::tessera::test_runner::assertion_counter();                                             \
        if (static_cast<bool>(expr)) {                                                             \
            ::tessera::test_runner::fail_require("!(" #expr ")", __FILE__, __LINE__);              \
        }                                                                                          \
    } while (false)

#define CHECK(expr)                                                                                \
    do {                                                                                           \
        ++::tessera::test_runner::assertion_counter();                                             \
        if (!(expr)) {                                                                             \
            ::tessera::test_runner::fail_check(#expr, __FILE__, __LINE__);                         \
        }                                                                                          \
    } while (false)

#define CHECK_FALSE(expr)                                                                          \
    do {                                                                                           \
        ++::tessera::test_runner::assertion_counter();                                             \
        if (static_cast<bool>(expr)) {                                                             \
            ::tessera::test_runner::fail_check("!(" #expr ")", __FILE__, __LINE__);                \
        }                                                                                          \
    } while (false)

#define STATIC_REQUIRE(expr)                                                                       \
    static_assert(expr, #expr);                                                                    \
    REQUIRE(expr)
