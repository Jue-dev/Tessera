#include "catch2/catch_test_macros.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <fstream>
#include <random>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#if defined(_MSC_VER)
#include <crtdbg.h>
#endif

namespace {

struct TestOutcome {
    std::string name;
    bool passed = false;
    std::string failure;
};

std::string xml_escape(std::string_view value) {
    std::string out;
    out.reserve(value.size());
    for (const char ch : value) {
        switch (ch) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            case '\'': out += "&apos;"; break;
            default: out += ch; break;
        }
    }
    return out;
}

} // namespace

int main(int argc, char** argv) {
#if defined(_MSC_VER)
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#if defined(_DEBUG)
    _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
    _CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_ERROR, _CRTDBG_FILE_STDERR);
#endif
#endif
    bool shuffle = false;
    std::uint64_t seed = 0x54455353455241ULL;
    std::string filter;
    std::string junit_path;
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg{argv[i]};
        if (arg == "--shuffle") {
            shuffle = true;
        } else if (arg == "--seed" && i + 1 < argc) {
            seed = std::strtoull(argv[++i], nullptr, 10);
        } else if (arg == "--filter" && i + 1 < argc) {
            filter = argv[++i];
        } else if (arg == "--junit" && i + 1 < argc) {
            junit_path = argv[++i];
        } else {
            std::fprintf(stderr, "Unknown or incomplete test option: %.*s\n",
                         static_cast<int>(arg.size()), arg.data());
            return 2;
        }
    }

    std::vector<::tessera::test_runner::TestCaseEntry> selected =
        ::tessera::test_runner::registry();
    if (!filter.empty()) {
        selected.erase(std::remove_if(selected.begin(), selected.end(), [&](const auto& tc) {
            return std::string_view{tc.name}.find(filter) == std::string_view::npos;
        }), selected.end());
    }
    if (shuffle) {
        std::mt19937_64 rng{seed};
        std::shuffle(selected.begin(), selected.end(), rng);
        std::printf("[INFO] shuffled test order (seed=%llu)\n",
                    static_cast<unsigned long long>(seed));
    }

    int passed = 0;
    int failed = 0;
    std::vector<TestOutcome> outcomes;
    outcomes.reserve(selected.size());
    for (const auto& tc : selected) {
        std::printf("[RUN ] %s\n", tc.name);
        std::fflush(stdout);
        const int checks_before = ::tessera::test_runner::check_failure_counter();
        TestOutcome outcome{.name = tc.name};
        try {
            tc.fn();
            if (::tessera::test_runner::check_failure_counter() == checks_before) {
                ++passed;
                outcome.passed = true;
            } else {
                ++failed;
                outcome.failure = "CHECK assertion failed";
                std::fprintf(stderr, "[FAILED] %s (check failure)\n", tc.name);
            }
        } catch (const ::tessera::test_runner::FailureException& ex) {
            ++failed;
            outcome.failure = ex.what();
            std::fprintf(stderr, "[FAILED] %s\n  %s\n", tc.name, ex.what());
        } catch (const std::exception& ex) {
            ++failed;
            outcome.failure = ex.what();
            std::fprintf(stderr, "[FAILED] %s (unexpected exception: %s)\n", tc.name, ex.what());
        } catch (...) {
            ++failed;
            outcome.failure = "unknown exception";
            std::fprintf(stderr, "[FAILED] %s (unknown exception)\n", tc.name);
        }
        outcomes.push_back(std::move(outcome));
    }

    if (!junit_path.empty()) {
        std::ofstream xml{junit_path, std::ios::binary};
        if (!xml) {
            std::fprintf(stderr, "Unable to open JUnit output: %s\n", junit_path.c_str());
            return 2;
        }
        xml << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            << "<testsuite name=\"Tessera\" tests=\"" << outcomes.size()
            << "\" failures=\"" << failed << "\" assertions=\""
            << ::tessera::test_runner::assertion_counter() << "\">\n";
        for (const auto& outcome : outcomes) {
            xml << "  <testcase classname=\"Tessera\" name=\""
                << xml_escape(outcome.name) << "\">";
            if (!outcome.passed) {
                xml << "<failure message=\"test failed\">"
                    << xml_escape(outcome.failure) << "</failure>";
            }
            xml << "</testcase>\n";
        }
        xml << "</testsuite>\n";
        if (!xml) {
            std::fprintf(stderr, "Failed while writing JUnit output: %s\n", junit_path.c_str());
            return 2;
        }
    }

    std::printf("===============================================================================\n");
    if (failed == 0) {
        std::printf("All tests passed (%d assertions in %d test cases)\n",
                    ::tessera::test_runner::assertion_counter(), passed);
        return 0;
    }
    std::fprintf(stderr, "test cases: %d | %d passed | %d failed\n",
                 passed + failed, passed, failed);
    return 1;
}
