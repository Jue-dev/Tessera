#include "tessera/rtti/python_bridge.hpp"

#include <algorithm>
#include <array>
#include <cstdint>

#include "tessera/memory/memory_reader.hpp"
#include "tessera/utility/string.hpp"

#include "readable_chunks.hpp"

namespace tessera::rtti {

namespace {

using detail::for_each_readable_chunk;

// Keep the scanner's own fingerprint strings out of the image being inspected.
// Otherwise a process that links Tessera would match the signatures embedded in
// this detector and report its own implementation as the target's Python runtime.
inline constexpr std::uint8_t kSignatureKey = 0xA7u;


template <std::size_t N>
[[nodiscard]] bool equals_signature(std::string_view value,
                                    const std::array<std::uint8_t, N>& encoded) noexcept {
    if (value.size() != N) {
        return false;
    }
    // Volatile reads prevent the compiler from folding the encoded bytes back
    // into a plaintext constant in the scanner's read-only data section.
    const volatile std::uint8_t* bytes = encoded.data();
    for (std::size_t i = 0; i < N; ++i) {
        if (static_cast<std::uint8_t>(value[i]) !=
            static_cast<std::uint8_t>(bytes[i] ^ kSignatureKey)) {
            return false;
        }
    }
    return true;
}

template <std::size_t N>
[[nodiscard]] bool starts_with_signature(
    std::string_view value, const std::array<std::uint8_t, N>& encoded) noexcept {
    if (value.size() < N) {
        return false;
    }
    return equals_signature(value.substr(0, N), encoded);
}

template <std::size_t N>
[[nodiscard]] bool contains_signature(
    std::string_view value, const std::array<std::uint8_t, N>& encoded) noexcept {
    if (value.size() < N) {
        return false;
    }
    for (std::size_t offset = 0; offset <= value.size() - N; ++offset) {
        if (equals_signature(value.substr(offset, N), encoded)) {
            return true;
        }
    }
    return false;
}

inline constexpr std::array<std::uint8_t, 26> kPyBuiltinFunction{{0xC5u, 0xD2u, 0xCEu, 0xCBu, 0xD3u, 0xCEu, 0xC9u, 0xF8u, 0xC1u, 0xD2u, 0xC9u, 0xC4u, 0xD3u, 0xCEu, 0xC8u, 0xC9u, 0xF8u, 0xC8u, 0xD5u, 0xF8u, 0xCAu, 0xC2u, 0xD3u, 0xCFu, 0xC8u, 0xC3u}};
inline constexpr std::array<std::uint8_t, 17> kPyGetsetDescriptor{{0xC0u, 0xC2u, 0xD3u, 0xD4u, 0xC2u, 0xD3u, 0xF8u, 0xC3u, 0xC2u, 0xD4u, 0xC4u, 0xD5u, 0xCEu, 0xD7u, 0xD3u, 0xC8u, 0xD5u}};
inline constexpr std::array<std::uint8_t, 17> kPyMemberDescriptor{{0xCAu, 0xC2u, 0xCAu, 0xC5u, 0xC2u, 0xD5u, 0xF8u, 0xC3u, 0xC2u, 0xD4u, 0xC4u, 0xD5u, 0xCEu, 0xD7u, 0xD3u, 0xC8u, 0xD5u}};
inline constexpr std::array<std::uint8_t, 33> kPyBadArgument{{0xC5u, 0xC6u, 0xC3u, 0x87u, 0xC6u, 0xD5u, 0xC0u, 0xD2u, 0xCAu, 0xC2u, 0xC9u, 0xD3u, 0x87u, 0xD3u, 0xC8u, 0x87u, 0xCEu, 0xC9u, 0xD3u, 0xC2u, 0xD5u, 0xC9u, 0xC6u, 0xCBu, 0x87u, 0xC1u, 0xD2u, 0xC9u, 0xC4u, 0xD3u, 0xCEu, 0xC8u, 0xC9u}};
inline constexpr std::array<std::uint8_t, 12> kPyBuiltins{{0xF8u, 0xF8u, 0xC5u, 0xD2u, 0xCEu, 0xCBu, 0xD3u, 0xCEu, 0xC9u, 0xD4u, 0xF8u, 0xF8u}};
inline constexpr std::array<std::uint8_t, 18> kPyEvalFrameEx{{0xF7u, 0xDEu, 0xE2u, 0xD1u, 0xC6u, 0xCBu, 0xF8u, 0xE2u, 0xD1u, 0xC6u, 0xCBu, 0xE1u, 0xD5u, 0xC6u, 0xCAu, 0xC2u, 0xE2u, 0xDFu}};
inline constexpr std::array<std::uint8_t, 14> kPyInitModule4{{0xF7u, 0xDEu, 0xF8u, 0xEEu, 0xC9u, 0xCEu, 0xD3u, 0xEAu, 0xC8u, 0xC3u, 0xD2u, 0xCBu, 0xC2u, 0x93u}};
inline constexpr std::array<std::uint8_t, 8> kPybind11{{0xD7u, 0xDEu, 0xC5u, 0xCEu, 0xC9u, 0xC3u, 0x96u, 0x96u}};
inline constexpr std::array<std::uint8_t, 16> kPybind11Detail{{0xD7u, 0xDEu, 0xC5u, 0xCEu, 0xC9u, 0xC3u, 0x96u, 0x96u, 0x9Du, 0x9Du, 0xC3u, 0xC2u, 0xD3u, 0xC6u, 0xCEu, 0xCBu}};
inline constexpr std::array<std::uint8_t, 21> kPybind11Conduit{{0xF8u, 0xD7u, 0xDEu, 0xC5u, 0xCEu, 0xC9u, 0xC3u, 0x96u, 0x96u, 0xF8u, 0xC4u, 0xC8u, 0xC9u, 0xC3u, 0xD2u, 0xCEu, 0xD3u, 0xF8u, 0xD1u, 0x96u, 0xF8u}};
inline constexpr std::array<std::uint8_t, 13> kBoostPython{{0xC5u, 0xC8u, 0xC8u, 0xD4u, 0xD3u, 0x9Du, 0x9Du, 0xD7u, 0xDEu, 0xD3u, 0xCFu, 0xC8u, 0xC9u}};
inline constexpr std::array<std::uint8_t, 22> kBoostPythonObjects{{0xC5u, 0xC8u, 0xC8u, 0xD4u, 0xD3u, 0x9Du, 0x9Du, 0xD7u, 0xDEu, 0xD3u, 0xCFu, 0xC8u, 0xC9u, 0x9Du, 0x9Du, 0xC8u, 0xC5u, 0xCDu, 0xC2u, 0xC4u, 0xD3u, 0xD4u}};
inline constexpr std::array<std::uint8_t, 12> kBoostPythonLib{{0xC5u, 0xC8u, 0xC8u, 0xD4u, 0xD3u, 0xF8u, 0xD7u, 0xDEu, 0xD3u, 0xCFu, 0xC8u, 0xC9u}};
inline constexpr std::array<std::uint8_t, 6> kPyxPrefix{{0xF8u, 0xF8u, 0xD7u, 0xDEu, 0xDFu, 0xF8u}};
inline constexpr std::array<std::uint8_t, 25> kCythonFunction{{0xC4u, 0xDEu, 0xD3u, 0xCFu, 0xC8u, 0xC9u, 0xF8u, 0xC1u, 0xD2u, 0xC9u, 0xC4u, 0xD3u, 0xCEu, 0xC8u, 0xC9u, 0xF8u, 0xC8u, 0xD5u, 0xF8u, 0xCAu, 0xC2u, 0xD3u, 0xCFu, 0xC8u, 0xC3u}};
inline constexpr std::array<std::uint8_t, 4> kVersion27{{0x95u, 0x89u, 0x90u, 0x89u}};
inline constexpr std::array<std::uint8_t, 5> kVersion310{{0x94u, 0x89u, 0x96u, 0x97u, 0x89u}};
inline constexpr std::array<std::uint8_t, 5> kVersion311{{0x94u, 0x89u, 0x96u, 0x96u, 0x89u}};
inline constexpr std::array<std::uint8_t, 5> kVersion312{{0x94u, 0x89u, 0x96u, 0x95u, 0x89u}};
inline constexpr std::array<std::uint8_t, 10> kPython27{{0xF7u, 0xDEu, 0xD3u, 0xCFu, 0xC8u, 0xC9u, 0x87u, 0x95u, 0x89u, 0x90u}};
inline constexpr std::array<std::uint8_t, 11> kPython310{{0xF7u, 0xDEu, 0xD3u, 0xCFu, 0xC8u, 0xC9u, 0x87u, 0x94u, 0x89u, 0x96u, 0x97u}};
inline constexpr std::array<std::uint8_t, 11> kPython311{{0xF7u, 0xDEu, 0xD3u, 0xCFu, 0xC8u, 0xC9u, 0x87u, 0x94u, 0x89u, 0x96u, 0x96u}};
inline constexpr std::array<std::uint8_t, 11> kPython312{{0xF7u, 0xDEu, 0xD3u, 0xCFu, 0xC8u, 0xC9u, 0x87u, 0x94u, 0x89u, 0x96u, 0x95u}};


} // namespace

Result<PythonEnvironmentInfo> PythonBridgeScanner::detect_environment(
    const Process& process,
    AddressRange module_range,
    const PeImage* pe) {
    if (module_range.empty()) {
        return fail(ErrorCode::InvalidArgument, "PythonBridgeScanner::detect_environment");
    }

    PythonEnvironmentInfo info{};

    // 1. PE imports are authoritative for a shared CPython runtime.
    if (pe != nullptr) {
        for (const auto& imp : pe->imports()) {
            if (utility::ascii_icontains(imp.module_name, "python")) {
                info.deployment = PythonDeployment::SharedLibrary;
                info.python_dll_name = imp.module_name;
                info.framework = PythonFramework::CPythonCAPI;
                if (utility::ascii_icontains(imp.module_name, "27")) {
                    info.version_hint = "2.7";
                } else if (utility::ascii_icontains(imp.module_name, "311")) {
                    info.version_hint = "3.11";
                } else if (utility::ascii_icontains(imp.module_name, "312")) {
                    info.version_hint = "3.12";
                } else if (utility::ascii_icontains(imp.module_name, "310")) {
                    info.version_hint = "3.10";
                } else if (utility::ascii_icontains(imp.module_name, "3")) {
                    info.version_hint = "3.x";
                }
                break;
            }
        }
    }

    bool has_cpython_core_fingerprint = false;
    // Track unique core signature kinds, not occurrences: duplicated copies of
    // one string in an image are not independent evidence of a static runtime.
    std::array<bool, 7> cpython_core_markers_seen{};
    bool has_pybind11 = false;
    bool has_pybind11_detail = false;
    bool has_pybind11_conduit = false;
    bool has_boost_python = false;
    bool has_boost_python_objects = false;
    bool has_boost_python_lib = false;
    bool has_cython_prefix = false;
    bool has_cython_runtime_type = false;

    auto strings_res = BinaryExplorer::scan_strings(process, module_range, 4, false);
    if (strings_res) {
        for (const auto& ds : *strings_res) {
            const std::string_view sv = ds.value;

            const std::array<bool, 7> cpython_markers{
                equals_signature(sv, kPyBuiltinFunction),
                equals_signature(sv, kPyGetsetDescriptor),
                equals_signature(sv, kPyMemberDescriptor),
                equals_signature(sv, kPyBadArgument),
                equals_signature(sv, kPyBuiltins),
                equals_signature(sv, kPyEvalFrameEx),
                equals_signature(sv, kPyInitModule4),
            };
            for (std::size_t marker_index = 0; marker_index < cpython_markers.size();
                 ++marker_index) {
                if (cpython_markers[marker_index]) {
                    has_cpython_core_fingerprint = true;
                    if (!cpython_core_markers_seen[marker_index]) {
                        cpython_core_markers_seen[marker_index] = true;
                        info.detected_fingerprints.push_back(ds.value);
                    }
                }
            }

            if (equals_signature(sv, kPybind11)) {
                has_pybind11 = true;
                info.detected_fingerprints.push_back(ds.value);
            }
            if (contains_signature(sv, kPybind11Detail)) {
                has_pybind11_detail = true;
                info.detected_fingerprints.push_back(ds.value);
            }
            if (equals_signature(sv, kPybind11Conduit)) {
                has_pybind11_conduit = true;
                info.detected_fingerprints.push_back(ds.value);
            }
            if (equals_signature(sv, kBoostPython)) {
                has_boost_python = true;
                info.detected_fingerprints.push_back(ds.value);
            }
            if (contains_signature(sv, kBoostPythonObjects)) {
                has_boost_python_objects = true;
                info.detected_fingerprints.push_back(ds.value);
            }
            if (equals_signature(sv, kBoostPythonLib)) {
                has_boost_python_lib = true;
                info.detected_fingerprints.push_back(ds.value);
            }
            if (starts_with_signature(sv, kPyxPrefix)) {
                has_cython_prefix = true;
                info.detected_fingerprints.push_back(ds.value);
            }
            if (equals_signature(sv, kCythonFunction)) {
                has_cython_runtime_type = true;
                info.detected_fingerprints.push_back(ds.value);
            }

            if (info.version_hint.empty()) {
                if (starts_with_signature(sv, kVersion27) ||
                    contains_signature(sv, kPython27)) {
                    info.version_hint = "2.7";
                } else if (starts_with_signature(sv, kVersion312) ||
                           contains_signature(sv, kPython312)) {
                    info.version_hint = "3.12";
                } else if (starts_with_signature(sv, kVersion311) ||
                           contains_signature(sv, kPython311)) {
                    info.version_hint = "3.11";
                } else if (starts_with_signature(sv, kVersion310) ||
                           contains_signature(sv, kPython310)) {
                    info.version_hint = "3.10";
                }
            }
        }
    }

    // A single generic marker is not sufficient to identify a binding framework.
    // Require independent framework-specific evidence to reduce false positives.
    if (has_pybind11 && (has_pybind11_detail || has_pybind11_conduit)) {
        info.framework = PythonFramework::PyBind11;
    } else if (has_boost_python && (has_boost_python_objects || has_boost_python_lib)) {
        info.framework = PythonFramework::BoostPython;
    } else if (has_cython_prefix && has_cython_runtime_type) {
        info.framework = PythonFramework::Cython;
    } else if (info.framework == PythonFramework::Unknown && has_cpython_core_fingerprint) {
        info.framework = PythonFramework::CPythonCAPI;
    }

    // A single generic CPython string can also occur in extension metadata.
    // Require two distinct core signature kinds before inferring a static runtime.
    // Repeated occurrences of one marker do not count as independent evidence.
    // Method/member tables alone prove C-API use, not how libpython is deployed.
    const auto cpython_core_fingerprint_count = static_cast<std::size_t>(
        std::count(cpython_core_markers_seen.begin(), cpython_core_markers_seen.end(), true));
    if (info.deployment == PythonDeployment::None && cpython_core_fingerprint_count >= 2) {
        info.deployment = PythonDeployment::StaticEmbedded;
    }

    return info;
}


} // namespace tessera::rtti
