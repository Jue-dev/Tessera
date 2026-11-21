#pragma once

#include <cstddef>
#include <span>
#include <vector>

#include "tessera/core/result.hpp"
#include "tessera/core/types.hpp"
#include "tessera/pattern/pattern.hpp"
#include "tessera/process/process.hpp"
#include "tessera/scanner/scanner.hpp"

namespace tessera::xref {

[[nodiscard]] Result<std::vector<Address>> find_pointer_refs(
    const Process& process,
    AddressRange range,
    Address target,
    const ScanOptions& options = {});

[[nodiscard]] Result<std::vector<std::vector<Address>>> find_pointer_refs_batch(
    const Process& process,
    AddressRange range,
    std::span<const Address> targets,
    const ScanOptions& options = {});

[[nodiscard]] Result<std::vector<Address>> find_rel32_refs(
    const Process& process,
    AddressRange range,
    Address target,
    const Pattern& prefix,
    std::size_t trailing_bytes = 0,
    const ScanOptions& options = {});

[[nodiscard]] Result<std::vector<Address>> find_calls(
    const Process& process,
    AddressRange range,
    Address target,
    const ScanOptions& options = {});

[[nodiscard]] Result<std::vector<Address>> find_jumps(
    const Process& process,
    AddressRange range,
    Address target,
    const ScanOptions& options = {});

[[nodiscard]] Result<std::vector<Address>> find_conditional_branches(
    const Process& process,
    AddressRange range,
    Address target,
    const ScanOptions& options = {});

[[nodiscard]] Result<std::vector<Address>> find_indirect_refs(
    const Process& process,
    AddressRange range,
    Address target,
    const ScanOptions& options = {});

} // namespace tessera::xref
