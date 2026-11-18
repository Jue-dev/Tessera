#pragma once

#include <chrono>
#include <cstdint>
#include <stop_token>
#include <string>
#include <string_view>
#include <vector>

#include "tessera/core/result.hpp"
#include "tessera/core/types.hpp"
#include "tessera/module/pe_image.hpp"
#include "tessera/process/process.hpp"

namespace tessera {

// Represents a loaded executable or DLL module inside a Process.
class Module {
public:
    Module(Process process,
           std::u16string name,
           std::u16string full_path,
           AddressRange range) noexcept
        : process_(std::move(process)),
          name_(std::move(name)),
          full_path_(std::move(full_path)),
          range_(range) {}

    [[nodiscard]] std::u16string_view name() const noexcept { return name_; }
    [[nodiscard]] std::u16string_view full_path() const noexcept { return full_path_; }
    [[nodiscard]] AddressRange range() const noexcept { return range_; }
    [[nodiscard]] Address base() const noexcept { return range_.begin(); }
    [[nodiscard]] std::uint64_t size() const noexcept { return range_.size(); }
    [[nodiscard]] const Process& process() const noexcept { return process_; }

    [[nodiscard]] Result<PeImage> image() const {
        return PeImage::from_memory(process_, range_.begin());
    }

    [[nodiscard]] Result<Section> section(std::string_view section_name) const {
        auto img = image();
        if (!img) {
            return std::unexpected(img.error());
        }
        return img->find_section(section_name);
    }

    [[nodiscard]] Result<Address> at_rva(Rva rva) const noexcept {
        return range_.at_rva(rva);
    }

    [[nodiscard]] Result<Rva> to_rva(Address address) const noexcept {
        return range_.to_rva(address);
    }

private:
    Process process_;
    std::u16string name_;
    std::u16string full_path_;
    AddressRange range_;
};

class ModuleCatalog {
public:
    [[nodiscard]] static Result<std::vector<Module>> snapshot(const Process& process);

    [[nodiscard]] static Result<Module> main_module(const Process& process);

    // Case-insensitive ordinal comparison on base module name (e.g. u"kernel32.dll").
    [[nodiscard]] static Result<Module> find(const Process& process, std::u16string_view name);

    [[nodiscard]] static Result<Module> containing(const Process& process, Address address);

    [[nodiscard]] static Result<Module> wait_for(
        const Process& process,
        std::u16string_view name,
        std::chrono::milliseconds timeout,
        std::stop_token stop = {},
        std::chrono::milliseconds poll_interval = std::chrono::milliseconds{25});
};

} // namespace tessera
