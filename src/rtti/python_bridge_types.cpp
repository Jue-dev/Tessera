#include "tessera/rtti/python_bridge.hpp"

#include <cstddef>
#include <cstdint>
#include <new>

#include "python_bridge_detail.hpp"

namespace tessera::rtti {

Result<std::vector<PyDiscoveredTypeObject>> PythonBridgeScanner::scan_type_objects(
    const Process& process,
    AddressRange module_range) {
    if (module_range.empty()) {
        return fail(ErrorCode::InvalidArgument, "PythonBridgeScanner::scan_type_objects");
    }

    try {
        MemoryReader reader{process};
        const std::uint8_t ptr_size = process.pointer_size();
        const std::size_t tp_name_off = 3u * ptr_size;
        const std::size_t min_type_obj_size = 32u * ptr_size;

        std::vector<PyDiscoveredTypeObject> results;

        for_each_readable_chunk(
            reader,
            module_range,
            256,
            [&](Address chunk_addr, const std::vector<std::byte>& b, bool is_exec) {
                if (is_exec) {
                    return;
                }
                for (std::size_t i = 0; i + min_type_obj_size <= b.size(); i += ptr_size) {
                    const std::uint64_t refcnt = read_ptr_at(b, i, ptr_size);
                    const std::uint64_t ob_size = read_ptr_at(b, i + 2 * ptr_size, ptr_size);
                    const std::uint64_t tp_name_ptr = read_ptr_at(b, i + tp_name_off, ptr_size);
                    const std::uint64_t tp_basicsize = read_ptr_at(b, i + 4 * ptr_size, ptr_size);
                    const std::uint64_t tp_itemsize = read_ptr_at(b, i + 5 * ptr_size, ptr_size);

                    if (!is_plausible_python_refcount(refcnt) || ob_size != 0) {
                        continue;
                    }
                    if (tp_basicsize < 2u * ptr_size || tp_basicsize > 0x10000ULL ||
                        tp_itemsize > 0x1000ULL) {
                        continue;
                    }
                    const Address name_addr{tp_name_ptr};
                    if (!module_range.contains(name_addr)) {
                        continue;
                    }
                    auto tname = reader.read_cstring(name_addr, 96);
                    if (!tname || !is_python_identifier(*tname, true) ||
                        tname->find('.') == std::string::npos) {
                        continue;
                    }

                    // PyTypeObject keeps tp_methods / tp_members / tp_getset at
                    // pointer-sized slots 29, 30 and 31 in supported CPython
                    // layouts (the scanned 32-slot prefix includes all three).
                    const auto read_table_address = [&](std::size_t field_offset,
                                                        std::size_t minimum_size) {
                        const std::uint64_t table_ptr = read_ptr_at(b, i + field_offset, ptr_size);
                        if (table_ptr == 0) {
                            return Address{};
                        }
                        const auto readable = reader.is_readable(
                            AddressRange{Address{table_ptr}, minimum_size});
                        return (readable && *readable) ? Address{table_ptr} : Address{};
                    };

                    PyDiscoveredTypeObject obj{};
                    obj.type_name = std::move(*tname);
                    obj.basic_size = static_cast<std::size_t>(tp_basicsize);
                    obj.item_size = static_cast<std::size_t>(tp_itemsize);
                    obj.type_object_address = Address{chunk_addr.value() + i};
                    obj.methods_table_address = read_table_address(29u * ptr_size, 4u * ptr_size);
                    obj.members_table_address = read_table_address(30u * ptr_size, 5u * ptr_size);
                    obj.getset_table_address = read_table_address(31u * ptr_size, 5u * ptr_size);
                    results.push_back(std::move(obj));
                }
            });

        return results;
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "PythonBridgeScanner::scan_type_objects");
    }
}

} // namespace tessera::rtti
