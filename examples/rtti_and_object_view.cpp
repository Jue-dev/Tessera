#include "tessera/tessera.hpp"

#include <cstdint>
#include <iostream>

namespace sample_game {

enum class Stance : std::int32_t {
    Standing = 0,
    Crouching = 1,
    Prone = 2,
};

// 1. Non-virtual plain C++ struct with bitfields
struct Transform {
    float x;
    float y;
    float z;
    std::uint32_t packed_flags; // bit 0: visible, bits 4..7: team_id
};

// 2. Polymorphic C++ class hierarchy
class Entity {
public:
    virtual ~Entity() = default;
    virtual int get_id() const noexcept { return id; }
    int id = 100;
};

class Player : public Entity {
public:
    int get_id() const noexcept override { return id + 1000; }
    virtual float get_health() const noexcept { return health; }
    float health = 95.5f;
};

} // namespace sample_game

int main() {
    using namespace tessera;
    using namespace tessera::reflection;
    using namespace tessera::rtti;

    std::cout << "=== Tessera Example 03: Non-Virtual & Polymorphic Reflection, ObjectView & RTTI ===\n\n";

    const Process proc = Process::current();
    TypeRegistry registry{};

    // 1. Register Enum
    auto stance_enum = EnumBuilder<sample_game::Stance>("sample_game::Stance")
                           .value("Standing", sample_game::Stance::Standing)
                           .value("Crouching", sample_game::Stance::Crouching)
                           .value("Prone", sample_game::Stance::Prone)
                           .build();
    (void)registry.register_type(stance_enum);

    // 2. Register Non-Virtual struct with bitfields
    auto transform_info =
        TypeBuilder<sample_game::Transform>("sample_game::Transform")
            .field("x", TypeId::from_name("float"), offsetof(sample_game::Transform, x), 4)
            .field("y", TypeId::from_name("float"), offsetof(sample_game::Transform, y), 4)
            .field("z", TypeId::from_name("float"), offsetof(sample_game::Transform, z), 4)
            .bitfield("visible",
                      TypeId::from_name("uint32"),
                      offsetof(sample_game::Transform, packed_flags),
                      4,
                      0,
                      1)
            .bitfield("team_id",
                      TypeId::from_name("uint32"),
                      offsetof(sample_game::Transform, packed_flags),
                      4,
                      4,
                      4)
            .build();
    (void)registry.register_type(transform_info);

    // Inspect and mutate non-virtual struct via ObjectView
    sample_game::Transform local_tr{
        .x = 12.5f, .y = 40.0f, .z = -3.25f, .packed_flags = (1u << 0) | (5u << 4)};
    ObjectView tr_view{proc, Address::from_ptr(&local_tr), transform_info};

    std::cout << "[Non-Virtual] Transform.x = " << tr_view.read_field<float>("x").value_or(0.0f)
              << " | visible = " << tr_view.read_bitfield("visible").value_or(0)
              << " | team_id = " << tr_view.read_bitfield("team_id").value_or(0) << "\n";

    (void)tr_view.write_field<float>("x", 99.75f);
    std::cout << "[Non-Virtual] After ObjectView::write_field -> local_tr.x = " << local_tr.x
              << "\n\n";

    // 3. Discover live MSVC RTTI in our own executable module
    sample_game::Player live_player{};
    const Address player_addr = Address::from_ptr(&live_player);

    if (auto main_mod = ModuleCatalog::main_module(proc)) {
        if (auto catalog = RttiCatalog::discover_all(proc, main_mod->range())) {
            std::cout << "[RTTI]        Discovered " << catalog->classes().size()
                      << " polymorphic classes in main module.\n";

            if (auto identified = catalog->identify_instance(proc, player_addr)) {
                std::cout << "[RTTI]        Live instance @ "
                          << hex::format_u64(player_addr.value()) << " identified as: "
                          << identified->demangled_name << " (vtable methods: "
                          << identified->virtual_methods.size() << ")\n";
            }

            if (auto base_addr =
                    catalog->cast_to(proc, player_addr, "sample_game::Entity")) {
                std::cout << "[RTTI]        Dynamic cast to base 'sample_game::Entity' -> "
                          << hex::format_u64(base_addr->value()) << "\n";
            }

            (void)catalog->export_to_registry(registry);
            std::cout << "[Registry]    Total registered types (virtual + non-virtual): "
                      << registry.all_types().size() << "\n";
        }
    }

    return 0;
}
