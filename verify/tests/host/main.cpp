#include <Windows.h>

#include <cstdint>
#include <cstdio>
#include <cstring>

extern "C" __declspec(dllexport) int __cdecl TesseraHostExportedAdd(int a, int b) {
    return a + b + 1000;
}

namespace {

struct alignas(16) HostPayload {
    char magic[16] = "TESSERA_HOST_OK";
    std::int32_t health = 1337;
    std::uint64_t secret_token = 0xCAFEBABE12345678ULL;
    const void* self_ptr = nullptr;
};

HostPayload g_payload{};

} // namespace

int main(int argc, char** argv) {
    g_payload.self_ptr = &g_payload;

    // Print payload address and exported function address then wait briefly if requested
    std::printf("PID=%lu PAYLOAD=0x%llX EXPORT=0x%llX\n",
                ::GetCurrentProcessId(),
                static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(&g_payload)),
                static_cast<unsigned long long>(
                    reinterpret_cast<std::uintptr_t>(&TesseraHostExportedAdd)));
    std::fflush(stdout);

    if (argc > 1 && std::strcmp(argv[1], "--wait") == 0) {
        ::Sleep(5000);
    }
    return 0;
}
