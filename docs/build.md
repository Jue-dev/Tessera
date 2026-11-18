# Building Tessera

## Prerequisites

- **OS**: Windows 10 / 11 (x64 or x86)
- **Compiler**: MSVC 19.38+ (Visual Studio 2022 17.8+ or Build Tools 18+) with `/std:c++23preview` or `/std:c++latest`
- **Build System**: CMake 3.28+ and Ninja

## Configure, Build, and Test via CMake Presets

From a Visual Studio Developer Prompt (`vcvars64.bat` for x64 or `vcvarsamd64_x86.bat` for x86):

```powershell
cmake --preset x64-debug
cmake --build --preset x64-debug
ctest --preset x64-debug
```

Available presets:
- `x64-debug`
- `x64-release`
- `x86-debug`
- `x86-release`

## Installing the SDK

```powershell
cmake --install out/build/x64-release --prefix out/install/x64-release
```

Downstream projects can then consume Tessera via:

```cmake
find_package(Tessera CONFIG REQUIRED)
target_link_libraries(my_app PRIVATE tessera::tessera)
```
