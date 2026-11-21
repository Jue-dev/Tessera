# PE and RTTI test fixtures

This directory contains deterministic source and metadata fixtures used by PE parsing and RTTI tests.

- rtti_fixture_x86.cpp and rtti_fixture_x64.cpp: compact MSVC-ABI virtual-class fixtures for 32-bit and 64-bit metadata.
- rtti_virtual_branch_fixture.cpp: a virtual-diamond hierarchy exercising branching and virtual-branching class hierarchy flags plus PMD base descriptors.
- rtti_typeinfo_vftable_x86.s and rtti_typeinfo_vftable_x64.s: metadata-only type_info vftable placeholders used when linking static PE fixtures; they are never used for runtime type operations.
- Generated rtti_virtual_branch_x86.dll and rtti_virtual_branch_x64.dll: static PE metadata fixtures parsed from file bytes, never loaded or executed by a Windows loader.

The virtual-branch fixtures were emitted with Clang's Microsoft C++ ABI code generator and LLD. The x86 link disables SafeSEH because the tiny assembly placeholder intentionally has no SEH metadata. Generated binaries are test inputs only, not SDK artifacts.
