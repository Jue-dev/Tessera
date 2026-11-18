# Virtual-branch RTTI fixtures

`rtti_virtual_branch_x64.dll` and `rtti_virtual_branch_x86.dll` are **static PE metadata fixtures**.
They are parsed from their file bytes by Tessera's PE/RTTI parser; they are not loaded or executed
by a Windows loader. The C++ source defines a virtual diamond (`VDiamond : VLeft, VRight`, with
both intermediate classes sharing virtual `VBase`). This makes the Microsoft ABI CHD carry both
the branching-hierarchy bit (`0x01`) and virtual-branching bit (`0x02`), while the Base Class
Descriptors provide per-base PMD metadata.

The fixtures were emitted with Clang 17's Microsoft C++ ABI code generator and linked with LLD 17.
A tiny COFF assembly symbol provides the `type_info` vftable placeholder needed for a metadata-only
link. The placeholder is not suitable for runtime type operations; it is sufficient for static
PE metadata parsing and is never dereferenced by the tests.

Reproduction from the repository root (using Clang 17):

```sh
clang-cl --target=x86_64-pc-windows-msvc /nologo /c /GR /EHs-c- /Zl /GS- /O1 /std:c++latest \
  /Foverify/portable/branch64.obj verify/tests/fixtures/rtti_virtual_branch_fixture.cpp
clang --target=x86_64-pc-windows-msvc -c verify/tests/fixtures/rtti_typeinfo_vftable_x64.s \
  -o verify/portable/typeinfo64.obj
lld-link /dll /noentry /nodefaultlib /noimplib /machine:x64 \
  /out:verify/tests/fixtures/rtti_virtual_branch_x64.dll \
  verify/portable/branch64.obj verify/portable/typeinfo64.obj \
  /export:as_virtual_base /export:as_virtual_left /export:as_virtual_right

clang-cl --target=i686-pc-windows-msvc /nologo /c /GR /EHs-c- /Zl /GS- /O1 /std:c++latest \
  /Foverify/portable/branch32.obj verify/tests/fixtures/rtti_virtual_branch_fixture.cpp
clang --target=i686-pc-windows-msvc -c verify/tests/fixtures/rtti_typeinfo_vftable_x86.s \
  -o verify/portable/typeinfo32.obj
lld-link /dll /noentry /nodefaultlib /noimplib /safeseh:no /machine:x86 \
  /out:verify/tests/fixtures/rtti_virtual_branch_x86.dll \
  verify/portable/branch32.obj verify/portable/typeinfo32.obj \
  /export:as_virtual_base /export:as_virtual_left /export:as_virtual_right
```

After generation, copy both DLLs to `verify/portable/fixtures/`. The x86 link uses `/safeseh:no`
because the tiny assembly placeholder intentionally contains no SEH metadata.
