#pragma once
#include <Windows.h>
LONG DetourTransactionBegin() noexcept;
LONG DetourTransactionAbort() noexcept;
LONG DetourTransactionCommit() noexcept;
LONG DetourUpdateThread(HANDLE) noexcept;
LONG DetourAttach(void**, void*) noexcept;
LONG DetourDetach(void**, void*) noexcept;
