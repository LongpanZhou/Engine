#pragma once
// ---------------------------------------------------------------------------
// Engine-ci/Driver/Lib/pure.h - kernel-side helpers with no kernel calls, kept
// here so the host unit tests can include them directly.
// ---------------------------------------------------------------------------
#include <cstddef>
#include <cstdint>

// Case-folded comparison, so a module search finds the loader's name whatever
// case it stored (ci.dll must match CI.dll). ASCII file names: folding a-z to
// A-Z is exact. A is a counted UNICODE_STRING buffer, so Count bounds every
// read; B must be NUL-terminated and end exactly at Count.
inline bool WideEqualsIgnoreCase(const wchar_t* A, const wchar_t* B, size_t Count)
{
    for (size_t i = 0; i < Count; ++i)
    {
        wchar_t a = A[i];
        wchar_t b = B[i];
        if (!a || !b) return false;                     // A ended early, or B is shorter than A

        if (a >= L'a' && a <= L'z') a = (wchar_t) (a - 0x20);
        if (b >= L'a' && b <= L'z') b = (wchar_t) (b - 0x20);
        if (a != b) return false;
    }

    return B[Count] == L'\0';                           // B must not have extra characters
}

// Object-directory pointers live in kernel space; a user-mode or low value in
// the chain is a malformed object and must stop the walk.
constexpr uint64_t ObjectKernelFloor = 0xFFFF800000000000ull;

inline bool IsObjectKernelPointer(uint64_t Value)
{
    return Value >= ObjectKernelFloor;
}
