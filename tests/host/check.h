#pragma once

#include <cstddef>
#include <cstdio>

inline unsigned g_Pass = 0;
inline unsigned g_Fail = 0;

// Byte-range predicates shared by the suites. Each returns one bool so the
// caller keeps one CHECK per assertion (check counts do not change).
inline bool AllBytesEqual(const void* Data, std::size_t Size, unsigned char Value)
{
    const auto* Bytes = static_cast<const unsigned char*>(Data);
    for (std::size_t i = 0; i < Size; ++i)
        if (Bytes[i] != Value) return false;
    return true;
}

inline bool AllBytesZero(const void* Data, std::size_t Size)
{
    return AllBytesEqual(Data, Size, 0);
}

inline bool AnyByteNonZero(const void* Data, std::size_t Size)
{
    return !AllBytesZero(Data, Size);
}

inline void Report(bool ok, const char* file, unsigned line, const char* expr)
{
    if (ok)
    {
        ++g_Pass;
        return;
    }
    ++g_Fail;
    std::printf("[FAIL] %s:%u: %s\n", file, line, expr);
}

#define CHECK(Cond) Report((Cond), __FILE__, __LINE__, #Cond)

// Shared summary tail: same line format and exit code for every suite.
inline int Summary(const char* suite)
{
    std::printf("\n==== %s: %u passed, %u failed ====\n", suite, g_Pass, g_Fail);
    return g_Fail ? 1 : 0;
}
