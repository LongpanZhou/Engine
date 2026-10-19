#pragma once

// Strings used by this program, stored XOR-encoded so the plain text does not appear in User.exe.
// Decode each one where it is used, for example: LoadLibraryA(Decode(NtdllName).data())
#include <array>
#include <cstddef>

constexpr char StringKey = 0x5A;

template<typename T, size_t N>
constexpr std::array<T, N> Encode(const T (&Str)[N])
{
    std::array<T, N> Encoded{};
    for (size_t i = 0; i < N - 1; i++)   // the terminating NUL is left as it is
        Encoded[i] = static_cast<T>(Str[i] ^ StringKey);
    return Encoded;
}

template<typename T, size_t N>
constexpr std::array<T, N> Decode(const std::array<T, N> &Encoded)
{
    std::array<T, N> Decoded = Encoded;
    for (size_t i = 0; i < N - 1; i++)
        Decoded[i] = static_cast<T>(Decoded[i] ^ StringKey);
    return Decoded;
}

constexpr auto NtdllName = Encode("ntdll.dll");
constexpr auto NtCompareSigningLevelsName = Encode("NtCompareSigningLevels");
constexpr auto PidLabel = Encode("PID: ");

// HVCI ("Memory integrity") state. The registry's own storage is the SYSTEM hive file on disk, which
// is parsed directly here, so no registry API is involved anywhere
constexpr auto SystemHivePath = Encode("C:\\Windows\\System32\\config\\SYSTEM");
constexpr auto HvciLabel = Encode("HVCI: ");
