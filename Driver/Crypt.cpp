#include <array>
#include "seed.h"

// XOR with SEED is self-inverse, so one core serves Encode and Decode; the trailing NUL is left as it is
template<typename T, size_t N>
constexpr std::array<T, N> XorSeed(const std::array<T, N> &In)
{
    std::array<T, N> out{};
    for (size_t i = 0; i + 1 < N; ++i)
        out[i] = static_cast<T>(In[i] ^ SEED);
    return out;
}

// Copies the string into an array first (Encode returns a new array, not a pointer into the literal)
template<typename T, size_t N>
constexpr std::array<T, N> Encode(const T (&Str)[N])
{
    std::array<T, N> tmp{};
    for (size_t i = 0; i + 1 < N; ++i)
        tmp[i] = Str[i];
    return XorSeed(tmp);
}

// Reverses Encode
template<typename T, size_t N>
constexpr std::array<T, N> Decode(const std::array<T, N> &Str)
{
    return XorSeed(Str);
}

// Encodes a byte pattern like a string, so one Decode serves both
template<size_t N>
constexpr std::array<char, N> EncodeBytes(const std::array<char, N> &Bytes)
{
    return XorSeed(Bytes);
}
