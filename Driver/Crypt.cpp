#include <array>
#include "seed.h"

// No more ChatGPT
// XOR is self-inverse, so one core serves encoding and decoding: every element except the
// terminator (the last one) is XORed with SEED
template<typename T, size_t N>
constexpr std::array<T, N> XorSeed(const std::array<T, N> &In)
{
    std::array<T, N> out{};
    for (size_t i = 0; i + 1 < N; ++i)
        out[i] = static_cast<T>(In[i] ^ SEED);
    return out;
}

// Don't criticize this pls, i want to keep naming constant with constexpr
template<typename T, size_t N>
constexpr std::array<T, N> Encode(const T (&Str)[N])
{
    std::array<T, N> tmp{};
    for (size_t i = 0; i + 1 < N; ++i)
        tmp[i] = Str[i];
    return XorSeed(tmp);
}

template<typename T, size_t N>
constexpr std::array<T, N> Decode(const std::array<T, N> &Str)
{
    return XorSeed(Str);
}

// Encodes a byte array the same way Encode encodes a string, so Decode gives the original bytes back for any SEED
template<size_t N>
constexpr std::array<char, N> EncodeBytes(const std::array<char, N> &Bytes)
{
    return XorSeed(Bytes);
}
