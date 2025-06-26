#include "seed.h"

// Hash are not used but left for future if you want to hide string
uint64_t Hash(const char *Str, uint64_t Seed)
{
    print(INFO("Seed: %p"), Seed);
    for (; *Str; ++Str)
        Seed ^= *Str;
    print(INFO("Hash: %p"), Seed);
    return Seed;
}

// No more ChatGPT
template<typename T, size_t N>
constexpr std::array<T, N> Encode(const T (&Str)[N])
{
    std::array<T, N> encrypted{};
    for (size_t i = 0; i < N-1; ++i)
        encrypted[i] = Str[i] ^ SEED;
    return encrypted;
}

// Don't criticize this pls, i want to keep naming constant with constexpr
template<typename T, size_t N>
constexpr std::array<T, N> Decode(const std::array<T, N> &Str)
{
    std::array<T, N> tmp = Str;
    for (size_t i = 0; i < N-1; ++i)
        tmp[i] ^= SEED;
    return tmp;
}