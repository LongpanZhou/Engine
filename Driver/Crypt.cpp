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

// XOR
constexpr char key = SEED & 0xff;
constexpr wchar_t wkey = SEED & 0xffff;

// No more ChatGPT
template<size_t N>
constexpr std::array<char, N> Encode(const char (&Str)[N])
{
    std::array<char, N> encrypted{};
    for (size_t i = 0; i < N; ++i)
        encrypted[i] = Str[i] ^ key;
    return encrypted;
}

template<size_t N>
constexpr std::array<wchar_t, N> Encode(const wchar_t (&Str)[N])
{
    std::array<wchar_t, N> encrypted{};
    for (size_t i = 0; i < N; ++i)
        encrypted[i] = Str[i] ^ wkey;
    return encrypted;
}

template<size_t N>
constexpr std::array<char, N> Decode(const std::array<char, N> &Str)
{
    std::array<char, N> tmp = Str;
    for (size_t i = 0; i < N; ++i)
        tmp[i] ^= key;
    return tmp;
}

template<size_t N>
constexpr std::array<wchar_t, N> Decode(const std::array<wchar_t, N> &Str)
{
    std::array<wchar_t, N> tmp = Str;
    for (size_t i = 0; i < N; ++i)
        tmp[i] ^= wkey;
    return tmp;
}
