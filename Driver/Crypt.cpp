#include "seed.h"
const char key = SEED & 0xff;
const wchar_t wkey = SEED & 0xffff;

#define ENCRYPT_STR(str) EncryptedString<sizeof(str)>(str)
#define ENCRYPT_WSTR(str) EncryptedWString<sizeof(str)/sizeof(wchar_t)>(str)

// Hash are not used but left for future if you want to hide string
constexpr uint64_t Hash(const char* Str, uint64_t Seed)
{
    print(INFO("Seed: %p"), Seed);
    //randomize hash with given seed
    for (; *Str; ++Str)
        Seed ^= *Str;
    print(INFO("Hash: %p"),Seed);
    return Seed;
}

template <size_t N>
struct EncryptedString {
    char data[N];

    // Compile-time encryption
    constexpr EncryptedString(const char (&str)[N]) : data{} {
        for (size_t i = 0; i < N; ++i)
            data[i] = str[i] ^ key;
    }

    // Runtime decryption
    const char* decrypt() {
        for (size_t i = 0; i < N; ++i)
            data[i] ^= key;
        return data;
    }
};

template <size_t N>
struct EncryptedWString {
    wchar_t data[N];

    // Compile-time encryption for wchar_t string literal
    constexpr EncryptedWString(const wchar_t (&str)[N]) : data{} {
        for (size_t i = 0; i < N; ++i)
            data[i] = str[i] ^ wkey;
    }

    // Runtime decryption (XOR again)
    const wchar_t* decrypt() {
        for (size_t i = 0; i < N; ++i)
            data[i] ^= wkey;
        return data;
    }
};