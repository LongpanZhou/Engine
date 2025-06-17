#include "seed.h"
const char key = SEED & 0xff;

#define ENCRYPT_STR(str) EncryptedString<sizeof(str)>(str)

// Hash are not used but left for future if you want to hide string
constexpr uint64_t Hash(const char* Str, uint64_t Seed)
{
    print(INFO("Seed: %p"), Seed);
    //randomize hash with given seed
    for (; *Str; ++Str)
        Seed ^= *Str;
    print(INFO("HASH: %p"),Seed);
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