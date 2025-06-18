#include "seed.h"

constexpr char key = SEED & 0xff;
constexpr wchar_t wkey = SEED & 0xffff;

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