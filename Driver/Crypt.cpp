// Hash are not used but left for future if you want to hide string
constexpr uint64_t TimeToSeed(const char* Time)
{
    //convert time to seed
    return
        (Time[0] - '0') * 10 * 3600 +  // Hours * 3600
        (Time[1] - '0') * 3600 +
        (Time[3] - '0') * 10 * 60 +    // Minutes * 60
        (Time[4] - '0') * 60 +
        (Time[6] - '0') * 10 +         // Seconds
        (Time[7] - '0');
}

constexpr uint64_t Hash(const char* Str, uint64_t Seed)
{
    print(INFO("Seed: %p"), Seed);
    //randomize hash with given seed
    for (; *Str; ++Str)
        Seed ^= *Str;
    print(INFO("HASH: %p"),Seed);
    return Seed;
}