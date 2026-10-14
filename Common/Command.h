#pragma once

// The command User.exe sends to the driver through the hooked NtCompareSigningLevels. Both programs include this file,
// so the layout is defined once. Changing it changes the wire format for both
enum
{
    read,
    write,
    scan,   // runs the NMI scan and writes the count of suspicious processors to DestAddress
};

// The first argument of a command call. The driver acts only on calls that carry this value
constexpr uint64_t CommandSecret = 0xFFFFFFFF;

struct Command
{
    void *SrcAddress;
    void *DestAddress;
    uint32_t SrcPID;
    uint32_t DestPID;
    uint32_t Size;
    uint32_t OpCode;
} __attribute__((packed));

static_assert(sizeof(Command) == 32, "Command must be 32 bytes on both sides");
