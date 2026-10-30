#pragma once
#include <cstddef>
#include <cstdint>

// Shared-memory command channel between the mapped driver and User.exe.
//
// The driver creates the section as \BaseNamedObjects\EngineCiShared (visible to
// user mode as Global\EngineCiShared), maps it into system space and services one
// request at a time from a system thread. User.exe maps the same section and
// stages the payload in the data area. No kernel function is patched, so there is
// nothing for PatchGuard to compare and nothing to restore on unload.
//
// Protocol (single outstanding request):
//   user : fill Op/TargetPid/RemoteAddress/Size and the data area, then Sequence++
//   driver: read the header, do the work, write Status, then Ack = Sequence
//   user : wait for Ack == Sequence, then read Status and the data area

constexpr uint32_t ChannelMagic   = 0x31494345;   // "ECI1"
constexpr uint32_t ChannelBytes   = 0x100000;     // 1 MiB section
constexpr uint32_t ChannelDataAt  = 0x40;         // payload starts here
constexpr uint32_t ChannelDataMax = ChannelBytes - ChannelDataAt;

enum ChannelOp : uint32_t
{
    op_ping  = 1,
    op_read  = 2,
    op_write = 3,
};

// Naturally aligned: 4-byte fields at 4-byte offsets, 8-byte fields at 8-byte
// offsets. Packing this struct makes the atomic accesses unaligned, which the
// freestanding driver cannot link (no libatomic).
struct alignas(8) ChannelHeader
{
    volatile uint32_t Magic;          // driver: ChannelMagic once the view is live
    volatile uint32_t Sequence;       // user: increments after a request is written
    volatile uint32_t Ack;            // driver: last Sequence it finished
    volatile int32_t  Status;         // driver: status of that request
    uint32_t Op;
    uint32_t TargetPid;               // op_read / op_write
    uint32_t Size;                    // bytes staged in the data area
    uint32_t Reserved;
    uint64_t RemoteAddress;           // VA in the target process
    uint64_t Heartbeat;               // op_ping: driver-side counter
};

static_assert(sizeof(ChannelHeader) <= ChannelDataAt, "header must fit before the data area");
static_assert((offsetof(ChannelHeader, Sequence) % 4) == 0, "Sequence must be 4-byte aligned");
static_assert((offsetof(ChannelHeader, Ack) % 4) == 0, "Ack must be 4-byte aligned");
