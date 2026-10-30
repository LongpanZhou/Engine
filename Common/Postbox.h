#pragma once
#include <cstddef>
#include <cstdint>

// Postbox: the driver <-> client mailbox described in out/research/AC-25_channel.md.
//
// The client owns one private committed page (or a heap block). The driver reads and
// writes it through the target CR3; there is no section, handle, name, or dedicated
// thread on the kernel side. One request is outstanding at a time:
//
//   client: fill Op/Pid/Address/Size and the body, derive/seal, then Seq++ (release)
//   driver: poll on its timer, verify the tag, execute, write Mac/Status/Ack = Seq
//   client: wait for Ack == Seq, verify the response tag, then read Status and the body
//
// Version 3 uses ChaCha20 for Op/Pid/Size/Address and the body, and 128-bit SipHash-2-4
// tags for requests/responses. The client CSPRNG key reaches the loader through a PBK1
// handoff; the driver derives and wipes. This is authenticated transport, not a trust
// boundary against a kernel AC or an in-process DLL.
//
// The opt-in POSTBOX_NMI build adds a constructed-IDT NMI gate (Driver/PostboxNmi.*)
// and the pb_nmi op; it does not change the mailbox or config layout.

constexpr uint32_t PostboxBytes = 0x10000;          // 64 KiB mailbox
constexpr uint32_t PostboxDataAt = 0x40;            // body starts after the header
constexpr uint32_t PostboxDataMax = PostboxBytes - PostboxDataAt;

enum PostboxOp : uint32_t
{
    pb_ping = 1,
    pb_read = 2,
    pb_write = 3,
    pb_stop = 4,
    pb_nmi = 5,             // POSTBOX_NMI builds only: query/self-test the NMI gate
};

// Naturally aligned: the atomic fields are 4-byte aligned and the 8-byte fields are
// 8-byte aligned. Packing this struct would make the atomic accesses unaligned.
struct alignas(8) PostboxHeader
{
    volatile uint32_t Seq;          // client increments after a request is written
    volatile uint32_t Ack;          // driver sets to Seq when the request is done
    volatile int32_t Status;        // NTSTATUS of the last request
    uint32_t Op;                    // PostboxOp
    uint32_t Pid;                   // client-side diagnostic; ignored by the driver
    uint32_t Size;                  // bytes in the body
    uint64_t Address;               // target VA for read/write
    uint64_t Nonce;                 // per-request 64-bit counter (MAC/cipher input)
    uint8_t Mac[16];                // 128-bit SipHash-2-4 tag
    uint64_t SessionId;             // per-session random ID (was Reserved[8])
};

static_assert(sizeof(PostboxHeader) == PostboxDataAt, "header must end at the body");
static_assert((offsetof(PostboxHeader, Seq) % 4) == 0, "Seq must be 4-byte aligned");
static_assert((offsetof(PostboxHeader, Address) % 8) == 0, "Address must be 8-byte aligned");

constexpr uint32_t PostboxConfigMagic = 0x50424F58;   // "PBOX"

// Passed from the loader to DriverEntry in the second argument. Version 3.
struct PostboxConfig
{
    uint32_t Magic;                 // PostboxConfigMagic
    uint32_t Version;               // 3
    uint32_t Pid;                   // mailbox owner
    uint32_t Reserved;
    uint64_t MailboxVa;             // user VA of the mailbox
    uint8_t Key[32];                // client-generated master key (wiped after KDF)
    uint64_t CreateTime;            // required client process creation time
    uint64_t SessionId;             // client-generated session ID
    uint8_t Reserved2[16];          // keeps the config at 0x58
};

// Client -> loader handoff, written at the start of the mailbox body before the first ping.
constexpr uint32_t PostboxHandoffMagic = 0x314B4250;   // "PBK1"
struct PostboxHandoff
{
    uint32_t Magic;
    uint32_t Version;               // 1
    uint64_t SessionId;
    uint64_t CreateTime;            // client process creation time, diagnostic
    uint8_t Key[32];                // master key; loader copies, then wipes
};
static_assert(sizeof(PostboxHandoff) == 0x38, "PostboxHandoff layout changed");

static_assert(sizeof(PostboxConfig) == 0x58, "PostboxConfig layout changed");
static_assert(offsetof(PostboxConfig, CreateTime) == 0x38, "CreateTime offset changed");
static_assert(offsetof(PostboxConfig, SessionId) == 0x40, "SessionId offset changed");
static_assert(offsetof(PostboxConfig, Reserved2) == 0x48, "Reserved2 offset changed");
