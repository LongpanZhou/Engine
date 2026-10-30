#pragma once
#include <cstddef>
#include <cstdint>

// Build-identity marker. The section name and tag are intentionally not the
// historical ".pbox"/"PBOXABI" strings. Keep the section name at most 8 bytes
// (PE section name limit). Both the driver and the loader include this header.
#define POSTBOX_SECTION_NAME ".pbx7Q2a"
#define POSTBOX_MARKER_TAG "PBX7Q2A"
constexpr char PostboxSectionName[] = POSTBOX_SECTION_NAME;
constexpr char PostboxMarkerTag[] = POSTBOX_MARKER_TAG;

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

// The mapped image is headerless and .pdata/.reloc are zeroed, so the driver cannot
// parse its own PE section table at runtime. The loader builds this compact layout
// from the file and passes it in the config. The driver applies it to the image PTE
// block before the channel starts: .text RX, writable sections RW/NX, everything
// else (header, .rdata, .pdata, .reloc, .pbox, pool padding) R/NX.
constexpr uint32_t PostboxLayoutMagic = 0x59414C50;   // "PLAY"
constexpr uint32_t PostboxLayoutVersion = 1;
constexpr uint32_t PostboxMaxSections = 8;

enum PostboxPageFlags : uint32_t
{
    PostboxPageRx = 0,              // executable, read-only
    PostboxPageRwNx = 1,            // writable, non-executable
    PostboxPageRNx = 2,             // read-only, non-executable
};

struct PostboxSectionLayout
{
    uint32_t Rva;
    uint32_t Size;
    uint32_t Flags;                 // PostboxPageFlags
    uint32_t Reserved;
};

struct PostboxImageLayout
{
    uint32_t Magic;                 // PostboxLayoutMagic
    uint32_t Version;               // PostboxLayoutVersion
    uint32_t ImageSize;             // SizeOfImage
    uint32_t SectionCount;          // header entry + PE sections, <= PostboxMaxSections
    uint64_t RawBase;               // pool allocation base (may precede ImageBase)
    uint64_t ImageBase;             // aligned mapped image base
    uint64_t AllocSize;             // page-rounded pool allocation size
    uint64_t Reserved;
    PostboxSectionLayout Sections[PostboxMaxSections];
};

static_assert(sizeof(PostboxSectionLayout) == 16, "section layout changed");
static_assert(sizeof(PostboxImageLayout) == 0xB0, "image layout changed");

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
    PostboxImageLayout Layout;      // loader-built image section map
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

static_assert(sizeof(PostboxConfig) == 0x108, "PostboxConfig layout changed");
static_assert(offsetof(PostboxConfig, CreateTime) == 0x38, "CreateTime offset changed");
static_assert(offsetof(PostboxConfig, SessionId) == 0x40, "SessionId offset changed");
static_assert(offsetof(PostboxConfig, Reserved2) == 0x48, "Reserved2 offset changed");
static_assert(offsetof(PostboxConfig, Layout) == 0x58, "Layout offset changed");
