#pragma once
#include <cstddef>
#include <cstdint>

// Build identity is a 64-bit FNV-1a hash of the driver file. The loader embeds
// only this value; the driver carries no marker section or ASCII tag.
#ifndef POSTBOX_BUILD_HASH
constexpr uint64_t POSTBOX_BUILD_HASH = 0x9061d574d28ac4b2ull;   // FNV-1a of Driver.sys
#endif

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
// tags for requests/responses. The client CSPRNG key reaches the loader through the PBX1 section
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
    pb_nmi_probe = 6,       // NMI_PROBE test builds only: callback RIP/RSP probe
    pb_stack_probe = 7,     // STACK_SPOOF test builds only: call-site stack capture
    pb_nmi_status = 8,      // NMI_PROBE test builds only: sanitizer activation/rewrite state
};

// Test-only NMI callback probe result. The driver registers KeRegisterNmiCallback,
// sends HalSendNMI to each core, and records the interrupted machine frame. The
// client prints this; the product build never uses it.
constexpr uint32_t PostboxNmiProbeMaxCores = 16;
struct PostboxNmiProbeCore
{
    uint64_t Rip;
    uint64_t Rsp;
    uint64_t Count;
    uint64_t InModule;
    uint64_t User;
};
static_assert(sizeof(PostboxNmiProbeCore) == 0x28, "NMI probe core ABI changed");

struct PostboxNmiProbeResult
{
    uint32_t CoreCount;
    uint32_t Reserved;
    PostboxNmiProbeCore Core[PostboxNmiProbeMaxCores];
};
static_assert(sizeof(PostboxNmiProbeResult) == 8 + 16 * 0x28, "NMI probe result ABI changed");

#ifdef NMI_PROBE
// Test-only sanitizer status. Reports whether the NMI sanitizer activated, the
// detector range it resolved, and the last record it rewrote (preserved count,
// real user flag, core, sanitized RIP/RSP). Product builds never compile it.
constexpr uint32_t PostboxNmiStatusMagic = 0x53544E4D;   // "MNTS"
struct PostboxNmiStatus
{
    uint32_t Magic;
    uint32_t Active;
    uint32_t Ready;
    uint32_t Reserved;
    uint64_t DetectorBase;
    uint64_t DetectorSize;
    uint64_t Writes;
    uint64_t LastCount;
    uint64_t LastUser;
    uint64_t LastCore;
    uint64_t LastRip;
    uint64_t LastRsp;
    uint64_t RefreshActive;
    uint64_t RefreshRun;
    uint64_t RefreshCount;
    uint64_t ListHead;
    uint64_t NtBase;
    uint64_t NtSize;
    uint64_t PsLoadedModuleList;
};
static_assert(sizeof(PostboxNmiStatus) == 0x88, "NMI status ABI changed");
#endif

// Test-only call-site stack probe. The MmCopyVirtualMemory trampoline records
// the fake-stack gadget, the real RSP, and the mapped real return address.
#ifdef STACK_PROBE
constexpr uint32_t PostboxStackProbeMagic = 0x4F4F5053;   // "SPOO"
struct PostboxStackProbeResult
{
    uint32_t Magic;
    uint32_t Hidden;
    uint64_t Gadget;
    uint64_t RealRsp;
    uint64_t FakeTop;
    uint64_t RealRet;
    uint64_t SpoofGadget;
    uint64_t SpoofRet;
    uint64_t MappedHits;
    uint64_t StackScanned;
    uint64_t Hit0;
    uint64_t Hit1;
    uint64_t Hit2;
    uint64_t Hit3;
    uint64_t RawHits;
    uint64_t RawScanned;
};
static_assert(sizeof(PostboxStackProbeResult) == 0x78, "stack probe result ABI changed");
#endif

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

constexpr uint32_t PostboxConfigMagic = 0x8E2B41D7;   // non-ASCII config tag

// The mapped image is headerless and .pdata/.reloc are zeroed, so the driver cannot
// parse its own PE section table at runtime. The loader builds this compact layout
// from the file and passes it in the config. The driver applies it to the image PTE
// block before the channel starts: .text RX, writable sections RW/NX, everything
// else (header, .rdata, .pdata, .reloc, .pbox, pool padding) R/NX.
constexpr uint32_t PostboxLayoutMagic = 0x3C9A6F52;   // non-ASCII layout tag
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
    uint64_t NtoskrnlBase;          // loader-resolved ntoskrnl image base
    PostboxSectionLayout Sections[PostboxMaxSections];
};

static_assert(sizeof(PostboxSectionLayout) == 16, "section layout changed");
static_assert(sizeof(PostboxImageLayout) == 0xB0, "image layout changed");

// Passed from the loader to DriverEntry in the second argument. Version 4
// (0x110 bytes: stage allocator/protect/free metadata).
struct PostboxConfig
{
    uint32_t Magic;                 // PostboxConfigMagic
    uint32_t Version;               // 4
    uint32_t Pid;                   // mailbox owner
    uint32_t Reserved;
    uint64_t MailboxVa;             // user VA of the mailbox
    uint8_t Key[32];                // client-generated master key (wiped after KDF)
    uint64_t CreateTime;            // required client process creation time
    uint64_t SessionId;             // client-generated session ID
    uint64_t MmAllocateIndependentPages; // loader-resolved stage allocator
    uint64_t MmSetPageProtection;        // loader-resolved stage protection
    PostboxImageLayout Layout;      // loader-built image section map
    uint64_t MmFreeIndependentPages;// loader-resolved stage free routine
};

// Client -> loader bootstrap handoff, carried in an unnamed pagefile-backed
// section. The client creates the section, keeps the creation handle, and spawns
// the loader with only that handle inherited. The loader maps the inherited
// handle, copies the record, unmaps/closes, and never touches the client address
// space. There is no name or DACL to discover; the handle value is passed on the
// loader command line. The section is page-granular and is deleted when the last
// handle closes.
//
// CreateTime is not independently verified by the loader any more (that needed a
// process handle + GetProcessTimes). The driver re-checks it with
// PsGetProcessCreateTimeQuadPart before it touches the mailbox (Postbox.cpp), so
// a forged record only fails PostboxStart.
constexpr uint32_t PostboxSectionHandoffMagic = 0x31584250;   // "PBX1"
constexpr uint32_t PostboxSectionHandoffVersion = 2;
constexpr uint32_t PostboxSectionBytes = 0x1000;              // one page

// Deferred-key handshake state, stored in PostboxSectionHandoff::Reserved. The
// client publishes the key only after the loader has finished provider/map work
// and signals LOADER_READY, so the key is not resident in the section during the
// loader's bring-up window.
constexpr uint32_t PostboxSectionStateWaiting = 0;
constexpr uint32_t PostboxSectionStateLoaderReady = 1;
constexpr uint32_t PostboxSectionStatePublishing = 4;
constexpr uint32_t PostboxSectionStateKeyReady = 2;
constexpr uint32_t PostboxSectionStateConsumed = 3;
constexpr uint32_t PostboxSectionStateWithdrawn = 5;

struct alignas(8) PostboxSectionHandoff
{
    uint32_t Magic;
    uint32_t Version;               // PostboxSectionHandoffVersion
    uint32_t Pid;                   // mailbox owner
    uint32_t Reserved;              // PostboxSectionState* handshake state
    uint64_t MailboxVa;             // user VA of the mailbox (8-byte aligned)
    uint64_t SessionId;             // per-session random ID
    uint64_t CreateTime;            // client process creation time, diagnostic
    uint8_t Key[32];                // master key; zero until LOADER_READY
};
static_assert(sizeof(PostboxSectionHandoff) == 0x48, "PostboxSectionHandoff layout changed");
static_assert(offsetof(PostboxSectionHandoff, MailboxVa) == 0x10,
              "PostboxSectionHandoff MailboxVa offset changed");
static_assert(offsetof(PostboxSectionHandoff, Key) == 0x28,
              "PostboxSectionHandoff Key offset changed");

static_assert(sizeof(PostboxConfig) == 0x110, "PostboxConfig layout changed");
static_assert(offsetof(PostboxConfig, CreateTime) == 0x38, "CreateTime offset changed");
static_assert(offsetof(PostboxConfig, SessionId) == 0x40, "SessionId offset changed");
static_assert(offsetof(PostboxConfig, MmAllocateIndependentPages) == 0x48,
              "MmAllocateIndependentPages offset changed");
static_assert(offsetof(PostboxConfig, MmSetPageProtection) == 0x50,
              "MmSetPageProtection offset changed");
static_assert(offsetof(PostboxConfig, Layout) == 0x58, "Layout offset changed");
static_assert(offsetof(PostboxConfig, MmFreeIndependentPages) == 0x108,
              "MmFreeIndependentPages offset changed");

// ---------------------------------------------------------------------------
// Config validation shared by the driver's PostboxStart and the host unit
// tests. Pure: no kernel calls and no side effects. On failure, *error (when
// non-null) receives the value PostboxStart reports in PostboxStartFailure for
// an invalid config (30, the entry value; the loader treats any non-zero as a
// failure). The checks run BEFORE MemSetPreStartNtoskrnl, so an invalid config
// does no kernel work.
// ---------------------------------------------------------------------------

constexpr uint32_t PostboxConfigVersion = 4;
constexpr uint32_t PostboxConfigReservedIndependent = 1;

// MmCopyMemory's documented user path stops below MmUserProbeAddress, not at
// 2^47. Use the tighter bound for every mailbox/target range check so a request
// near the old limit fails cleanly in PostboxCopy instead of inside the API.
constexpr uint64_t PostboxUserLimit = 0x00007FFFFFFF0000ull;

// Page-flag precedence when several sections share one page: executable wins
// (never downgrade a code page), then writable, else read-only/NX.
inline uint32_t PostboxMergePageFlags(uint32_t Current, uint32_t Incoming)
{
    if (Incoming == PostboxPageRx) return PostboxPageRx;
    if (Incoming == PostboxPageRwNx && Current != PostboxPageRx) return PostboxPageRwNx;
    return Current;
}

// Protocol body lengths shared by the driver poll and the client, so the two
// sides cannot drift. A request carries a body only for pb_write.
inline uint32_t PostboxRequestBodyLen(uint32_t Op, uint32_t Size)
{
    return Op == pb_write ? Size : 0;
}

// A response carries no body when the request failed; pb_read returns Size,
// pb_nmi returns 8, and the probe/status ops return their fixed result structs.
inline uint32_t PostboxResponseBodyLen(int32_t Status, uint32_t Op, uint32_t Size)
{
    if (Status != 0) return 0;
    switch (Op)
    {
    case pb_read: return Size;
    case pb_nmi:  return static_cast<uint32_t>(sizeof(uint64_t));
#ifdef NMI_PROBE
    case pb_nmi_probe:  return static_cast<uint32_t>(sizeof(PostboxNmiProbeResult));
    case pb_nmi_status: return static_cast<uint32_t>(sizeof(PostboxNmiStatus));
#endif
#ifdef STACK_PROBE
    case pb_stack_probe: return static_cast<uint32_t>(sizeof(PostboxStackProbeResult));
#endif
    default: return 0;
    }
}

// ---------------------------------------------------------------------------
// PostboxPollAttached decision rules, extracted so the host tests can exercise
// every branch without a live client mailbox.
// ---------------------------------------------------------------------------

enum class PostboxSeqVerdict
{
    Reject,        // not the next sequence and not the same sequence
    Idle,          // same Seq/session/nonce, already acknowledged: keepalive only
    AuthFailure,   // session mismatch or nonce did not advance
    Candidate,     // next Seq (or same-Seq stop candidate): open/MAC it
};

inline PostboxSeqVerdict PostboxSequenceVerdict(uint32_t Seq, uint32_t LastSeq,
                                                uint64_t SessionId,
                                                uint64_t ExpectedSessionId,
                                                uint64_t Nonce, uint64_t LastNonce,
                                                uint32_t Ack)
{
    const int32_t Ahead = static_cast<int32_t>(Seq - LastSeq);
    const bool SameSeq = (Ahead == 0);

    // Accept the next sequence for a normal request. A same-Seq request is only
    // considered for an authenticated pb_stop: after a lost response the client
    // reuses the last Seq, so the stop must work whether the driver processed
    // the original request or not.
    if (Ahead != 1 && !SameSeq) return PostboxSeqVerdict::Reject;

    // A valid idle header is the only unauthenticated state that keeps the
    // watchdog alive: same session, same nonce, acknowledged sequence. A
    // wrong-session or far-ahead header must not reset it.
    if (SameSeq && SessionId == ExpectedSessionId && Nonce == LastNonce && Ack == Seq)
        return PostboxSeqVerdict::Idle;

    if (SessionId != ExpectedSessionId || Nonce <= LastNonce)
        return PostboxSeqVerdict::AuthFailure;

    return PostboxSeqVerdict::Candidate;
}

// Pre-MAC shape check: known op, body-size rule (zero-body ops must be Size 0,
// all others nonzero), and the same-Seq restriction to pb_stop.
inline bool PostboxRequestShapeOk(bool KnownOp, bool ZeroBodyOp, uint32_t Op,
                                  uint32_t Size, uint32_t StageBytes, bool SameSeq)
{
    const bool SizeOk = Size <= StageBytes && (ZeroBodyOp ? Size == 0 : Size != 0);
    return KnownOp && SizeOk && !(SameSeq && Op != pb_stop);
}

// Post-MAC read/write range check: the target must be a user VA below
// MmUserProbeAddress, the size must fit the stage, and a write must not
// overlap the mailbox header (it would clobber Seq/Ack/Status mid-request).
inline bool PostboxRequestRangeOk(uint32_t Op, uint32_t Size, uint64_t Address,
                                  uint64_t MailboxVa, uint32_t StageBytes)
{
    if (Op != pb_read && Op != pb_write) return true;

    const bool InRange = Address && Address < PostboxUserLimit && Size <= StageBytes &&
                         Address <= (PostboxUserLimit - 1 - Size);
    const bool OverlapsHeader = InRange && Op == pb_write && Size != 0 &&
                                Address < MailboxVa + PostboxDataAt &&
                                Address + Size > MailboxVa;
    return InRange && !OverlapsHeader;
}

inline bool PostboxConfigValid(const PostboxConfig& cfg, uint32_t* error = nullptr)
{
    auto fail = [&]() { if (error) *error = 30; return false; };

    if (cfg.Magic != PostboxConfigMagic || cfg.Version != PostboxConfigVersion ||
        !cfg.Pid || !cfg.MailboxVa || !cfg.CreateTime || !cfg.SessionId)
        return fail();
    if (!cfg.Layout.NtoskrnlBase) return fail();
    // The self-free reaper may only call MmFreeIndependentPages on an
    // independent allocation; a pool image must fail closed.
    if (!(cfg.Reserved & PostboxConfigReservedIndependent)) return fail();
    if (cfg.MailboxVa > PostboxUserLimit - PostboxBytes || (cfg.MailboxVa & 7))
        return fail();

    bool keyNonZero = false;
    for (uint32_t i = 0; i < sizeof(cfg.Key); ++i)
        keyNonZero |= (cfg.Key[i] != 0);
    if (!keyNonZero) return fail();

    if (!cfg.MmAllocateIndependentPages || !cfg.MmSetPageProtection ||
        !cfg.MmFreeIndependentPages)
        return fail();

    if (error) *error = 0;
    return true;
}
