// Postbox command channel: a timer DPC queues a work item; the work item polls a mailbox
// in the client's own private memory. No section, no handle, no named object, no dedicated
// thread. Included by main.cpp only when POSTBOX_CHANNEL is defined; the default build
// keeps the shared-memory channel in Channel.cpp.
//
// See out/research/AC-25_channel.md for the threat model, the alternatives, and the
// residual artifacts (the armed KTIMER and the transient worker frame).
#ifdef POSTBOX_CHANNEL

#include "../Common/Postbox.h"
#include "../Common/PostboxCrypto.h"

// Build marker for the loader's --postbox guard. It lives in its own PE
// section so mapload can verify the section table instead of scanning the
// whole file for four incidental bytes. Layout is shared with mapload/main.cpp:
//   POSTBOX_MARKER_TAG + NUL + u32 little-endian ABI version (3) + 4 reserved.
// The volatile read in PostboxStart keeps the section reachable from
// DriverEntry, so -Wl,--gc-sections cannot discard it.
__attribute__((section(POSTBOX_SECTION_NAME), used, aligned(16)))
static const volatile uint8_t PostboxSectionMarker[16] = {
    'P', 'B', 'X', '7', 'Q', '2', 'A', 0x00,
    0x03, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
};

// Minimal kernel layouts, kept local so the channel does not depend on the vendor headers
// declaring these types. Sizes are the x64 Windows 10 layouts; the static_asserts catch a
// header change at compile time.
struct PostboxTimer
{
    _DISPATCHER_HEADER Header;          // 0x00, 0x18 bytes
    uint64_t DueTime;                   // 0x18
    _LIST_ENTRY TimerListEntry;         // 0x20
    void* Dpc;                          // 0x30
    uint32_t Processor;                 // 0x38
    uint32_t Period;                    // 0x3c
};
static_assert(sizeof(PostboxTimer) == 0x40, "KTIMER layout changed");

struct PostboxDpc
{
    uint32_t TargetInfo;                // 0x00
    _SINGLE_LIST_ENTRY DpcListEntry;    // 0x08
    uint64_t ProcessorHistory;          // 0x10
    void* DeferredRoutine;              // 0x18
    void* DeferredContext;              // 0x20
    void* SystemArgument1;              // 0x28
    void* SystemArgument2;              // 0x30
    void* DpcData;                      // 0x38
};
static_assert(sizeof(PostboxDpc) == 0x40, "KDPC layout changed");
static_assert(offsetof(PostboxDpc, DeferredRoutine) == 0x18, "KDPC DeferredRoutine offset changed");
static_assert(offsetof(PostboxDpc, DpcData) == 0x38, "KDPC DpcData offset changed");

struct PostboxWork
{
    _LIST_ENTRY List;                   // 0x00
    void* WorkerRoutine;                // 0x10
    void* Parameter;                    // 0x18
};
static_assert(sizeof(PostboxWork) == 0x20, "WORK_QUEUE_ITEM layout changed");

using FnKeInitializeTimerEx = void (*)(PostboxTimer*, int32_t);
using FnKeInitializeDpc = void (*)(PostboxDpc*, void (*)(void*, void*, void*, void*), void*);
using FnKeSetCoalescableTimer = uint32_t (*)(PostboxTimer*, _LARGE_INTEGER, uint32_t, uint32_t, PostboxDpc*);
using FnKeCancelTimer = uint8_t (*)(PostboxTimer*);
using FnKeFlushQueuedDpcs = void (*)();
using FnExQueueWorkItem = void (*)(PostboxWork*, int32_t);
using FnPsLookupProcessByProcessId = int32_t (*)(void*, void**);
using FnObDereferenceObject = void (*)(void*);
using FnKeDelayExecutionThread = int32_t (*)(int32_t, uint8_t, _LARGE_INTEGER*);
using FnKeStackAttachProcess = void (*)(void*, void*);      // PEPROCESS, PKAPC_STATE
using FnKeUnstackDetachProcess = void (*)(void*);           // PKAPC_STATE
using FnPsAcquireProcessExitSynchronization = int32_t (*)(void*);
using FnPsReleaseProcessExitSynchronization = void (*)(void*);
using FnPsGetProcessCreateTimeQuadPart = int64_t (*)(void*);
using FnPsGetCurrentProcess = void* (*)();
using FnExAllocatePoolWithTag = void* (*)(uint32_t, size_t, uint32_t);
using FnExFreePool = void (*)(void*);
using FnMmAllocateIndependentPages = void* (*)(size_t Size, uint32_t Arg2,
                                               uint32_t Arg3, uint32_t Arg4);
using FnMmSetPageProtection = uint8_t (*)(void* Addr, size_t Size, uint32_t Protect);
using FnMmFreeIndependentPages = void (*)(void* Addr, size_t Size);

// MM_COPY_ADDRESS is a union of PVOID/PHYSICAL_ADDRESS; 8 bytes on x64.
union PostboxCopyAddress
{
    void* VirtualAddress;
    int64_t PhysicalAddress;
};
static_assert(sizeof(PostboxCopyAddress) == 8, "MM_COPY_ADDRESS ABI changed");

using FnMmCopyMemory = int32_t (*)(void* Target, PostboxCopyAddress Source,
                                   size_t Size, uint32_t Flags, size_t* Done);
using FnMmCopyVirtualMemory = int32_t (*)(void* SourceProcess, void* SourceAddress,
                                          void* TargetProcess, void* TargetAddress,
                                          size_t Size, int32_t PreviousMode, size_t* Done);
using FnKeIpiGenericCall = uint64_t (*)(uint64_t (*)(uint64_t), uint64_t);

static address g_KeInitializeTimerEx = 0;
static address g_KeInitializeDpc = 0;
static address g_KeSetCoalescableTimer = 0;
static address g_KeCancelTimer = 0;
static address g_KeFlushQueuedDpcs = 0;
static address g_ExQueueWorkItem = 0;
static address g_PsLookupProcessByProcessId = 0;
static address g_ObDereferenceObject = 0;
static address g_KeDelayExecutionThread = 0;
static address g_KeStackAttachProcess = 0;
static address g_KeUnstackDetachProcess = 0;
static address g_PsAcquireProcessExitSynchronization = 0;
static address g_PsReleaseProcessExitSynchronization = 0;
static address g_PsGetProcessCreateTimeQuadPart = 0;
static address g_PsGetCurrentProcess = 0;
static address g_ExAllocatePoolWithTag = 0;
static address g_ExFreePool = 0;
static address g_MmAllocateIndependentPages = 0;
static address g_MmSetPageProtection = 0;
static address g_MmFreeIndependentPages = 0;
static bool PostboxStageIndependent = false;
static address g_MmCopyMemory = 0;
static address g_MmCopyVirtualMemory = 0;
static address g_KeIpiGenericCall = 0;

static PostboxTimer PostboxTimerObject;
static PostboxDpc PostboxDpcObject;
static PostboxWork PostboxWorkItem;
static volatile long PostboxRunning = 0;
static volatile long PostboxInFlight = 0;
static pb::PostboxKeys PostboxKeys{};
static uint64_t PostboxSessionId = 0;
static uint64_t PostboxLastNonce = 0;
// The request/response stage is a separate NonPagedPoolNx allocation. It is never
// mapped through the page tables: the request paths translate only the client VA
// with PostboxCopy and use the stage as a plain kernel buffer. This avoids
// the 2 MB PDE alias that made the earlier large-page stage experiment bugcheck
// 0x1A. The 64 KiB size keeps the protocol's full body; the allocation may be
// large-page-backed, which is fine while it is never aliased.
constexpr uint32_t PostboxStageBytes = PostboxDataMax;
static uint8_t* PostboxStage = nullptr;
static uint32_t PostboxLastSeq = 0;
static uint32_t PostboxPeriodMs = 4;
static uint32_t PostboxIdleTicks = 0;
static uint32_t PostboxDeadTicks = 0;
static PostboxConfig PostboxCfg{};
static void* PostboxProcess = nullptr;

#ifdef POSTBOX_NMI
bool PostboxNmiInstall();
void PostboxNmiUninstall();
bool PostboxNmiSelfTest(uint64_t* Count);
uint64_t PostboxNmiCount();
#endif

// MmCopyMemory's documented user path stops below MmUserProbeAddress, not at 2^47.
// Use the tighter bound for every mailbox/target range check so a request near the
// old limit fails cleanly in PostboxCopy instead of inside the API.
constexpr uint64_t PostboxUserLimit = 0x00007FFFFFFF0000ull;

// The linker-defined image base. A RIP-relative reference resolves to the runtime
// pool base after the loader applies relocations, so this is the mapped image base.
extern "C" _IMAGE_DOS_HEADER __ImageBase;

static bool PostboxResolve();

// Self-map entry for a VA. The kernel's PTE_BASE maps the page tables, so this
// is a direct kernel VA write with no physical alias and no user-half supervisor
// PTE. Large-page mappings are refused: the image is a page-granular pool block.
static uint64_t* SelfMapEntry(address Va)
{
    const uint64_t PteBase = (uint64_t) GetPteBase();
    if (!PteBase) return nullptr;
    constexpr uint64_t Mask = (1ull << 39) - 8;
    return (uint64_t*) (uintptr_t) (PteBase + (((uint64_t) Va >> 9) & Mask));
}

static bool GetPteForVa(address Va, uint64_t*& Entry)
{
    uint64_t* Pte = SelfMapEntry(Va);
    if (!Pte) return false;
    uint64_t* Pde = SelfMapEntry(address((uint64_t) (uintptr_t) Pte));
    uint64_t* Pdpte = SelfMapEntry(address((uint64_t) (uintptr_t) Pde));
    uint64_t* Pml4e = SelfMapEntry(address((uint64_t) (uintptr_t) Pdpte));
    if (!Pml4e || !Pdpte || !Pde || !Pte) return false;

    if (!(*Pml4e & 1) || !(*Pdpte & 1) || !(*Pde & 1)) return false;
    if (*Pdpte & (1ull << 7)) return false;       // 1 GB page
    if (*Pde & (1ull << 7)) return false;         // 2 MB page
    if (!(*Pte & 1)) return false;

    Entry = Pte;
    return true;
}

// Set W and NX on one 4 KB image page through the self-map, then invlpg the
// current CPU. ProtectImageSections follows the loop with a global IPI flush.
static bool SetPageProtection(address Va, bool Write, bool Execute)
{
    uint64_t* Entry = nullptr;
    if (!GetPteForVa(Va, Entry)) return false;

    uint64_t Value = *Entry;
    if (Write) Value |= 2;
    else       Value &= ~2ull;
    if (Execute) Value &= ~(1ull << 63);
    else         Value |= (1ull << 63);

    __atomic_store_n(Entry, Value, __ATOMIC_RELEASE);
    invlpg(Va);
    return true;
}

struct PostboxTlbRange
{
    uint64_t Start;
    uint64_t End;
};

// KeIpiGenericCall callback: runs on every CPU at IPI_LEVEL and only invlpg's.
static uint64_t PostboxFlushTlb(uint64_t Context)
{
    const PostboxTlbRange* Range = (const PostboxTlbRange*) (uintptr_t) Context;
    for (uint64_t Va = Range->Start; Va < Range->End; Va += 0x1000)
        invlpg(address(Va));
    return 0;
}

// Apply the loader-built section map to the image block. The header and
// .pdata/.reloc are zeroed in the mapped image, so this map is the only source of
// section permissions. Every page from ImageBase to the page-rounded end of the
// pool block is covered: .text RX, writable sections RW/NX, everything else
// (header, .rdata, .pdata, .reloc, .pbox, padding) R/NX. No page is left RWX.
bool ProtectImageSections(const PostboxConfig* Config)
{
    if (!Config || Config->Layout.Magic != PostboxLayoutMagic ||
        Config->Layout.Version != PostboxLayoutVersion)
    {
        print(ERROR("Postbox: image layout missing or invalid"));
        return false;
    }

    const PostboxImageLayout& L = Config->Layout;
    if (L.ImageSize == 0 || L.AllocSize == 0 || L.SectionCount == 0 ||
        L.SectionCount > PostboxMaxSections)
        return false;

    // Resolve KeIpiGenericCall before the PTE walk: the global flush needs it.
    if (!PostboxResolve())
    {
        print(ERROR("Postbox: resolve failed before image protection"));
        return false;
    }

    const address ImageBase = address((uint64_t) (uintptr_t) &__ImageBase);
    if ((uint64_t) ImageBase != L.ImageBase || (L.ImageBase & 0xFFF) != 0)
    {
        print(ERROR("Postbox: image base mismatch (runtime %p, layout %p)"),
              (void*) (uintptr_t) ImageBase, (void*) (uintptr_t) L.ImageBase);
        return false;
    }

    const uint64_t End = (L.RawBase + L.AllocSize) & ~0xFFFull;
    if (L.ImageBase < L.RawBase || L.ImageBase >= End ||
        L.ImageBase + L.ImageSize > End)
    {
        print(ERROR("Postbox: image layout range is invalid"));
        return false;
    }

    uint32_t Pages = 0;
    for (uint64_t Va = L.ImageBase; Va < End; Va += 0x1000)
    {
        uint32_t Flags = PostboxPageRNx;
        for (uint32_t i = 0; i < L.SectionCount; ++i)
        {
            const PostboxSectionLayout& S = L.Sections[i];
            const uint64_t SecStart = L.ImageBase + S.Rva;
            const uint64_t SecEnd = SecStart + S.Size;
            const uint64_t PageEnd = Va + 0x1000;
            if (PageEnd <= (SecStart & ~0xFFFull) ||
                Va >= ((SecEnd + 0xFFF) & ~0xFFFull))
                continue;

            if (S.Flags == PostboxPageRx)
                Flags = PostboxPageRx;
            else if (S.Flags == PostboxPageRwNx && Flags != PostboxPageRx)
                Flags = PostboxPageRwNx;
        }

        const bool Write = (Flags == PostboxPageRwNx);
        const bool Execute = (Flags == PostboxPageRx);
        if (!SetPageProtection(address(Va), Write, Execute))
        {
            print(ERROR("Postbox: protect page %p failed"), (void*) (uintptr_t) Va);
            return false;
        }
        ++Pages;
    }

    // The per-page invlpg only covers the current CPU. A T2 AC can cache the
    // pre-protection RWX entry on the other CPU; flush every CPU so the stale
    // entry cannot write .text or execute .data after the split.
    if (!g_KeIpiGenericCall)
    {
        print(ERROR("Postbox: KeIpiGenericCall not resolved"));
        return false;
    }
    PostboxTlbRange Range{ L.ImageBase, End };
    ((FnKeIpiGenericCall) g_KeIpiGenericCall)(
        &PostboxFlushTlb, (uint64_t) (uintptr_t) &Range);

    print(INFO("Postbox: image protections applied (%u pages, %u sections)"),
          Pages, L.SectionCount);
    return true;
}

static void PostboxPoll();

static bool PostboxResolved = false;

static bool PostboxResolve()
{
    if (PostboxResolved) return true;
    address Ntoskrnl = GetNtoskrnl();
    if (!Ntoskrnl)
    {
        print(ERROR("Postbox: ntoskrnl not found"));
        return false;
    }

    static const char EncodedNames[][40] = {
        "LfJojujbmj{fUjnfsFy",
        "LfJojujbmj{fEqd",
        "LfTfuDpbmftdbcmfUjnfs",
        "LfDbodfmUjnfs",
        "LfGmvtiRvfvfeEqdt",
        "FyRvfvfXpslJufn",
        "QtMpplvqQspdfttCzQspdfttJe",
        "PcEfsfgfsfodfPckfdu",
        "LfEfmbzFyfdvujpoUisfbe",
        "LfTubdlBuubdiQspdftt",
        "LfVotubdlEfubdiQspdftt",
        "QtBdrvjsfQspdfttFyjuTzodispoj{bujpo",
        "QtSfmfbtfQspdfttFyjuTzodispoj{bujpo",
        "QtHfuQspdfttDsfbufUjnfRvbeQbsu",
        "FyBmmpdbufQppmXjuiUbh",          // ExAllocatePoolWithTag
        "FyGsffQppm",                      // ExFreePool
        "NnDpqzNfnpsz",                    // MmCopyMemory
        "NnDpqzWjsuvbmNfnpsz",             // MmCopyVirtualMemory
        "LfJqjHfofsjdDbmm",                // KeIpiGenericCall
        "QtHfuDvssfouQspdftt",             // PsGetCurrentProcess
    };

    // The resolve table is stored ROT1-encoded so the image does not carry the plaintext
    // export names. This is anti-static-scan, not secrecy: it is decoded in a stack buffer
    // and wiped after the resolve. The resolved pointers remain in .data.
    char Decoded[20][40] = {};
    const char* Names[20] = {};
    for (uint32_t i = 0; i < 20; ++i)
    {
        uint32_t j = 0;
        for (; j < 39 && EncodedNames[i][j]; ++j)
            Decoded[i][j] = (char) (EncodedNames[i][j] - 1);
        Decoded[i][j] = 0;
        Names[i] = Decoded[i];
    }

    address Functions[20] = {};
    FindFuncExportsBatch(Ntoskrnl, Names, Functions, 20);

    g_KeInitializeTimerEx = Functions[0];
    g_KeInitializeDpc = Functions[1];
    g_KeSetCoalescableTimer = Functions[2];
    g_KeCancelTimer = Functions[3];
    g_KeFlushQueuedDpcs = Functions[4];
    g_ExQueueWorkItem = Functions[5];
    g_PsLookupProcessByProcessId = Functions[6];
    g_ObDereferenceObject = Functions[7];
    g_KeDelayExecutionThread = Functions[8];
    g_KeStackAttachProcess = Functions[9];
    g_KeUnstackDetachProcess = Functions[10];
    g_PsAcquireProcessExitSynchronization = Functions[11];
    g_PsReleaseProcessExitSynchronization = Functions[12];
    g_PsGetProcessCreateTimeQuadPart = Functions[13];
    g_ExAllocatePoolWithTag = Functions[14];
    g_ExFreePool = Functions[15];
    g_MmCopyMemory = Functions[16];
    g_MmCopyVirtualMemory = Functions[17];
    g_KeIpiGenericCall = Functions[18];
    g_PsGetCurrentProcess = Functions[19];

    for (uint32_t i = 0; i < 20; ++i)
    {
        if (!Functions[i])
        {
            print(ERROR("Postbox: export %s not found"), Names[i]);
            for (uint32_t k = 0; k < 20; ++k)
            {
                volatile char* p = Decoded[k];
                for (uint32_t j = 0; j < 40; ++j) p[j] = 0;
            }
            return false;
        }
    }
    for (uint32_t i = 0; i < 20; ++i)
    {
        volatile char* p = Decoded[i];
        for (uint32_t j = 0; j < 40; ++j) p[j] = 0;
    }

    // The ROT1 table stays resident for now. Wiping it at runtime requires a
    // writable .rdata window and a global TLB flush; the first live attempt was
    // not observable because the lab VM hung, so it is deferred to a clean-VM
    // test. The loader-side import strip removes the PE descriptor/name strings.

    PostboxResolved = true;
    return true;
}

// Both directions use MmCopyVirtualMemory against the cached client EPROCESS:
// read = client user VA -> kernel stage, write = kernel stage -> client user VA.
// The API performs its own attach/exit synchronization, so the poll no longer
// calls KeStackAttachProcess or PsAcquireProcessExitSynchronization. This keeps
// the user-half supervisor PTE removed and cuts the driver's explicit CR3 churn.
static bool PostboxCopy(void* MailboxProcess, address UserVa, void* Buffer,
                        size_t Size, bool Write)
{
    if (!Size) return true;
    if ((uint64_t) UserVa >= PostboxUserLimit ||
        Size > PostboxUserLimit - (uint64_t) UserVa)
        return false;

    size_t Done = 0;
    int32_t Status;
    if (!Write)
    {
        // Source = client user VA, target = kernel stage, both expressed against
        // the cached client EPROCESS. MmCopyVirtualMemory performs the attach
        // internally, so the driver no longer calls KeStackAttachProcess itself.
        Status = ((FnMmCopyVirtualMemory) g_MmCopyVirtualMemory)(
            MailboxProcess, (void*) (uintptr_t) UserVa,
            ((FnPsGetCurrentProcess) g_PsGetCurrentProcess)(), Buffer,
            Size, 0 /* KernelMode */, &Done);
    }
    else
    {
        Status = ((FnMmCopyVirtualMemory) g_MmCopyVirtualMemory)(
            MailboxProcess, Buffer, MailboxProcess, (void*) (uintptr_t) UserVa,
            Size, 0 /* KernelMode */, &Done);
    }
    return Status >= 0 && Done == Size;
}

// Cancels the timer and waits for queued DPCs. Safe at PASSIVE, including from the work
// routine itself (a work item is not a DPC, so flushing DPCs cannot wait on this thread).
static void PostboxCancel()
{
    __atomic_store_n(&PostboxRunning, 0, __ATOMIC_RELEASE);
    ((FnKeCancelTimer) g_KeCancelTimer)(&PostboxTimerObject);
    ((FnKeFlushQueuedDpcs) g_KeFlushQueuedDpcs)();
#ifdef POSTBOX_NMI
    // PASSIVE-only: callers are the work routine and PostboxStop.
    PostboxNmiUninstall();
#endif
}

// Re-arms the periodic timer. PASSIVE_LEVEL (PostboxStart or the work routine).
// Returns false when the timer was not armed (running clear or KeSetCoalescableTimer
// returned a failure); PostboxStart treats that as a failed start.
static bool PostboxArm(uint32_t PeriodMs, uint32_t ToleranceMs)
{
    if (!__atomic_load_n(&PostboxRunning, __ATOMIC_ACQUIRE)) return false;
    _LARGE_INTEGER Due{};
    Due.QuadPart = -((int64_t) PeriodMs * 10000);
    const uint32_t Status = ((FnKeSetCoalescableTimer) g_KeSetCoalescableTimer)(
        &PostboxTimerObject, Due, PeriodMs, ToleranceMs, &PostboxDpcObject);
    return Status == 0;
}

// Slow the timer after a run of idle polls. Also called on a failed lookup/header read.
static void PostboxIdleTick()
{
    if (PostboxPeriodMs == 4 && ++PostboxIdleTicks >= 500)
    {
        PostboxPeriodMs = 250;
        (void) PostboxArm(250, 50);
    }
}

// Authenticated response: seal the body (already staged) first, then the tag, then Status,
// then Ack. The client treats Ack as the release marker and verifies the tag before use.
static bool PostboxRespond(uint64_t MailboxVa, void* MailboxProcess, uint32_t Seq, uint64_t Nonce,
                           uint32_t RequestOp, int32_t Status, const uint8_t* Body,
                           uint32_t BodyLen)
{
    uint8_t Tag[16];
    pb::MacResponseTag(Tag, PostboxKeys, PostboxSessionId, Seq, Seq, Status, Nonce,
                       RequestOp, Body, BodyLen);

    if (BodyLen != 0 &&
        !PostboxCopy(MailboxProcess, (address) (MailboxVa + PostboxDataAt),
                     (void*) Body, BodyLen, true))
        return false;

    if (!PostboxCopy(MailboxProcess, (address) (MailboxVa + offsetof(PostboxHeader, Mac)),
                     Tag, sizeof(Tag), true))
        return false;

    __atomic_thread_fence(__ATOMIC_RELEASE);
    if (!PostboxCopy(MailboxProcess, (address) (MailboxVa + offsetof(PostboxHeader, Status)),
                     &Status, sizeof(Status), true))
        return false;

    __atomic_thread_fence(__ATOMIC_RELEASE);
    return PostboxCopy(MailboxProcess, (address) (MailboxVa + offsetof(PostboxHeader, Ack)),
                       &Seq, sizeof(Seq), true);
}

// Volatile wipe for stack copies of the header/body. The compiler must not elide it.
static void PostboxWipe(void* Data, size_t Size)
{
    if (!Data) return;
    volatile uint8_t* p = (volatile uint8_t*) Data;
    while (Size--) *p++ = 0;
}

// Wipes and releases the separate NX stage. Safe to call more than once; the pointer
// is cleared so a later stop/watchdog path cannot double-free.
static void PostboxFreeStage()
{
    if (!PostboxStage) return;
    PostboxWipe(PostboxStage, PostboxStageBytes);
    if (PostboxStageIndependent && g_MmFreeIndependentPages)
        ((FnMmFreeIndependentPages) g_MmFreeIndependentPages)(
            PostboxStage, PostboxStageBytes);
    else
        ((FnExFreePool) g_ExFreePool)(PostboxStage);
    PostboxStage = nullptr;
    PostboxStageIndependent = false;
}

// The client EPROCESS reference is acquired once at start, not per poll. Release it
// only after the last in-flight poll has detached and dropped its exit synchronization.
static void PostboxReleaseProcess()
{
    void* Process = PostboxProcess;
    PostboxProcess = nullptr;
    if (Process && g_ObDereferenceObject)
        ((FnObDereferenceObject) g_ObDereferenceObject)(Process);
}

static void PostboxMaybeReleaseProcess()
{
    if (!__atomic_load_n(&PostboxRunning, __ATOMIC_ACQUIRE))
        PostboxReleaseProcess();
}

// A dead client must not leave an armed timer forever. Failures are counted only after the
// idle backoff has reached 250 ms, so 240 failures is about 60 s. A successful header read
// or request resets the count; the watchdog then cancels the timer and wipes the config.
static void PostboxDeadReset()
{
    PostboxDeadTicks = 0;
}

static void PostboxDeadTick()
{
    if (PostboxPeriodMs != 250) return;
    if (++PostboxDeadTicks < 240) return;
    PostboxCancel();
    PostboxFreeStage();
    PostboxWipe(&PostboxCfg, sizeof(PostboxCfg));
    pb::WipePostboxKeys(&PostboxKeys);
    PostboxSessionId = 0;
    PostboxLastNonce = 0;
}

// Runs at DISPATCH_LEVEL on the per-CPU DPC stack. It does no memory access: only the
// in-flight exchange and the queue. The mailbox work happens in PostboxWorkRoutine.
static void PostboxDpcRoutine(void*, void*, void*, void*)
{
    if (!__atomic_load_n(&PostboxRunning, __ATOMIC_ACQUIRE)) return;

    if (__atomic_exchange_n(&PostboxInFlight, 1, __ATOMIC_ACQ_REL) == 0)
        ((FnExQueueWorkItem) g_ExQueueWorkItem)(&PostboxWorkItem, 1);   // DelayedWorkQueue
}

// Runs at PASSIVE_LEVEL in an existing system worker thread.
static void PostboxWorkRoutine(void*)
{
    if (__atomic_load_n(&PostboxRunning, __ATOMIC_ACQUIRE))
        PostboxPoll();

    __atomic_store_n(&PostboxInFlight, 0, __ATOMIC_RELEASE);
}

// The poll body. The caller has already attached the worker to MailboxProcess and
// holds its reference; this routine must not dereference it.
static void PostboxPollAttached(void* MailboxProcess)
{
    const uint32_t MailboxPid = PostboxCfg.Pid;
    const uint64_t MailboxVa = PostboxCfg.MailboxVa;
    if (!MailboxPid || !MailboxVa) return;

    PostboxHeader Sealed{};
    if (!PostboxCopy(MailboxProcess, (address) MailboxVa, &Sealed, sizeof(Sealed), false))
    {
        PostboxWipe(&Sealed, sizeof(Sealed));
        PostboxDeadTick();
        PostboxIdleTick();
        return;
    }

    const uint32_t Seq = __atomic_load_n(&Sealed.Seq, __ATOMIC_ACQUIRE);
    const int32_t Ahead = (int32_t) (Seq - PostboxLastSeq);
    const bool SameSeq = (Ahead == 0);
    // Accept the next sequence for a normal request. A same-Seq request is only considered
    // for an authenticated pb_stop: after a lost response the client reuses the last Seq, so
    // the stop must work whether the driver processed the original request or not.
    if (Ahead != 1 && !SameSeq)
    {
        PostboxDeadTick();
        PostboxIdleTick();
        PostboxWipe(&Sealed, sizeof(Sealed));
        return;
    }

    // A valid idle header is the only unauthenticated state that keeps the watchdog
    // alive: same session, same nonce, acknowledged sequence. A wrong-session or
    // far-ahead header must not reset it.
    if (Ahead == 0 && Sealed.SessionId == PostboxSessionId &&
        Sealed.Nonce == PostboxLastNonce && Sealed.Ack == Seq)
    {
        PostboxDeadReset();
        PostboxIdleTick();
        PostboxWipe(&Sealed, sizeof(Sealed));
        return;
    }

    if (Sealed.SessionId != PostboxSessionId || Sealed.Nonce <= PostboxLastNonce)
    {
        PostboxDeadTick();
        PostboxIdleTick();
        PostboxWipe(&Sealed, sizeof(Sealed));
        return;
    }

    // Decrypt the 20-byte header only to learn Op/Size for MAC coverage; do not trust or
    // act on these values until the tag verifies below.
    PostboxHeader Plain = Sealed;
    pb::OpenRequestHeader(reinterpret_cast<uint8_t*>(&Plain), PostboxKeys,
                          PostboxSessionId, Sealed.Nonce);

    const uint32_t Op = Plain.Op;
    const uint32_t Size = Plain.Size;
    const uint64_t Address = Plain.Address;
    const bool KnownOp = Op == pb_ping || Op == pb_read || Op == pb_write || Op == pb_stop
#ifdef POSTBOX_NMI
                         || Op == pb_nmi
#endif
                         ;
    const bool SizeOk = Size <= PostboxStageBytes &&
                        ((Op == pb_ping || Op == pb_stop || Op == pb_nmi) ? Size == 0 : Size != 0);
    if (!KnownOp || !SizeOk || (SameSeq && Op != pb_stop))
    {
        PostboxWipe(&Plain, sizeof(Plain));
        PostboxWipe(&Sealed, sizeof(Sealed));
        PostboxDeadTick();
        PostboxIdleTick();
        return;
    }

    const uint32_t BodyLen = (Op == pb_write) ? Size : 0;
    const uint32_t StageBytes = (Op == pb_read || Op == pb_write) ? Size :
                                (Op == pb_nmi) ? (uint32_t) sizeof(uint64_t) : 0;

    const address DataVa = (address) (MailboxVa + PostboxDataAt);
    if (BodyLen != 0 &&
        !PostboxCopy(MailboxProcess, DataVa, PostboxStage, BodyLen, false))
    {
        PostboxWipe(&Plain, sizeof(Plain));
        PostboxWipe(&Sealed, sizeof(Sealed));
        PostboxWipe(PostboxStage, BodyLen);
        PostboxDeadTick();
        PostboxIdleTick();
        return;
    }

    uint8_t Tag[16];
    pb::MacRequestTag(Tag, PostboxKeys, PostboxSessionId, Seq, Sealed.Nonce, Op,
                      reinterpret_cast<const uint8_t*>(&Sealed), PostboxStage, BodyLen);
    if (!pb::Mac128Equal(Tag, Sealed.Mac))
    {
        PostboxWipe(&Plain, sizeof(Plain));
        PostboxWipe(&Sealed, sizeof(Sealed));
        PostboxWipe(PostboxStage, BodyLen);
        PostboxDeadTick();
        PostboxIdleTick();
        return;
    }

    // Authenticated. Consume the sequence/nonce before any response write: if the response
    // is lost, the client's next request is Seq + 1 and must not look like a replay.
    PostboxLastSeq = Seq;
    PostboxLastNonce = Sealed.Nonce;
    PostboxDeadReset();
    PostboxIdleTicks = 0;
    if (PostboxPeriodMs != 4)
    {
        PostboxPeriodMs = 4;
        (void) PostboxArm(4, 1);
    }

    int32_t Status = 0;
    const uint8_t* ResponseBody = nullptr;
    uint32_t ResponseLen = 0;

    if (Op == pb_read || Op == pb_write)
    {
        // The prototype is self-process only: the target is the mailbox owner. This keeps
        // the channel from becoming an arbitrary-process R/W primitive for anyone who can
        // write the mailbox. Cross-process access needs an allowlist.
        const bool InRange = Address && Address < PostboxUserLimit && Size <= PostboxStageBytes &&
                             Address <= (PostboxUserLimit - 1 - Size);
        // A write into the mailbox's own 0x40-byte header can clobber Seq/Ack/Status
        // mid-request; reject any write range that overlaps it.
        const bool OverlapsHeader = InRange && Op == pb_write && Size != 0 &&
                                    Address < MailboxVa + PostboxDataAt &&
                                    Address + Size > MailboxVa;

        if (!InRange || OverlapsHeader)
        {
            Status = (int32_t) 0xC000000D;          // STATUS_INVALID_PARAMETER
        }
        else if (Op == pb_write)
        {
            pb::OpenRequestBody(PostboxStage, Size, PostboxKeys, PostboxSessionId, Sealed.Nonce);
            const bool Ok = PostboxCopy(MailboxProcess, (address) Address,
                                        PostboxStage, Size, true);
            Status = Ok ? 0 : (int32_t) 0xC0000005;
            PostboxWipe(PostboxStage, Size);
        }
        else
        {
            const bool Ok = PostboxCopy(MailboxProcess, (address) Address,
                                        PostboxStage, Size, false);
            if (Ok)
            {
                pb::SealResponseBody(PostboxStage, Size, PostboxKeys, PostboxSessionId, Sealed.Nonce);
                ResponseBody = PostboxStage;
                ResponseLen = Size;
            }
            else
            {
                Status = (int32_t) 0xC0000005;      // STATUS_ACCESS_VIOLATION
            }
        }
    }
#ifdef POSTBOX_NMI
    else if (Op == pb_nmi)
    {
        if (Address > 1)
        {
            Status = (int32_t) 0xC000000D;          // STATUS_INVALID_PARAMETER
        }
        else
        {
            uint64_t NmiCount = PostboxNmiCount();
            if (Address == 1)
            {
                // Transient gate: install, run the self-IPI test, restore the Windows
                // IDT in the same work item. No private IDTR survives the request, so
                // a failed timer/NMI path cannot leave an unremovable gate behind.
                uint64_t After = 0;
                if (!PostboxNmiInstall())
                {
                    Status = (int32_t) 0xC0000001;  // STATUS_UNSUCCESSFUL
                }
                else
                {
                    const bool Ok = PostboxNmiSelfTest(&After);
                    PostboxNmiUninstall();
                    if (Ok)
                        NmiCount = After;
                    else
                        Status = (int32_t) 0xC0000001;
                }
            }
            if (Status == 0)
            {
                __builtin_memcpy(PostboxStage, &NmiCount, sizeof(NmiCount));
                pb::SealResponseBody(PostboxStage, sizeof(NmiCount), PostboxKeys,
                                     PostboxSessionId, Sealed.Nonce);
                ResponseBody = PostboxStage;
                ResponseLen = sizeof(NmiCount);
            }
        }
    }
#endif

    // Do not publish a response body after the client has moved on. This narrows the
    // timeout/body-overwrite race; the stage keeps the MAC and the published bytes identical.
    uint32_t CurrentSeq = 0;
    uint64_t CurrentNonce = 0;
    if (!PostboxCopy(MailboxProcess, (address) MailboxVa, &CurrentSeq, sizeof(CurrentSeq), false) ||
        !PostboxCopy(MailboxProcess, (address) (MailboxVa + offsetof(PostboxHeader, Nonce)),
                     &CurrentNonce, sizeof(CurrentNonce), false) ||
        CurrentSeq != Seq || CurrentNonce != Sealed.Nonce)
    {
        PostboxWipe(&Plain, sizeof(Plain));
        PostboxWipe(&Sealed, sizeof(Sealed));
        PostboxWipe(PostboxStage, StageBytes);
        return;
    }

    PostboxRespond(MailboxVa, MailboxProcess, Seq, Sealed.Nonce, Op, Status, ResponseBody, ResponseLen);
    PostboxWipe(PostboxStage, StageBytes);

    if (Op == pb_stop)
    {
        // The stop is authenticated and acknowledged; now cancel. The work item clears
        // PostboxInFlight on its way out, so do not wait here.
        PostboxCancel();
        PostboxFreeStage();
        PostboxWipe(&PostboxCfg, sizeof(PostboxCfg));
        pb::WipePostboxKeys(&PostboxKeys);
        PostboxSessionId = 0;
        PostboxLastNonce = 0;
    }

    PostboxWipe(&Plain, sizeof(Plain));
    PostboxWipe(&Sealed, sizeof(Sealed));
}

// Wrapper: attach the system worker to the mailbox process for the duration of the poll.
// The old NO_MAP_TABLE PTE path claimed a PTE in the *current* process; in the
// System process that search walks the kernel half and fails, while in the client's
// context it finds a free user PTE. The attach reference is dropped only after detach.
static void PostboxPoll()
{
    if (!__atomic_load_n(&PostboxRunning, __ATOMIC_ACQUIRE)) return;
    const uint32_t Pid = PostboxCfg.Pid;
    if (!Pid || !PostboxCfg.MailboxVa)
    {
        // A zeroed/corrupted config must not leave the fast timer armed forever:
        // the dead-client watchdog is bypassed by this early return, and a manual
        // map has no unload callback. Cancel and wipe here (PASSIVE, work routine).
        PostboxCancel();
        PostboxFreeStage();
        PostboxWipe(&PostboxCfg, sizeof(PostboxCfg));
        pb::WipePostboxKeys(&PostboxKeys);
        PostboxSessionId = 0;
        PostboxLastNonce = 0;
        return;
    }

    // The EPROCESS reference and create-time check were done once in PostboxStart.
    void* Process = PostboxProcess;
    if (!Process)
    {
        PostboxDeadTick();
        PostboxIdleTick();
        PostboxMaybeReleaseProcess();
        return;
    }

    // No explicit attach: PostboxCopy uses MmCopyVirtualMemory with the cached
    // client EPROCESS as both source and target. This removes the driver's
    // KeStackAttachProcess/detach and PsAcquire/ReleaseExitSynchronization pair
    // from every poll (the copy API still switches CR3 internally).
    PostboxPollAttached(Process);
    PostboxMaybeReleaseProcess();
}

// Starts the channel from a loader-supplied config. PASSIVE_LEVEL (DriverEntry).
bool PostboxStart(const PostboxConfig* Config)
{
    // Reachability reference that keeps .pbox in the file for the loader's marker
    // check. The mapper deliberately does not copy .pbox into the published image,
    // so the mapped byte is zero; only a corrupt 0xFF fails the start.
    if (PostboxSectionMarker[0] == 0xFF)
        return false;

    if (__atomic_load_n(&PostboxRunning, __ATOMIC_ACQUIRE)) return true;
    if (!Config || Config->Magic != PostboxConfigMagic || Config->Version != 3 ||
        !Config->Pid || !Config->MailboxVa || !Config->CreateTime || !Config->SessionId) return false;
    if (Config->MailboxVa > PostboxUserLimit - PostboxBytes || (Config->MailboxVa & 7)) return false;

    bool KeyNonZero = false;
    for (uint32_t i = 0; i < sizeof(Config->Key); ++i)
        KeyNonZero |= (Config->Key[i] != 0);
    if (!KeyNonZero) return false;

    PostboxCfg = *Config;
    // Keep the independent-page stage helpers outside the config wipe.
    g_MmAllocateIndependentPages = (address) Config->MmAllocateIndependentPages;
    g_MmSetPageProtection = (address) Config->MmSetPageProtection;
    g_MmFreeIndependentPages = (address) Config->MmFreeIndependentPages;
    PostboxCfg.MmAllocateIndependentPages = 0;
    PostboxCfg.MmSetPageProtection = 0;
    PostboxCfg.MmFreeIndependentPages = 0;
    // The magic/version are validation-only. Leaving the 8-byte "PBOX"+version
    // prefix in .data makes the resident control block trivially findable by a
    // magic scan; wipe it after the check.
    PostboxCfg.Magic = 0;
    PostboxCfg.Version = 0;
    // The section map is only needed by ProtectImageSections(), which ran before
    // this copy. Do not leave the RVAs/sizes in the resident .data image.
    PostboxWipe(&PostboxCfg.Layout, sizeof(PostboxCfg.Layout));
    PostboxLastSeq = 0;
    PostboxLastNonce = 0;
    PostboxInFlight = 0;
    PostboxSessionId = Config->SessionId;

    uint8_t Master[32];
    for (uint32_t i = 0; i < sizeof(Master); ++i) Master[i] = Config->Key[i];
    pb::DerivePostboxKeys(&PostboxKeys, Master);   // wipes Master
    PostboxWipe(&PostboxCfg.Key, sizeof(PostboxCfg.Key));

    if (!PostboxResolve())
    {
        PostboxWipe(&PostboxCfg, sizeof(PostboxCfg));
        pb::WipePostboxKeys(&PostboxKeys);
        PostboxSessionId = 0;
        return false;
    }

    // Acquire the client reference and verify its create time once, not per poll.
    void* Process = nullptr;
    if (((FnPsLookupProcessByProcessId) g_PsLookupProcessByProcessId)(
            (void*) (uintptr_t) PostboxCfg.Pid, &Process) < 0 || !Process)
    {
        PostboxWipe(&PostboxCfg, sizeof(PostboxCfg));
        pb::WipePostboxKeys(&PostboxKeys);
        PostboxSessionId = 0;
        return false;
    }
    if ((uint64_t) ((FnPsGetProcessCreateTimeQuadPart) g_PsGetProcessCreateTimeQuadPart)(Process) !=
        PostboxCfg.CreateTime)
    {
        ((FnObDereferenceObject) g_ObDereferenceObject)(Process);
        PostboxWipe(&PostboxCfg, sizeof(PostboxCfg));
        pb::WipePostboxKeys(&PostboxKeys);
        PostboxSessionId = 0;
        return false;
    }
    PostboxProcess = Process;

    // Separate NX stage. Prefer page-granular independent pages so the channel
    // does not leave a 64 KiB 'Ntfs' NonPagedPoolNx entry for its lifetime; fall
    // back to the pool when an older loader did not pass the helpers.
    PostboxStage = nullptr;
    PostboxStageIndependent = false;
    if (g_MmAllocateIndependentPages && g_MmSetPageProtection && g_MmFreeIndependentPages)
    {
        PostboxStage = (uint8_t*) ((FnMmAllocateIndependentPages)
            g_MmAllocateIndependentPages)(PostboxStageBytes, 0xFFFFFFFF, 0, 0);
        if (PostboxStage)
        {
            if (((FnMmSetPageProtection) g_MmSetPageProtection)(
                    PostboxStage, PostboxStageBytes, 0x04 /* PAGE_READWRITE */))
            {
                PostboxStageIndependent = true;
            }
            else
            {
                ((FnMmFreeIndependentPages) g_MmFreeIndependentPages)(
                    PostboxStage, PostboxStageBytes);
                PostboxStage = nullptr;
            }
        }
    }
    if (!PostboxStage)
    {
        PostboxStage = (uint8_t*) ((FnExAllocatePoolWithTag) g_ExAllocatePoolWithTag)(
            0x200 /* NonPagedPoolNx */, PostboxStageBytes, 0x7366744E /* 'Ntfs' */);
        PostboxStageIndependent = false;
    }
    if (!PostboxStage)
    {
        print(ERROR("Postbox: NX stage allocation failed"));
        PostboxReleaseProcess();
        PostboxWipe(&PostboxCfg, sizeof(PostboxCfg));
        pb::WipePostboxKeys(&PostboxKeys);
        PostboxSessionId = 0;
        return false;
    }
    PostboxWipe(PostboxStage, PostboxStageBytes);

#ifdef POSTBOX_NMI
    // The IDT is not touched at start. The gate is installed transiently only for
    // the pb_nmi self-test, then the Windows IDT is restored in the same work item.
#endif

    // ExInitializeWorkItem's fields, without pulling in the macro from the vendor headers
    PostboxWorkItem.List.Flink = nullptr;
    PostboxWorkItem.List.Blink = nullptr;
    PostboxWorkItem.WorkerRoutine = (void*) &PostboxWorkRoutine;
    PostboxWorkItem.Parameter = nullptr;

    ((FnKeInitializeTimerEx) g_KeInitializeTimerEx)(&PostboxTimerObject, 0);   // NotificationTimer
    ((FnKeInitializeDpc) g_KeInitializeDpc)(&PostboxDpcObject, &PostboxDpcRoutine, nullptr);

    PostboxPeriodMs = 4;
    PostboxIdleTicks = 0;
    PostboxDeadTicks = 0;
    __atomic_store_n(&PostboxRunning, 1, __ATOMIC_RELEASE);
    if (!PostboxArm(4, 1))
    {
        // A start without an armed timer is a resident channel-less image. Fail
        // closed and let the loader free/zero the image.
        print(ERROR("Postbox: KeSetCoalescableTimer failed; start aborted"));
        __atomic_store_n(&PostboxRunning, 0, __ATOMIC_RELEASE);
        PostboxFreeStage();
        PostboxReleaseProcess();
        PostboxWipe(&PostboxCfg, sizeof(PostboxCfg));
        pb::WipePostboxKeys(&PostboxKeys);
        PostboxSessionId = 0;
        return false;
    }

    print(INFO("Postbox: live, pid %u mailbox %p, 4 ms timer"),
          PostboxCfg.Pid, (void*) (uintptr_t) PostboxCfg.MailboxVa);
    return true;
}

// External teardown (DriverExit / SCM unload). PASSIVE_LEVEL. A manual map has no unload
// callback, so the client's op_stop is the path that matters there.
void PostboxStop()
{
#ifdef POSTBOX_NMI
    // Also covers a second stop after the timer was already cancelled.
    PostboxNmiUninstall();
#endif
    if (!__atomic_load_n(&PostboxRunning, __ATOMIC_ACQUIRE))
    {
        for (uint32_t i = 0; i < 1000 && __atomic_load_n(&PostboxInFlight, __ATOMIC_ACQUIRE); ++i)
        {
            _LARGE_INTEGER Interval{};
            Interval.QuadPart = -10000;
            ((FnKeDelayExecutionThread) g_KeDelayExecutionThread)(0, 0, &Interval);
        }
        PostboxReleaseProcess();
        return;
    }

    PostboxCancel();

    // The work item is not tracked by KeFlushQueuedDpcs; give it up to 1 s to finish.
    for (uint32_t i = 0; i < 1000 && __atomic_load_n(&PostboxInFlight, __ATOMIC_ACQUIRE); ++i)
    {
        _LARGE_INTEGER Interval{};
        Interval.QuadPart = -10000;                 // 1 ms
        ((FnKeDelayExecutionThread) g_KeDelayExecutionThread)(0, 0, &Interval);
    }

    PostboxFreeStage();
    PostboxReleaseProcess();
    PostboxWipe(&PostboxCfg, sizeof(PostboxCfg));
    pb::WipePostboxKeys(&PostboxKeys);
    PostboxSessionId = 0;
    PostboxLastNonce = 0;
    PostboxLastSeq = 0;
    print(INFO("Postbox: stopped"));
}

#endif // POSTBOX_CHANNEL
