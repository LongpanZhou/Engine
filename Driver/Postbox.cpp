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
//   POSTBOX_MARKER_TAG + NUL + u32 little-endian ABI version (4) + 4 reserved.
// The volatile read in PostboxStart keeps the section reachable from
// DriverEntry, so -Wl,--gc-sections cannot discard it.
__attribute__((section(POSTBOX_SECTION_NAME), used, aligned(16)))
static const volatile uint8_t PostboxSectionMarker[16] = {
    'P', 'B', 'X', '7', 'Q', '2', 'A', 0x00,
    0x04, 0x00, 0x00, 0x00,
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
using FnPsCreateSystemThread = int32_t (*)(void** ThreadHandle, uint32_t DesiredAccess,
                                           void* ObjectAttributes, void* ProcessHandle,
                                           void* ClientId, void* StartRoutine,
                                           void* StartContext);
using FnZwClose = int32_t (*)(void* Handle);

static address g_KeInitializeTimerEx_Raw = 0;
static address g_KeInitializeDpc_Raw = 0;
static address g_KeSetCoalescableTimer_Raw = 0;
static address g_KeCancelTimer_Raw = 0;
static address g_KeFlushQueuedDpcs_Raw = 0;
static address g_ExQueueWorkItem_Raw = 0;
static address g_PsLookupProcessByProcessId_Raw = 0;
static address g_ObDereferenceObject_Raw = 0;
static address g_KeDelayExecutionThread_Raw = 0;
static address g_KeStackAttachProcess = 0;
static address g_KeUnstackDetachProcess = 0;
static address g_PsAcquireProcessExitSynchronization_Raw = 0;
static address g_PsReleaseProcessExitSynchronization_Raw = 0;
static address g_PsGetProcessCreateTimeQuadPart_Raw = 0;
static address g_PsGetCurrentProcess_Raw = 0;
static address g_ExAllocatePoolWithTag_Raw = 0;
static address g_ExFreePool_Raw = 0;
static address g_MmAllocateIndependentPages = 0;
static address g_MmSetPageProtection = 0;
static address g_MmFreeIndependentPages = 0;

static address g_MmCopyMemory = 0;
static address g_MmCopyVirtualMemory_Raw = 0;
static address g_KeIpiGenericCall = 0;
static address g_PsCreateSystemThread_Raw = 0;
static address g_ZwClose_Raw = 0;

static volatile long PostboxRunning = 0;
static volatile long PostboxInFlight = 0;
static volatile long PostboxTeardown = 0;
static volatile long PostboxReaperStarted = 0;

// The reaper stub is assembly in PostboxReaper.S. It runs as a system thread,
// waits for the work routine to return, frees the state page, then tail-jumps to
// MmFreeIndependentPages so the free returns to PspSystemThreadStartup.
extern "C" uint64_t PostboxReaperBase = 0;   // loader allocation base (RawBase)
extern "C" uint64_t PostboxReaperSize = 0;   // loader allocation size (AllocSize)
extern "C" uint64_t PostboxReaperFree = 0;   // resolved MmFreeIndependentPages
extern "C" void PostboxReaperEntry();
extern "C" void PostboxReaperPrepare();

// Resolved ntoskrnl routines used after the state page exists. They are copied
// out of .data into the state page by PostboxStart and zeroed in .data, so a
// static .data scan sees no routine table. KeIpiGenericCall stays in .data: the
// pre-start ProtectImageSections path needs it before the state page exists.
struct PostboxImports
{
    address KeInitializeTimerEx;
    address KeInitializeDpc;
    address KeSetCoalescableTimer;
    address KeCancelTimer;
    address KeFlushQueuedDpcs;
    address ExQueueWorkItem;
    address PsLookupProcessByProcessId;
    address ObDereferenceObject;
    address KeDelayExecutionThread;
    address PsGetProcessCreateTimeQuadPart;
    address ExAllocatePoolWithTag;
    address ExFreePool;
    address MmCopyVirtualMemory;
    address PsGetCurrentProcess;
    address PsAcquireProcessExitSynchronization;
    address PsReleaseProcessExitSynchronization;
    address PsCreateSystemThread;
    address ZwClose;
};

// The live protocol state (config, keys, timer/DPC/work, client EPROCESS, stage)
// lives on a separate independent RW/NX page. Only this pointer stays in .data.
struct PostboxState
{
    PostboxConfig Cfg;
    pb::PostboxKeys Keys;
    PostboxTimer Timer;
    PostboxDpc Dpc;
    PostboxWork Work;
    void* Process;
    uint8_t* Stage;
    uint64_t SessionId;
    uint64_t LastNonce;
    uint32_t LastSeq;
    uint32_t AuthFailures;
    bool StageIndependent;
    PostboxImports Imports;
};
static PostboxState* PostboxStatePtr = nullptr;

#define g_KeInitializeTimerEx (PostboxStatePtr->Imports.KeInitializeTimerEx)
#define g_KeInitializeDpc (PostboxStatePtr->Imports.KeInitializeDpc)
#define g_KeSetCoalescableTimer (PostboxStatePtr->Imports.KeSetCoalescableTimer)
#define g_KeCancelTimer (PostboxStatePtr->Imports.KeCancelTimer)
#define g_KeFlushQueuedDpcs (PostboxStatePtr->Imports.KeFlushQueuedDpcs)
#define g_ExQueueWorkItem (PostboxStatePtr->Imports.ExQueueWorkItem)
#define g_PsLookupProcessByProcessId (PostboxStatePtr->Imports.PsLookupProcessByProcessId)
#define g_ObDereferenceObject (PostboxStatePtr->Imports.ObDereferenceObject)
#define g_KeDelayExecutionThread (PostboxStatePtr->Imports.KeDelayExecutionThread)
#define g_PsGetProcessCreateTimeQuadPart (PostboxStatePtr->Imports.PsGetProcessCreateTimeQuadPart)
#define g_ExAllocatePoolWithTag (PostboxStatePtr->Imports.ExAllocatePoolWithTag)
#define g_ExFreePool (PostboxStatePtr->Imports.ExFreePool)
#define g_MmCopyVirtualMemory (PostboxStatePtr->Imports.MmCopyVirtualMemory)
#define g_PsGetCurrentProcess (PostboxStatePtr->Imports.PsGetCurrentProcess)
#define g_PsAcquireProcessExitSynchronization (PostboxStatePtr->Imports.PsAcquireProcessExitSynchronization)
#define g_PsReleaseProcessExitSynchronization (PostboxStatePtr->Imports.PsReleaseProcessExitSynchronization)
#define g_PsCreateSystemThread (PostboxStatePtr->Imports.PsCreateSystemThread)
#define g_ZwClose (PostboxStatePtr->Imports.ZwClose)

constexpr uint32_t StageBytes = PostboxDataMax;
constexpr uint32_t StageAllocBytes = (StageBytes + 0xFFFu) & ~0xFFFu;
static uint32_t PostboxPeriodMs = 4;
static uint32_t PostboxIdleTicks = 0;
static uint32_t PostboxDeadTicks = 0;

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
uint32_t PostboxStartFailure = 0;

bool ProtectImageSections(const PostboxConfig* Config)
{
    PostboxStartFailure = 20;
    if (!Config || Config->Layout.Magic != PostboxLayoutMagic ||
        Config->Layout.Version != PostboxLayoutVersion)
    {
        print(ERROR("Postbox: image layout missing or invalid"));
        return false;
    }

    const PostboxImageLayout& L = Config->Layout;
    if (L.ImageSize == 0 || L.AllocSize == 0 || L.SectionCount == 0 ||
        L.SectionCount > PostboxMaxSections)
    {
        PostboxStartFailure = 21;
        return false;
    }

    // Resolve KeIpiGenericCall before the PTE walk: the global flush needs it.
    if (!PostboxResolve())
    {
        print(ERROR("Postbox: resolve failed before image protection"));
        if (PostboxStartFailure < 100)
            PostboxStartFailure = 22;
        return false;
    }

    const address ImageBase = address((uint64_t) (uintptr_t) &__ImageBase);
    if ((uint64_t) ImageBase != L.ImageBase || (L.ImageBase & 0xFFF) != 0)
    {
        print(ERROR("Postbox: image base mismatch (runtime %p, layout %p)"),
              (void*) (uintptr_t) ImageBase, (void*) (uintptr_t) L.ImageBase);
        PostboxStartFailure = 23;
        return false;
    }

    const uint64_t End = (L.RawBase + L.AllocSize) & ~0xFFFull;
    if (L.ImageBase < L.RawBase || L.ImageBase >= End ||
        L.ImageBase + L.ImageSize > End)
    {
        print(ERROR("Postbox: image layout range is invalid"));
        PostboxStartFailure = 24;
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
            PostboxStartFailure = 25;
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
        PostboxStartFailure = 26;
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
        PostboxStartFailure = 90;
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
        "QtHfuQspdfttDsfbufUjnfRvbeQbsu",
        "FyBmmpdbufQppmXjuiUbh",          // ExAllocatePoolWithTag
        "FyGsffQppm",                      // ExFreePool
        "NnDpqzWjsuvbmNfnpsz",             // MmCopyVirtualMemory
        "LfJqjHfofsjdDbmm",                // KeIpiGenericCall
        "QtHfuDvssfouQspdftt",             // PsGetCurrentProcess
        "QtBdrvjsfQspdfttFyjuTzodispoj{bujpo",  // PsAcquireProcessExitSynchronization
        "QtSfmfbtfQspdfttFyjuTzodispoj{bujpo",  // PsReleaseProcessExitSynchronization
        "QtDsfbufTztufnUisfbe",           // PsCreateSystemThread
        "OuDmptf",                        // NtClose (ZwClose alias)
    };

    // The resolve table is stored ROT1-encoded so the image does not carry the plaintext
    // export names. This is anti-static-scan, not secrecy: it is decoded in a stack buffer
    // and wiped after the resolve. The resolved pointers remain in .data.
    char Decoded[19][40] = {};
    const char* Names[19] = {};
    for (uint32_t i = 0; i < 19; ++i)
    {
        uint32_t j = 0;
        for (; j < 39 && EncodedNames[i][j]; ++j)
            Decoded[i][j] = (char) (EncodedNames[i][j] - 1);
        Decoded[i][j] = 0;
        Names[i] = Decoded[i];
    }

    address Functions[19] = {};
    FindFuncExportsBatch(Ntoskrnl, Names, Functions, 19);

    g_KeInitializeTimerEx_Raw = Functions[0];
    g_KeInitializeDpc_Raw = Functions[1];
    g_KeSetCoalescableTimer_Raw = Functions[2];
    g_KeCancelTimer_Raw = Functions[3];
    g_KeFlushQueuedDpcs_Raw = Functions[4];
    g_ExQueueWorkItem_Raw = Functions[5];
    g_PsLookupProcessByProcessId_Raw = Functions[6];
    g_ObDereferenceObject_Raw = Functions[7];
    g_KeDelayExecutionThread_Raw = Functions[8];
    g_PsGetProcessCreateTimeQuadPart_Raw = Functions[9];
    g_ExAllocatePoolWithTag_Raw = Functions[10];
    g_ExFreePool_Raw = Functions[11];
    g_MmCopyVirtualMemory_Raw = Functions[12];
    g_KeIpiGenericCall = Functions[13];
    g_PsGetCurrentProcess_Raw = Functions[14];
    g_PsAcquireProcessExitSynchronization_Raw = Functions[15];
    g_PsReleaseProcessExitSynchronization_Raw = Functions[16];
    g_PsCreateSystemThread_Raw = Functions[17];
    g_ZwClose_Raw = Functions[18];

    for (uint32_t i = 0; i < 19; ++i)
    {
        if (!Functions[i])
        {
            print(ERROR("Postbox: export %s not found"), Names[i]);
            PostboxStartFailure = 100 + i;
            for (uint32_t k = 0; k < 19; ++k)
            {
                volatile char* p = Decoded[k];
                for (uint32_t j = 0; j < 40; ++j) p[j] = 0;
            }
            return false;
        }
    }
    for (uint32_t i = 0; i < 19; ++i)
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
            ((FnPsGetCurrentProcess) g_PsGetCurrentProcess)(), Buffer,
            MailboxProcess, (void*) (uintptr_t) UserVa,
            Size, 0 /* KernelMode */, &Done);
    }
    return Status >= 0 && Done == Size;
}

// Cancels the timer and waits for queued DPCs. Safe at PASSIVE, including from the work
// routine itself (a work item is not a DPC, so flushing DPCs cannot wait on this thread).
static void PostboxCancel()
{
    __atomic_store_n(&PostboxRunning, 0, __ATOMIC_RELEASE);
    ((FnKeCancelTimer) g_KeCancelTimer)(&PostboxStatePtr->Timer);
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
        &PostboxStatePtr->Timer, Due, PeriodMs, ToleranceMs, &PostboxStatePtr->Dpc);
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
    pb::MacResponseTag(Tag, PostboxStatePtr->Keys, PostboxStatePtr->SessionId, Seq, Seq, Status, Nonce,
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
    if (!PostboxStatePtr || !PostboxStatePtr->Stage) return;
    PostboxWipe(PostboxStatePtr->Stage, StageBytes);
    if (PostboxStatePtr->StageIndependent && g_MmFreeIndependentPages)
        ((FnMmFreeIndependentPages) g_MmFreeIndependentPages)(
            PostboxStatePtr->Stage, StageAllocBytes);
    else
        ((FnExFreePool) g_ExFreePool)(PostboxStatePtr->Stage);
    PostboxStatePtr->Stage = nullptr;
    PostboxStatePtr->StageIndependent = false;
}

// Wipes the live config/keys/pointers but leaves the state page resident: the
// WORK_QUEUE_ITEM and KTIMER/KDPC live there, and the worker may still touch the
// item after the routine returns. The page is private RW/NX and no longer holds
// the keys/config after this call.
static void PostboxFreeState()
{
    if (!PostboxStatePtr) return;
    // Every caller has already run KeCancelTimer + KeFlushQueuedDpcs, so the
    // cancelled timer and its DPC can be wiped. This removes their pointers back
    // into the image from the resident state page. The WORK_QUEUE_ITEM is left
    // alone: the worker may still be executing on top of it.
    PostboxWipe(&PostboxStatePtr->Timer, sizeof(PostboxTimer));
    PostboxWipe(&PostboxStatePtr->Dpc, sizeof(PostboxDpc));
    pb::WipePostboxKeys(&PostboxStatePtr->Keys);
    PostboxWipe(&PostboxStatePtr->Cfg, sizeof(PostboxConfig));
    // Do NOT clear Process here. The caller's PostboxMaybeReleaseProcess (watchdog,
    // pb_stop, invalid-config) is the only path that drops the cached EPROCESS
    // reference; erasing the pointer first would leak the reference every stop.
    PostboxStatePtr->Stage = nullptr;
    PostboxStatePtr->SessionId = 0;
    PostboxStatePtr->LastNonce = 0;
    PostboxStatePtr->LastSeq = 0;
    PostboxStatePtr->AuthFailures = 0;
    PostboxStatePtr->StageIndependent = false;
}

// Releases the state page itself. Only safe when no timer/DPC/work item can still
// touch it: failed starts (never armed) and a stopped channel with in-flight clear.
static void PostboxFreeStatePage()
{
    // Exchange first so a second teardown cannot free the same page. Wipe the
    // whole 4 KiB, not just sizeof(PostboxState): the tail must not disclose
    // stale kernel memory if the allocator did not zero it.
    PostboxState* State = (PostboxState*) __atomic_exchange_n(
        (void**) &PostboxStatePtr, nullptr, __ATOMIC_ACQ_REL);
    if (!State) return;
    PostboxWipe(State, 0x1000);
    if (g_MmFreeIndependentPages)
        ((FnMmFreeIndependentPages) g_MmFreeIndependentPages)(State, 0x1000);
}

// Reaper thread body. The assembly entry calls this at PASSIVE, then tail-jumps
// to MmFreeIndependentPages. Wait for the worker to clear InFlight (which happens
// after it clears the work item and the caller releases the EPROCESS), then give
// the worker's ret and the loader's post-entry ROT1 wipe time to finish.
extern "C" void PostboxReaperPrepare()
{
    for (uint32_t i = 0; i < 1000 && __atomic_load_n(&PostboxInFlight, __ATOMIC_ACQUIRE); ++i)
    {
        _LARGE_INTEGER Interval{};
        Interval.QuadPart = -10000;   // 1 ms
        ((FnKeDelayExecutionThread) g_KeDelayExecutionThread)(0, 0, &Interval);
    }
    _LARGE_INTEGER Delay{};
    Delay.QuadPart = -5000000;        // 500 ms
    ((FnKeDelayExecutionThread) g_KeDelayExecutionThread)(0, 0, &Delay);

    // The worker has returned; the WORK_QUEUE_ITEM is no longer in use. Free the
    // state page before the image that holds this stub and its globals is released.
    PostboxFreeStatePage();
}

// Creates the system thread whose entry is the assembly tail-jump stub. The
// thread frees the loader allocation (RawBase/AllocSize), not the aligned image
// base, and then returns to PspSystemThreadStartup.
static bool PostboxStartReaper()
{
    if (__atomic_exchange_n(&PostboxReaperStarted, 1, __ATOMIC_ACQ_REL) != 0)
        return true;
    if (!g_PsCreateSystemThread || !g_ZwClose || !g_MmFreeIndependentPages ||
        !PostboxReaperBase || !PostboxReaperSize)
    {
        __atomic_store_n(&PostboxReaperStarted, 0, __ATOMIC_RELEASE);
        return false;
    }

    PostboxReaperFree = (uint64_t) g_MmFreeIndependentPages;

    void* ThreadHandle = nullptr;
    const int32_t Status = ((FnPsCreateSystemThread) g_PsCreateSystemThread)(
        &ThreadHandle, 0x1FFFFF /* THREAD_ALL_ACCESS */, nullptr, nullptr, nullptr,
        (void*) &PostboxReaperEntry, nullptr);
    if (Status < 0 || !ThreadHandle)
    {
        __atomic_store_n(&PostboxReaperStarted, 0, __ATOMIC_RELEASE);
        print(ERROR("Postbox: reaper thread creation failed"));
        return false;
    }
    ((FnZwClose) g_ZwClose)(ThreadHandle);
    print(INFO("Postbox: reaper armed"));
    return true;
}

// The client EPROCESS reference is acquired once at start, not per poll. Release it
// only after the last in-flight poll has detached and dropped its exit synchronization.
static void PostboxReleaseProcess()
{
    if (!PostboxStatePtr) return;
    void* Process = PostboxStatePtr->Process;
    PostboxStatePtr->Process = nullptr;
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
    PostboxFreeState();
    PostboxStartReaper();
    PostboxStatePtr->SessionId = 0;
    PostboxStatePtr->LastNonce = 0;
}

// Runs at DISPATCH_LEVEL on the per-CPU DPC stack. It does no memory access: only the
// in-flight exchange and the queue. The mailbox work happens in PostboxWorkRoutine.
static void PostboxDpcRoutine(void*, void*, void*, void*)
{
    if (!__atomic_load_n(&PostboxRunning, __ATOMIC_ACQUIRE)) return;

    if (__atomic_exchange_n(&PostboxInFlight, 1, __ATOMIC_ACQ_REL) == 0)
        ((FnExQueueWorkItem) g_ExQueueWorkItem)(&PostboxStatePtr->Work, 1);   // DelayedWorkQueue
}

// Runs at PASSIVE_LEVEL in an existing system worker thread.
static void PostboxWorkRoutine(void*)
{
    PostboxState* State = PostboxStatePtr;
    if (__atomic_load_n(&PostboxRunning, __ATOMIC_ACQUIRE))
        PostboxPoll();

    // Terminal work item: running is clear and the timer is cancelled, so no DPC
    // can queue this item again. The worker already loaded WorkerRoutine; clear
    // the fields so the resident state page keeps no pointer back into the image.
    // Use the captured State, not the global, so a restart cannot redirect this
    // clear at the new page.
    if (!__atomic_load_n(&PostboxRunning, __ATOMIC_ACQUIRE) && State)
    {
        State->Work.WorkerRoutine = nullptr;
        State->Work.Parameter = nullptr;
        State->Work.List.Flink = nullptr;
        State->Work.List.Blink = nullptr;
    }

    __atomic_store_n(&PostboxInFlight, 0, __ATOMIC_RELEASE);
}

// The poll body. The caller has already attached the worker to MailboxProcess and
// holds its reference; this routine must not dereference it.
static void PostboxPollAttached(void* MailboxProcess)
{
    const uint32_t MailboxPid = PostboxStatePtr->Cfg.Pid;
    const uint64_t MailboxVa = PostboxStatePtr->Cfg.MailboxVa;
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
    const int32_t Ahead = (int32_t) (Seq - PostboxStatePtr->LastSeq);
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
    if (Ahead == 0 && Sealed.SessionId == PostboxStatePtr->SessionId &&
        Sealed.Nonce == PostboxStatePtr->LastNonce && Sealed.Ack == Seq)
    {
        PostboxDeadReset();
        PostboxIdleTick();
        PostboxWipe(&Sealed, sizeof(Sealed));
        return;
    }

    if (Sealed.SessionId != PostboxStatePtr->SessionId || Sealed.Nonce <= PostboxStatePtr->LastNonce)
    {
        if (PostboxStatePtr->AuthFailures != 0xFFFFFFFFu) ++PostboxStatePtr->AuthFailures;
        PostboxDeadTick();
        PostboxIdleTick();
        PostboxWipe(&Sealed, sizeof(Sealed));
        return;
    }

    // Decrypt the 20-byte header only to learn Op/Size for MAC coverage; do not trust or
    // act on these values until the tag verifies below.
    PostboxHeader Plain = Sealed;
    pb::OpenRequestHeader(reinterpret_cast<uint8_t*>(&Plain), PostboxStatePtr->Keys,
                          PostboxStatePtr->SessionId, Sealed.Nonce);

    const uint32_t Op = Plain.Op;
    const uint32_t Size = Plain.Size;
    const uint64_t Address = Plain.Address;
    const bool KnownOp = Op == pb_ping || Op == pb_read || Op == pb_write || Op == pb_stop
#ifdef POSTBOX_NMI
                         || Op == pb_nmi
#endif
                         ;
    const bool SizeOk = Size <= StageBytes &&
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
    const uint32_t BodyBytes = (Op == pb_read || Op == pb_write) ? Size :
                               (Op == pb_nmi) ? (uint32_t) sizeof(uint64_t) : 0;

    const address DataVa = (address) (MailboxVa + PostboxDataAt);
    if (BodyLen != 0 &&
        !PostboxCopy(MailboxProcess, DataVa, PostboxStatePtr->Stage, BodyLen, false))
    {
        PostboxWipe(&Plain, sizeof(Plain));
        PostboxWipe(&Sealed, sizeof(Sealed));
        PostboxWipe(PostboxStatePtr->Stage, BodyLen);
        PostboxDeadTick();
        PostboxIdleTick();
        return;
    }

    uint8_t Tag[16];
    pb::MacRequestTag(Tag, PostboxStatePtr->Keys, PostboxStatePtr->SessionId, Seq, Sealed.Nonce, Op,
                      reinterpret_cast<const uint8_t*>(&Sealed), PostboxStatePtr->Stage, BodyLen);
    if (!pb::Mac128Equal(Tag, Sealed.Mac))
    {
        if (PostboxStatePtr->AuthFailures != 0xFFFFFFFFu) ++PostboxStatePtr->AuthFailures;
        PostboxWipe(&Plain, sizeof(Plain));
        PostboxWipe(&Sealed, sizeof(Sealed));
        PostboxWipe(PostboxStatePtr->Stage, BodyLen);
        PostboxDeadTick();
        PostboxIdleTick();
        return;
    }

    // Authenticated. Consume the sequence/nonce before any response write: if the response
    // is lost, the client's next request is Seq + 1 and must not look like a replay.
    PostboxStatePtr->LastSeq = Seq;
    PostboxStatePtr->LastNonce = Sealed.Nonce;
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
        const bool InRange = Address && Address < PostboxUserLimit && Size <= StageBytes &&
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
            pb::OpenRequestBody(PostboxStatePtr->Stage, Size, PostboxStatePtr->Keys, PostboxStatePtr->SessionId, Sealed.Nonce);
            const bool Ok = PostboxCopy(MailboxProcess, (address) Address,
                                        PostboxStatePtr->Stage, Size, true);
            Status = Ok ? 0 : (int32_t) 0xC0000005;
            PostboxWipe(PostboxStatePtr->Stage, Size);
        }
        else
        {
            const bool Ok = PostboxCopy(MailboxProcess, (address) Address,
                                        PostboxStatePtr->Stage, Size, false);
            if (Ok)
            {
                pb::SealResponseBody(PostboxStatePtr->Stage, Size, PostboxStatePtr->Keys, PostboxStatePtr->SessionId, Sealed.Nonce);
                ResponseBody = PostboxStatePtr->Stage;
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
                __builtin_memcpy(PostboxStatePtr->Stage, &NmiCount, sizeof(NmiCount));
                pb::SealResponseBody(PostboxStatePtr->Stage, sizeof(NmiCount), PostboxStatePtr->Keys,
                                     PostboxStatePtr->SessionId, Sealed.Nonce);
                ResponseBody = PostboxStatePtr->Stage;
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
        PostboxWipe(PostboxStatePtr->Stage, BodyBytes);
        return;
    }

    PostboxRespond(MailboxVa, MailboxProcess, Seq, Sealed.Nonce, Op, Status, ResponseBody, ResponseLen);
    PostboxWipe(PostboxStatePtr->Stage, BodyBytes);

    if (Op == pb_stop)
    {
        // The stop is authenticated and acknowledged; now cancel. The work item clears
        // PostboxInFlight on its way out, so do not wait here.
        PostboxCancel();
        PostboxFreeStage();
        PostboxFreeState();
        PostboxStartReaper();
        PostboxStatePtr->SessionId = 0;
        PostboxStatePtr->LastNonce = 0;
    }

    PostboxWipe(&Plain, sizeof(Plain));
    PostboxWipe(&Sealed, sizeof(Sealed));
}

// Poll entry: the worker holds the cached client EPROCESS and the process exit
// synchronization; PostboxCopy uses MmCopyVirtualMemory with explicit processes,
// so the poll does not attach or detach itself.
static void PostboxPoll()
{
    if (!__atomic_load_n(&PostboxRunning, __ATOMIC_ACQUIRE)) return;
    const uint32_t Pid = PostboxStatePtr->Cfg.Pid;
    if (!Pid || !PostboxStatePtr->Cfg.MailboxVa)
    {
        // A zeroed/corrupted config must not leave the fast timer armed forever:
        // the dead-client watchdog is bypassed by this early return, and a manual
        // map has no unload callback. Cancel and wipe here (PASSIVE, work routine).
        PostboxCancel();
        PostboxFreeStage();
        PostboxFreeState();
        PostboxStartReaper();
        PostboxStatePtr->SessionId = 0;
        PostboxStatePtr->LastNonce = 0;
        PostboxMaybeReleaseProcess();
        return;
    }

    // The EPROCESS reference and create-time check were done once in PostboxStart.
    void* Process = PostboxStatePtr->Process;
    if (!Process)
    {
        PostboxDeadTick();
        PostboxIdleTick();
        PostboxMaybeReleaseProcess();
        return;
    }

    // No explicit attach: PostboxCopy uses MmCopyVirtualMemory with explicit
    // processes. Keep the process exit synchronization, though: MmCopyVirtualMemory
    // does not acquire it, and the cached EPROCESS reference alone does not stop
    // the address space from being torn down mid-copy.
    const int32_t ExitStatus =
        ((FnPsAcquireProcessExitSynchronization) g_PsAcquireProcessExitSynchronization)(Process);
    if (ExitStatus < 0)
    {
        PostboxDeadTick();
        PostboxIdleTick();
        PostboxMaybeReleaseProcess();
        return;
    }
    PostboxPollAttached(Process);
    ((FnPsReleaseProcessExitSynchronization) g_PsReleaseProcessExitSynchronization)(Process);
    PostboxMaybeReleaseProcess();
}

// Starts the channel from a loader-supplied config. PASSIVE_LEVEL (DriverEntry).
bool PostboxStart(const PostboxConfig* Config)
{
    PostboxStartFailure = 30;
    // Reachability reference that keeps .pbox in the file for the loader's marker
    // check. The mapper deliberately does not copy .pbox into the published image,
    // so the mapped byte is zero; only a corrupt 0xFF fails the start.
    if (PostboxSectionMarker[0] == 0xFF)
        return false;

    if (__atomic_load_n(&PostboxRunning, __ATOMIC_ACQUIRE)) return true;
    if (!Config || Config->Magic != PostboxConfigMagic || Config->Version != 4 ||
        !Config->Pid || !Config->MailboxVa || !Config->CreateTime || !Config->SessionId) return false;
    if (Config->MailboxVa > PostboxUserLimit - PostboxBytes || (Config->MailboxVa & 7)) return false;

    bool KeyNonZero = false;
    for (uint32_t i = 0; i < sizeof(Config->Key); ++i)
        KeyNonZero |= (Config->Key[i] != 0);
    if (!KeyNonZero) return false;

    // The state page needs the independent-page helpers before it can be allocated.
    g_MmAllocateIndependentPages = (address) Config->MmAllocateIndependentPages;
    g_MmSetPageProtection = (address) Config->MmSetPageProtection;
    g_MmFreeIndependentPages = (address) Config->MmFreeIndependentPages;
    if (!g_MmAllocateIndependentPages || !g_MmSetPageProtection || !g_MmFreeIndependentPages)
        return false;

    // A previous start may have left the page resident (watchdog/stop). Never
    // overwrite the only pointer: free it first when no worker is in flight.
    if (PostboxStatePtr)
    {
        if (__atomic_load_n(&PostboxInFlight, __ATOMIC_ACQUIRE) != 0)
            return false;
        PostboxReleaseProcess();
        PostboxFreeStatePage();
    }

    PostboxStatePtr = (PostboxState*) ((FnMmAllocateIndependentPages)
        g_MmAllocateIndependentPages)(0x1000, 0xFFFFFFFF, 0, 0);
    if (!PostboxStatePtr) return false;
    if (!((FnMmSetPageProtection) g_MmSetPageProtection)(
            PostboxStatePtr, 0x1000, 0x04 /* PAGE_READWRITE */))
    {
        ((FnMmFreeIndependentPages) g_MmFreeIndependentPages)(PostboxStatePtr, 0x1000);
        PostboxStatePtr = nullptr;
        return false;
    }
    PostboxWipe(PostboxStatePtr, 0x1000);

    PostboxStatePtr->Cfg = *Config;
    PostboxStatePtr->Cfg.MmAllocateIndependentPages = 0;
    PostboxStatePtr->Cfg.MmSetPageProtection = 0;
    PostboxStatePtr->Cfg.MmFreeIndependentPages = 0;
    // The magic/version are validation-only. Leaving the 8-byte "PBOX"+version
    // prefix in .data makes the resident control block trivially findable by a
    // magic scan; wipe it after the check.
    PostboxStatePtr->Cfg.Magic = 0;
    PostboxStatePtr->Cfg.Version = 0;
    // The reaper frees the loader allocation, not the aligned image base. Save
    // RawBase/AllocSize before the layout copy is wiped. Lab build: the Postbox
    // manual-map layout is always independent pages, and the known-good
    // de9f061c loader predates Config.Reserved, so trust the layout here. The
    // Reserved-bit gate returns for the production loader.
    PostboxReaperBase = Config->Layout.RawBase;
    PostboxReaperSize = Config->Layout.AllocSize;
    // The section map is only needed by ProtectImageSections(), which ran before
    // this copy. Do not leave the RVAs/sizes in the resident .data image.
    PostboxWipe(&PostboxStatePtr->Cfg.Layout, sizeof(PostboxStatePtr->Cfg.Layout));
    PostboxStatePtr->LastSeq = 0;
    PostboxStatePtr->LastNonce = 0;
    PostboxInFlight = 0;
    PostboxStatePtr->SessionId = Config->SessionId;

    uint8_t Master[32];
    for (uint32_t i = 0; i < sizeof(Master); ++i) Master[i] = Config->Key[i];
    pb::DerivePostboxKeys(&PostboxStatePtr->Keys, Master);   // wipes Master
    PostboxWipe(&PostboxStatePtr->Cfg.Key, sizeof(PostboxStatePtr->Cfg.Key));

    if (!PostboxResolve())
    {
        PostboxFreeStatePage();
        return false;
    }

    // Move the resolved routine table out of .data and zero the raw slots. The
    // state page already exists, so every later use goes through the macros.
    PostboxStatePtr->Imports.KeInitializeTimerEx = g_KeInitializeTimerEx_Raw;
    PostboxStatePtr->Imports.KeInitializeDpc = g_KeInitializeDpc_Raw;
    PostboxStatePtr->Imports.KeSetCoalescableTimer = g_KeSetCoalescableTimer_Raw;
    PostboxStatePtr->Imports.KeCancelTimer = g_KeCancelTimer_Raw;
    PostboxStatePtr->Imports.KeFlushQueuedDpcs = g_KeFlushQueuedDpcs_Raw;
    PostboxStatePtr->Imports.ExQueueWorkItem = g_ExQueueWorkItem_Raw;
    PostboxStatePtr->Imports.PsLookupProcessByProcessId = g_PsLookupProcessByProcessId_Raw;
    PostboxStatePtr->Imports.ObDereferenceObject = g_ObDereferenceObject_Raw;
    PostboxStatePtr->Imports.KeDelayExecutionThread = g_KeDelayExecutionThread_Raw;
    PostboxStatePtr->Imports.PsGetProcessCreateTimeQuadPart = g_PsGetProcessCreateTimeQuadPart_Raw;
    PostboxStatePtr->Imports.ExAllocatePoolWithTag = g_ExAllocatePoolWithTag_Raw;
    PostboxStatePtr->Imports.ExFreePool = g_ExFreePool_Raw;
    PostboxStatePtr->Imports.MmCopyVirtualMemory = g_MmCopyVirtualMemory_Raw;
    PostboxStatePtr->Imports.PsGetCurrentProcess = g_PsGetCurrentProcess_Raw;
    PostboxStatePtr->Imports.PsAcquireProcessExitSynchronization =
        g_PsAcquireProcessExitSynchronization_Raw;
    PostboxStatePtr->Imports.PsReleaseProcessExitSynchronization =
        g_PsReleaseProcessExitSynchronization_Raw;
    PostboxStatePtr->Imports.PsCreateSystemThread = g_PsCreateSystemThread_Raw;
    PostboxStatePtr->Imports.ZwClose = g_ZwClose_Raw;

    g_KeInitializeTimerEx_Raw = 0;
    g_KeInitializeDpc_Raw = 0;
    g_KeSetCoalescableTimer_Raw = 0;
    g_KeCancelTimer_Raw = 0;
    g_KeFlushQueuedDpcs_Raw = 0;
    g_ExQueueWorkItem_Raw = 0;
    g_PsLookupProcessByProcessId_Raw = 0;
    g_ObDereferenceObject_Raw = 0;
    g_KeDelayExecutionThread_Raw = 0;
    g_PsGetProcessCreateTimeQuadPart_Raw = 0;
    g_ExAllocatePoolWithTag_Raw = 0;
    g_ExFreePool_Raw = 0;
    g_MmCopyVirtualMemory_Raw = 0;
    g_PsGetCurrentProcess_Raw = 0;
    g_PsAcquireProcessExitSynchronization_Raw = 0;
    g_PsReleaseProcessExitSynchronization_Raw = 0;
    g_PsCreateSystemThread_Raw = 0;
    g_ZwClose_Raw = 0;

    // Acquire the client reference and verify its create time once, not per poll.
    void* Process = nullptr;
    if (((FnPsLookupProcessByProcessId) g_PsLookupProcessByProcessId)(
            (void*) (uintptr_t) PostboxStatePtr->Cfg.Pid, &Process) < 0 || !Process)
    {
        PostboxFreeStatePage();
        return false;
    }
    if ((uint64_t) ((FnPsGetProcessCreateTimeQuadPart) g_PsGetProcessCreateTimeQuadPart)(Process) !=
        PostboxStatePtr->Cfg.CreateTime)
    {
        ((FnObDereferenceObject) g_ObDereferenceObject)(Process);
        PostboxFreeStatePage();
        return false;
    }
    PostboxStatePtr->Process = Process;

    // Separate NX stage. Prefer page-granular independent pages so the channel
    // does not leave a 64 KiB 'Ntfs' NonPagedPoolNx entry for its lifetime; fall
    // back to the pool when an older loader did not pass the helpers.
    PostboxStatePtr->Stage = nullptr;
    PostboxStatePtr->StageIndependent = false;
    if (g_MmAllocateIndependentPages && g_MmSetPageProtection && g_MmFreeIndependentPages)
    {
        PostboxStatePtr->Stage = (uint8_t*) ((FnMmAllocateIndependentPages)
            g_MmAllocateIndependentPages)(StageAllocBytes, 0xFFFFFFFF, 0, 0);
        if (PostboxStatePtr->Stage)
        {
            if (((FnMmSetPageProtection) g_MmSetPageProtection)(
                    PostboxStatePtr->Stage, StageAllocBytes, 0x04 /* PAGE_READWRITE */))
            {
                PostboxStatePtr->StageIndependent = true;
            }
            else
            {
                ((FnMmFreeIndependentPages) g_MmFreeIndependentPages)(
                    PostboxStatePtr->Stage, StageAllocBytes);
                PostboxStatePtr->Stage = nullptr;
            }
        }
    }
    if (!PostboxStatePtr->Stage)
    {
        PostboxStatePtr->Stage = (uint8_t*) ((FnExAllocatePoolWithTag) g_ExAllocatePoolWithTag)(
            0x200 /* NonPagedPoolNx */, StageBytes, 0x7366744E /* 'Ntfs' */);
        PostboxStatePtr->StageIndependent = false;
    }
    if (!PostboxStatePtr->Stage)
    {
        print(ERROR("Postbox: NX stage allocation failed"));
        PostboxReleaseProcess();
        PostboxFreeStatePage();
        return false;
    }
    PostboxWipe(PostboxStatePtr->Stage, StageBytes);

#ifdef POSTBOX_NMI
    // The IDT is not touched at start. The gate is installed transiently only for
    // the pb_nmi self-test, then the Windows IDT is restored in the same work item.
#endif

    // ExInitializeWorkItem's fields, without pulling in the macro from the vendor headers
    PostboxStatePtr->Work.List.Flink = nullptr;
    PostboxStatePtr->Work.List.Blink = nullptr;
    PostboxStatePtr->Work.WorkerRoutine = (void*) &PostboxWorkRoutine;
    PostboxStatePtr->Work.Parameter = nullptr;

    ((FnKeInitializeTimerEx) g_KeInitializeTimerEx)(&PostboxStatePtr->Timer, 0);   // NotificationTimer
    ((FnKeInitializeDpc) g_KeInitializeDpc)(&PostboxStatePtr->Dpc, &PostboxDpcRoutine, nullptr);

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
        // The timer/DPC were initialized just above; cancel and flush before the
        // state page that contains them is freed, even if the arm call queued one.
        PostboxCancel();
        PostboxFreeStage();
        PostboxReleaseProcess();
        PostboxFreeStatePage();
        return false;
    }

    print(INFO("Postbox: live, pid %u mailbox %p, 4 ms timer"),
          PostboxStatePtr->Cfg.Pid, (void*) (uintptr_t) PostboxStatePtr->Cfg.MailboxVa);
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
    // One teardown owner. A concurrent second stop must not free the state page
    // under the first one; it returns and lets the owner finish.
    if (__atomic_exchange_n(&PostboxTeardown, 1, __ATOMIC_ACQ_REL) != 0)
        return;

    if (!__atomic_load_n(&PostboxRunning, __ATOMIC_ACQUIRE))
    {
        for (uint32_t i = 0; i < 1000 && __atomic_load_n(&PostboxInFlight, __ATOMIC_ACQUIRE); ++i)
        {
            _LARGE_INTEGER Interval{};
            Interval.QuadPart = -10000;
            ((FnKeDelayExecutionThread) g_KeDelayExecutionThread)(0, 0, &Interval);
        }
        if (__atomic_load_n(&PostboxInFlight, __ATOMIC_ACQUIRE) != 0)
        {
            print(ERROR("Postbox: worker still in flight; leaving state resident"));
            __atomic_store_n(&PostboxTeardown, 0, __ATOMIC_RELEASE);
            return;
        }
        // A worker that passed the Running check just before the watchdog/stop
        // may have re-armed the timer after the first cancel. Cancel/flush again
        // before releasing the state page.
        if (PostboxStatePtr)
        {
            ((FnKeCancelTimer) g_KeCancelTimer)(&PostboxStatePtr->Timer);
            ((FnKeFlushQueuedDpcs) g_KeFlushQueuedDpcs)();
        }
        PostboxReleaseProcess();
        if (!PostboxStartReaper())
            PostboxFreeStatePage();
        __atomic_store_n(&PostboxTeardown, 0, __ATOMIC_RELEASE);
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

    // A worker that passed the Running check just before PostboxCancel may have
    // re-armed the timer after the first cancel. If it is still in flight, leave
    // the whole state resident; its terminal path owns teardown.
    if (__atomic_load_n(&PostboxInFlight, __ATOMIC_ACQUIRE) != 0)
    {
        print(ERROR("Postbox: worker still in flight; leaving state resident"));
        __atomic_store_n(&PostboxTeardown, 0, __ATOMIC_RELEASE);
        return;
    }

    // Quiesced: cancel/flush again to cover the re-arm window, then release.
    ((FnKeCancelTimer) g_KeCancelTimer)(&PostboxStatePtr->Timer);
    ((FnKeFlushQueuedDpcs) g_KeFlushQueuedDpcs)();
    PostboxFreeStage();
    PostboxReleaseProcess();
    PostboxFreeState();
    if (!PostboxStartReaper())
        PostboxFreeStatePage();
    print(INFO("Postbox: stopped"));
    __atomic_store_n(&PostboxTeardown, 0, __ATOMIC_RELEASE);
}

#endif // POSTBOX_CHANNEL
