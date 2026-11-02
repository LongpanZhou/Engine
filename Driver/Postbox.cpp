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
// Staging slots for the three independent-page helpers. PostboxStart fills them
// from the loader config, moves them into PostboxState.Imports as soon as the
// state page exists, and zeroes them. No later path reads these.
static address g_MmAllocateIndependentPages_Raw = 0;
static address g_MmSetPageProtection_Raw = 0;
static address g_MmFreeIndependentPages_Raw = 0;

static address g_MmCopyMemory = 0;
static address g_MmCopyVirtualMemory_Raw = 0;
static address g_PsCreateSystemThread_Raw = 0;
static address g_ZwClose_Raw = 0;

static volatile long PostboxRunning = 0;
// Cleared by the assembly worker wrapper after PostboxWorkRoutine returns, so
// the reaper cannot free the image while the C worker is still in its epilogue.
extern "C" volatile long PostboxInFlight = 0;
static volatile long PostboxTeardown = 0;
static volatile long PostboxReaperStarted = 0;

// The reaper stub is assembly in PostboxReaper.S. It runs as a system thread,
// waits for the work routine to return, frees the state page, then tail-jumps to
// MmFreeIndependentPages so the free returns to PspSystemThreadStartup. The
// thread's StartContext is the state page; the image range and free routine are
// read from it before the page is wiped, so no reaper context lives in .data.
struct PostboxState;
struct PostboxReaperPlan
{
    uint64_t Base;
    uint64_t Size;
    uint64_t Free;
};
extern "C" void PostboxReaperEntry();
extern "C" uint64_t PostboxReaperPrepare(PostboxState* State, PostboxReaperPlan* Plan);
// Assembly worker wrapper: calls PostboxWorkRoutine, then clears PostboxInFlight
// after the C worker has returned. Only the wrapper's add/ret remain in image
// code when the reaper sees InFlight == 0.
extern "C" void PostboxWorkEntry();
extern "C" void PostboxWorkRoutine(void*);

// Resolved ntoskrnl routines used after the state page exists. They are copied
// out of .data into the state page by PostboxStart and zeroed in .data, so a
// static .data scan sees no routine table. KeIpiGenericCall stays in .data: the
// pre-start ProtectImageSections path needs it before the state page exists. The
// three independent-page helpers are staged in .data only long enough to create
// and protect the state page, then they move here too.
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
    address MmAllocateIndependentPages;
    address MmSetPageProtection;
    address MmFreeIndependentPages;
};

// NMI-gate imports. Kept in the state page so the NMI build's .data does not
// carry eight ntoskrnl routine pointers. PostboxNmiInstall runs after the state
// page exists; PostboxNmiUninstall runs before the page is freed.
struct PostboxNmiImports
{
    uint64_t KeQueryActiveProcessors;
    uint64_t KeQueryActiveProcessorCountEx;
    uint64_t KeSetSystemAffinityThreadEx;
    uint64_t KeRevertToUserAffinityThreadEx;
    uint64_t KeGetCurrentProcessorNumberEx;
    uint64_t KeStallExecutionProcessor;
    uint64_t MmMapIoSpace;
    uint64_t MmUnmapIoSpace;
};

#ifdef E3_DPC_PROBE
// Test-only E3 result block. Appended to PostboxState so the shipped layout is
// unchanged; KD reads it at state+0x348. Magic is "E3TLB001".
struct PostboxE3Result
{
    uint64_t Magic;
    uint64_t Va;
    uint64_t PteBefore;
    uint64_t PteAfter;
    uint64_t Pre;       // CPU-1 read before the PTE change
    uint64_t P1;        // CPU-1 read after the PTE change, before the flush
    uint64_t P2;        // CPU-1 read after the KeIpiGenericCall flush
    uint64_t Cpu1;
    uint64_t Cpu2;
    uint64_t Phase;     // 0x100 complete; 0xE0..0xEC failure
};
#endif

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
    // Loader allocation passed to the reaper. Kept in the state page, not .data,
    // so the image base/size do not reappear in the resident image during stop.
    uint64_t ReaperBase;
    uint64_t ReaperSize;
    // B-01: the only config value the poll needs. Kept outside the Cfg copy so
    // the whole PostboxConfig can be wiped once start has consumed Pid/CreateTime.
    // Appended after the reaper fields so every existing state offset is stable.
    uint64_t MailboxVa;
    // C-01: ntoskrnl/PTE-base/PfnDatabase bases live here, not in .data. The
    // pre-protection path uses Mem.cpp's transient statics; PostboxStart adopts
    // them into this field and zeroes the statics.
    PostboxMemCaches Caches;
    PostboxNmiImports NmiImports;
#ifdef E3_DPC_PROBE
    PostboxE3Result E3;
#endif
};
#ifdef E3_DPC_PROBE
static_assert(offsetof(PostboxState, E3) == 0x348, "E3 result offset changed");
#endif
static PostboxState* PostboxStatePtr = nullptr;
static uint32_t PostboxPollRefs = 0;
static bool PostboxPollTeardown = false;

// Mem.cpp calls this on every lookup. Before the state page exists it returns
// null, so the transient static cache is used; after PostboxStart it returns the
// state-page copy and the statics stay zero.
PostboxMemCaches* PostboxGetMemCaches()
{
    return PostboxStatePtr ? &PostboxStatePtr->Caches : nullptr;
}

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
#define g_MmAllocateIndependentPages (PostboxStatePtr->Imports.MmAllocateIndependentPages)
#define g_MmSetPageProtection (PostboxStatePtr->Imports.MmSetPageProtection)
#define g_MmFreeIndependentPages (PostboxStatePtr->Imports.MmFreeIndependentPages)

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

static bool PostboxResolve(address* IpiGenericCallOut = nullptr);

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

#ifdef T2_PROBE
// Test-only E3 probe. Runs from KeIpiGenericCall on every CPU; only CPU 1
// performs the write. The .text page is RX after the PTE loop; a stale RW TLB
// entry lets the write succeed, otherwise the raw kernel write bugchecks 0xBE.
static uint64_t g_T2GetProcessorNumberEx = 0;

static uint64_t T2ProbeCallback(uint64_t Context)
{
    if (!Context || !g_T2GetProcessorNumberEx) return 0;
    struct { uint16_t Group; uint8_t Number; uint8_t Reserved; } Pn{};
    ((void (*)(void*)) g_T2GetProcessorNumberEx)(&Pn);
    if (Pn.Number != 1) return 0;

    volatile uint8_t* P = (volatile uint8_t*) (uintptr_t) (Context + 0x4FF0);
    const uint8_t Old = *P;
    *P = 0xAA;
    *P = Old;
    return 0;
}

static void T2Probe(uint64_t Base, uint64_t Ipi, uint32_t Phase)
{
    print(INFO("[T2] P%u probe start base=%p"), Phase, (void*) (uintptr_t) Base);
    ((FnKeIpiGenericCall) Ipi)(&T2ProbeCallback, Base);
}
#endif

#ifdef E3_DPC_PROBE
// Test-only E3 CPU-1 stale-TLB probe. Never part of the shipped build.
//
// Two independent pages A and B are filled with 0x41 and 0x42. A's PTE is
// rewritten to B's PFN while CPU 1 still holds the A translation. A DPC targeted
// at CPU 1 records the read before the product KeIpiGenericCall+invlpg flush
// (P1: stale 0x41) and after it (P2: 0x42). The result block lives in the state
// page at +0x348 for KD.
using FnKeSetTargetProcessorDpc = void (*)(PostboxDpc*, uint8_t);
using FnKeInsertQueueDpc = uint8_t (*)(PostboxDpc*, void*, void*);
using FnKeGetCurrentProcessorNumberEx = void (*)(void*);
using FnKeSetSystemAffinityThreadEx = uint64_t (*)(uint64_t);
using FnKeRevertToUserAffinityThreadEx = void (*)(uint64_t);

static PostboxDpc E3Dpc1;
static PostboxDpc E3Dpc2;
static uint64_t* E3Pte = nullptr;
static uint64_t E3PteOld = 0;
static uint64_t E3PteNew = 0;
static uint8_t* E3PageA = nullptr;
static uint8_t* E3PageB = nullptr;
static volatile long E3PhaseDone = 0;
static volatile long E3Started = 0;
static address E3SetTarget = 0;
static address E3InsertDpc = 0;
static address E3GetProc = 0;

static uint32_t E3CurrentProcessor()
{
    struct { uint16_t Group; uint8_t Number; uint8_t Reserved; } Pn{};
    if (E3GetProc) ((FnKeGetCurrentProcessorNumberEx) E3GetProc)(&Pn);
    return Pn.Number;
}

static void E3DpcPhase1(void*, void*, void*, void*)
{
    PostboxState* S = PostboxStatePtr;
    if (!S) return;
    S->E3.Cpu1 = E3CurrentProcessor();
    volatile uint64_t* A = (volatile uint64_t*) (uintptr_t) E3PageA;
    S->E3.Pre = *A;
    __atomic_store_n(E3Pte, E3PteNew, __ATOMIC_RELEASE);
    S->E3.P1 = *A;
    __atomic_store_n(&E3PhaseDone, 1, __ATOMIC_RELEASE);
}

static void E3DpcPhase2(void*, void*, void*, void*)
{
    PostboxState* S = PostboxStatePtr;
    if (!S) return;
    S->E3.Cpu2 = E3CurrentProcessor();
    volatile uint64_t* A = (volatile uint64_t*) (uintptr_t) E3PageA;
    S->E3.P2 = *A;
    __atomic_store_n(&E3PhaseDone, 2, __ATOMIC_RELEASE);
}

static bool E3WaitDone(long Want)
{
    for (uint64_t i = 0; i < 100000000ull; ++i)
    {
        if (__atomic_load_n(&E3PhaseDone, __ATOMIC_ACQUIRE) == Want) return true;
        __builtin_ia32_pause();
    }
    return false;
}

static void E3FlushPage(address Ipi, uint64_t Va)
{
    PostboxTlbRange Range{ Va, Va + 0x1000 };
    ((FnKeIpiGenericCall) Ipi)(&PostboxFlushTlb, (uint64_t) (uintptr_t) &Range);
}

static void E3RunProbe()
{
    PostboxState* S = PostboxStatePtr;
    if (!S) return;
    S->E3.Magic = 0x4533544C42303031ull;   // "E3TLB001"
    S->E3.Phase = 1;

    uint64_t* PteA = nullptr;
    uint64_t* PteB = nullptr;
    uint64_t OldAffinity = 0;
    constexpr uint64_t PfnMask = 0x000FFFFFFFFFF000ull;

    if (!g_MmAllocateIndependentPages || !g_MmSetPageProtection || !g_MmFreeIndependentPages)
    { S->E3.Phase = 0xE1; return; }

    const address Nt = GetNtoskrnl();
    if (!Nt) { S->E3.Phase = 0xE2; return; }
    E3SetTarget = FindFuncExports(Nt, "KeSetTargetProcessorDpc");
    E3InsertDpc = FindFuncExports(Nt, "KeInsertQueueDpc");
    E3GetProc = FindFuncExports(Nt, "KeGetCurrentProcessorNumberEx");
    const address SetAffinity = FindFuncExports(Nt, "KeSetSystemAffinityThreadEx");
    const address RevertAffinity = FindFuncExports(Nt, "KeRevertToUserAffinityThreadEx");
    const address Ipi = FindFuncExports(Nt, "KeIpiGenericCall");
    if (!E3SetTarget || !E3InsertDpc || !E3GetProc || !Ipi ||
        !SetAffinity || !RevertAffinity)
    { S->E3.Phase = 0xE3; return; }

    E3PageA = (uint8_t*) ((FnMmAllocateIndependentPages) g_MmAllocateIndependentPages)(
        0x1000, 0xFFFFFFFF, 0, 0);
    E3PageB = (uint8_t*) ((FnMmAllocateIndependentPages) g_MmAllocateIndependentPages)(
        0x1000, 0xFFFFFFFF, 0, 0);
    if (!E3PageA || !E3PageB) { S->E3.Phase = 0xE4; goto cleanup; }
    if (!((FnMmSetPageProtection) g_MmSetPageProtection)(E3PageA, 0x1000, 0x04) ||
        !((FnMmSetPageProtection) g_MmSetPageProtection)(E3PageB, 0x1000, 0x04))
    { S->E3.Phase = 0xE5; goto cleanup; }

    for (uint32_t i = 0; i < 0x1000; ++i) { E3PageA[i] = 0x41; E3PageB[i] = 0x42; }

    if (!GetPteForVa(address((uint64_t) (uintptr_t) E3PageA), PteA) ||
        !GetPteForVa(address((uint64_t) (uintptr_t) E3PageB), PteB) || PteA == PteB)
    { S->E3.Phase = 0xE6; goto cleanup; }

    E3PteOld = *PteA;
    E3PteNew = (E3PteOld & ~PfnMask) | (*PteB & PfnMask);
    if ((E3PteOld & 1) == 0 || (E3PteNew & 1) == 0 ||
        ((E3PteOld ^ E3PteNew) & PfnMask) == 0)
    { S->E3.Phase = 0xE7; goto cleanup; }

    E3Pte = PteA;
    S->E3.Va = (uint64_t) (uintptr_t) E3PageA;
    S->E3.PteBefore = E3PteOld;
    S->E3.PteAfter = E3PteNew;

    OldAffinity = ((FnKeSetSystemAffinityThreadEx) SetAffinity)(2);   // CPU 1
    for (uint64_t i = 0; i < 100000000ull && E3CurrentProcessor() != 1; ++i)
        __builtin_ia32_pause();

    ((FnKeInitializeDpc) g_KeInitializeDpc)(&E3Dpc1, &E3DpcPhase1, nullptr);
    ((FnKeInitializeDpc) g_KeInitializeDpc)(&E3Dpc2, &E3DpcPhase2, nullptr);
    ((FnKeSetTargetProcessorDpc) E3SetTarget)(&E3Dpc1, 1);
    ((FnKeSetTargetProcessorDpc) E3SetTarget)(&E3Dpc2, 1);

    __atomic_store_n(&E3PhaseDone, 0, __ATOMIC_RELEASE);
    if (!((FnKeInsertQueueDpc) E3InsertDpc)(&E3Dpc1, nullptr, nullptr))
    { S->E3.Phase = 0xE8; goto cleanup; }
    if (!E3WaitDone(1)) { S->E3.Phase = 0xE9; goto cleanup; }

    E3FlushPage(Ipi, (uint64_t) (uintptr_t) E3PageA);

    __atomic_store_n(&E3PhaseDone, 0, __ATOMIC_RELEASE);
    if (!((FnKeInsertQueueDpc) E3InsertDpc)(&E3Dpc2, nullptr, nullptr))
    { S->E3.Phase = 0xEA; goto cleanup; }
    if (!E3WaitDone(2)) { S->E3.Phase = 0xEB; goto cleanup; }

    S->E3.Phase = 0x100;

cleanup:
    if (E3Pte)
    {
        __atomic_store_n(E3Pte, E3PteOld, __ATOMIC_RELEASE);
        invlpg(address((uint64_t) (uintptr_t) E3PageA));
        E3FlushPage(Ipi, (uint64_t) (uintptr_t) E3PageA);
        E3Pte = nullptr;
    }
    if (E3PageA) ((FnMmFreeIndependentPages) g_MmFreeIndependentPages)(E3PageA, 0x1000);
    if (E3PageB) ((FnMmFreeIndependentPages) g_MmFreeIndependentPages)(E3PageB, 0x1000);
    E3PageA = nullptr;
    E3PageB = nullptr;
    ((FnKeRevertToUserAffinityThreadEx) RevertAffinity)(OldAffinity);
}
#endif

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
        L.SectionCount > PostboxMaxSections || L.NtoskrnlBase == 0)
    {
        PostboxStartFailure = 21;
        return false;
    }

    // The loader resolved ntoskrnl before mapping. Hand it to the memory layer
    // so the driver can resolve PsInitialSystemProcess/PsLoadedModuleList without
    // importing them (and without a __imp_ IAT slot in the mapped image).
    MemSetPreStartNtoskrnl(L.NtoskrnlBase);

    // Resolve KeIpiGenericCall before the PTE walk: the global flush needs it.
    // Keep it in a local, not .data, so the image has no routine pointer there.
    address IpiGenericCall = 0;
    if (!PostboxResolve(&IpiGenericCall))
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
    if (!IpiGenericCall)
    {
        print(ERROR("Postbox: KeIpiGenericCall not resolved"));
        PostboxStartFailure = 26;
        return false;
    }
#ifdef T2_PROBE
    T2Probe(L.ImageBase, (uint64_t) (uintptr_t) IpiGenericCall, 1);
#endif
    PostboxTlbRange Range{ L.ImageBase, End };
    ((FnKeIpiGenericCall) IpiGenericCall)(
        &PostboxFlushTlb, (uint64_t) (uintptr_t) &Range);
#ifdef T2_PROBE
    T2Probe(L.ImageBase, (uint64_t) (uintptr_t) IpiGenericCall, 2);
#endif

    print(INFO("Postbox: image protections applied (%u pages, %u sections)"),
          Pages, L.SectionCount);
    return true;
}

static void PostboxPoll();

static bool PostboxResolved = false;

static bool PostboxResolve(address* IpiGenericCallOut)
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
#ifdef T2_PROBE
    {
        const char* ProbeName = "KeGetCurrentProcessorNumberEx";
        address ProbeFn = 0;
        FindFuncExportsBatch(Ntoskrnl, &ProbeName, &ProbeFn, 1);
        g_T2GetProcessorNumberEx = (uint64_t) (uintptr_t) ProbeFn;
        if (!g_T2GetProcessorNumberEx)
            print(ERROR("T2_PROBE: KeGetCurrentProcessorNumberEx not resolved"));
    }
#endif

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
    if (IpiGenericCallOut) *IpiGenericCallOut = Functions[13];
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
    PostboxWipe(PostboxStatePtr->Stage, StageAllocBytes);
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
    // C-01 cache residue: no worker can use the memory caches after the caller
    // has quiesced; wipe them now rather than leaving kernel bases resident.
    PostboxWipe(&PostboxStatePtr->Caches, sizeof(PostboxMemCaches));
    // Do NOT clear Process here. The caller's PostboxMaybeReleaseProcess (watchdog,
    // pb_stop, invalid-config) is the only path that drops the cached EPROCESS
    // reference; erasing the pointer first would leak the reference every stop.
    PostboxStatePtr->Stage = nullptr;
    PostboxStatePtr->MailboxVa = 0;
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
    // The free helper now lives inside the page this call is about to wipe. Read
    // it out first; the g_Mm* macros must not be used after the exchange because
    // PostboxStatePtr is already null.
    const address Free = State->Imports.MmFreeIndependentPages;
    PostboxWipe(State, 0x1000);
    if (Free)
        ((FnMmFreeIndependentPages) Free)(State, 0x1000);
}

// Reaper thread body. The assembly entry calls this at PASSIVE with the state
// page as its argument, then tail-jumps to MmFreeIndependentPages. Wait for the
// worker to clear InFlight (which happens after it clears the work item and the
// caller releases the EPROCESS), then give the worker's ret and the loader's
// post-entry ROT1 wipe time to finish.
//
// Returns 1 with Plan filled when the caller may free the image. Returns 0 when
// the worker is still in flight or the page is no longer ours; the stub then
// returns without freeing anything. Leaking is deliberate: freeing the state page
// or image under a stalled worker is a use-after-free/bugcheck.
extern "C" uint64_t PostboxReaperPrepare(PostboxState* State, PostboxReaperPlan* Plan)
{
    if (!State || !Plan) return 0;

    // Save the delay/free helpers before the sensitive residue is wiped.
    const address DelayThread = State->Imports.KeDelayExecutionThread;
    if (!DelayThread) return 0;
    for (uint32_t i = 0; i < 1000 && __atomic_load_n(&PostboxInFlight, __ATOMIC_ACQUIRE); ++i)
    {
        _LARGE_INTEGER Interval{};
        Interval.QuadPart = -10000;   // 1 ms
        ((FnKeDelayExecutionThread) DelayThread)(0, 0, &Interval);
    }

    // K-06: the bounded wait expired with the worker still in flight. Do not
    // free the state page or the image; leave both resident.
    if (__atomic_load_n(&PostboxInFlight, __ATOMIC_ACQUIRE) != 0)
        return 0;

    const uint64_t Base = State->ReaperBase;
    const uint64_t Size = State->ReaperSize;
    const address Free = State->Imports.MmFreeIndependentPages;
    if (!Base || !Size || !Free)
        return 0;

    // T2: the worker is quiescent and the reaper only needs the locals above.
    // Wipe the import/cache/reaper residue before the 500 ms grace period, so
    // the state page does not expose 21 ntoskrnl pointers or the image range.
    PostboxWipe(&State->Imports, sizeof(PostboxImports));
    PostboxWipe(&State->Caches, sizeof(PostboxMemCaches));
    State->ReaperBase = 0;
    State->ReaperSize = 0;

    _LARGE_INTEGER Delay{};
    Delay.QuadPart = -5000000;        // 500 ms
    ((FnKeDelayExecutionThread) DelayThread)(0, 0, &Delay);

    // Exchange first so a concurrent stop cannot free the same page twice. If a
    // new state page replaced this one, leave the old page alone.
    PostboxState* Expected = State;
    if (!__atomic_compare_exchange_n((PostboxState**) &PostboxStatePtr, &Expected,
                                     nullptr, false, __ATOMIC_ACQ_REL,
                                     __ATOMIC_ACQUIRE))
        return 0;

    PostboxWipe(State, 0x1000);
    ((FnMmFreeIndependentPages) Free)(State, 0x1000);

    Plan->Base = Base;
    Plan->Size = Size;
    Plan->Free = (uint64_t) Free;
    return 1;
}

// Creates the system thread whose entry is the assembly tail-jump stub. The
// thread frees the loader allocation (RawBase/AllocSize), not the aligned image
// base, and then returns to PspSystemThreadStartup.
static bool PostboxStartReaper()
{
    if (__atomic_exchange_n(&PostboxReaperStarted, 1, __ATOMIC_ACQ_REL) != 0)
        return true;
    // The import macros dereference PostboxStatePtr. A second stop after a failed
    // reaper can arrive with the page already freed; refuse instead of faulting.
    if (!PostboxStatePtr)
    {
        __atomic_store_n(&PostboxReaperStarted, 0, __ATOMIC_RELEASE);
        return false;
    }
    PostboxState* State = PostboxStatePtr;
    const address CreateThread = State->Imports.PsCreateSystemThread;
    const address CloseThread = State->Imports.ZwClose;
    if (!CreateThread || !CloseThread || !State->Imports.MmFreeIndependentPages ||
        !State->ReaperBase || !State->ReaperSize)
    {
        __atomic_store_n(&PostboxReaperStarted, 0, __ATOMIC_RELEASE);
        return false;
    }

    // The reaper frees the state page, so read the close routine into a local
    // before the thread can run. The StartContext is the state page itself.
    void* ThreadHandle = nullptr;
    const int32_t Status = ((FnPsCreateSystemThread) CreateThread)(
        &ThreadHandle, 0x1FFFFF /* THREAD_ALL_ACCESS */, nullptr, nullptr, nullptr,
        (void*) &PostboxReaperEntry, State);
    if (Status < 0 || !ThreadHandle)
    {
        __atomic_store_n(&PostboxReaperStarted, 0, __ATOMIC_RELEASE);
        print(ERROR("Postbox: reaper thread creation failed"));
        return false;
    }
    ((FnZwClose) CloseThread)(ThreadHandle);
    print(INFO("Postbox: reaper armed"));
    return true;
}

// The client EPROCESS reference is acquired once at start, not per poll. The
// poll acquires/releases the exit synchronization around each mailbox exchange.
// Teardown sets a flag and waits for the last poll reference before it
// dereferences the EPROCESS, so a stop cannot free it under an in-flight poll.
static void PostboxReleaseProcess()
{
    if (!PostboxStatePtr) return;
    __atomic_store_n(&PostboxPollTeardown, true, __ATOMIC_RELEASE);
    for (uint32_t i = 0; i < 100000 &&
                       __atomic_load_n(&PostboxPollRefs, __ATOMIC_ACQUIRE); ++i)
        __builtin_ia32_pause();
    if (__atomic_load_n(&PostboxPollRefs, __ATOMIC_ACQUIRE) != 0)
        return;

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
    // Finish every state-page write before the reaper can free the page.
    PostboxStatePtr->SessionId = 0;
    PostboxStatePtr->LastNonce = 0;
    PostboxStartReaper();
}

// Runs at DISPATCH_LEVEL on the per-CPU DPC stack. It does no memory access: only the
// in-flight exchange and the queue. The mailbox work happens in PostboxWorkRoutine.
static void PostboxDpcRoutine(void*, void*, void*, void*)
{
    if (!__atomic_load_n(&PostboxRunning, __ATOMIC_ACQUIRE)) return;

    if (__atomic_exchange_n(&PostboxInFlight, 1, __ATOMIC_ACQ_REL) == 0)
        ((FnExQueueWorkItem) g_ExQueueWorkItem)(&PostboxStatePtr->Work, 1);   // DelayedWorkQueue
}

// Runs at PASSIVE_LEVEL in an existing system worker thread. The assembly
// PostboxWorkEntry wrapper calls this and clears PostboxInFlight only after it
// returns; do not clear InFlight here.
extern "C" void PostboxWorkRoutine(void*)
{
    PostboxState* State = PostboxStatePtr;
    if (__atomic_load_n(&PostboxRunning, __ATOMIC_ACQUIRE))
    {
#ifdef E3_DPC_PROBE
        // Run the test-only CPU-1 probe once, before the first mailbox poll.
        if (__atomic_exchange_n(&E3Started, 1, __ATOMIC_ACQ_REL) == 0)
            E3RunProbe();
#endif
        PostboxPoll();
    }

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
}

// The poll body. The caller has already attached the worker to MailboxProcess and
// holds its reference; this routine must not dereference it.
static void PostboxPollAttached(void* MailboxProcess)
{
    const uint64_t MailboxVa = PostboxStatePtr->MailboxVa;
    if (!MailboxVa) return;

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
        // Finish every state-page write before the reaper can free the page.
        PostboxStatePtr->SessionId = 0;
        PostboxStatePtr->LastNonce = 0;
        PostboxStartReaper();
    }

    PostboxWipe(&Plain, sizeof(Plain));
    PostboxWipe(&Sealed, sizeof(Sealed));
}

// Poll entry: the worker holds the cached client EPROCESS and the process exit
// synchronization; PostboxCopy uses MmCopyVirtualMemory with explicit processes,
// so the poll does not attach or detach itself.
static void PostboxPoll()
{
    if (__atomic_load_n(&PostboxPollTeardown, __ATOMIC_ACQUIRE)) return;
    __atomic_add_fetch(&PostboxPollRefs, 1, __ATOMIC_ACQ_REL);
    if (__atomic_load_n(&PostboxPollTeardown, __ATOMIC_ACQUIRE) ||
        !__atomic_load_n(&PostboxRunning, __ATOMIC_ACQUIRE))
    {
        __atomic_sub_fetch(&PostboxPollRefs, 1, __ATOMIC_ACQ_REL);
        return;
    }

    if (!PostboxStatePtr || !PostboxStatePtr->MailboxVa)
    {
        // A zeroed/corrupted state must not leave the fast timer armed forever:
        // the dead-client watchdog is bypassed by this early return, and a manual
        // map has no unload callback. Cancel and wipe here (PASSIVE, work routine).
        PostboxCancel();
        PostboxFreeStage();
        PostboxFreeState();
        // Finish every state-page write before the reaper can free the page.
        PostboxStatePtr->SessionId = 0;
        PostboxStatePtr->LastNonce = 0;
        __atomic_sub_fetch(&PostboxPollRefs, 1, __ATOMIC_ACQ_REL);
        PostboxMaybeReleaseProcess();
        PostboxStartReaper();
        return;
    }

    // The EPROCESS reference and create-time check were done once in PostboxStart.
    void* Process = PostboxStatePtr->Process;
    if (!Process)
    {
        PostboxDeadTick();
        PostboxIdleTick();
        __atomic_sub_fetch(&PostboxPollRefs, 1, __ATOMIC_ACQ_REL);
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
        __atomic_sub_fetch(&PostboxPollRefs, 1, __ATOMIC_ACQ_REL);
        PostboxMaybeReleaseProcess();
        return;
    }
    PostboxPollAttached(Process);
    ((FnPsReleaseProcessExitSynchronization) g_PsReleaseProcessExitSynchronization)(Process);
    __atomic_sub_fetch(&PostboxPollRefs, 1, __ATOMIC_ACQ_REL);
    PostboxMaybeReleaseProcess();
}

// Starts the channel from a loader-supplied config. PASSIVE_LEVEL (DriverEntry).
bool PostboxStart(const PostboxConfig* Config)
{
    PostboxStartFailure = 30;
    PostboxPollRefs = 0;
    PostboxPollTeardown = false;

    if (__atomic_load_n(&PostboxRunning, __ATOMIC_ACQUIRE)) return true;
    if (!Config || Config->Magic != PostboxConfigMagic || Config->Version != 4 ||
        !Config->Pid || !Config->MailboxVa || !Config->CreateTime || !Config->SessionId)
        return false;
    if (!Config->Layout.NtoskrnlBase) return false;
    MemSetPreStartNtoskrnl(Config->Layout.NtoskrnlBase);
    // The self-free reaper may only call MmFreeIndependentPages on an independent
    // allocation. The loader sets Reserved bit 0 for that layout; fail closed for
    // a pool image instead of arming a wrong free.
    if (!(Config->Reserved & 1u)) return false;
    if (Config->MailboxVa > PostboxUserLimit - PostboxBytes || (Config->MailboxVa & 7)) return false;

    bool KeyNonZero = false;
    for (uint32_t i = 0; i < sizeof(Config->Key); ++i)
        KeyNonZero |= (Config->Key[i] != 0);
    if (!KeyNonZero) return false;

    // The state page needs the independent-page helpers before it can be allocated.
    // Validate them from the loader config here; they are staged in .data only for
    // the two calls that create and protect the page, then the page owns them
    // (Imports below).
    if (!Config->MmAllocateIndependentPages || !Config->MmSetPageProtection ||
        !Config->MmFreeIndependentPages)
        return false;

    // A previous start may have left the page resident (watchdog/stop). Never
    // overwrite the only pointer: free it first when no worker is in flight. The
    // old page carries its own free helper, so this works after the raw slots were
    // zeroed at the end of the previous start.
    if (PostboxStatePtr)
    {
        if (__atomic_load_n(&PostboxInFlight, __ATOMIC_ACQUIRE) != 0)
            return false;
        PostboxReleaseProcess();
        PostboxFreeStatePage();
    }

    g_MmAllocateIndependentPages_Raw = (address) Config->MmAllocateIndependentPages;
    g_MmSetPageProtection_Raw = (address) Config->MmSetPageProtection;
    g_MmFreeIndependentPages_Raw = (address) Config->MmFreeIndependentPages;

    PostboxStatePtr = (PostboxState*) ((FnMmAllocateIndependentPages)
        g_MmAllocateIndependentPages_Raw)(0x1000, 0xFFFFFFFF, 0, 0);
    if (!PostboxStatePtr)
    {
        g_MmAllocateIndependentPages_Raw = 0;
        g_MmSetPageProtection_Raw = 0;
        g_MmFreeIndependentPages_Raw = 0;
        return false;
    }
    if (!((FnMmSetPageProtection) g_MmSetPageProtection_Raw)(
            PostboxStatePtr, 0x1000, 0x04 /* PAGE_READWRITE */))
    {
        ((FnMmFreeIndependentPages) g_MmFreeIndependentPages_Raw)(PostboxStatePtr, 0x1000);
        PostboxStatePtr = nullptr;
        g_MmAllocateIndependentPages_Raw = 0;
        g_MmSetPageProtection_Raw = 0;
        g_MmFreeIndependentPages_Raw = 0;
        return false;
    }
    PostboxWipe(PostboxStatePtr, 0x1000);
    // C-01: move the pre-protection ntoskrnl/PTE/Pfn caches into the state page
    // and clear their .data slots before any later lookup runs.
    MemAdoptCaches(&PostboxStatePtr->Caches);

    // The page owns the three helpers now. Copy them before any failure path can
    // reach PostboxFreeStatePage, then zero the .data slots so a static .data scan
    // finds no page-allocator pointer after start.
    PostboxStatePtr->Imports.MmAllocateIndependentPages = g_MmAllocateIndependentPages_Raw;
    PostboxStatePtr->Imports.MmSetPageProtection = g_MmSetPageProtection_Raw;
    PostboxStatePtr->Imports.MmFreeIndependentPages = g_MmFreeIndependentPages_Raw;
    g_MmAllocateIndependentPages_Raw = 0;
    g_MmSetPageProtection_Raw = 0;
    g_MmFreeIndependentPages_Raw = 0;

    PostboxStatePtr->Cfg = *Config;
    // B-01: the poll needs the mailbox VA; keep it outside the Cfg copy, which is
    // wiped as soon as start has consumed Pid/CreateTime.
    PostboxStatePtr->MailboxVa = Config->MailboxVa;
    PostboxStatePtr->Cfg.MmAllocateIndependentPages = 0;
    PostboxStatePtr->Cfg.MmSetPageProtection = 0;
    PostboxStatePtr->Cfg.MmFreeIndependentPages = 0;
    // The magic/version are validation-only. Leaving the 8-byte config tag plus
    // version in .data makes the resident control block trivially findable by a
    // magic scan; wipe it after the check.
    PostboxStatePtr->Cfg.Magic = 0;
    PostboxStatePtr->Cfg.Version = 0;
    // The reaper frees the loader allocation, not the aligned image base. Save
    // RawBase/AllocSize in the state page (not .data) before the layout copy is
    // wiped. The Config.Reserved gate above guarantees the independent layout.
    PostboxStatePtr->ReaperBase = Config->Layout.RawBase;
    PostboxStatePtr->ReaperSize = Config->Layout.AllocSize;
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
    // Pid/CreateTime are the last config fields any path reads; keep Pid for the
    // start log, then drop the whole copy below.
    const uint32_t MailboxPid = PostboxStatePtr->Cfg.Pid;
    const uint64_t CreateTime = PostboxStatePtr->Cfg.CreateTime;
    void* Process = nullptr;
    if (((FnPsLookupProcessByProcessId) g_PsLookupProcessByProcessId)(
            (void*) (uintptr_t) MailboxPid, &Process) < 0 || !Process)
    {
        PostboxFreeStatePage();
        return false;
    }
    if ((uint64_t) ((FnPsGetProcessCreateTimeQuadPart) g_PsGetProcessCreateTimeQuadPart)(Process) !=
        CreateTime)
    {
        ((FnObDereferenceObject) g_ObDereferenceObject)(Process);
        PostboxFreeStatePage();
        return false;
    }
    PostboxStatePtr->Process = Process;
    // B-01: Pid/CreateTime were the last config fields any runtime path needs.
    // Wipe the entire copy; the poll uses MailboxVa, auth uses SessionId/Keys.
    PostboxWipe(&PostboxStatePtr->Cfg, sizeof(PostboxConfig));

    // Separate NX stage. Independent pages only: a pool fallback would leave a
    // 64 KiB 'Ntfs' BigPool entry for the channel lifetime (V-27). Fail closed
    // if the loader did not pass the helpers or the allocation/protection fails.
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
        print(ERROR("Postbox: independent-page NX stage unavailable; failing closed"));
        PostboxReleaseProcess();
        PostboxFreeStatePage();
        return false;
    }
    PostboxWipe(PostboxStatePtr->Stage, StageAllocBytes);

#ifdef POSTBOX_NMI
    // The IDT is not touched at start. The gate is installed transiently only for
    // the pb_nmi self-test, then the Windows IDT is restored in the same work item.
#endif

    // ExInitializeWorkItem's fields, without pulling in the macro from the vendor headers
    PostboxStatePtr->Work.List.Flink = nullptr;
    PostboxStatePtr->Work.List.Blink = nullptr;
    PostboxStatePtr->Work.WorkerRoutine = (void*) &PostboxWorkEntry;
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
          MailboxPid, (void*) (uintptr_t) PostboxStatePtr->MailboxVa);
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
