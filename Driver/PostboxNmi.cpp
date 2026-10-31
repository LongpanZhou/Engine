// Constructed-IDT NMI gate for the Postbox build.
//
// This follows the physmem_remapper reference: save the Windows NMI gate, install
// a copy of the IDT with vector 2 pointing at an assembly trampoline, and chain
// every non-self-test NMI back to the original handler with the trap frame intact.
//
// The gate is system-wide because a work item can run on any CPU. It is opt-in
// (POSTBOX_NMI) and is removed by pb_stop / PostboxStop; the fixed image stays
// mapped, so an in-flight handler can never jump into freed memory.
//
// One constructed IDT is shared by every CPU, and the install mask is 64 bits, so
// the gate supports up to 64 active CPUs in processor group 0 only. Install refuses
// larger or multi-group systems before the first lidt instead of gating a subset.
// There is no hot-add support: a CPU that appears after install keeps the stock IDT.
//
// What this buys: a self-test can deliver a real NMI without bugchecking Windows,
// and the count proves the gate/trampoline/stack handling are live. It does NOT
// hide the driver from an NMI-based sampler: the IDTR, the 4 KiB constructed
// table, and the gate remain observable. See AC-25/AC-26 for the tradeoff.

#ifdef POSTBOX_NMI

#include "../Common/Postbox.h"

struct PostboxIdtr
{
    uint16_t Limit;
    uint64_t Base;
} __attribute__((packed));
static_assert(sizeof(PostboxIdtr) == 10, "IDTR layout changed");

struct PostboxIdtGate
{
    uint16_t OffsetLow;
    uint16_t Selector;
    uint8_t Ist;                    // bits 2:0 = IST index, 7:3 reserved
    uint8_t Type;                   // 0x8E = present, DPL 0, interrupt gate
    uint16_t OffsetMid;
    uint32_t OffsetHigh;
    uint32_t Zero;
} __attribute__((packed));
static_assert(sizeof(PostboxIdtGate) == 16, "IDT gate layout changed");

static PostboxIdtGate* PostboxIdt = nullptr;
static PostboxIdtr* PostboxOldIdt = nullptr;
static bool PostboxIdtIndependent = false;
static uint64_t PostboxNmiInstalledMask = 0;

// Referenced by PostboxNmi.S. used/noinline keep LTO from dropping the entry
// points that the non-LTO assembly object resolves against.
extern "C" void PostboxNmiStub();
extern "C" __attribute__((used)) uint64_t PostboxOriginalNmiHandler = 0;
static volatile uint64_t PostboxNmiTicks = 0;
static volatile uint64_t PostboxNmiHandled = 0;
static volatile uint64_t PostboxNmiLastRip = 0;
static volatile uint64_t PostboxNmiLastCs = 0;
static volatile uint64_t PostboxNmiLastHandledRip = 0;
static volatile long PostboxNmiInFlight = 0;
static volatile long PostboxNmiActive = 0;
static bool PostboxNmiQuiesceAndZero();
static volatile long PostboxNmiSelfTestPending = 0;

// KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS) returns the system-wide count.
static const uint16_t PostboxAllProcessorGroups = 0xFFFF;

using FnKeQueryActiveProcessors = uint64_t (*)();
using FnKeQueryActiveProcessorCountEx = uint32_t (*)(uint16_t GroupNumber);
using FnKeSetSystemAffinityThreadEx = uint64_t (*)(uint64_t);
using FnKeRevertToUserAffinityThreadEx = void (*)(uint64_t);
using FnKeGetCurrentProcessorNumberEx = void (*)(void*);
using FnKeStallExecutionProcessor = void (*)(uint32_t);
using FnMmMapIoSpace = void* (*)(int64_t, uint64_t, uint32_t);
using FnMmUnmapIoSpace = void (*)(void*, uint64_t);

static uint64_t g_KeQueryActiveProcessors = 0;
static uint64_t g_KeQueryActiveProcessorCountEx = 0;
static uint64_t g_KeSetSystemAffinityThreadEx = 0;
static uint64_t g_KeRevertToUserAffinityThreadEx = 0;
static uint64_t g_KeGetCurrentProcessorNumberEx = 0;
static uint64_t g_KeStallExecutionProcessor = 0;
static uint64_t g_MmMapIoSpace = 0;
static uint64_t g_MmUnmapIoSpace = 0;

struct PostboxProcessorNumber
{
    uint16_t Group;
    uint8_t Number;
    uint8_t Reserved;
};
static_assert(sizeof(PostboxProcessorNumber) == 4, "PROCESSOR_NUMBER layout changed");

static uint64_t PostboxNmiGateHandler(const PostboxIdtGate& Gate)
{
    return ((uint64_t) Gate.OffsetHigh << 32) | ((uint64_t) Gate.OffsetMid << 16) |
           Gate.OffsetLow;
}

static void PostboxNmiSetGateHandler(PostboxIdtGate* Gate, uint64_t Handler)
{
    Gate->OffsetLow = (uint16_t) (Handler & 0xFFFF);
    Gate->OffsetMid = (uint16_t) ((Handler >> 16) & 0xFFFF);
    Gate->OffsetHigh = (uint32_t) (Handler >> 32);
}

// Runs on the NMI stack with interrupts disabled, possibly with user GS. Only
// RIP-relative globals and lock-free atomics are touched here: no print, no
// allocation, no locks, no GS-relative access. Context[15]/[16] are the
// interrupted RIP/CS: the stub pushes 15 registers before the hardware frame.
extern "C" __attribute__((used, noinline))
uint8_t PostboxNmiDispatch(uint64_t* Context)
{
    __atomic_add_fetch(&PostboxNmiInFlight, 1, __ATOMIC_ACQ_REL);

    if (Context)
    {
        PostboxNmiLastRip = Context[15];
        PostboxNmiLastCs = Context[16];
    }

    __atomic_add_fetch(&PostboxNmiTicks, 1, __ATOMIC_RELAXED);

    uint8_t Result = 0;
    // A self-test NMI is consumed; every other NMI is chained to Windows.
    if (__atomic_exchange_n(&PostboxNmiSelfTestPending, 0, __ATOMIC_ACQ_REL))
    {
        if (Context) PostboxNmiLastHandledRip = Context[15];
        __atomic_add_fetch(&PostboxNmiHandled, 1, __ATOMIC_RELAXED);
        Result = 1;
    }

    __atomic_sub_fetch(&PostboxNmiInFlight, 1, __ATOMIC_ACQ_REL);
    return Result;
}

uint64_t PostboxNmiCount()
{
    return __atomic_load_n(&PostboxNmiTicks, __ATOMIC_ACQUIRE);
}

static void PostboxNmiReadIdt(PostboxIdtr* Idtr)
{
    __asm__ __volatile__("sidt %0" : "=m"(*Idtr));
}

static void PostboxNmiWriteIdt(const PostboxIdtr* Idtr)
{
    __asm__ __volatile__("lidt %0" : : "m"(*Idtr));
}

static uint64_t PostboxNmiReadMsr(uint32_t Msr)
{
    uint32_t Low = 0;
    uint32_t High = 0;
    __asm__ __volatile__("rdmsr" : "=a"(Low), "=d"(High) : "c"(Msr));
    return ((uint64_t) High << 32) | Low;
}

static void PostboxNmiWriteMsr(uint32_t Msr, uint64_t Value)
{
    __asm__ __volatile__("wrmsr" : : "c"(Msr), "a"((uint32_t) Value),
                         "d"((uint32_t) (Value >> 32)));
}

// Deliver an NMI to the current CPU through the local APIC. x2APIC uses the ICR
// MSR; xAPIC needs the APIC page mapped because IA32_APIC_BASE holds a physical
// address, not the kernel VA the HAL uses. Destination shorthand self (bit 18)
// and delivery mode NMI (bits 10:8 = 4) need no destination field.
static bool PostboxNmiSendSelf(void** Mapping)
{
    *Mapping = nullptr;
    const uint64_t ApicBase = PostboxNmiReadMsr(0x1B);       // IA32_APIC_BASE
    if (!(ApicBase & (1ull << 11))) return false;           // global enable

    const uint64_t Icr = (1ull << 18) | (4ull << 8);
    if (ApicBase & (1ull << 10))                            // x2APIC
    {
        PostboxNmiWriteMsr(0x830, Icr);
        __atomic_thread_fence(__ATOMIC_SEQ_CST);
        return true;
    }

    if (!g_MmMapIoSpace || !g_MmUnmapIoSpace) return false;
    void* ApicMapping = ((FnMmMapIoSpace) g_MmMapIoSpace)(
        (int64_t) (ApicBase & 0xFFFFF000ull), 0x1000, 0);   // MmNonCached
    if (!ApicMapping) return false;

    volatile uint32_t* Apic = (volatile uint32_t*) ApicMapping;
    Apic[0x300 / 4] = (uint32_t) Icr;
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    *Mapping = ApicMapping;
    return true;
}

bool PostboxNmiSelfTest(uint64_t* Count)
{
    if (!Count || !__atomic_load_n(&PostboxNmiActive, __ATOMIC_ACQUIRE) ||
        !g_KeStallExecutionProcessor)
        return false;

    // Fail closed on an ungated CPU: group >0, >64 CPUs, or a hot-added CPU has the
    // stock IDT, so the self-IPI would reach nt!KiNmiInterrupt instead of the gate.
    PostboxProcessorNumber Pn{};
    ((FnKeGetCurrentProcessorNumberEx) g_KeGetCurrentProcessorNumberEx)(&Pn);
    if (Pn.Group != 0 || Pn.Number >= 64 ||
        !(PostboxNmiInstalledMask & (1ull << Pn.Number)))
    {
        print(ERROR("PostboxNmi: self-test on ungated CPU %u"), (uint32_t) Pn.Number);
        return false;
    }

    const uint64_t Before = __atomic_load_n(&PostboxNmiTicks, __ATOMIC_ACQUIRE);
    const uint64_t HandledBefore = __atomic_load_n(&PostboxNmiHandled, __ATOMIC_ACQUIRE);
    print(INFO("PostboxNmi: self-test start, ticks %I64u handled %I64u last rip %p cs 0x%I64X"),
          (unsigned long long) Before, (unsigned long long) HandledBefore,
          (void*) (uintptr_t) PostboxNmiLastRip,
          (unsigned long long) PostboxNmiLastCs);
    __atomic_store_n(&PostboxNmiSelfTestPending, 1, __ATOMIC_RELEASE);
    void* ApicMapping = nullptr;
    if (!PostboxNmiSendSelf(&ApicMapping))
    {
        __atomic_store_n(&PostboxNmiSelfTestPending, 0, __ATOMIC_RELEASE);
        return false;
    }

    // Wait for the handler to consume the self-test NMI, not merely for any NMI
    // count increase: a chained hardware NMI must not satisfy the test. Bound the
    // wait to ~2 ms; the self-IPI is delivered immediately on this target.
    for (uint32_t i = 0; i < 20; ++i)
    {
        if (__atomic_load_n(&PostboxNmiHandled, __ATOMIC_ACQUIRE) != HandledBefore) break;
        ((FnKeStallExecutionProcessor) g_KeStallExecutionProcessor)(100);
    }
    if (ApicMapping)
        ((FnMmUnmapIoSpace) g_MmUnmapIoSpace)(ApicMapping, 0x1000);
    __atomic_store_n(&PostboxNmiSelfTestPending, 0, __ATOMIC_RELEASE);

    *Count = __atomic_load_n(&PostboxNmiHandled, __ATOMIC_ACQUIRE);
    const uint64_t HandledAfter = *Count;
    const uint64_t HandledRip = __atomic_load_n(&PostboxNmiLastHandledRip, __ATOMIC_ACQUIRE);
    const uint64_t DriverBase = (uint64_t) (uintptr_t) &PostboxNmiStub - 0x1000;
    const bool Handled = HandledAfter != HandledBefore;
    const bool InDriver = HandledRip >= DriverBase && HandledRip < DriverBase + 0x20000;
    print(INFO("PostboxNmi: self-test done, ticks %I64u handled %I64u rip %p in-driver %u"),
          (unsigned long long) __atomic_load_n(&PostboxNmiTicks, __ATOMIC_ACQUIRE),
          (unsigned long long) HandledAfter, (void*) (uintptr_t) HandledRip,
          (uint32_t) InDriver);
    // The handled RIP must be in the driver image: this rejects a test that was
    // satisfied by an external NMI consumed while the pending flag was set.
    return Handled && InDriver;
}

static bool PostboxNmiResolve()
{
    address Ntoskrnl = GetNtoskrnl();
    if (!Ntoskrnl) return false;

    // ROT1-encoded so the image does not carry the plaintext NMI/affinity export
    // names. Decoded into a stack buffer and wiped after the resolve.
    static const char EncodedNames[8][40] = {
        "LfRvfszBdujwfQspdfttpst",          // KeQueryActiveProcessors
        "LfTfuTztufnBggjojuzUisfbeFy",      // KeSetSystemAffinityThreadEx
        "LfSfwfsuUpVtfsBggjojuzUisfbeFy",  // KeRevertToUserAffinityThreadEx
        "LfHfuDvssfouQspdfttpsOvncfsFy",    // KeGetCurrentProcessorNumberEx
        "LfTubmmFyfdvujpoQspdfttps",        // KeStallExecutionProcessor
        "NnNbqJpTqbdf",                     // MmMapIoSpace
        "NnVonbqJpTqbdf",                   // MmUnmapIoSpace
        "LfRvfszBdujwfQspdfttpsDpvouFy",    // KeQueryActiveProcessorCountEx
    };

    char Decoded[8][40] = {};
    const char* Names[8] = {};
    for (uint32_t i = 0; i < 8; ++i)
    {
        uint32_t j = 0;
        for (; j < 39 && EncodedNames[i][j]; ++j)
            Decoded[i][j] = (char) (EncodedNames[i][j] - 1);
        Decoded[i][j] = 0;
        Names[i] = Decoded[i];
    }

    address Functions[8] = {};
    FindFuncExportsBatch(Ntoskrnl, Names, Functions, 8);

    bool Ok = true;
    for (uint32_t i = 0; i < 5; ++i)
    {
        if (!Functions[i])
        {
            print(ERROR("PostboxNmi: missing export %s"), Names[i]);
            Ok = false;
        }
    }
    // Required: without the system-wide count the install gate cannot prove that
    // group 0 holds every active CPU before it starts replacing IDTs.
    if (!Functions[7])
    {
        print(ERROR("PostboxNmi: missing export %s"), Names[7]);
        Ok = false;
    }
    if (!Functions[5] || !Functions[6])
        print(WARN("PostboxNmi: APIC mapping exports missing; self-test unavailable"));

    for (uint32_t i = 0; i < 8; ++i)
    {
        volatile char* p = Decoded[i];
        for (uint32_t j = 0; j < 40; ++j) p[j] = 0;
    }

    g_KeQueryActiveProcessors = Functions[0];
    g_KeQueryActiveProcessorCountEx = Functions[7];
    g_KeSetSystemAffinityThreadEx = Functions[1];
    g_KeRevertToUserAffinityThreadEx = Functions[2];
    g_KeGetCurrentProcessorNumberEx = Functions[3];
    g_KeStallExecutionProcessor = Functions[4];
    g_MmMapIoSpace = Functions[5];
    g_MmUnmapIoSpace = Functions[6];
    return Ok && g_KeQueryActiveProcessors && g_KeQueryActiveProcessorCountEx &&
           g_KeSetSystemAffinityThreadEx && g_KeRevertToUserAffinityThreadEx &&
           g_KeGetCurrentProcessorNumberEx && g_KeStallExecutionProcessor;
}

static bool PostboxNmiRestore(const uint64_t Mask, uint64_t Active)
{
    if (!Mask) return true;
    const uint64_t OriginalAffinity =
        ((FnKeSetSystemAffinityThreadEx) g_KeSetSystemAffinityThreadEx)(1);

    bool Ok = true;
    for (uint32_t i = 0; i < 64; ++i)
    {
        const uint64_t Bit = 1ull << i;
        if (!(Mask & Bit) || !(Active & Bit)) continue;
        ((FnKeSetSystemAffinityThreadEx) g_KeSetSystemAffinityThreadEx)(Bit);
        PostboxNmiWriteIdt(&PostboxOldIdt[i]);

        // Verify the restore on the CPU that owns this IDTR. A CPU that silently
        // keeps the constructed IDTR must not have its table/handler wiped.
        PostboxIdtr Check{};
        PostboxNmiReadIdt(&Check);
        if (Check.Base != PostboxOldIdt[i].Base || Check.Limit != PostboxOldIdt[i].Limit)
        {
            print(ERROR("PostboxNmi: IDTR restore verification failed on CPU %u"), i);
            Ok = false;
        }
    }

    ((FnKeSetSystemAffinityThreadEx) g_KeSetSystemAffinityThreadEx)(OriginalAffinity);
    ((FnKeRevertToUserAffinityThreadEx) g_KeRevertToUserAffinityThreadEx)(OriginalAffinity);
    return Ok;
}

static void PostboxNmiFreeIdt()
{
    if (!PostboxIdt) return;
    PostboxWipe(PostboxIdt, sizeof(PostboxIdtGate) * 256);
    if (PostboxIdtIndependent && g_MmFreeIndependentPages)
        ((FnMmFreeIndependentPages) g_MmFreeIndependentPages)(
            PostboxIdt, sizeof(PostboxIdtGate) * 256);
    else
        ((FnExFreePool) g_ExFreePool)(PostboxIdt);
    PostboxIdt = nullptr;
    PostboxIdtIndependent = false;
}

static bool PostboxNmiAllocState()
{
    if (PostboxIdt || PostboxOldIdt) return false;
    if (!g_ExAllocatePoolWithTag || !g_ExFreePool) return false;

    // The 4 KiB IDT is the only session-visible NMI allocation. Prefer page-granular
    // independent pages so it is not a 'Ntfs' BigPool entry during the self-test;
    // fall back to NonPagedPoolNx when the loader did not pass the helpers.
    PostboxIdt = nullptr;
    PostboxIdtIndependent = false;
    if (g_MmAllocateIndependentPages && g_MmSetPageProtection && g_MmFreeIndependentPages)
    {
        PostboxIdt = (PostboxIdtGate*) ((FnMmAllocateIndependentPages)
            g_MmAllocateIndependentPages)(sizeof(PostboxIdtGate) * 256, 0xFFFFFFFF, 0, 0);
        if (PostboxIdt)
        {
            if (((FnMmSetPageProtection) g_MmSetPageProtection)(
                    PostboxIdt, sizeof(PostboxIdtGate) * 256, 0x04 /* PAGE_READWRITE */))
            {
                PostboxIdtIndependent = true;
            }
            else
            {
                ((FnMmFreeIndependentPages) g_MmFreeIndependentPages)(
                    PostboxIdt, sizeof(PostboxIdtGate) * 256);
                PostboxIdt = nullptr;
            }
        }
    }
    if (!PostboxIdt)
    {
        PostboxIdt = (PostboxIdtGate*) ((FnExAllocatePoolWithTag) g_ExAllocatePoolWithTag)(
            0x200 /* NonPagedPoolNx */, sizeof(PostboxIdtGate) * 256, 0x7366744E /* 'Ntfs' */);
        PostboxIdtIndependent = false;
    }

    PostboxOldIdt = (PostboxIdtr*) ((FnExAllocatePoolWithTag) g_ExAllocatePoolWithTag)(
        0x200, sizeof(PostboxIdtr) * 64, 0x7366744E);

    if (!PostboxIdt || !PostboxOldIdt)
    {
        PostboxNmiFreeIdt();
        if (PostboxOldIdt)
        {
            ((FnExFreePool) g_ExFreePool)(PostboxOldIdt);
            PostboxOldIdt = nullptr;
        }
        return false;
    }

    PostboxWipe(PostboxIdt, sizeof(PostboxIdtGate) * 256);
    PostboxWipe(PostboxOldIdt, sizeof(PostboxIdtr) * 64);
    return true;
}

static void PostboxNmiFreeState()
{
    PostboxNmiFreeIdt();
    if (PostboxOldIdt)
    {
        PostboxWipe(PostboxOldIdt, sizeof(PostboxIdtr) * 64);
        ((FnExFreePool) g_ExFreePool)(PostboxOldIdt);
        PostboxOldIdt = nullptr;
    }
}

bool PostboxNmiInstall()
{
    if (__atomic_load_n(&PostboxNmiActive, __ATOMIC_ACQUIRE)) return true;
    if (!PostboxNmiResolve())
    {
        print(ERROR("PostboxNmi: export resolve failed"));
        return false;
    }

    // Capability gate. One constructed IDT is shared by all CPUs and the install
    // mask is 64 bits, so only a single group-0 system of at most 64 CPUs can be
    // gated completely. Check this BEFORE any lidt: on a grouped or larger system
    // some CPUs would keep the stock IDT and the self-test would be partial.
    const uint32_t TotalCpus =
        ((FnKeQueryActiveProcessorCountEx) g_KeQueryActiveProcessorCountEx)(
            PostboxAllProcessorGroups);
    if (TotalCpus == 0 || TotalCpus > 64)
    {
        print(ERROR("PostboxNmi: %u active CPUs, gate supports up to 64 in group 0"),
              TotalCpus);
        return false;
    }

    const uint64_t Active = ((FnKeQueryActiveProcessors) g_KeQueryActiveProcessors)();
    if (!Active)
    {
        print(ERROR("PostboxNmi: KeQueryActiveProcessors returned 0"));
        return false;
    }

    // KeQueryActiveProcessors covers group 0 only. Equal cardinality means every
    // active CPU is in group 0; the per-CPU affinity check below then proves each.
    // Count set bits with a plain loop rather than a popcnt builtin.
    uint32_t GroupZeroCpus = 0;
    for (uint64_t Bits = Active; Bits != 0; Bits &= Bits - 1) ++GroupZeroCpus;
    if (GroupZeroCpus != TotalCpus)
    {
        print(ERROR("PostboxNmi: group 0 has %u of %u active CPUs; grouped systems "
                    "are unsupported"),
              GroupZeroCpus, TotalCpus);
        return false;
    }

    PostboxIdtr Current{};
    PostboxNmiReadIdt(&Current);
    if (!Current.Base || Current.Limit < 0x2F)
    {
        print(ERROR("PostboxNmi: invalid IDTR base %p limit 0x%X"),
              (void*) (uintptr_t) Current.Base, (uint32_t) Current.Limit);
        return false;
    }

    const uint32_t Entries = ((uint32_t) Current.Limit + 1) / 16;
    if (Entries < 3)
    {
        print(ERROR("PostboxNmi: IDT has %u entries"), Entries);
        return false;
    }

    const PostboxIdtGate* Live = (const PostboxIdtGate*) (uintptr_t) Current.Base;
    const PostboxIdtGate WindowsNmi = Live[2];
    if (!(WindowsNmi.Type & 0x80) ||
        ((WindowsNmi.Type & 0x0F) != 0xE && (WindowsNmi.Type & 0x0F) != 0xF))
    {
        print(ERROR("PostboxNmi: NMI gate type 0x%X is not present/interrupt"),
              (uint32_t) WindowsNmi.Type);
        return false;
    }

    const uint64_t OriginalHandler = PostboxNmiGateHandler(WindowsNmi);
    if (!OriginalHandler)
    {
        print(ERROR("PostboxNmi: original NMI handler is zero"));
        return false;
    }

    if (!PostboxNmiAllocState())
    {
        print(ERROR("PostboxNmi: failed to allocate the constructed state"));
        return false;
    }

    PostboxOriginalNmiHandler = OriginalHandler;

    const uint32_t Copy = Entries < 256 ? Entries : 256;
    for (uint32_t i = 0; i < Copy; ++i) PostboxIdt[i] = Live[i];
    for (uint32_t i = Copy; i < 256; ++i)
    {
        PostboxIdt[i].OffsetLow = 0;
        PostboxIdt[i].Selector = 0;
        PostboxIdt[i].Ist = 0;
        PostboxIdt[i].Type = 0;
        PostboxIdt[i].OffsetMid = 0;
        PostboxIdt[i].OffsetHigh = 0;
        PostboxIdt[i].Zero = 0;
    }

    PostboxIdt[2] = WindowsNmi;
    PostboxIdt[2].Ist = WindowsNmi.Ist & 7;
    PostboxIdt[2].Type = 0x8E;
    PostboxIdt[2].Zero = 0;
    PostboxNmiSetGateHandler(&PostboxIdt[2], (uint64_t) (uintptr_t) &PostboxNmiStub);

    PostboxIdtr Constructed{};
    Constructed.Limit = (uint16_t) (Copy * 16 - 1);   // never exceed the 4 KiB table
    Constructed.Base = (uint64_t) (uintptr_t) &PostboxIdt[0];

    const uint64_t OriginalAffinity =
        ((FnKeSetSystemAffinityThreadEx) g_KeSetSystemAffinityThreadEx)(1);
    print(INFO("PostboxNmi: original affinity 0x%I64X"), (unsigned long long) OriginalAffinity);
    uint64_t Mask = 0;
    uint32_t Installed = 0;
    bool Ok = true;
    for (uint32_t i = 0; i < 64; ++i)
    {
        const uint64_t Bit = 1ull << i;
        if (!(Active & Bit)) continue;

        ((FnKeSetSystemAffinityThreadEx) g_KeSetSystemAffinityThreadEx)(Bit);
        PostboxProcessorNumber Pn{};
        ((FnKeGetCurrentProcessorNumberEx) g_KeGetCurrentProcessorNumberEx)(&Pn);
        if (Pn.Group != 0 || Pn.Number != i)
        {
            print(ERROR("PostboxNmi: affinity for CPU %u landed on group %u CPU %u"), i,
                  (uint32_t) Pn.Group, (uint32_t) Pn.Number);
            Ok = false;
            break;
        }
        PostboxNmiReadIdt(&PostboxOldIdt[i]);
        PostboxNmiWriteIdt(&Constructed);
        Mask |= Bit;
        ++Installed;
    }
    // Observed on 19041: KeSetSystemAffinityThreadEx returns 0 for this system worker
    // (no prior system affinity). The set(0)+revert(0) pair clears SystemAffinityActive;
    // a revert to the active mask alone still leaves the EXWORKER warning.
    ((FnKeSetSystemAffinityThreadEx) g_KeSetSystemAffinityThreadEx)(OriginalAffinity);
    ((FnKeRevertToUserAffinityThreadEx) g_KeRevertToUserAffinityThreadEx)(OriginalAffinity);

    // Fail closed: either every active CPU uses the constructed IDT, or none does.
    if (!Ok || Mask != Active)
    {
        print(ERROR("PostboxNmi: install incomplete, mask 0x%I64X active 0x%I64X"),
              (unsigned long long) Mask, (unsigned long long) Active);
        if (PostboxNmiRestore(Mask, Active))
        {
            // Wait out any handler that started before the restore, then wipe the
            // constructed state; a failed install must not leave a private IDT behind.
            if (!PostboxNmiQuiesceAndZero())
                print(ERROR("PostboxNmi: install failure left NMI state intact"));
        }
        else
        {
            print(ERROR("PostboxNmi: restore failed; leaving NMI state intact"));
        }
        return false;
    }

    PostboxNmiInstalledMask = Mask;
    __atomic_store_n(&PostboxNmiActive, 1, __ATOMIC_RELEASE);
    print(INFO("Postbox: NMI gate installed on %u CPU(s) in group 0, vector 2 -> %p "
               "(grouped or >64-CPU systems refused)"),
          Installed, (void*) (uintptr_t) &PostboxNmiStub);
    return true;
}

// After every CPU is back on the Windows IDTR, wait until no stub invocation is
// still in the dispatch path, then wipe the constructed table and saved IDTRs. The
// handler pointer is preserved separately so an in-flight stub can still chain.
static bool PostboxNmiQuiesceAndZero()
{
    _LARGE_INTEGER Delay{};
    Delay.QuadPart = -10000;                 // 1 ms
    for (uint32_t i = 0; i < 10; ++i)
    {
        if (!__atomic_load_n(&PostboxNmiInFlight, __ATOMIC_ACQUIRE))
            break;
        ((FnKeDelayExecutionThread) g_KeDelayExecutionThread)(0, 0, &Delay);
    }
    if (__atomic_load_n(&PostboxNmiInFlight, __ATOMIC_ACQUIRE))
    {
        print(ERROR("PostboxNmi: handler still in flight; leaving table intact"));
        return false;
    }

    // Leave PostboxOriginalNmiHandler pointing at nt!KiNmiInterrupt. A stub that
    // started before the IDTR restore may still execute `jmp *handler`; zeroing it
    // would turn a rare in-flight NMI into a jump to NULL. The table/old IDTRs are
    // zeroed, and the counters/last RIP/CS are diagnostic residue.
    __atomic_store_n(&PostboxNmiTicks, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&PostboxNmiHandled, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&PostboxNmiLastRip, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&PostboxNmiLastCs, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&PostboxNmiLastHandledRip, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&PostboxNmiSelfTestPending, 0, __ATOMIC_RELAXED);
    PostboxNmiFreeState();
    return true;
}

void PostboxNmiUninstall()
{
    if (!__atomic_load_n(&PostboxNmiActive, __ATOMIC_ACQUIRE) && !PostboxNmiInstalledMask)
        return;

    __atomic_store_n(&PostboxNmiActive, 0, __ATOMIC_RELEASE);
    const uint64_t Mask = PostboxNmiInstalledMask;
    PostboxNmiInstalledMask = 0;
    if (!Mask) return;

    const uint64_t Active = ((FnKeQueryActiveProcessors) g_KeQueryActiveProcessors)();
    if (PostboxNmiRestore(Mask, Active))
    {
        PostboxNmiQuiesceAndZero();
        print(INFO("Postbox: NMI gate removed"));
    }
    else
    {
        print(ERROR("PostboxNmi: restore failed; leaving NMI state intact"));
    }
}

#endif // POSTBOX_NMI
