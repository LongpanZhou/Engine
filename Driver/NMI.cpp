// NMI.cpp — IDT hook that hides this driver from NMI-based checks.
//
// How it hides: gate 2 (NMI) is redirected to a stub on every CPU. For each NMI the stub looks at the
// interrupted RIP:
//   - RIP outside this driver's image: the NMI is handed to the original handler untouched. The OS's NMI
//     machinery and every registered NMI callback run as always, and the interrupted thread resumes normally
//   - RIP inside this driver's image: the stub claims the NMI and returns straight to the interrupted code
//     (iret to the exact saved context). The OS's handler never runs, so its registered NMI callbacks never
//     run either: no record, no "RIP not in a valid module" line, and no stack to walk
//
// Both paths are register-neutral. RAX is pushed and popped on every path, and RFLAGS is restored by the CPU
// itself (iret on the claim path, the original handler's own trap frame on the pass path). There is no shared
// state, so nested NMIs (an NMI arriving while a first one is inside the stub) are safe by construction: the
// nested stub sees a RIP inside this image too, claims, and irets straight back into the outer stub.
//
// A claimed NMI means one expected NMI-callback record goes missing for that core in tools that count
// records. The reference tool here derives "invalid drivers" from the object-directory walk, not from callback
// records, so nothing is flagged; if a tool ever counts records, the claim path is the one to revisit.

// The kernel routines needed here, declared because the vendor headers do not include them. KeGenericCallDpc
// is documented to run Routine once on every processor and return only after all of them have run.
// KeGetCurrentProcessorNumberEx with a null number argument returns a flat per-processor index (0..N-1); the
// legacy KeGetCurrentProcessorNumber import does not exist in this WDK import library
extern "C"
{
    void KeGenericCallDpc(void *Routine, void *Context);
    void KeSignalCallDpcSynchronize(void *Dpc);
    void KeSignalCallDpcDone(void *Dpc);
    uint32_t KeGetCurrentProcessorNumberEx(void *ProcNumber);
}

#define CurrentCpu() KeGetCurrentProcessorNumberEx(nullptr)

// The stub's holder. Declared separately so live code can reference the FUNCTION: with LTO + --gc-sections,
// labels defined inside inline asm are invisible to the linker's section graph, and an unreferenced function
// gets its whole section (labels included) discarded. Function == label address, confirmed by disassembly
extern "C" void NmiHideStubHolder();

// The original gate 2 target, saved by IDTHook and restored by IDTUnHook. The stub's final jump reads it
// through this variable, so it must exist at a fixed address the asm can reference
extern "C" uint64_t OriginalNMIHandler = 0;

// This driver's image range. An interrupted RIP inside it gets claimed (hidden). Set by DriverEntry from the
// loader entry, before the hook goes on
extern "C" uint64_t HideStart = 0;
extern "C" uint64_t HideEnd = 0;

// Stub counters, incremented by the asm itself with a lock inc. The heartbeat thread prints them; when they
// stop moving, the stub stopped running. Read them in the debugger after any freeze. 'used' keeps the
// definitions alive through LTO even when C code only reads them indirectly
extern "C" __attribute__((used)) uint64_t NmiPasses = 0;
extern "C" __attribute__((used)) uint64_t NmiClaims = 0;

// The stub's labels, so C can compare against the exact stub range for double-hook detection
extern "C" char asm_nmi_hide_start[];
extern "C" char asm_nmi_hide_end[];

// Saved per-CPU original targets. Every processor has its own IDT, each with its own saved gate
constexpr uint32_t MaxCpu = 64;
static uint64_t OldHandlerPerCpu[MaxCpu];
static bool NmiHooked = false;

// The x64 interrupt gate descriptor (16 bytes). Only the target address gets rewritten; selector, IST index
// and attributes stay exactly as the kernel put them, so the stub is entered with the same stack placement
// and interrupt-off semantics as the original handler
struct IDT_GATE
{
    uint16_t OffsetLow;
    uint16_t Selector;
    uint8_t Ist;
    uint8_t Type;       // 0x8E = present, DPL 0, 64-bit interrupt gate
    uint16_t OffsetMid;
    uint32_t OffsetHigh;
    uint32_t Zero;
};

// Gate target <-> the three split fields. Kept as functions so every read/write site uses one convention
static uint64_t GateTarget(const IDT_GATE *Gate)
{
    return (uint64_t) Gate->OffsetLow | ((uint64_t) Gate->OffsetMid << 16) | ((uint64_t) Gate->OffsetHigh << 32);
}

static void WriteGateTarget(IDT_GATE *Gate, uint64_t Target)
{
    // The IDT pages are mapped read-only (PTE without the write bit). Writing through a read-only supervisor
    // page with CR0.WP set faults with bugcheck 0xBE (ATTEMPTED_WRITE_TO_READONLY_MEMORY), as this hook
    // demonstrated on its first live test. Clear the WP bit for the duration of the patch, then restore it.
    // Running at DISPATCH_LEVEL with interrupts disabled, no other code on this CPU can observe the cleared bit
    uint64_t Cr0;
    __asm__ volatile ("movq %%cr0, %0" : "=r"(Cr0) : : "memory");
    uint64_t Cr0NoWp = Cr0 & ~(1ULL << 16);
    __asm__ volatile ("movq %0, %%cr0" : : "r"(Cr0NoWp) : "memory");

    Gate->OffsetLow = (uint16_t) Target;
    Gate->OffsetMid = (uint16_t) (Target >> 16);
    Gate->OffsetHigh = (uint32_t) (Target >> 32);

    __asm__ volatile ("movq %0, %%cr0" : : "r"(Cr0) : "memory");
}

// The IDT location. sidt is the only straightforward way to reach it
struct IDT_REGISTER
{
    uint16_t Limit;
    uint64_t Base;
} __attribute__((packed));

// On entry, the machine frame from the interrupt itself is [rsp..rsp+0x28]: RIP, CS, RFLAGS, RSP, SS, with RIP
// lowest. The gate keeps the original's selector/IST/attributes, so the stub is entered exactly where the
// original handler would have been: same stack, interrupts off
//
// Claim: the frame at [rsp+8] already holds the interrupted context, so the only preparation is to drop the
// saved RAX back off the stack; iretq then resumes the thread exactly where it was, at the true RIP, with no
// handler and no callback record
// Pass: RAX is restored and the NMI is handed to the original handler. The jump reads the saved value through
// a rip-relative pointer, so no register is borrowed for the target address
__attribute__((used, noinline)) extern "C" void NmiHideStubHolder()
{
    asm volatile(
        ".intel_syntax noprefix\n"

        ".globl asm_nmi_hide_start\n"
        "asm_nmi_hide_start:\n"

        // Interrupted RIP
        "    push rax\n"
        "    mov rax, qword ptr [rsp+8]\n"

        // RIP outside this driver's image? Pass the NMI on untouched
        "    cmp rax, qword ptr [rip+HideStart]\n"
        "    jb 2f\n"
        "    cmp rax, qword ptr [rip+HideEnd]\n"
        "    jae 2f\n"

        // Claim: restore RAX, then return to the interrupted context as if the NMI never happened
        "    lock inc qword ptr [rip+NmiClaims]\n"
        "    pop rax\n"
        "    iretq\n"

        "2:\n"
        "    lock inc qword ptr [rip+NmiPasses]\n"
        "    pop rax\n"
        "    jmp qword ptr [rip+OriginalNMIHandler]\n"

        "asm_nmi_hide_end:\n"
        ".att_syntax prefix\n"
    );
}

// Runs on each CPU at DISPATCH_LEVEL (interrupts off), via KeGenericCallDpc. The gate is patched for this CPU
// only, so the per-CPU saved values stay without races even though all CPUs execute concurrently
static void HookCpuDpc(void *Dpc, void *, void *SystemArgument1, void *SystemArgument2)
{
    // The function's address is where the asm stub starts (no prologue is emitted for an asm-only body), so
    // this both gives the gate target and keeps the .text section holding the labels alive
    uint64_t Stub = (uint64_t) NmiHideStubHolder;

    uint32_t Cpu = CurrentCpu();
    if (Cpu < MaxCpu)
    {
        IDT_REGISTER Idtr = {};
        __asm__ volatile ("sidt %0" : "=m"(Idtr));

        auto *Gate = (IDT_GATE *) (Idtr.Base + sizeof(IDT_GATE) * 2);
        uint64_t Old = GateTarget(Gate);
        OldHandlerPerCpu[Cpu] = Old;

        if (Old == Stub)
        {
            // Already hooked (a previous handbook did not restore): keep the first saved original
            print(WARN("IDTHook: gate 2 on cpu %u already points at the stub"), Cpu);
        }
        else
        {
            // All processors share the kernel's handler, so the first saved value becomes the global one
            if (!OriginalNMIHandler || OriginalNMIHandler == Stub) OriginalNMIHandler = Old;
            WriteGateTarget(Gate, Stub);
        }

        // Read-back: the gate must now hold the stub address, or the patch did not fully land on this CPU
        uint64_t Now = GateTarget(Gate);
        if (Now != Stub) print(ERROR("IDTHook: cpu %u gate read-back MISMATCH: %p, expected %p"), Cpu, (void *) Now, (void *) Stub);
        else print(INFO("IDTHook: cpu %u gate 2 %p -> %p"), Cpu, (void *) Old, (void *) Now);
    }

    // KeGenericCallDpc's contract: Synchronize takes SystemArgument2, Done takes SystemArgument1. Passing the
    // KDPC object here wedges both CPUs forever in KeSignalCallDpcSynchronize (the freeze sc start hung on)
    KeSignalCallDpcSynchronize(SystemArgument2);
    KeSignalCallDpcDone(SystemArgument1);
}

// Same walk in reverse. A gate is only restored if it still points at the stub, so hand edits in between are
// not overwritten with a stale saved value
static void UnhookCpuDpc(void *Dpc, void *, void *SystemArgument1, void *SystemArgument2)
{
    uint32_t Cpu = CurrentCpu();
    if (Cpu < MaxCpu)
    {
        IDT_REGISTER Idtr = {};
        __asm__ volatile ("sidt %0" : "=m"(Idtr));

        auto *Gate = (IDT_GATE *) (Idtr.Base + sizeof(IDT_GATE) * 2);
        if (GateTarget(Gate) == (uint64_t) NmiHideStubHolder && OldHandlerPerCpu[Cpu])
        {
            uint64_t Old = OldHandlerPerCpu[Cpu];
            WriteGateTarget(Gate, Old);
            OldHandlerPerCpu[Cpu] = 0;
            print(INFO("IDTUnHook: cpu %u gate restored to %p"), Cpu, (void *) Old);
        }
    }

    KeSignalCallDpcSynchronize(SystemArgument2);
    KeSignalCallDpcDone(SystemArgument1);
}

// Redirects gate 2 (NMI) to the hide stub on every CPU. Requires HideStart/HideEnd to be set already, and
// HVCI to be off: with HVCI on, descriptor table shadowing makes the gate rewrite impossible, so hooking is
// skipped instead of risking a fault at the write
bool IDTHook()
{
    if (NmiHooked) return true;
    if (IsHVCIEnabled())
    {
        print(WARN("IDTHook: HVCI is on, gate 2 left alone"));
        return false;
    }
    if (!HideStart || HideEnd <= HideStart)
    {
        print(ERROR("IDTHook: HideStart/HideEnd not set, refusing to hook"));
        return false;
    }

    KeGenericCallDpc((void *) HookCpuDpc, nullptr);

    if (OriginalNMIHandler && OriginalNMIHandler != (uint64_t) NmiHideStubHolder)
    {
        NmiHooked = true;
        print(OK("IDTHook: gate 2 hooked, original handler %p"), (void *) OriginalNMIHandler);
        return true;
    }

    print(ERROR("IDTHook: gate 2 not hooked (original handler not found)"));
    return false;
}

// Puts the original handlers back on every CPU. Called by DriverExit before anything else runs
void IDTUnHook()
{
    if (!NmiHooked) return;
    NmiHooked = false;

    KeGenericCallDpc((void *) UnhookCpuDpc, nullptr);
    OriginalNMIHandler = 0;
    print(INFO("IDTUnHook: original handlers restored"));
}
