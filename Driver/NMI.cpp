// Interrupt gate, 16 bytes on x64
struct IDT_GATE
{
    uint16_t OffsetLow;
    uint16_t Selector;
    uint8_t IST;
    uint8_t TypeAttributes;
    uint16_t OffsetMid;
    uint32_t OffsetHigh;
    uint32_t Reserved;
};

IDT_GATE localIDT[256];

// Windows' own NMI and #PF handlers. The stubs below jump to them
extern "C" uint64_t OriginalNMIHandler = 0;
extern "C" uint64_t OriginalPFHandler = 0;

// C symbol names in assembly need the compiler's label prefix ('_' on macOS, none on Windows)
#define LABEL_STR2(Name) #Name
#define LABEL_STR(Name) LABEL_STR2(Name)
#define C_LABEL(Name) LABEL_STR(__USER_LABEL_PREFIX__) #Name

// The general-purpose registers as asm_nmi_handler saves them. Lowest address first, the reverse of the push order
struct NMI_REGISTERS
{
    uint64_t R15, R14, R13, R12, R11, R10, R9, R8, Rbp, Rdi, Rsi, Rdx, Rcx, Rbx, Rax;
};

// The CPU pushes this frame when an NMI arrives. It sits just above the saved registers
struct NMI_FRAME
{
    uint64_t Rip;
    uint64_t Cs;
    uint64_t Rflags;
    uint64_t Rsp;
    uint64_t Ss;
};

constexpr uint32_t NMI_STACK_BYTES = 0x400;   // how much of the interrupted stack is copied at NMI level
constexpr uint32_t NMI_MAX_FRAMES = 16;

// What the most recent NMI on one processor interrupted: its address, a copy of its stack, and the frames
// unwound from that copy
struct NMI_RECORD
{
    uint64_t Rip;
    uint64_t Rsp;
    uint64_t Cs;
    bool Recorded;           // set once this scan has recorded an NMI on this processor
    uint32_t StackBytes;
    uint8_t Stack[NMI_STACK_BYTES];
    uint32_t FrameCount;
    uint64_t Frames[NMI_MAX_FRAMES];
};

constexpr uint32_t MaxNmiProcessors = 64;
NMI_RECORD NmiRecords[MaxNmiProcessors];

// Per-processor handshake between RunNmiScan and the NMI handlers. RunNmiScan arms a processor just before it sends
// that processor an NMI. The first NMI on an armed processor is recorded, and every other NMI is ignored. The
// handler moves Armed -> Recording -> Recorded, and RunNmiScan moves the processor back to Idle only once its record
// is complete, so a record is never read while it is being written
constexpr uint32_t NmiIdle = 0;
constexpr uint32_t NmiArmed = 1;
constexpr uint32_t NmiRecording = 2;
constexpr uint32_t NmiRecorded = 3;
uint32_t NmiState[MaxNmiProcessors];

// How many times CollectNmiRecord checks a record that is still being written before it gives up on it
constexpr uint32_t MaxCollectSpins = 1000000;

// Set by IDTHook. The handler does nothing unless this is true, and IDTHook turns it on only when HVCI is off.
// (The HVCI query itself cannot run at NMI level, so it is asked once here and the result is stored.)
bool NmiHandlerEnabled = false;

// Declared here because the vendor headers are not in this checkout; the signature is the kernel's
extern "C" uint32_t KeGetCurrentProcessorNumberEx(void *ProcessorNumber);

// ---- Stack capture (NMI level) and unwinding (normal level) ----

// x64 unwind data, as the compiler writes it into the image's exception directory (.pdata)
struct RUNTIME_FUNCTION
{
    uint32_t BeginAddress;   // RVA of the function's first byte
    uint32_t EndAddress;     // RVA just past its last byte
    uint32_t UnwindData;     // RVA of its UNWIND_INFO
};

struct UNWIND_CODE
{
    uint8_t CodeOffset;      // offset into the prolog, just after this operation
    uint8_t UnwindOp : 4;
    uint8_t OpInfo : 4;
};

struct UNWIND_INFO
{
    uint8_t VersionAndFlags; // version in the low 3 bits, flags in the high 5
    uint8_t SizeOfProlog;
    uint8_t CountOfCodes;    // number of 2-byte UNWIND_CODE slots, not operations
    uint8_t FrameRegisterAndOffset;
    // UNWIND_CODE slots follow
};

constexpr uint8_t UWOP_PUSH_NONVOL = 0;
constexpr uint8_t UWOP_ALLOC_LARGE = 1;
constexpr uint8_t UWOP_ALLOC_SMALL = 2;
constexpr uint8_t UWOP_SET_FPREG = 3;
constexpr uint8_t UWOP_SAVE_NONVOL = 4;
constexpr uint8_t UWOP_SAVE_NONVOL_FAR = 5;
constexpr uint8_t UWOP_SAVE_XMM128 = 8;
constexpr uint8_t UWOP_SAVE_XMM128_FAR = 9;
constexpr uint8_t UNW_FLAG_CHAININFO = 0x4;

// The kernel's KeGetCurrentThread is inline in the WDK and not exported, so read the current thread from the KPCR
inline void *KeGetCurrentThread()
{
    uint64_t Thread;
    __asm__ volatile ("movq %%gs:0x188, %0" : "=r"(Thread));
    return (void *) Thread;
}

// Declared here because the vendor headers are not in this checkout; the signatures are the kernel's
extern "C"
{
    RUNTIME_FUNCTION *RtlLookupFunctionEntry(uint64_t ControlPc, uint64_t *ImageBase, void *HistoryTable);
}

// Copies the interrupted thread's stack from the interrupted RSP up to the top of the stack, or NMI_STACK_BYTES,
// whichever is smaller. The top is the thread's StackBase (KTHREAD offset 0x30, as the nmi project uses; not verified
// here). Runs at NMI level, so it only reads memory: no locks, no paged memory.
void CaptureNmiStack(NMI_RECORD *Record)
{
    uint64_t Rsp = Record->Rsp;
    uint64_t StackBase = *(uint64_t *) ((uint8_t *) KeGetCurrentThread() + 0x030);
    uint64_t Available = StackBase > Rsp ? StackBase - Rsp : 0;
    uint32_t Bytes = Available < NMI_STACK_BYTES ? (uint32_t) Available : NMI_STACK_BYTES;

    memcpy(Record->Stack, (void *) Rsp, Bytes);
    Record->StackBytes = Bytes;
}

// Reads one 8-byte value from a record's stack copy. Fails if the address is outside the copy
bool ReadNmiStack(const NMI_RECORD *Record, uint64_t Address, uint64_t *Value)
{
    if (Address < Record->Rsp) return false;

    uint64_t Offset = Address - Record->Rsp;
    if (Offset + sizeof(uint64_t) > Record->StackBytes) return false;

    memcpy(Value, Record->Stack + Offset, sizeof(*Value));
    return true;
}

// How far the prolog moved RSP, counting only the steps that had run by PrologOffset.
// Returns false for prolog steps this walker does not handle (a frame register, machine frames, chained entries).
bool PrologStackAdjust(const UNWIND_INFO *Info, uint32_t PrologOffset, uint64_t *Adjust)
{
    if (((Info->VersionAndFlags >> 3) & UNW_FLAG_CHAININFO) || (Info->FrameRegisterAndOffset & 0x0F))
        return false;

    const UNWIND_CODE *Codes = (const UNWIND_CODE *) ((const uint8_t *) Info + 4);
    uint64_t Total = 0;

    for (uint32_t i = 0; i < Info->CountOfCodes;)
    {
        const UNWIND_CODE *Code = &Codes[i];
        bool Applied = Code->CodeOffset <= PrologOffset;
        uint32_t Slots = 1;

        switch (Code->UnwindOp)
        {
        case UWOP_PUSH_NONVOL:
            if (Applied) Total += 8;
            break;
        case UWOP_ALLOC_LARGE:
            if (Code->OpInfo == 0)
            {
                Slots = 2;
                if (Applied) Total += *(const uint16_t *) &Codes[i + 1] * 8;
            }
            else
            {
                Slots = 3;
                if (Applied) Total += *(const uint32_t *) &Codes[i + 1];
            }
            break;
        case UWOP_ALLOC_SMALL:
            if (Applied) Total += Code->OpInfo * 8 + 8;
            break;
        case UWOP_SAVE_NONVOL:
        case UWOP_SAVE_XMM128:
            Slots = 2;
            break;
        case UWOP_SAVE_NONVOL_FAR:
        case UWOP_SAVE_XMM128_FAR:
            Slots = 3;
            break;
        default:
            return false;   // UWOP_SET_FPREG, machine frames, epilogs, spare codes
        }

        i += Slots;
    }

    *Adjust = Total;
    return true;
}

// Walks a captured stack from the interrupted RIP upward. Each frame's return address is read from the copy at the
// address where the function's entry RSP points. The walk stops at a frame it cannot unwind, or when the copy ends.
// Runs at PASSIVE_LEVEL, because it looks up unwind data.
void WalkNmiStack(NMI_RECORD *Record)
{
    uint64_t Rip = Record->Rip;
    uint64_t Rsp = Record->Rsp;
    uint32_t Count = 0;

    while (Count < NMI_MAX_FRAMES)
    {
        uint64_t ImageBase = 0;
        RUNTIME_FUNCTION *Function = RtlLookupFunctionEntry(Rip, &ImageBase, nullptr);
        if (!Function) break;   // no unwind data here: stop rather than guess

        UNWIND_INFO *Info = (UNWIND_INFO *) (ImageBase + Function->UnwindData);
        uint32_t PrologOffset = (uint32_t) (Rip - (ImageBase + Function->BeginAddress));
        uint64_t Adjust = 0;
        if (!PrologStackAdjust(Info, PrologOffset, &Adjust)) break;

        // The return address sits at the function's entry RSP: the current RSP plus what the prolog pushed
        uint64_t EntryRsp = Rsp + Adjust;
        uint64_t ReturnAddress = 0;
        if (!ReadNmiStack(Record, EntryRsp, &ReturnAddress)) break;

        Record->Frames[Count++] = ReturnAddress;
        Rip = ReturnAddress;
        Rsp = EntryRsp + 8;
    }

    Record->FrameCount = Count;
}

// Records an NMI on a processor that RunNmiScan armed, and only the first one. Called at NMI level, so it only reads
// and writes memory and uses atomic operations
void RecordArmedNmi(const NMI_FRAME *Frame)
{
    uint32_t Cpu = KeGetCurrentProcessorNumberEx(nullptr);
    if (Cpu >= MaxNmiProcessors) return;
    if (__atomic_load_n(&NmiState[Cpu], __ATOMIC_SEQ_CST) != NmiArmed) return;   // the usual case: no scan running here

    uint32_t Expected = NmiArmed;
    if (!__atomic_compare_exchange_n(&NmiState[Cpu], &Expected, NmiRecording, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
        return;

    NMI_RECORD *Record = &NmiRecords[Cpu];
    Record->Rip = Frame->Rip;
    Record->Rsp = Frame->Rsp;
    Record->Cs = Frame->Cs;

    // Only kernel-mode stacks are copied. For an NMI in usermode, Rsp is a user address that may not be resident, and
    // touching it at NMI level faults and takes the machine down. The caller skips usermode records anyway
    if ((Frame->Cs & 3) == 0) CaptureNmiStack(Record);
    else Record->StackBytes = 0;

    Record->Recorded = true;
    __atomic_store_n(&NmiState[Cpu], NmiRecorded, __ATOMIC_SEQ_CST);
}

// Called by asm_nmi_handler with every general-purpose register saved.
// It records what the NMI interrupted on a processor RunNmiScan armed, then returns false, so Windows' own handler still runs.
// Return true only if the NMI is ours and should resume the interrupted code. Changes made to *Regs are what the
// interrupted code sees.
// Must not use floating point or SSE, take locks, or touch paged memory: it runs at NMI level.
extern "C" bool NMIInterruptHandler(NMI_REGISTERS *Regs)
{
    // With HVCI on, the handler does not run: the NMI goes straight to Windows
    if (!NmiHandlerEnabled) return false;

    NMI_FRAME *Frame = (NMI_FRAME *) (Regs + 1);   // the CPU's frame starts right after the saved registers
    RecordArmedNmi(Frame);
    return false;
}

// asm_nmi_handler saves every general-purpose register, calls NMIInterruptHandler, then either resumes the
// interrupted code with iretq, or hands the untouched interrupt frame to Windows' handler.
// asm_pf_handler only passes control on to Windows' #PF handler.
__asm__(
    ".globl " C_LABEL(asm_nmi_handler) "\n"
    C_LABEL(asm_nmi_handler) ":\n"
    "    push %rax\n"
    "    push %rbx\n"
    "    push %rcx\n"
    "    push %rdx\n"
    "    push %rsi\n"
    "    push %rdi\n"
    "    push %rbp\n"
    "    push %r8\n"
    "    push %r9\n"
    "    push %r10\n"
    "    push %r11\n"
    "    push %r12\n"
    "    push %r13\n"
    "    push %r14\n"
    "    push %r15\n"
    "    mov %rsp, %rbx\n"                    // rbx = the saved registers; it is callee-saved, so it survives the call
    "    and $-16, %rsp\n"                    // the calling convention needs a 16-byte aligned stack at the call
    "    sub $0x20, %rsp\n"                   // 32 bytes of shadow space (Windows x64)
#ifdef _WIN32
    "    mov %rbx, %rcx\n"                    // first argument (Windows x64)
#else
    "    mov %rbx, %rdi\n"                    // first argument (System V, used by the host test build)
#endif
    "    call " C_LABEL(NMIInterruptHandler) "\n"
    "    mov %rbx, %rsp\n"                    // back to the saved registers
    "    test %al, %al\n"                     // pops do not change the flags, so the result survives them
    "    pop %r15\n"
    "    pop %r14\n"
    "    pop %r13\n"
    "    pop %r12\n"
    "    pop %r11\n"
    "    pop %r10\n"
    "    pop %r9\n"
    "    pop %r8\n"
    "    pop %rbp\n"
    "    pop %rdi\n"
    "    pop %rsi\n"
    "    pop %rdx\n"
    "    pop %rcx\n"
    "    pop %rbx\n"
    "    pop %rax\n"
    "    jnz 1f\n"
    "    jmp *" C_LABEL(OriginalNMIHandler) "(%rip)\n"   // not ours: Windows' handler gets the untouched frame
    "1:\n"
    "    iretq\n"
    ".globl " C_LABEL(asm_pf_handler) "\n"
    C_LABEL(asm_pf_handler) ":\n"
    "    jmp *" C_LABEL(OriginalPFHandler) "(%rip)\n"
);
extern "C" void asm_nmi_handler();
extern "C" void asm_pf_handler();

// Handler address stored in an interrupt gate
uint64_t GateOffset(const IDT_GATE &Gate)
{
    return (uint64_t) Gate.OffsetLow | ((uint64_t) Gate.OffsetMid << 16) | ((uint64_t) Gate.OffsetHigh << 32);
}

// Builds a gate with the same selector and attributes as WindowsGate, pointing at Handler
IDT_GATE CreateInterruptHandler(IDT_GATE WindowsGate, uint64_t Handler)
{
    IDT_GATE handler = WindowsGate;
    handler.OffsetLow = Handler & 0xFFFF;
    handler.OffsetMid = (Handler >> 16) & 0xFFFF;
    handler.OffsetHigh = Handler >> 32;
    return handler;
}

// IDT
void IDTHandle()
{

}

// The IDTR that Windows uses, kept so IDTUnHook can put it back
interrupt_descriptor_table WindowsIDTR;

// KeGenericCallDpc runs a routine once on every active processor. Declared here because the vendor headers
// are not in this checkout; the signatures are the WDK's.
struct _KDPC;
typedef void (*PKDEFERRED_ROUTINE)(_KDPC *Dpc, void *DeferredContext, void *SystemArgument1, void *SystemArgument2);
extern "C"
{
    void KeGenericCallDpc(PKDEFERRED_ROUTINE Routine, void *Context);
    unsigned char KeSignalCallDpcSynchronize(void *SystemArgument2);
    void KeSignalCallDpcDone(void *SystemArgument1);
}

// Runs on each processor. It waits until every processor has arrived, loads the IDTR in Context, then reports done
void LoadIDTROnProcessor(_KDPC *Dpc, void *Context, void *SystemArgument1, void *SystemArgument2)
{
    KeSignalCallDpcSynchronize(SystemArgument2);
    lidt(*(interrupt_descriptor_table *) Context);
    KeSignalCallDpcDone(SystemArgument1);
}

bool IDTHook()
{
    // Decide now, at normal level, whether the NMI handler may run
    NmiHandlerEnabled = !IsHVCIEnabled();
    print(INFO("IDTHook: HVCI %s, NMI handler %s"), NmiHandlerEnabled ? "off" : "on", NmiHandlerEnabled ? "enabled" : "disabled");

    // With HVCI on the handler never runs, so the IDT is left alone (the call-stack method does not need it)
    if (!NmiHandlerEnabled) return true;

    // Get windows IDT
    WindowsIDTR = sidt();
    IDT_GATE *windowsIDT = (IDT_GATE *) WindowsIDTR.base;
    print(INFO("IDTHook: Windows IDT at %p, limit %u"), (void *) WindowsIDTR.base, (uint32_t) WindowsIDTR.limit);
    if (!windowsIDT)
    {
        print(ERROR("IDTHook: IDT base is null"));
        return false;
    }

    // Construct local handler
    memcpy(localIDT, windowsIDT, sizeof(localIDT));

    // NMI and PF: the new gates point at the stubs, which pass control on to the Windows handlers
    OriginalNMIHandler = GateOffset(windowsIDT[2]);
    OriginalPFHandler = GateOffset(windowsIDT[14]);
    localIDT[2] = CreateInterruptHandler(windowsIDT[2], (uint64_t) &asm_nmi_handler);
    localIDT[14] = CreateInterruptHandler(windowsIDT[14], (uint64_t) &asm_pf_handler);

    // Load the table on every processor, not just this one (the limit is the last valid byte, so size - 1)
    interrupt_descriptor_table LocalIDTR;
    LocalIDTR.base = &localIDT;
    LocalIDTR.limit = sizeof(localIDT) - 1;
    print(INFO("IDTHook: loading the new IDT on every processor (KeGenericCallDpc)"));
    KeGenericCallDpc(LoadIDTROnProcessor, &LocalIDTR);
    print(INFO("IDTHook: new IDT loaded on every processor"));

    return true;
}

// Puts the Windows IDTR back on every processor
bool IDTUnHook()
{
    if (!WindowsIDTR.base) return false;

    KeGenericCallDpc(LoadIDTROnProcessor, &WindowsIDTR);
    return true;
}

// Returns true if Rip lies inside a loaded kernel module. Walks PsLoadedModuleList, so call at PASSIVE_LEVEL
bool IsRipInKernelModule(uint64_t Rip)
{
    _LIST_ENTRY *Head = (_LIST_ENTRY *) *__imp_PsLoadedModuleList;

    for (_LIST_ENTRY *Current = Head->Flink; Current != Head; Current = Current->Flink)
    {
        _KLDR_DATA_TABLE_ENTRY *Module = CONTAINING_RECORD(Current, _KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        uint64_t Base = (uint64_t) Module->DllBase;

        if (Rip >= Base && Rip < Base + Module->SizeOfImage) return true;
    }

    return false;
}

// Counts processors whose most recent NMI interrupted kernel code outside every loaded module. NMIs that
// interrupted user-mode code (CS with RPL 3) are skipped. Call at PASSIVE_LEVEL
uint32_t CountNmiInterruptsOutsideModules()
{
    uint32_t Suspicious = 0;

    for (uint32_t Cpu = 0; Cpu < MaxNmiProcessors; Cpu++)
    {
        NMI_RECORD *Record = &NmiRecords[Cpu];

        if (!Record->Recorded) continue;
        if ((Record->Cs & 3) == 3) continue;

        if (!IsRipInKernelModule(Record->Rip))
        {
            print(INFO("CPU %u: last NMI interrupted RIP %p outside every kernel module"), Cpu, (void *) Record->Rip);
            Suspicious++;
        }
    }

    return Suspicious;
}

// ---- Call-stack method: used when HVCI is on, where the IDT handler does not run ----

typedef uint8_t (*PNMI_CALLBACK_FUNCTION)(void *Context, uint8_t Handled);

// Kernel functions for this method. Declared here because the vendor headers are not in this checkout
extern "C"
{
    void *KeRegisterNmiCallback(PNMI_CALLBACK_FUNCTION Callback, void *Context);
    void KeDeregisterNmiCallback(void *Handle);
    void KeInitializeAffinityEx(_KAFFINITY_EX *Affinity);
    void KeAddProcessorAffinityEx(_KAFFINITY_EX *Affinity, uint32_t Processor);
    void HalSendNMI(_KAFFINITY_EX *Affinity);
    int32_t KeDelayExecutionThread(uint8_t WaitMode, uint8_t Alertable, int64_t *Interval);
}

// The part of the 64-bit task state segment this method reads. It is packed, as the CPU lays it out
#pragma pack(push, 1)
struct TASK_STATE_SEGMENT_64
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
#pragma pack(pop)

// Reads IA32_GS_BASE, which in kernel mode points at this processor's KPCR
uint64_t ReadGsBaseHardware()
{
    uint32_t Low;
    uint32_t High;
    __asm__ volatile("rdmsr" : "=a"(Low), "=d"(High) : "c"(0xC0000101));
    return ((uint64_t) High << 32) | Low;
}

// How NmiCallback finds the KPCR. ReadGsBaseHardware in the driver; the tests replace it
uint64_t (*ReadKpcrAddress)() = ReadGsBaseHardware;

// Runs in NMI context on the processor that took the NMI, while RunNmiScan has it registered.
// The CPU pushed its interrupt frame on the NMI stack, whose top is TSS.Ist3, so the frame's RIP is the
// interrupted address. Returns FALSE, so Windows still gets the NMI.
uint8_t NmiCallback(void *Context, uint8_t Handled)
{
    uint64_t Kpcr = ReadKpcrAddress();
    TASK_STATE_SEGMENT_64 *Tss = *(TASK_STATE_SEGMENT_64 **) (Kpcr + 0x008);   // the KPCR's pointer to the TSS
    NMI_FRAME *Frame = (NMI_FRAME *) (Tss->Ist3 - sizeof(NMI_FRAME));
    RecordArmedNmi(Frame);

    return 0;
}

// Ends the wait for one processor. If no NMI came, the processor is disarmed, so an NMI that arrives later is ignored,
// and this returns false. If one was recorded, this waits until the handler has finished writing it, then returns true
bool CollectNmiRecord(uint32_t Cpu)
{
    uint32_t State = NmiArmed;
    if (__atomic_compare_exchange_n(&NmiState[Cpu], &State, NmiIdle, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) return false;
    if (State == NmiIdle) return false;

    // The handler is still writing this record. Wait for it, but not forever: a handler that never finishes must not
    // hang the scan. After the limit, the processor is disarmed and its record is dropped
    for (uint32_t Spin = 0; Spin < MaxCollectSpins; Spin++)
    {
        State = NmiRecorded;
        if (__atomic_compare_exchange_n(&NmiState[Cpu], &State, NmiIdle, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) return true;
        __asm__ volatile("pause");
    }

    __atomic_store_n(&NmiState[Cpu], NmiIdle, __ATOMIC_SEQ_CST);
    NmiRecords[Cpu].Recorded = false;
    print(WARN("CPU %u: NMI record did not finish, dropped"), Cpu);
    return false;
}

// Sends an NMI to every processor and records what each one interrupted.
// With HVCI on, the call-stack method records them (a callback registered for the scan). With HVCI off, the IDT
// handler records them. Call at PASSIVE_LEVEL. Returns how many processors interrupted kernel code outside every
// loaded module.
uint32_t RunNmiScan()
{
    // IDTHook already decided whether the handler runs. When it does not (HVCI on), the callback records the NMIs
    bool hvci = !NmiHandlerEnabled;
    void *handle = nullptr;

    memset(NmiRecords, 0, sizeof(NmiRecords));

    if (hvci)
    {
        handle = KeRegisterNmiCallback(NmiCallback, nullptr);
        if (!handle)
        {
            print(ERROR("could not register the NMI callback"));
            return 0;
        }
    }

    // Arm every processor, then send all the NMIs at once. Each processor records only its own NMI, so they do not
    // interfere, and one wait covers them all
    uint32_t cores = win::KeQueryActiveProcessorCount(nullptr);
    if (cores > MaxNmiProcessors) cores = MaxNmiProcessors;
    int64_t delay = -100 * 10000;   // 100 ms, relative, in 100-nanosecond units

    _KAFFINITY_EX affinity{};
    KeInitializeAffinityEx(&affinity);
    for (uint32_t core = 0; core < cores; core++)
    {
        KeAddProcessorAffinityEx(&affinity, core);
        __atomic_store_n(&NmiState[core], NmiArmed, __ATOMIC_SEQ_CST);   // from here, the first NMI on this core is recorded
    }
    HalSendNMI(&affinity);

    KeDelayExecutionThread(0, 0, &delay);   // KernelMode, not alertable: let the NMIs finish first

    if (hvci) KeDeregisterNmiCallback(handle);

    // Collect each record once it is complete, then unwind its stack (normal level, so the unwind data can be looked up)
    for (uint32_t core = 0; core < cores; core++)
    {
        if (CollectNmiRecord(core)) WalkNmiStack(&NmiRecords[core]);
    }

    return CountNmiInterruptsOutsideModules();
}
