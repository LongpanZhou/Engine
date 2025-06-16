// #include "LazyImport.cpp"
//
// typedef void (__fastcall *KeStackAttachProcess_t)(address process_address, std::uint64_t* apc_state);
// typedef void (__fastcall *KeUnstackDetachProcess_t)(std::uint64_t* apc_state);
//
// KeStackAttachProcess_t KeStackAttachProcess;
// KeUnstackDetachProcess_t KeUnstackDetachProcess;
//
// _KPROCESS *KProcess;
// _KAPC_STATE KapcState;

enum
{
    read,
    write,
};

struct Command
{
    address SrcAddress;
    address DestAddress;
    uint32_t SrcPID, DestPID;
    uint32_t Size, OpCode;
};

// NtCompareSigningLevels
using func_type = uint64_t (__fastcall*)();
func_type OriginalFunc;

address *pData;
char Signature[] = "4C 8B 05 ? ? ? ? 33 C0 4D 85 C0 74 ? 49 8B C0 E8 ? ? ? ? F7 D8";

uint64_t __fastcall Func(uint64_t Secret, Command* pCommand)
{
    static Command cmd;

    // I see dead people
    if (Secret == 0xFFFFFFFF)
    {
        cr3 usermodeCR3 = ((_KPROCESS*)EnumerateEProcess(L"User.exe"))->DirectoryTableBase;
        AccessVirtualMemory(pCommand,usermodeCR3,&cmd,sizeof(cmd));
        address process = EnumerateEProcess(L"", cmd.DestPID);
        cr3 tmp = ((_KPROCESS*)process)->DirectoryTableBase;

        print(INFO("Usermode address: %p"), process);
        print(INFO("Usermode cr3: %p"), tmp);

        switch (cmd.OpCode)
        {
            case read:
                AccessVirtualMemory(cmd.SrcAddress, tmp, cmd.DestAddress, cmd.Size);
                break;
            case write:
                AccessVirtualMemory(cmd.SrcAddress, tmp, cmd.DestAddress, cmd.Size);
                break;
            default:
                print(WARN("Invalid OpCode %d"), cmd.OpCode);
        }
    }

    // Return original
    return OriginalFunc();
}

void Hook()
{
    // Import functions
    // address ntoskrnl = EnumerateKProcess(L"ntoskrnl.exe");
    // KeStackAttachProcess = (KeStackAttachProcess_t)FindFuncExports(ntoskrnl, "KeStackAttachProcess");
    // KeUnstackDetachProcess = (KeUnstackDetachProcess_t)FindFuncExports(ntoskrnl, "KeUnstackDetachProcess");

    // Data ptr swap
    address instruction = (uint64_t)SectionScan(L"", L"ntoskrnl.exe", "PAGE", Signature) + 0x3;
    pData = (address *) (instruction + 0x4 + *(uint32_t *) instruction);

    // Exchange
    OriginalFunc = (func_type)xchg_ptr(pData, &Func);
    print(INFO("HOOKED"));
}

void UnHook()
{
    // Check if dataptr exist
    if (!pData) return;

    // Exchange
    xchg_ptr(pData, OriginalFunc);
    print(INFO("UNHOOKED"));
}

/*
    extern "C"
    {
        void KeStackAttachProcess(arch::address process_address, std::uint64_t* apc_state);

        void KeUnstackDetachProcess(std::uint64_t* apc_state);
    }

    ALWAYS_INLINE arch::address xchg_ptr(arch::address target, arch::address value) {
        arch::address old = value;
        asm volatile ("xchg %0, (%1)"
                       : "=r"(old)
                       : "r"(target), "0"(value)
                       : "memory");
        return old;
    }
 */