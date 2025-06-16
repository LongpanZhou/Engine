#include "LazyImport.cpp"
#include "Crypt.cpp"

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
    void* SrcAddress;
    void* DestAddress;
    uint64_t SrcPID;
    uint64_t DestPID;
    uint32_t Size;
    uint32_t OpCode;
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

        cr3 processCR3 = ((_KPROCESS*)EnumerateEProcess(L"", cmd.DestPID))->DirectoryTableBase;
        void* buffer = win::ExAllocatePoolWithTag(pool_type::NonPagedPool, cmd.Size, 0);

        print(INFO("Usermode cr3: %p"), usermodeCR3);
        print(INFO("Process cr3: %p"), processCR3);
        print(INFO("SrcAddress: %p, DestAddress: %p, SrcPID: %p, DestPID: %p, Size: %p, OpCode: %p")
                        ,cmd.SrcAddress,cmd.DestAddress,cmd.SrcPID,cmd.DestPID,cmd.Size,cmd.OpCode);

        switch (cmd.OpCode)
        {
            case read:
                AccessVirtualMemory(cmd.DestAddress,processCR3,buffer,cmd.Size, false);
                AccessVirtualMemory(cmd.SrcAddress,usermodeCR3,buffer,cmd.Size, true);
                break;
            case write:
                AccessVirtualMemory(cmd.SrcAddress,usermodeCR3,buffer,cmd.Size, false);
                AccessVirtualMemory(cmd.DestAddress,processCR3,buffer,cmd.Size, true);
                break;
            default:
                print(WARN("Invalid OpCode %d"), cmd.OpCode);
        }
        win::ExFreePool(buffer);
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