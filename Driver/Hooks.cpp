#include "../Common/Command.h"

// NtCompareSigningLevels: Signature, UserExeName and PageSectionName are in Strings.h
using func_type = uint64_t (__fastcall*)(uint64_t, Command *);
func_type OriginalFunc;
address *pData;

// Copies Size bytes between two address spaces through a fixed-size stack buffer, so the kernel stack
// never depends on the Size the caller sent
bool CopyVirtualMemory(address SrcAddress, cr3 SrcCR3, address DestAddress, cr3 DestCR3, uint32_t Size)
{
    char buffer[0x400];
    while (Size)
    {
        uint32_t Chunk = Size < sizeof(buffer) ? Size : sizeof(buffer);
        if (!AccessVirtualMemory(SrcAddress, SrcCR3, (void *) buffer, Chunk, false)) return false;
        if (!AccessVirtualMemory(DestAddress, DestCR3, (void *) buffer, Chunk, true)) return false;

        SrcAddress = address((uint64_t) SrcAddress + Chunk);
        DestAddress = address((uint64_t) DestAddress + Chunk);
        Size -= Chunk;
    }
    return true;
}

// Defined in NMI.cpp, which is included after this file
uint32_t RunNmiScan();

// Runs one command from User.exe. A command that cannot be read or resolved is dropped, and the caller
// still goes on to the original function
void HandleCommand(Command *pCommand)
{
    // Local, not static: a shared command would be overwritten by concurrent callers
    Command cmd;

    _EPROCESS *pUser = EnumerateEProcess(Decode(UserExeName).data());
    if (!pUser) return;
    cr3 usermodeCR3 = ((_KPROCESS *) pUser)->DirectoryTableBase;

    // A command that cannot be read is dropped, not replayed from an earlier call
    if (!AccessVirtualMemory(pCommand, usermodeCR3, &cmd, sizeof(cmd))) return;

    _EPROCESS *pProcess = EnumerateEProcess(L"", cmd.DestPID);
    if (!pProcess) return;
    cr3 processCR3 = ((_KPROCESS *) pProcess)->DirectoryTableBase;

    print(INFO("Usermode cr3: %p"), usermodeCR3);
    print(INFO("Process cr3: %p"), processCR3);
    print(INFO("SrcAddress: %p, DestAddress: %p, SrcPID: %p, DestPID: %p, Size: %p, OpCode: %p")
          , cmd.SrcAddress, cmd.DestAddress, cmd.SrcPID, cmd.DestPID, cmd.Size, cmd.OpCode);

    switch (cmd.OpCode)
    {
        case read:
            if (!CopyVirtualMemory(cmd.DestAddress, processCR3, cmd.SrcAddress, usermodeCR3, cmd.Size))
                print(WARN("Read failed"));
            break;
        case write:
            if (!CopyVirtualMemory(cmd.SrcAddress, usermodeCR3, cmd.DestAddress, processCR3, cmd.Size))
                print(WARN("Write failed"));
            break;
        case scan:
        {
            uint32_t Suspicious = RunNmiScan();
            if (!AccessVirtualMemory(cmd.DestAddress, usermodeCR3, &Suspicious, sizeof(Suspicious), true))
                print(WARN("Scan result not written"));
            break;
        }
        default:
            print(WARN("Invalid OpCode %d"), cmd.OpCode);
    }
}

// Hook Func
uint64_t __fastcall Func(uint64_t Secret, Command *pCommand)
{
    // I see dead people
    if (Secret == CommandSecret) HandleCommand(pCommand);

    // Return original, called with the same arguments it was called with
    return OriginalFunc(Secret, pCommand);
}

// Hook
bool Hook()
{
    // Check if dataptr empty
    if (pData) return true;

    // Find the signature in the PAGE section of ntoskrnl; either step can fail
    address ntoskrnl = GetNtoskrnl();
    if (!ntoskrnl) return false;
    address match = SectionScan(ntoskrnl, Decode(PageSectionName).data(), Decode(Signature).data());
    if (!match) return false;

    // Data ptr swap. The displacement is signed: a global placed before the instruction has a negative offset
    address instruction = match + 0x3;
    pData = (address *) (instruction + 0x4 + *(int32_t *) instruction);

    // Exchange
    OriginalFunc = (func_type) xchg_ptr(pData, &Func);
    print(INFO("HOOKED"));
    return true;
}

// UnHook
void UnHook()
{
    // Check if dataptr exist
    if (!pData) return;

    // Exchange
    xchg_ptr(pData, OriginalFunc);
    print(INFO("UNHOOKED"));
}

/*
    ALWAYS_INLINE arch::address xchg_ptr(arch::address target, arch::address value) {
        arch::address old = value;
        asm volatile ("xchg %0, (%1)"
                       : "=r"(old)
                       : "r"(target), "0"(value)
                       : "memory");
        return old;
    }
 */
