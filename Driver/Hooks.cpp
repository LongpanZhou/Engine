#include "../Common/Command.h"

// NtCompareSigningLevels: Signature, UserExeName and PageSectionName are in Strings.h
using func_type = uint64_t (__fastcall*)(uint64_t, Command *);
func_type OriginalFunc;
address *pData;

// PID of User.exe as last found. It is only a hint: FindUserProcess checks the process it names before using it
uint64_t UserExePid = -1;

// Finds User.exe. The cached PID is tried first: the walk compares PIDs only, and the name is checked on the one process
// found. If that process is not User.exe (the PID was reused, or User.exe was restarted), the full name search runs
_EPROCESS *FindUserProcess()
{
    auto UserName = Decode(UserExeName);

    uint64_t Pid = __atomic_load_n(&UserExePid, __ATOMIC_SEQ_CST);
    if (Pid != (uint64_t) -1)
    {
        _EPROCESS *pCached = EnumerateEProcess(L"", Pid);
        if (pCached && ProcessHasName(pCached, UserName.data())) return pCached;
    }

    _EPROCESS *pUser = EnumerateEProcess(UserName.data());
    if (pUser) __atomic_store_n(&UserExePid, (uint64_t) pUser->UniqueProcessId, __ATOMIC_SEQ_CST);
    return pUser;
}

// Runs one command from User.exe. A command that cannot be read or resolved is dropped, and the caller
// still goes on to the original function
void HandleCommand(Command *pCommand)
{
    // Local, not static: a shared command would be overwritten by concurrent callers
    Command cmd;

    _EPROCESS *pUser = FindUserProcess();
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
    print(INFO("Hook: looking up ntoskrnl"));
    address ntoskrnl = GetNtoskrnl();
    if (!ntoskrnl)
    {
        print(ERROR("Hook: ntoskrnl not found"));
        return false;
    }
    print(INFO("Hook: ntoskrnl base %p, searching PAGE section for the signature"), (void *) ntoskrnl);
    address match = SectionScan(ntoskrnl, Decode(PageSectionName).data(), Decode(Signature).data());
    if (!match)
    {
        print(ERROR("Hook: signature not found in PAGE section"));
        return false;
    }
    print(INFO("Hook: signature match at %p"), (void *) match);

    // Data ptr swap. The displacement is signed: a global placed before the instruction has a negative offset
    address instruction = match + 0x3;
    pData = (address *) (instruction + 0x4 + *(int32_t *) instruction);
    print(INFO("Hook: target pointer at %p, current value %p"), (void *) pData, (void *) *(uint64_t *) pData);

    // Exchange
    OriginalFunc = (func_type) __atomic_exchange_n((uint64_t *) pData, (uint64_t) &Func, __ATOMIC_SEQ_CST);
    print(INFO("HOOKED"));
    return true;
}

// UnHook
void UnHook()
{
    // Check if dataptr exist
    if (!pData) return;

    // Exchange
    __atomic_exchange_n((uint64_t *) pData, (uint64_t) OriginalFunc, __ATOMIC_SEQ_CST);
    print(INFO("UNHOOKED"));
}
