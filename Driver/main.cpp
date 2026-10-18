#include "Func.cpp"
#include "Hooks.cpp"
#include "NMI.cpp"

// Kernel thread routines, declared here because the vendor headers do not include them
extern "C" int32_t PsCreateSystemThread(void **ThreadHandle, uint32_t DesiredAccess, void *ObjectAttributes,
                                        void *ProcessHandle, void *StartupContext, void *StartRoutine);
extern "C" void PsTerminateSystemThread(int32_t ExitStatus);
extern "C" int32_t KeDelayExecutionThread(uint8_t WaitMode, uint8_t Alertable, int64_t *Interval);
extern "C" int32_t ZwClose(void *Handle);

// Set by DriverExit so the heartbeat thread stops itself; the thread checks the flag every cycle
static volatile long HeartbeatStop = 0;

// Prints the stub's counters every 2 s. These lines ARE the bug locator: if they keep streaming in the
// debugger log while something else appears stuck, the kernel is alive and the stop is elsewhere (for
// example the tool's own worker waiting for a swallowed NMI record); if they stop, the kernel itself froze
// between load and stop, narrowing the window to the last printed step
static void HeartbeatThread(void *)
{
    while (!HeartbeatStop)
    {
        print(INFO("Heartbeat: nmi passes=%llu claims=%llu"),
              __atomic_load_n(&NmiPasses, __ATOMIC_SEQ_CST),
              __atomic_load_n(&NmiClaims, __ATOMIC_SEQ_CST));

        // Relative, in 100-nanosecond units: negative is "wait this long"
        int64_t Wait = -2 * 1000 * 1000 * 10LL;
        KeDelayExecutionThread(0, 0, &Wait);
    }

    PsTerminateSystemThread(0);
}

// The vendor's entry point walks this table to run global constructors. The driver has none that need to run,
// so the table is empty. Add an entry here if a global object with a runtime constructor is introduced
extern "C" void (*__CTOR_LIST__[2])() = {nullptr, nullptr};

win::ntstatus DriverExit(win::DRIVER_OBJECT*)
{
    // Unhook the command channel and free the mapping table first. The IDT gate is restored last: while this
    // callback runs, the image is still alive, and an NMI landing in it hides better through our claim stub
    // than it would record through the original handler. Restoring is safe this late because the image is
    // only freed after this callback returns, inside Mm's unload path
    UnHook();
    UnlinkMapTable();
    UnhideDriverObject();
    IDTUnHook();
    return win::ntstatus::success;
}

win::ntstatus DriverEntry(win::DRIVER_OBJECT* DriverObject, win::UNICODE_STRING*)
{
    // Functions
    // _EPROCESS* pEProcess = EnumerateEProcess(L"notepad.exe");
    // void* pModule = EnumerateModuleBaseAddress(pEProcess, L"ntdll.dll");
    // print(INFO("Module Address: %p"), pModule);
    //
    // void *tmp = EnumerateKProcess(L"ntoskrnl.exe");
    // AccessVirtualMemory(tmp, 0x1ad000, &tmp, sizeof(tmp));
    // print(INFO("KProcess Address: %p"), tmp);
    //
    // GetNtoskrnl();

    // Encryption
    // constexpr auto Cstr = Encode("Hello World");
    // print(INFO("Encoded: %s"), Cstr.data());
    // print(INFO("Decoded: %s"), Decode(Cstr).data());
    //
    // constexpr auto Wstr = Encode(L"Hello World");
    // print(INFO("Encoded: %ws"), Wstr.data());
    // print(INFO("Decoded: %ws"), Decode(Wstr).data());

    print(INFO("DriverEntry: start, DriverObject %p"), (void *) DriverObject);

    // Hook (STATUS_UNSUCCESSFUL if ntoskrnl or the signature cannot be found). NO_HOOK test builds skip it: the hook
    // writes a function pointer inside ntoskrnl's SeCiCallbacks table, which PatchGuard checks (bugcheck 0x109)
#ifndef NO_HOOK
    print(INFO("DriverEntry: step 1 Hook()"));
    if (!Hook())
    {
        print(ERROR("DriverEntry: Hook() failed, returning 0xC0000001"));
        return static_cast<win::ntstatus>(0xC0000001);
    }
    print(INFO("DriverEntry: step 1 Hook() ok"));
#else
    print(INFO("DriverEntry: NO_HOOK test build, NtCompareSigningLevels not hooked"));
#endif

    // The dedicated mapping table, if it is enabled (off by default)
    if (MapTableEnabled)
    {
        print(INFO("DriverEntry: step 2 LinkMapTable()"));
        bool Linked = LinkMapTable();
        print(INFO("DriverEntry: step 2 LinkMapTable() returned %u"), (uint32_t) Linked);
    }

    // Set before the unlink, so an unload only undoes what DriverEntry actually did. A manually mapped driver
    // (kdmapper) gets a NULL DriverObject and no unload callback, so only set it when there is one
    if (DriverObject) DriverObject->DriverUnload = DriverExit;

    // Unlink the driver from PsLoadedModuleList, so module walks no longer report it. A manually mapped driver
    // (kdmapper) has no loader entry, so this reports and skips
    print(INFO("DriverEntry: step 3 UnlinkDriverFromModuleList()"));
    if (DriverObject) UnlinkDriverFromModuleList(DriverObject);

    // Publish this driver's image range for the NMI hide stub in NMI.cpp. The loader entry is still readable
    // after the unlink (only its list links were cut), so the range comes from the same entry that was walked
    if (DriverObject && DriverObject->DriverSection)
    {
        auto *Entry = (_KLDR_DATA_TABLE_ENTRY *) DriverObject->DriverSection;
        HideStart = (address) Entry->DllBase;
        HideEnd = HideStart + Entry->SizeOfImage;
        print(INFO("DriverEntry: hide range %p-%p"), (void *) HideStart, (void *) HideEnd);
    }

    // Watch gate 2 (NMI): any NMI that lands inside this driver's image is claimed by the stub and returned to
    // the interrupted code directly, so NMI callbacks never record this driver's RIPs
    print(INFO("DriverEntry: step 4 IDTHook()"));
    if (!IDTHook()) print(WARN("DriverEntry: IDTHook() failed, NMI callbacks will record real RIPs"));

    // Hide the driver object itself, so walks of the \Driver directory (the reference tool's "validate driver
    // objects" check) see neither this driver's module nor its object, and flag nothing as invalid
    if (DriverObject)
    {
        print(INFO("DriverEntry: step 5 HideDriverObject()"));
        HideDriverObject(DriverObject);
    }

    // Heartbeat: a system thread printing the stub's counters every 2 s. If it stops while the VM misbehaves,
    // the kernel died at that point; if it keeps printing, the kernel is alive and the stop is elsewhere.
    // Started last, so an earlier step can fail cleanly without a thread to stop
    HeartbeatStop = 0;
    void *HeartbeatHandle = nullptr;
    if (PsCreateSystemThread(&HeartbeatHandle, 0x001FFFFF, nullptr, nullptr, nullptr, (void *) HeartbeatThread) < 0)
        print(WARN("DriverEntry: heartbeat thread did not start"));
    else
    {
        // The thread runs on its own; only the handle is needed to release the object reference
        ZwClose(HeartbeatHandle);
        print(INFO("DriverEntry: heartbeat running"));
    }

    print(INFO("DriverEntry: success"));
    return win::ntstatus::success;
}
