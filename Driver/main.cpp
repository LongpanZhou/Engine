#include "Func.cpp"
#include "Hooks.cpp"
#include "NMI.cpp"

// The vendor's entry point walks this table to run global constructors. The driver has none that need to run,
// so the table is empty. Add an entry here if a global object with a runtime constructor is introduced
extern "C" void (*__CTOR_LIST__[2])() = {nullptr, nullptr};

win::ntstatus DriverExit(win::DRIVER_OBJECT*)
{
    UnHook();
    IDTUnHook();
    UnlinkMapTable();
    return win::ntstatus::success;
}

win::ntstatus DriverEntry(win::DRIVER_OBJECT* DriverObject, win::UNICODE_STRING*)
{
    // Initialization

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

    // Hook (STATUS_UNSUCCESSFUL if ntoskrnl or the signature cannot be found)
    print(INFO("DriverEntry: step 1 Hook()"));
    if (!Hook())
    {
        print(ERROR("DriverEntry: Hook() failed, returning 0xC0000001"));
        return static_cast<win::ntstatus>(0xC0000001);
    }
    print(INFO("DriverEntry: step 1 Hook() ok"));

    // NMI. If it fails, undo the hook: a driver that fails to load must not leave a hook pointing at its code
    print(INFO("DriverEntry: step 2 IDTHook()"));
    if (!IDTHook())
    {
        print(ERROR("DriverEntry: IDTHook() failed, undoing Hook()"));
        UnHook();
        return static_cast<win::ntstatus>(0xC0000001);
    }
    print(INFO("DriverEntry: step 2 IDTHook() ok"));

    // The dedicated mapping table, if it is enabled (off by default)
    if (MapTableEnabled)
    {
        print(INFO("DriverEntry: step 3 LinkMapTable()"));
        bool Linked = LinkMapTable();
        print(INFO("DriverEntry: step 3 LinkMapTable() returned %u"), (uint32_t) Linked);
    }

    // Set last, once everything is in place, so an unload only undoes what DriverEntry actually did
    DriverObject->DriverUnload = DriverExit;
    print(INFO("DriverEntry: success"));
    return win::ntstatus::success;
}
