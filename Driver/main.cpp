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

    // Hook (STATUS_UNSUCCESSFUL if ntoskrnl or the signature cannot be found)
    if (!Hook()) return static_cast<win::ntstatus>(0xC0000001);

    // NMI. If it fails, undo the hook: a driver that fails to load must not leave a hook pointing at its code
    if (!IDTHook())
    {
        UnHook();
        return static_cast<win::ntstatus>(0xC0000001);
    }

    // The dedicated mapping table, if it is enabled (off by default)
    if (MapTableEnabled) LinkMapTable();

    // Set last, once everything is in place, so an unload only undoes what DriverEntry actually did
    DriverObject->DriverUnload = DriverExit;
    return win::ntstatus::success;
}
