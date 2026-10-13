#include "Func.cpp"
#include "Hooks.cpp"
#include "NMI.cpp"

void DriverExit(PDRIVER_OBJECT)
{
    // UnHook();
    IDTUnHook();
}

extern "C"
ntstatus DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING)
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
    if (!Hook()) return static_cast<ntstatus>(0xC0000001);

    // NMI. If it fails, undo the hook: a driver that fails to load must not leave a hook pointing at its code
    if (!IDTHook())
    {
        UnHook();
        return static_cast<ntstatus>(0xC0000001);
    }

    // Set last, once everything is in place, so an unload only undoes what DriverEntry actually did
    DriverObject->DriverUnload = DriverExit;
    return ntstatus::success;
}
