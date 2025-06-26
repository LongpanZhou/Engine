#include "Func.cpp"
#include "Hooks.cpp"
#include "NMI.cpp"

ntstatus DriverExit(PDRIVER_OBJECT)
{
    // UnHook();
    return ntstatus::success;
}

extern "C"
ntstatus DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING)
{
    // Initialization
    // DriverObject->DriverUnload = DriverExit;

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

    // Hook
    Hook();

    // NMI
    IDTHook();
    return ntstatus::success;
}
