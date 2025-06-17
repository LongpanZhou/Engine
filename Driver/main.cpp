#include "Func.cpp"
#include "Hooks.cpp"
#include "Crypt.cpp"

ntstatus DriverExit(PDRIVER_OBJECT)
{
    UnHook();
    return ntstatus::success;
}

extern "C"
ntstatus DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING)
{
    // Initialization
    // DriverObject->DriverUnload = DriverExit;

    // Main
    // _EPROCESS* pEProcess = EnumerateEProcess(L"notepad.exe");
    // void* pModule = EnumerateModuleBaseAddress(pEProcess, L"ntdll.dll");
    // print(INFO("Module Address: %p"), pModule);
    //
    // void *tmp = EnumerateKProcess(L"ntoskrnl.exe");
    // auto t = AccessVirtualMemory<void *>(tmp, 0x1ad000);

    // Encryption
    // print(INFO("Seed: %p"), SEED);
    // auto str = ENCRYPT_STR("Hello world!");
    // print(INFO("Encrypt: %s"),str.data);
    // print(INFO("Decrypt: %s"),str.decrypt());
    //
    // auto wstr = ENCRYPT_WSTR(L"Hello world!");
    // print(INFO("Encrypt: %ws"),wstr.data);
    // print(INFO("Decrypt: %ws"),wstr.decrypt());

    Hook();
    return ntstatus::success;
}