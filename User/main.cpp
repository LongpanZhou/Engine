#include <iostream>
#include <windows.h>
#include "Strings.h"
#include "../Common/Command.h"

typedef NTSTATUS(WINAPI* NtCompareSigningLevels)(uint64_t Secret, void* pCommand);

int main()
{
    int x,y;
    // Load lib
    HMODULE Dll = LoadLibraryA(Decode(NtdllName).data());
    if (!Dll) return NULL;

    // Load func
    auto Func = (NtCompareSigningLevels)GetProcAddress(Dll, Decode(NtCompareSigningLevelsName).data());
    if (!Func) return NULL;

    // Call func
    static Command cmd;
    uint32_t PID = GetCurrentProcessId();
    std::cout << Decode(PidLabel).data() << PID << std::endl;

    // Read
    x = 9999, y = 1111;
    cmd.SrcAddress = &x;
    cmd.DestAddress = &y;
    cmd.SrcPID = PID;
    cmd.DestPID = PID;
    cmd.OpCode = read;
    cmd.Size = sizeof(int);
    Func(CommandSecret,&cmd);
    std::cout << x << y << std::endl;
    std::cout << &x << &y << std::endl;

    // Write
    x = 9999, y = 1111;
    cmd.SrcAddress = &x;
    cmd.DestAddress = &y;
    cmd.SrcPID = PID;
    cmd.DestPID = PID;
    cmd.OpCode = write;
    cmd.Size = sizeof(int);
    Func(CommandSecret,&cmd);
    std::cout << x << y << std::endl;
    std::cout << &x << &y << std::endl;

    // Scan for NMIs that interrupted code outside every kernel module. The driver writes the count to Suspicious
    uint32_t Suspicious = 0;
    cmd.DestAddress = &Suspicious;
    cmd.OpCode = scan;
    Func(CommandSecret,&cmd);
    std::cout << Decode(ScanLabel).data() << Suspicious << std::endl;

    // Stay alive so the driver can find this process by name, but sleep between calls instead of spinning a core
    cmd.OpCode = -1;
    while (true)
    {
        Func(CommandSecret,&cmd);
        Sleep(1000);
    }

    return NULL;
}