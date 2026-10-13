#include <iostream>
#include <windows.h>
#include "Strings.h"

#define secret 0xFFFFFFFF

typedef NTSTATUS(WINAPI* NtCompareSigningLevels)(uint64_t Secret, void* pCommand);

enum
{
    read,
    write,
};

// Must match Driver/Hooks.cpp's Command byte for byte (32 bytes, PIDs are 32-bit)
struct Command
{
    void* SrcAddress;
    void* DestAddress;
    uint32_t SrcPID;
    uint32_t DestPID;
    uint32_t Size;
    uint32_t OpCode;
} __attribute__((packed));

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
    Func(secret,&cmd);
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
    Func(secret,&cmd);
    std::cout << x << y << std::endl;
    std::cout << &x << &y << std::endl;

    // Stay alive so the driver can find this process by name, but sleep between calls instead of spinning a core
    cmd.OpCode = -1;
    while (true)
    {
        Func(secret,&cmd);
        Sleep(1000);
    }

    return NULL;
}