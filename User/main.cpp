#include <iostream>
#include <windows.h>

#define secret 0xFFFFFFFF

typedef NTSTATUS(WINAPI* NtCompareSigningLevels)(uint64_t Secret, void* pCommand);

enum
{
    read,
    write,
};

struct Command
{
    void* SrcAddress;
    void* DestAddress;
    uint64_t SrcPID;
    uint64_t DestPID;
    uint32_t Size;
    uint32_t OpCode;
};

int main()
{
    int x,y;
    // Load lib
    HMODULE Dll = LoadLibraryA("ntdll.dll");
    if (!Dll) return NULL;

    // Load func
    auto Func = (NtCompareSigningLevels)GetProcAddress(Dll, "NtCompareSigningLevels");
    if (!Func) return NULL;

    // Call func
    static Command cmd;
    uint32_t PID = GetCurrentProcessId();
    std::cout << "PID: " << PID << std::endl;

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

    cmd.OpCode = -1;
    while (true)
    {
        Func(secret,&cmd);
    }

    return NULL;
}