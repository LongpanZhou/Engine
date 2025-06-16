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
    uint32_t SrcPID, DestPID;
    uint32_t Size, OpCode;
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

    // Read
    x = 0, y = 1;
    cmd.SrcAddress = &x;
    cmd.DestAddress = &y;
    cmd.SrcPID = GetCurrentProcessId();
    cmd.DestPID = GetCurrentProcessId();
    cmd.OpCode = read;
    Func(secret,&cmd);
    cmd.Size = sizeof(int);
    std::cout << x << y << std::endl;
    std::cout << &x << &y << std::endl;

    // Write
    x = 0, y = 1;
    cmd.SrcAddress = &x;
    cmd.DestAddress = &y;
    cmd.SrcPID = GetCurrentProcessId();
    cmd.DestPID = GetCurrentProcessId();
    cmd.OpCode = write;
    cmd.Size = sizeof(int);
    Func(secret,&cmd);
    std::cout << x << y << std::endl;
    std::cout << &x << &y << std::endl;
    system("pause");

    return NULL;
}