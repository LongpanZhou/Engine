// User.exe: the command side of the NtCompareSigningLevels channel. Sends one Command to the
// hooked driver (ping, read, write) and prints each response
#include <windows.h>
#include <cstdint>
#include <iostream>
#include "Strings.h"
#include "../Common/Command.h"

typedef NTSTATUS(WINAPI* NtCompareSigningLevels)(uint64_t Secret, void* pCommand);

int main()
{
    int x, y;

    // Load ntdll (not import-linked) and resolve the hooked syscall from it
    HMODULE Dll = LoadLibraryA(Decode(NtdllName).data());
    if (!Dll) return 1;

    auto Func = (NtCompareSigningLevels)GetProcAddress(Dll, Decode(NtCompareSigningLevelsName).data());
    if (!Func) return 1;

    // Command buffer lives past the syscall return
    static Command cmd;
    uint32_t PID = GetCurrentProcessId();
    std::cout << Decode(PidLabel).data() << PID << std::endl;

    uint64_t Response = 0;
    cmd.SrcAddress = &Response;
    cmd.DestAddress = nullptr;
    cmd.SrcPID = PID;
    cmd.DestPID = PID;      // unused by ping, filled for a uniform command
    cmd.OpCode = ping;
    cmd.Size = sizeof(Response);
    Func(CommandSecret, &cmd);
    std::cout << ((Response >> 32) == CommandSecret ? "ping: alive, heartbeat " : "ping: NO ANSWER, ")
              << (Response & 0xFFFFFFFF) << std::endl;

    // Read: the driver copies the target (&y -> DestAddress) into our buffer (&x -> SrcAddress)
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

    // Write: the driver copies our buffer (&x -> SrcAddress) into the target (&y -> DestAddress)
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

    // Keep the console open so the results can be read
    system("pause");

    return NULL;
}
