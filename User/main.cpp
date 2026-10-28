// User.exe: the user side of the shared-memory channel. Maps
// Global\EngineCiShared and runs ping / read / write against the mapped driver.
// No syscall is hooked and no ntdll export is called.
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <iostream>
#include "../Common/Command.h"

static ChannelHeader* g_Header = nullptr;
static uint8_t* g_Data = nullptr;

static bool Connect()
{
    for (int attempt = 0; attempt < 100; ++attempt)
    {
        HANDLE Mapping = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, L"Global\\EngineCiShared");
        if (Mapping)
        {
            void* View = MapViewOfFile(Mapping, FILE_MAP_ALL_ACCESS, 0, 0, ChannelBytes);
            CloseHandle(Mapping);
            if (View)
            {
                ChannelHeader* Header = (ChannelHeader*) View;
                if (Header->Magic == ChannelMagic)
                {
                    g_Header = Header;
                    g_Data = (uint8_t*) View + ChannelDataAt;
                    return true;
                }
                UnmapViewOfFile(View);
            }
        }
        Sleep(50);
    }
    return false;
}

// Publishes one request and waits for the driver to acknowledge that sequence
static bool Submit(uint32_t TimeoutMs)
{
    const uint32_t Sequence = g_Header->Sequence + 1;
    MemoryBarrier();
    g_Header->Sequence = Sequence;
    MemoryBarrier();

    for (uint32_t i = 0; i < TimeoutMs; ++i)
    {
        if (g_Header->Ack == Sequence)
        {
            MemoryBarrier();
            return true;
        }
        Sleep(1);
    }
    return false;
}

static void Request(uint32_t Op, uint32_t Pid, uint64_t Remote, uint32_t Size)
{
    g_Header->Op = Op;
    g_Header->TargetPid = Pid;
    g_Header->RemoteAddress = Remote;
    g_Header->Size = Size;
}

int main()
{
    if (!Connect())
    {
        std::cout << "channel: driver not reachable (mapped and running?)" << std::endl;
        return 1;
    }
    std::cout << "channel: connected" << std::endl;

    Request(op_ping, 0, 0, 0);
    if (!Submit(2000))
    {
        std::cout << "ping: timeout" << std::endl;
        return 1;
    }
    std::cout << "ping: status=" << std::hex << g_Header->Status << std::dec
              << " heartbeat=" << g_Header->Heartbeat << std::endl;

    // read: the driver copies the target VA into the shared data area
    int x = 9999, y = 1111;
    Request(op_read, GetCurrentProcessId(), (uint64_t) (uintptr_t) &y, sizeof(int));
    if (!Submit(2000))
    {
        std::cout << "read: timeout" << std::endl;
        return 1;
    }
    memcpy(&x, g_Data, sizeof(int));
    std::cout << "read: status=" << std::hex << g_Header->Status << std::dec
              << " x=" << x << " y=" << y << std::endl;

    // write: the driver copies the shared data area into the target VA
    x = 4242;
    memcpy(g_Data, &x, sizeof(int));
    Request(op_write, GetCurrentProcessId(), (uint64_t) (uintptr_t) &y, sizeof(int));
    if (!Submit(2000))
    {
        std::cout << "write: timeout" << std::endl;
        return 1;
    }
    std::cout << "write: status=" << std::hex << g_Header->Status << std::dec
              << " x=" << x << " y=" << y << std::endl;

    std::cout << "channel: done, press enter to exit" << std::endl;
    std::cin.get();
    return 0;
}
