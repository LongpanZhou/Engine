// User.exe: the user side of the shared-memory channel. Maps
// Global\EngineCiShared and runs ping / read / write against the mapped driver.
// No syscall is hooked and no ntdll export is called.
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <iostream>
#include "../Common/Command.h"

static ChannelHeader* g_Header = nullptr;
static uint8_t* g_Data = nullptr;

static bool Connect()
{
    const wchar_t* Names[3] = { L"Global\\EngineCiShared", L"EngineCiShared", L"Local\\EngineCiShared" };
    DWORD LastError = 0;

    // Session-independent lookup: ask the object manager directly for the
    // candidate paths the driver's context may have used.
    static const wchar_t* NtPaths[3] = {
        L"\\BaseNamedObjects\\EngineCiShared",
        L"\\Sessions\\0\\BaseNamedObjects\\EngineCiShared",
        L"\\Sessions\\1\\BaseNamedObjects\\EngineCiShared",
    };

    struct US { USHORT Length; USHORT MaximumLength; PWSTR Buffer; };
    struct OA { ULONG Length; ULONG Pad; HANDLE Root; US* Name; ULONG Attributes;
                ULONG Pad2; void* Sd; void* Sqos; };

    HMODULE Ntdll = GetModuleHandleW(L"ntdll.dll");
    auto NtOpenSection = (LONG (NTAPI*)(PHANDLE, ACCESS_MASK, OA*))
        GetProcAddress(Ntdll, "NtOpenSection");
    auto NtMapViewOfSection = (LONG (NTAPI*)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T,
        PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG))
        GetProcAddress(Ntdll, "NtMapViewOfSection");

    for (int attempt = 0; attempt < 40; ++attempt)
    {
        for (int i = 0; i < 3; ++i)
        {
            SetLastError(0);
            HANDLE Mapping = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, Names[i]);
            if (Mapping)
            {
                void* View = MapViewOfFile(Mapping, FILE_MAP_ALL_ACCESS, 0, 0, ChannelBytes);
                CloseHandle(Mapping);
                if (View)
                {
                    ChannelHeader* Header = (ChannelHeader*) View;
                    for (int spin = 0; spin < 100 && Header->Magic != ChannelMagic; ++spin) Sleep(10);
                    if (Header->Magic == ChannelMagic)
                    {
                        std::cout << "channel: connected (name index " << i << ")" << std::endl;
                        g_Header = Header;
                        g_Data = (uint8_t*) View + ChannelDataAt;
                        return true;
                    }
                    UnmapViewOfFile(View);
                }
            }
            LastError = GetLastError();
        }

        if (NtOpenSection && NtMapViewOfSection)
        {
            for (int i = 0; i < 3; ++i)
            {
                US Name = {};
                Name.Buffer = (PWSTR) NtPaths[i];
                Name.Length = (USHORT) (wcslen(NtPaths[i]) * sizeof(wchar_t));
                Name.MaximumLength = (USHORT) (Name.Length + sizeof(wchar_t));
                OA Attr = {};
                Attr.Length = sizeof(Attr);
                Attr.Name = &Name;
                Attr.Attributes = 0x40;   // OBJ_CASE_INSENSITIVE

                HANDLE Section = NULL;
                LONG Status = NtOpenSection(&Section, 0x000F001F, &Attr);
                if (Status >= 0)
                {
                    void* Base = nullptr;
                    SIZE_T Size = 0;
                    LONG MapStatus = NtMapViewOfSection(Section, GetCurrentProcess(), &Base, 0, 0,
                                                        nullptr, &Size, 1, 0, PAGE_READWRITE);
                    std::cout << "channel: nt path " << i << " open=0 map=" << MapStatus << std::endl;
                    if (MapStatus >= 0 && ((ChannelHeader*) Base)->Magic == ChannelMagic)
                    {
                        g_Header = (ChannelHeader*) Base;
                        g_Data = (uint8_t*) Base + ChannelDataAt;
                        return true;
                    }
                }
                else if (attempt == 39)
                {
                    std::cout << "channel: nt path " << i << " open status 0x"
                              << std::hex << (ULONG) Status << std::dec << std::endl;
                }
            }
        }
        Sleep(50);
    }

    std::cout << "channel: open failed, last error " << LastError << std::endl;
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
