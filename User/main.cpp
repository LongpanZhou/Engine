#include <windows.h>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>
#include "Strings.h"
#include "../Common/Command.h"

typedef NTSTATUS(WINAPI* NtCompareSigningLevels)(uint64_t Secret, void* pCommand);

// ---------------------------------------------------------------------------
// HVCI state, read from the registry's storage file. HKLM\SYSTEM is backed by
// C:\Windows\System32\config\SYSTEM in the "regf" hive format: bins of cells, addressed by 32-bit
// indexes from the data area at 0x1000. Record offsets are the fixed ones of this Windows build
// (identical to the kernel's in-memory CM_KEY_NODE/CM_KEY_VALUE layout). No Windows API: plain CRT
// file reading only
//
// Path walked: root -> Select -> (Current: ControlSet number)
//                     -> ControlSet00N -> Control -> CI -> State -> (HVCIEnabled: DWORD)
// ---------------------------------------------------------------------------

static std::vector<uint8_t> HiveData;
static const size_t HiveDataBase = 0x1000;

static const uint8_t *Cell(uint32_t Idx)
{
    size_t Off = HiveDataBase + (size_t) Idx;
    if (Off + 4 > HiveData.size()) return nullptr;
    int32_t Size = *(const int32_t *)(HiveData.data() + Off);
    if (Size <= 0 || Off + 4 + Size > HiveData.size()) return nullptr;
    return HiveData.data() + Off + 4;
}

// The inline name of a key/value record may be stored as single bytes or UTF-16; either is compared
// against Name
static bool NameIs(const uint8_t *R, size_t LenOff, size_t NameOff, const char *Name)
{
    uint16_t Len = *(const uint16_t *)(R + LenOff);
    size_t n = strlen(Name);
    if (Len != n) return false;

    size_t i = 0;
    while (i < n && R[NameOff + i] == (uint8_t) Name[i] && R[NameOff + i] >= 0x20 && R[NameOff + i] <= 0x7E) ++i;
    if (i == n) return true;

    // UTF-16 form: a zero byte between the characters
    i = 0;
    while (i < n && R[NameOff + i * 2] == (uint8_t) Name[i] && R[NameOff + i * 2 + 1] == 0) ++i;
    return i == n;
}

// Key ("nk") record: 0x00 'nk', 0x18 subkey count, 0x1C subkey list, 0x28 value count, 0x2C value
// list, 0x48 name length, 0x4C name
static bool ChildCell(uint32_t Key, const char *Name, uint32_t &Out)
{
    const uint8_t *R = Cell(Key);
    if (!R || R[0] != 'n' || R[1] != 'k') return false;
    uint32_t Count = *(const uint32_t *)(R + 0x18);
    uint32_t List = *(const uint32_t *)(R + 0x1C);
    if (Count == 0 || List == 0) return false;

    const uint8_t *L = Cell(List);
    if (!L || L[0] != 'l') return false;

    // "lf"/"lh": (hash, index) pairs; "li": indexes of keys; "ri": indexes of lists, followed once
    std::vector<uint32_t> Entries;
    uint16_t C = *(const uint16_t *)(L + 2);
    if (L[1] == 'f' || L[1] == 'h' || L[1] == 'i')
    {
        if (C != Count) return false;
        size_t Step = L[1] == 'i' ? 4 : 8;
        if (4 + (size_t) C * Step > HiveData.size() - (size_t) (L - HiveData.data())) return false;
        for (uint16_t i = 0; i < C; ++i)
        {
            uint32_t Cell = *(const uint32_t *)(L + 4 + (size_t) i * Step + (L[1] == 'i' ? 0 : 4));
            if (Cell) Entries.push_back(Cell);
        }
    }
    else if (L[1] == 'r')
    {
        if (4 + (size_t) C * 4 > HiveData.size() - (size_t) (L - HiveData.data())) return false;
        for (uint16_t i = 0; i < C; ++i)
        {
            uint32_t Sub = *(const uint32_t *)(L + 4 + (size_t) i * 4);
            const uint8_t *S = Cell(Sub);
            if (!S || S[0] != 'l') continue;
            uint16_t SC = *(const uint16_t *)(S + 2);
            for (uint16_t j = 0; j < SC; ++j)
            {
                uint32_t Cell = *(const uint32_t *)(S + 4 + (size_t) j * 4);
                if (Cell) Entries.push_back(Cell);
            }
        }
    }
    else return false;

    for (uint32_t E : Entries)
    {
        const uint8_t *K = Cell(E);
        if (K && K[0] == 'n' && K[1] == 'k' && NameIs(K, 0x48, 0x4C, Name))
        {
            Out = E;
            return true;
        }
    }
    return false;
}

// Value ("vk") record: 0x00 'vk', 0x06 name length, 0x08 data size (0x80000000 = inline, the data
// is the word at 0x0C itself), 0x0C data cell, 0x10 type, 0x12 name
static bool DwordOf(uint32_t Key, const char *Name, uint32_t &Out)
{
    const uint8_t *R = Cell(Key);
    if (!R || R[0] != 'n' || R[1] != 'k') return false;
    uint32_t Count = *(const uint32_t *)(R + 0x28);
    uint32_t List = *(const uint32_t *)(R + 0x2C);
    if (Count == 0 || List == 0) return false;

    const uint8_t *V = Cell(List);
    if (!V || *(const uint32_t *) V != Count) return false;

    for (uint32_t i = 0; i < Count; ++i)
    {
        uint32_t Entry = *(const uint32_t *)(V + 4 + (size_t) i * 4);
        const uint8_t *K = Cell(Entry);
        if (!K || K[0] != 'v' || K[1] != 'k') return false;
        if (!NameIs(K, 0x06, 0x12, Name)) continue;

        uint32_t Type = *(const uint32_t *)(K + 0x10);
        uint32_t Size = *(const uint32_t *)(K + 0x08);
        if (Type != 4) return false;   // REG_DWORD

        if (Size & 0x80000000)
        {
            Out = *(const uint32_t *)(K + 0x0C);   // inline: data is the word itself
            return true;
        }

        uint32_t DataCell = *(const uint32_t *)(K + 0x0C);
        // The data cell carries its own size word, the DWORD is right behind it
        Out = *(const uint32_t *)(HiveData.data() + HiveDataBase + (size_t) DataCell + 4);
        return true;
    }
    return false;
}

// Reads HVCI ("Memory integrity") state. The driver must not use any Windows API, so the state is
// read where the registry keeps it: inside the SYSTEM hive file that backs HKLM\SYSTEM. Same
// location the systems viewers use: ...\\Control\\CI\\State, value HVCIEnabled
bool ReadHvciEnabled()
{
    HiveData.clear();
    std::ifstream File(Decode(SystemHivePath).data(), std::ios::binary);
    if (!File)
    {
        std::cout << Decode(HvciLabel).data() << "SYSTEM hive not readable" << std::endl;
        return false;
    }
    HiveData.assign((std::istreambuf_iterator<char>(File)), std::istreambuf_iterator<char>());
    if (HiveData.size() < HiveDataBase + 4 || memcmp(HiveData.data(), "regf", 4))
    {
        std::cout << Decode(HvciLabel).data() << "not a registry hive" << std::endl;
        return false;
    }

    uint32_t RootCell = *(const uint32_t *)(HiveData.data() + 0x24);

    uint32_t SelectCell = 0;
    if (!ChildCell(RootCell, "Select", SelectCell))
    {
        std::cout << Decode(HvciLabel).data() << "Select key not found" << std::endl;
        return false;
    }

    uint32_t CurrentSet = 0;
    if (!DwordOf(SelectCell, "Current", CurrentSet))
    {
        std::cout << Decode(HvciLabel).data() << "Select\\Current not found" << std::endl;
        return false;
    }

    std::string SetName = CurrentSet >= 100 ? "ControlSet" + std::to_string(CurrentSet) :
                          CurrentSet >= 10 ? "ControlSet0" + std::to_string(CurrentSet) :
                                            "ControlSet00" + std::to_string(CurrentSet);

    uint32_t SetCell = 0, ControlCell = 0, CiCell = 0, StateCell = 0, Hvci = 0;
    if (!ChildCell(RootCell, SetName.c_str(), SetCell) ||
        !ChildCell(SetCell, "Control", ControlCell) ||
        !ChildCell(ControlCell, "CI", CiCell) ||
        !ChildCell(CiCell, "State", StateCell) ||
        !DwordOf(StateCell, "HVCIEnabled", Hvci))
    {
        std::cout << Decode(HvciLabel).data() << "state path not found (" << SetName
                  << "\\Control\\CI\\State)" << std::endl;
        return false;
    }

    return Hvci != 0;
}

int main(int argc, char *argv[])
{
    // HVCI ("Memory integrity") state, read straight out of the registry's storage file
    std::cout << Decode(HvciLabel).data() << (ReadHvciEnabled() ? "on" : "off") << std::endl;

    if (argc > 1 && argv[1][0] == '-')
        return 0;   // parse-only mode: print the HVCI line above and leave

    int x, y;

    // Load lib
    HMODULE Dll = LoadLibraryA(Decode(NtdllName).data());
    if (!Dll) return 1;

    // Load func
    auto Func = (NtCompareSigningLevels)GetProcAddress(Dll, Decode(NtCompareSigningLevelsName).data());
    if (!Func) return 1;

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

    // Stay alive so the driver can find this process by name, but sleep between calls instead of spinning a core
    cmd.OpCode = -1;
    while (true)
    {
        Func(CommandSecret,&cmd);
        Sleep(1000);
    }

    return NULL;
}
