#include "Lib/structs.h"
#include "Lib/utils.h"
#include "Mem.cpp"

address EnumerateModuleBaseAddress(_EPROCESS *pEProcess, const wchar_t *ModuleName)
{
    // Check if EProcess is empty
    if (!pEProcess) return nullptr;
    print(INFO("EProcess Address: %p"), pEProcess);
    print(INFO("Target Module Name: %ws"), ModuleName);

    // Get KProcess n CR3
    _KPROCESS *pKProcess = (_KPROCESS *) pEProcess;
    cr3 CR3 = {pKProcess->DirectoryTableBase};
    print(INFO("KProcess Address: %p"), pKProcess);
    print(INFO("KProcess CR3: %p"), CR3);

    // Get PEB (Process Environment Block)
    _PEB *pPeb = pEProcess->Peb;
    if (!pPeb) return nullptr;

    // Read LDR (Loader Dynamic Resources)
    _PEB_LDR_DATA *pLdr;
    AccessVirtualMemory(&pPeb->Ldr, CR3, &pLdr, sizeof(_PEB_LDR_DATA));
    if (!pLdr) return nullptr;

    // Init variables for loop
    wchar_t pBuffer[256];
    _LIST_ENTRY moduleList;
    AccessVirtualMemory(&pLdr->InLoadOrderModuleList, CR3, &moduleList, sizeof(_LIST_ENTRY));

    _LDR_DATA_TABLE_ENTRY entry;
    UNICODE_STRING moduleName;

    _LIST_ENTRY *pHead = moduleList.Flink;
    _LIST_ENTRY *pCurrent = moduleList.Flink;

    // Loop through all modules
    do
    {
        // Get LDR Entry
        if (!AccessVirtualMemory(pCurrent, CR3, &entry, sizeof(_LDR_DATA_TABLE_ENTRY)))
            break;

        // Get module name n increment pCurrent
        moduleName = entry.BaseDllName;
        pCurrent = entry.InLoadOrderLinks.Flink;

        // Check if Dll is valid
        if (!(entry.DllBase && moduleName.Length && moduleName.Buffer))
            continue;

        // Read memory into buffer
        if (!AccessVirtualMemory(moduleName.Buffer, CR3, &pBuffer, sizeof(pBuffer)))
            continue;

        // Print info
        print(INFO("Module Name: %ws"), pBuffer);

        // Str cmp
        if (!wcscmp(pBuffer, ModuleName))
            return entry.DllBase;
    } while (pCurrent != pHead);

    // Not Found
    print(ERROR("%ws NOT FOUND!"), ModuleName);
    return nullptr;
}

address EnumerateKProcess(const wchar_t *ProcessName, const uint64_t PID = -1)
{
    // Parameters
    print(INFO("Target KProcess Name: %ws"), ProcessName);
    print(INFO("Target PID: %p"), PID);

    // Init variables for loop
    _LIST_ENTRY *pHead = (_LIST_ENTRY *) win::PsLoadedModuleList;
    _LIST_ENTRY *pCurrent = pHead;

    _KLDR_DATA_TABLE_ENTRY *entry;
    _UNICODE_STRING moduleName;

    // Loop through all kernel modules
    do
    {
        // Get KLDR entry n get module name n increment pCurrent
        entry = CONTAINING_RECORD(pCurrent, _KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        moduleName = entry->BaseDllName;
        pCurrent = pCurrent->Flink;

        // Check if module is valid
        if (!(entry->DllBase && moduleName.Length && moduleName.Buffer))
            continue;

        // Print info
        print(INFO("Module Name: %ws"), moduleName.Buffer);

        // Str cmp
        if (!wcscmp(moduleName.Buffer, ProcessName))
            return entry->DllBase;
    } while (pCurrent != pHead);

    // Not Found
    print(ERROR("%ws NOT FOUND!"), ProcessName);
    return nullptr;
}

_EPROCESS *EnumerateEProcess(const wchar_t *ProcessName, const uint64_t PID = -1)
{
    // Parameters
    print(INFO("Target EProcess Name: %ws"), ProcessName);
    print(INFO("Target PID: %p"), PID);
    size_t targetLen = wcslen(ProcessName);

    // Get system default EProcess n ListEntry
    _EPROCESS *Process = (_EPROCESS *) win::PsInitialSystemProcess;
    _LIST_ENTRY *pHead = &(Process->ActiveProcessLinks);
    _LIST_ENTRY *pCurrent = pHead;

    // Loop through all process
    do
    {
        // Get EProcess from ListEntry
        _EPROCESS *pProcess = CONTAINING_RECORD(pCurrent, _EPROCESS, ActiveProcessLinks);
        pCurrent = pCurrent->Flink;

        // PID cmp
        print(INFO("Process Name: %s, PID: %d"), pProcess->ImageFileName, pProcess->UniqueProcessId);
        if (pProcess->UniqueProcessId == (void *) PID)
            return pProcess;

        // Check if EProcess has ImageFilePointer n FilePath
        if (!pProcess->ImageFilePointer || !pProcess->ImageFilePointer->FileName.Length)
            continue;

        // Print info
        print(INFO("File Path: %ws"),
              pProcess->ImageFilePointer->FileName.Buffer);

        // Sub str cmp
        size_t processLen = pProcess->ImageFilePointer->FileName.Length / sizeof(wchar_t);
        if (targetLen && !wcscmp(pProcess->ImageFilePointer->FileName.Buffer + processLen - targetLen, ProcessName))
            return pProcess;
    } while (pCurrent != pHead);

    // Not Found
    print(ERROR("%ws NOT FOUND!"), ProcessName);
    return nullptr;
}

constexpr uint8_t HexToByte(char c) {
    return (c >= '0' && c <= '9') ? c - '0' :
           (c >= 'A' && c <= 'F') ? c - 'A' + 0xA :
           (c >= 'a' && c <= 'f') ? c - 'a' + 0xA :
           0xFF; // Invalid
}

template<size_t N>
constexpr std::array<char, N> PatternToBytes(const char (&Signature)[N])
{
    std::array<char, N> Bytes{};
    size_t i = 0;
    size_t len = 0;

    while (i < N - 1)
    {
        switch (Signature[i])
        {
            case ' ':
                break;
            case '?':
                ++i; // ? can only be followed by ' ' or '?'
                Bytes[len++] = '?';
                break;
            default:
                char high = HexToByte(Signature[i]);
                char low = HexToByte(Signature[++i]);
                Bytes[len++] = (high << 4 | low);
        }
        ++i;
    }

    Bytes[len] = '\0';
    return Bytes;
}

address SignatureScan(const void *StartAddress, const void *EndAddress, const char *Signature)
{
    print(INFO("Start Address: %p"), StartAddress);
    print(INFO("End Address: %p"), EndAddress);
    print(INFO("Signature Address: %p"), Signature);
    size_t size = strlen(Signature);

    for (const char *Current = (char *) StartAddress; Current <= (char *) ((size_t) EndAddress - size); ++Current)
        for (size_t i = 0; i <= size; ++i)
        {
            if (i == size)
            {
                print(INFO("Signature: %p"), Current);
                return Current;
            }

            if (Signature[i] != '?' && Signature[i] != Current[i])
                break;
        }

    print(ERROR("SIGNATURE NOT FOUND!"));
    return nullptr;
}

address SectionScan(const wchar_t *ProcessName, const wchar_t *ModuleName, const char *SectionName,
                    const char *Signature)
{
    // Print info
    print(INFO("ProcessName: %ws"), ProcessName);
    print(INFO("ModuleName: %ws"), ModuleName);
    print(INFO("SectionName: %s"), SectionName);
    print(INFO("Signature: %s"), Signature);

    // Initialize variables (empty = Kernel, else = User)
    address BaseAddress = ProcessName[0] == L'\0'
                              ? EnumerateKProcess(ModuleName)
                              : EnumerateModuleBaseAddress(EnumerateEProcess(ProcessName), ModuleName);
    if (!BaseAddress) return nullptr;

    // Get section
    auto dosHeader = (_IMAGE_DOS_HEADER *) BaseAddress;
    print(INFO("dosHeader: %p"), dosHeader);
    if (!dosHeader) return nullptr;

    auto ntHeader = (_IMAGE_NT_HEADERS64 *) (BaseAddress + dosHeader->e_lfanew);
    print(INFO("ntHeader: %p"), ntHeader);
    if (!ntHeader) return nullptr;

    auto fileHeader = &ntHeader->FileHeader;
    print(INFO("fileHeader: %p"), fileHeader);
    if (!fileHeader) return nullptr;

    auto optionalHeader = &ntHeader->OptionalHeader;
    print(INFO("optionalHeader: %p"), optionalHeader);
    if (!optionalHeader) return nullptr;

    auto sectionHeader = (_IMAGE_SECTION_HEADER *) ((uint64_t) optionalHeader + sizeof(_IMAGE_OPTIONAL_HEADER64));
    print(INFO("sectionHeader: %p"), sectionHeader);
    if (!(sectionHeader)) return nullptr;

    // loop
    void *sectionStart{};
    void *sectionEnd{};

    // Find Section
    for (int i = 0; i < fileHeader->NumberOfSections; i++)
    {
        print(INFO("Section Name: %s"), sectionHeader[i].Name);
        if (!memcmp(sectionHeader[i].Name, SectionName, std::min(8, (int) strlen(SectionName))))
        {
            sectionStart = BaseAddress + sectionHeader[i].VirtualAddress;
            sectionEnd = BaseAddress + sectionHeader[i].VirtualAddress + sectionHeader[i].Misc.VirtualSize;
            break;
        }
    }

    // Signature Scan
    return SignatureScan(sectionStart, sectionEnd, Signature);
}
