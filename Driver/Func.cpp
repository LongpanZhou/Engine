#include "Lib/structs.h"
#include "Lib/utils.h"
#include "Crypt.cpp"
#include "Mem.cpp"

address EnumerateModuleBaseAddress(_EPROCESS *pEProcess, const wchar_t *ModuleName)
{
    // Check if EProcess is empty
    if (!pEProcess) return nullptr;

    // Get KProcess n CR3
    _KPROCESS *pKProcess = (_KPROCESS *) pEProcess;
    cr3 CR3 = {pKProcess->DirectoryTableBase};
    print(INFO("EProcess Address: %p"), pEProcess);
    print(INFO("Target Module Name: %ws"), ModuleName);
    print(INFO("KProcess CR3: %p"), CR3);

    // Get PEB (Process Environment Block)
    _PEB *pPeb = pEProcess->Peb;
    if (!pPeb) return nullptr;

    // Read LDR (Loader Dynamic Resources): the pointer stored at &pPeb->Ldr, not the struct it points to
    _PEB_LDR_DATA *pLdr;
    AccessVirtualMemory(&pPeb->Ldr, CR3, &pLdr, sizeof(pLdr));
    if (!pLdr) return nullptr;

    // Init variables for loop
    wchar_t pBuffer[256];
    _LIST_ENTRY moduleList;
    AccessVirtualMemory(&pLdr->InLoadOrderModuleList, CR3, &moduleList, sizeof(_LIST_ENTRY));

    _LDR_DATA_TABLE_ENTRY entry;
    win::UNICODE_STRING moduleName;

    // The head is the sentinel inside PEB_LDR_DATA; it is not a module, so the walk stops when it comes back
    _LIST_ENTRY *pHead = (_LIST_ENTRY *) &pLdr->InLoadOrderModuleList;
    _LIST_ENTRY *pCurrent = moduleList.Flink;

    // Loop through all modules
    while (pCurrent != pHead)
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

        // Read only the name and its terminator, so a short name at the end of a page does not read past it
        size_t NameBytes = moduleName.Length < sizeof(pBuffer) - sizeof(wchar_t) ? moduleName.Length : sizeof(pBuffer) - sizeof(wchar_t);
        if (!AccessVirtualMemory(moduleName.Buffer, CR3, &pBuffer, NameBytes))
            continue;
        pBuffer[NameBytes / sizeof(wchar_t)] = L'\0';

        // Print info
        print(INFO("Module Name: %ws"), pBuffer);

        // Str cmp
        if (!wcscmp(pBuffer, ModuleName))
            return entry.DllBase;
    }

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
    _LIST_ENTRY *pHead = (_LIST_ENTRY *) *__imp_PsLoadedModuleList;
    _LIST_ENTRY *pCurrent = pHead->Flink;   // the list head is not a module

    _KLDR_DATA_TABLE_ENTRY *entry;
    _UNICODE_STRING moduleName;

    // Loop through all kernel modules
    while (pCurrent != pHead)
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
    }

    // Not Found
    print(ERROR("%ws NOT FOUND!"), ProcessName);
    return nullptr;
}

// True if the process's image path ends in ProcessName, with a '\' before it. Only the file name counts, not the directory
bool ProcessHasName(_EPROCESS *pProcess, const wchar_t *ProcessName)
{
    if (!pProcess->ImageFilePointer || !pProcess->ImageFilePointer->FileName.Length) return false;

    size_t targetLen = wcslen(ProcessName);
    size_t processLen = pProcess->ImageFilePointer->FileName.Length / sizeof(wchar_t);
    if (!targetLen || processLen <= targetLen) return false;

    const wchar_t *FileName = pProcess->ImageFilePointer->FileName.Buffer;
    size_t NameStart = processLen - targetLen;
    return FileName[NameStart - 1] == L'\\' && !memcmp(FileName + NameStart, ProcessName, targetLen * sizeof(wchar_t));
}

_EPROCESS *EnumerateEProcess(const wchar_t *ProcessName, const uint64_t PID = -1)
{
    // Parameters
    print(INFO("Target EProcess Name: %ws"), ProcessName);
    print(INFO("Target PID: %p"), PID);

    // Get system default EProcess n ListEntry
    _EPROCESS *Process = (_EPROCESS *) *__imp_PsInitialSystemProcess;
    _LIST_ENTRY *pHead = &(Process->ActiveProcessLinks);
    _LIST_ENTRY *pCurrent = pHead;

    // Loop through all process
    do
    {
        // Get EProcess from ListEntry
        _EPROCESS *pProcess = CONTAINING_RECORD(pCurrent, _EPROCESS, ActiveProcessLinks);
        pCurrent = pCurrent->Flink;

        // PID cmp
        print(INFO("Process Name: %s, PID: %p"), pProcess->ImageFileName, pProcess->UniqueProcessId);
        if (pProcess->UniqueProcessId == (void *) PID)
            return pProcess;

        // Check if EProcess has ImageFilePointer n FilePath
        if (!pProcess->ImageFilePointer || !pProcess->ImageFilePointer->FileName.Length)
            continue;

        // Print info
        print(INFO("File Path: %ws"),
              pProcess->ImageFilePointer->FileName.Buffer);

        if (ProcessHasName(pProcess, ProcessName)) return pProcess;
    } while (pCurrent != pHead);

    // Not Found
    print(ERROR("%ws NOT FOUND!"), ProcessName);
    return nullptr;
}

// Hex to bytes
constexpr uint8_t HexToByte(char c) {
    return (c >= '0' && c <= '9') ? c - '0' :
           (c >= 'A' && c <= 'F') ? c - 'A' + 0xA :
           (c >= 'a' && c <= 'f') ? c - 'a' + 0xA :
           0xFF; // Invalid
}

// Pattern to Bytes
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

// Signature Scan
address SignatureScan(const void *StartAddress, const void *EndAddress, const char *Signature)
{
    print(INFO("Start Address: %p"), StartAddress);
    print(INFO("End Address: %p"), EndAddress);
    print(INFO("Signature Address: %p"), Signature);
    size_t size = strlen(Signature);

    // Nothing to search: a missing range, or one shorter than the signature (the bound below would wrap)
    if (!StartAddress || !EndAddress || (size_t) EndAddress - (size_t) StartAddress < size)
    {
        print(ERROR("SIGNATURE NOT FOUND!"));
        return nullptr;
    }

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

// Section Signature Scan
address SectionScan(address BaseAddress, const char *SectionName, const char *Signature)
{
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
        if (!memcmp(sectionHeader[i].Name, SectionName, strlen(SectionName)))
        {
            sectionStart = BaseAddress + sectionHeader[i].VirtualAddress;
            sectionEnd = BaseAddress + sectionHeader[i].VirtualAddress + sectionHeader[i].Misc.VirtualSize;
            break;
        }
    }

    // Section not found: there is nothing to scan
    if (!sectionStart)
    {
        print(ERROR("SECTION NOT FOUND!"));
        return nullptr;
    }

    // Signature Scan
    return SignatureScan(sectionStart, sectionEnd, Signature);
}

// Encoded runtime strings and the hook signature
#include "Strings.h"

// Get ntoskrnl.exe address
address GetNtoskrnl()
{
    // IDT
    interrupt_descriptor_table idt = sidt();

    // Start on a page boundary. The scan steps 4 KB at a time, so an unaligned start never lands on a page header
    address base = (address) ((uint64_t) idt.base & ~0xFFFull);

    // Validity checks walk the page tables of the System process, which map all of kernel memory.
    // (Calling them with a constant in place of a CR3 checks against the wrong tables.)
    cr3 SystemCR3 = {((_KPROCESS *) *__imp_PsInitialSystemProcess)->DirectoryTableBase};

    // Brute Force
    auto NtoskrnlFile = Decode(NtoskrnlName);
    uint64_t Steps = 0;     // pages visited by the scan
    uint64_t MzSeen = 0;    // pages where a valid DOS header was found
    print(INFO("GetNtoskrnl: start, IDT base %p, scanning down in 4 KB steps"), (void *) base);
    do {
        Steps++;
        if ((Steps & 0x3FF) == 0) print(INFO("GetNtoskrnl: step %llu at %p"), Steps, (void *) base);

        // Get Data Directory
        auto dosHeader = (_IMAGE_DOS_HEADER *)base;
        if (!IsAddressValid(dosHeader, SystemCR3) || dosHeader->e_magic != 0x5A4D)
            continue;
        MzSeen++;
        print(INFO("GetNtoskrnl: MZ header at %p (step %llu)"), (void *) base, Steps);

        auto ntHeader = (_IMAGE_NT_HEADERS64 *)(base + dosHeader->e_lfanew);
        if (!IsAddressValid(ntHeader, SystemCR3) || ntHeader->Signature != 0x4550)
        {
            print(INFO("GetNtoskrnl: %p has no valid PE header"), (void *) base);
            continue;
        }

        auto dataDir = ntHeader->OptionalHeader.DataDirectory;
        if (dataDir->VirtualAddress == 0)
        {
            print(INFO("GetNtoskrnl: %p has no export directory"), (void *) base);
            continue;
        }

        auto exportDir = (_IMAGE_EXPORT_DIRECTORY *)(base + dataDir->VirtualAddress);
        if (!IsAddressValid(exportDir, SystemCR3))
        {
            print(INFO("GetNtoskrnl: export directory of %p is not mapped"), (void *) base);
            continue;
        }

        // Get module name from export directory
        const char* name = (const char*)(base + exportDir->Name);
        if (!IsAddressValid(name, SystemCR3))
        {
            print(INFO("GetNtoskrnl: export name of %p is not mapped"), (void *) base);
            continue;
        }

        // Check ntoskrnl.exe
        if (strcmp(name, NtoskrnlFile.data()))
        {
            print(INFO("GetNtoskrnl: %p is module %s, not ntoskrnl"), (void *) base, name);
            continue;
        }

        // Ntoskrnl.exe
        print(INFO("GetNtoskrnl: found ntoskrnl.exe at %p after %llu steps"), (void *) base, Steps);
        return base;
    } while (base -= 0x1000);

    print(ERROR("GetNtoskrnl: NOT FOUND after %llu steps, %llu valid DOS headers, base reached 0"), Steps, MzSeen);
    return nullptr;
}

// Lazy Import
address FindFuncExports(address BaseAddress, const char *FuncName)
{
    // Get Export Directory
    auto dosHeader = (_IMAGE_DOS_HEADER *) BaseAddress;
    print(INFO("dosHeader: %p"), dosHeader);
    if (!dosHeader) return nullptr;

    auto ntHeader = (_IMAGE_NT_HEADERS64 *) (BaseAddress + dosHeader->e_lfanew);
    print(INFO("ntHeader: %p"), ntHeader);
    if (!ntHeader) return nullptr;

    auto dataDir = ntHeader->OptionalHeader.DataDirectory;
    print(INFO("dataDir: %p"), dataDir);
    if (!dataDir) return nullptr;

    auto exportDir = (_IMAGE_EXPORT_DIRECTORY *) (BaseAddress + dataDir->VirtualAddress);
    print(INFO("exportDir: %p"), exportDir);
    if (!exportDir) return nullptr;

    // Get FuncAddress
    uint32_t *functions = (uint32_t *) (BaseAddress + exportDir->AddressOfFunctions);
    print(INFO("functions: %p"), functions);
    if (!functions) return nullptr;

    // Get NameOrdinalAddress
    uint16_t *ordinals = (uint16_t *) (BaseAddress + exportDir->AddressOfNameOrdinals);
    print(INFO("ordinals: %p"), ordinals);
    if (!ordinals) return nullptr;

    // Get NameAddress
    uint32_t *names = (uint32_t *) (BaseAddress + exportDir->AddressOfNames);
    print(INFO("names: %p"), names);
    if (!names) return nullptr;

    // Loop through export table
    for (uint32_t i = 0; i < exportDir->NumberOfNames; ++i)
    {
        const char *funcName = (const char *) (BaseAddress + names[i]);
        print(INFO("Function Name: %s"), funcName);

        if (!strcmp(funcName, FuncName))
        {
            return BaseAddress + functions[ordinals[i]];;
        }
    }

    print(ERROR("EXPORT FUNCTION NOT FOUND!"));
    return nullptr;
}

// SystemCodeIntegrityInformation (class 0x67) returns a length and a bit mask of code integrity options
struct SYSTEM_CODEINTEGRITY_INFORMATION
{
    uint32_t Length;
    uint32_t CodeIntegrityOptions;
};

constexpr uint32_t SystemCodeIntegrityInformationClass = 0x67;
constexpr uint32_t CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED = 0x400;

// Declared here because the vendor headers are not in this checkout; the signature is the kernel's
extern "C" int32_t ZwQuerySystemInformation(uint32_t SystemInformationClass, void *SystemInformation,
                                            uint32_t SystemInformationLength, uint32_t *ReturnLength);

// Returns true if HVCI (hypervisor-enforced code integrity, "Memory integrity") is on for kernel code.
// If the query fails, this returns false, which means "not known to be on".
bool IsHVCIEnabled()
{
    SYSTEM_CODEINTEGRITY_INFORMATION info{};
    info.Length = sizeof(info);

    int32_t status = ZwQuerySystemInformation(SystemCodeIntegrityInformationClass, &info, sizeof(info), nullptr);
    if (status < 0) return false;   // NTSTATUS values below zero are errors

    return (info.CodeIntegrityOptions & CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED) != 0;
}