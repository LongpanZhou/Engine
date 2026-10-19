// Process & module enumeration: the kernel's module list (PsLoadedModuleList), the EPROCESS list and a
// process's PEB loader list, all read through AccessVirtualMemory (Mem.cpp) with the CR3 of the target

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
        constexpr size_t MaxNameBytes = sizeof(pBuffer) - sizeof(wchar_t);   // room for the L'\0'
        size_t NameBytes = moduleName.Length < MaxNameBytes ? moduleName.Length : MaxNameBytes;
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

// Case-folded comparison, so the search finds the module however the loader stored its name's case
// (ci.dll must match CI.dll). ASCII file names: folding a-z to A-Z is exact
static bool WideEqualsIgnoreCase(const wchar_t *A, const wchar_t *B)
{
    while (*A || *B)
    {
        wchar_t a = (*A >= L'a' && *A <= L'z') ? (wchar_t) (*A - 0x20) : *A;
        wchar_t b = (*B >= L'a' && *B <= L'z') ? (wchar_t) (*B - 0x20) : *B;
        if (a != b) return false;
        ++A;
        ++B;
    }
    return true;
}

address EnumerateKProcess(const wchar_t *ProcessName)
{
    // Parameters
    print(INFO("Target KProcess Name: %ws"), ProcessName);

    // Init variables for loop. Reading __imp_PsLoadedModuleList itself yields the value in the import slot: the
    // address of PsLoadedModuleList, the list head. Dereferencing the identifier (*...) would name the first
    // module instead of the head, which skips ntoskrnl and makes the loop walk garbage
    _LIST_ENTRY *pHead = (_LIST_ENTRY *) __imp_PsLoadedModuleList;
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
        // print(INFO("Module Name: %ws"), moduleName.Buffer);

        // Str cmp
        if (WideEqualsIgnoreCase(moduleName.Buffer, ProcessName))
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

    // Walk bound: a torn or corrupt Flink must not turn this into an endless walk or a walk off
    // the list (the same MaxWalk pattern as the module-list walkers in Hide.cpp). Real process
    // counts are far below the bound, so a well-formed list ends long before it
    constexpr uint32_t MaxProcessWalk = 4096;
    uint32_t Count = 0;

    // The Flink read has a race window: the list is mutated at process create/exit under locks
    // this walk does not take, so an entry may unlink between being observed and being followed.
    // The walk only follows links it just observed valid; no EPROCESS lifetime is extended here
    do
    {
        // Get EProcess from ListEntry
        _EPROCESS *pProcess = CONTAINING_RECORD(pCurrent, _EPROCESS, ActiveProcessLinks);
        pCurrent = pCurrent->Flink;
        Count++;

        // PID cmp
        // print(INFO("Process Name: %s, PID: %p"), pProcess->ImageFileName, pProcess->UniqueProcessId);
        if (pProcess->UniqueProcessId == (void *) PID)
            return pProcess;

        // Check if EProcess has ImageFilePointer n FilePath
        if (!pProcess->ImageFilePointer || !pProcess->ImageFilePointer->FileName.Length)
            continue;

        // Print info
        // print(INFO("File Path: %ws"),
        //       pProcess->ImageFilePointer->FileName.Buffer);

        if (ProcessHasName(pProcess, ProcessName)) return pProcess;
    } while (pCurrent && pCurrent != pHead && Count < MaxProcessWalk);

    // Not Found
    print(ERROR("%ws NOT FOUND!"), ProcessName);
    return nullptr;
}
