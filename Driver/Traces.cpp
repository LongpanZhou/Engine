// Trace cleaning. Three cleaners, all located by runtime signature + export table, no imports, no
// hardcoded offsets beyond the record layouts. Compiled after Scan.cpp, Mem.cpp, Process.cpp and Strings.h:
// reuses SectionScan, FindFuncExports, GetNtoskrnl, EnumerateKProcess and the encoded strings

// Shared helpers
// ---------------------------------------------------------------------------

// Canonical kernel pointers are FFFF8.... and up; guards every dereference below against garbage hits
constexpr uint64_t KernelPointerFloor = 0xFFFF800000000000;

bool IsKernelPointer(uint64_t Value)
{
    return Value >= KernelPointerFloor;
}

// rip-relative reference -> absolute address: disp32 sits at OffsetOffset, the instruction ends after
// InstructionSize bytes (the reference cleaner's ResolveRelativeAddress, renamed)
address ResolveRipRelative(const void *Instruction, uint32_t OffsetOffset, uint32_t InstructionSize)
{
    auto Instr = (size_t) Instruction;
    int32_t Offset = *(int32_t *) (Instr + OffsetOffset);
    return (address) (Instr + InstructionSize + Offset);
}

// Pattern scan over one module image: PAGE first, then .text, like the reference cleaner's FindPatternImage
address ScanModuleImage(address Base, const char *Pattern)
{
    if (!Base)
    {
        print(ERROR("ScanModuleImage: no base address"));
        return nullptr;
    }

    if (address Match = SectionScan(Base, Decode(PageSectionName).data(), Pattern))
        return Match;

    return SectionScan(Base, Decode(TextSectionName).data(), Pattern);
}

// Walks the export directory by hand so the cleaners create no import table entries; data exports come
// back as the variable itself (this is how PsLoadedModuleResource is reached without MmGetSystemRoutineAddress)
address ResolveKernelSymbol(const char *Name)
{
    address Nt = GetNtoskrnl();
    if (!Nt)
    {
        print(ERROR("ResolveKernelSymbol: ntoskrnl not found"));
        return nullptr;
    }

    return FindFuncExports(Nt, Name);
}

// Case-folded equality of two UNICODE_STRINGs (the names compared here are ASCII file names, so
// folding the 6th bit is exact). Null buffers, odd lengths or mismatched lengths do not match
static bool WideNameEquals(const _UNICODE_STRING* A, const _UNICODE_STRING* B)
{
    if (!A || !B || !A->Buffer || !B->Buffer) return false;
    if (A->Length != B->Length || (A->Length & 1)) return false;

    for (uint32_t i = 0; i < A->Length / sizeof(wchar_t); ++i)
        if (!(A->Buffer[i] == B->Buffer[i] || (A->Buffer[i] | 0x20) == (B->Buffer[i] | 0x20)))
            return false;

    return true;
}

// PE timestamp of a loaded image (file header), the second PiDDB lookup key next to the driver name
uint32_t GetImageDataTimeStamp(address ImageBase)
{
    if (!ImageBase || !IsKernelPointer(ImageBase)) return 0;

    auto Dos = (_IMAGE_DOS_HEADER *) ImageBase;
    if (Dos->e_magic != 0x5A4D) return 0;

    auto Nt = (_IMAGE_NT_HEADERS64 *) (ImageBase + Dos->e_lfanew);
    if (Nt->Signature != 0x4550) return 0;

    return Nt->FileHeader.TimeDateStamp;
}

// ---------------------------------------------------------------------------
// Cleaner 1: PiDDBCacheTable
// ---------------------------------------------------------------------------

// Every load attempt is filed in CI's "PiDDB process cache" (an AVL tree keyed by name, then PE
// timestamp, plus a circular housekeeping list threading every entry, both in ntoskrnl), and cache
// walks by anti-cheat tooling still see our entry after everything else about the load is gone. This
// cleaner makes ZERO kernel calls: the list head comes from a code signature, and instead of deleting
// the entry — a hand-rolled AVL delete would have to replicate Rtl's rebalancing exactly, and one
// wrong balance byte corrupts the table for CI itself — it camouflages the entry in place by
// copying a benign entry's name + timestamp + load status over ours. The tree's links and balance
// factors stay untouched, and because the copied key already exists elsewhere in the tree, every
// lookup still resolves to a record with identical data
struct _PiDDB_CACHE_ENTRY
{
    struct _LIST_ENTRY List;             //0x0 housekeeping list every entry is threaded onto
    struct _UNICODE_STRING DriverName;   //0x10
    uint32_t TimeDateStamp;              //0x20 PE timestamp of the entry's binary
    int32_t LoadStatus;                  //0x24 NTSTATUS of the recorded load
    uint8_t ShimEngineData[16];          //0x28 shim-engine data, uninitialized for custom drivers
};

// Most entries a walk may visit before giving up (the live table on 19041 held 142); the bound
// keeps a corrupt list from turning the walk into an endless loop
constexpr uint32_t MaxPiDDBEntries = 0x800;

// Shared with the MmUnloadedDrivers cleaner below (it takes the same ERESOURCE)
typedef int (*ExAcquireResourceExclusiveLite_t)(VOID* Resource, uint8_t Wait);
typedef int (*ExReleaseResourceLite_t)(VOID* Resource);

// The housekeeping list head, nt!PiDDBCacheList, from the InsertTailList block in nt!PiLookupInDDBCache
// (see the signature comment in Strings.h). The entries hang off the head, Flink to Flink, back around
// to the head, so the whole cache is reachable without ever touching the AVL tree
static _LIST_ENTRY* FindPiDDBCacheList(address Nt)
{
    address Match = ScanModuleImage(Nt, Decode(PiDDBCacheListSignature).data());
    if (!Match)
    {
        print(ERROR("PiDDB: list signature not found"));
        return nullptr;
    }

    // The lea sits at the match itself; its disp32 at +3, the instruction is 7 bytes
    auto List = (_LIST_ENTRY *) ResolveRipRelative((const char *) Match, 3, 7);
    if (!IsKernelPointer((uint64_t) List))
    {
        print(ERROR("PiDDB: list head %p is not a kernel pointer"), (void *) List);
        return nullptr;
    }

    return List;
}

// Copies Donor's identity (name + timestamp + load status) onto Target, if the name fits Target's
// own buffer. Every write is small and naturally aligned, so a CI thread reading the entry
// concurrently sees either the old or the new value — both valid records — and no lock is needed
static bool CamouflagePiDDBEntry(_PiDDB_CACHE_ENTRY* Target, const _PiDDB_CACHE_ENTRY* Donor)
{
    if (Donor->DriverName.Length + sizeof(wchar_t) > Target->DriverName.MaximumLength)
        return false;

    Target->TimeDateStamp = Donor->TimeDateStamp;
    Target->LoadStatus = Donor->LoadStatus;

    uint32_t Chars = Donor->DriverName.Length / sizeof(wchar_t);
    for (uint32_t i = 0; i < Chars; ++i)
        Target->DriverName.Buffer[i] = Donor->DriverName.Buffer[i];
    Target->DriverName.Buffer[Chars] = L'\0';
    Target->DriverName.Length = Donor->DriverName.Length;
    return true;
}

// Walks every well-formed entry on the housekeeping list, head -> ... -> head, handing each one to
// Visitor. Returns false when a malformed record (or the MaxPiDDBEntries bound) stopped the walk
// early; the caller decides whether that matters
template<typename F>
static bool ForEachPiDDBEntry(_LIST_ENTRY* Head, F Visitor)
{
    uint32_t Walked = 0;

    for (_LIST_ENTRY* Link = Head->Flink; Link && Link != Head && Walked < MaxPiDDBEntries; Link = Link->Flink)
    {
        // Stop at the first entry that does not look like a cache record: following links through a
        // torn or malformed entry would read garbage as pointers
        auto Entry = (_PiDDB_CACHE_ENTRY *) Link;
        if (!IsKernelPointer((uint64_t) Link->Flink) ||
            (Entry->DriverName.Length & 1) || Entry->DriverName.Length > 512 ||
            (Entry->DriverName.Length && !IsKernelPointer((uint64_t) Entry->DriverName.Buffer)))
        {
            print(WARN("PiDDB: malformed entry %p, walk stopped"), (void *) Entry);
            return false;
        }

        Walked++;
        Visitor(Entry);
    }

    return Walked < MaxPiDDBEntries;
}

// Hides this driver's records in the PiDDB cache without calling a single kernel routine. Matching is
// by name only: earlier load cycles of the same binary carry different timestamps, and every entry
// naming this driver is a trace. True when the walk completed; false means a structure was missing,
// not that a record existed
bool ClearPiDDBCache(win::DRIVER_OBJECT* DriverObject)
{
    if (!DriverObject || !DriverObject->DriverSection)
    {
        print(ERROR("PiDDB: no DriverObject or DriverSection (manual mapping?), nothing to clean"));
        return false;
    }

    auto Kldr = (_KLDR_DATA_TABLE_ENTRY *) DriverObject->DriverSection;
    if (!Kldr->BaseDllName.Buffer || !Kldr->BaseDllName.Length)
    {
        print(ERROR("PiDDB: loader entry has no BaseDllName"));
        return false;
    }

    print(INFO("PiDDB: target %ws, timestamp %08x"), Kldr->BaseDllName.Buffer, Kldr->TimeDateStamp);

    address Nt = GetNtoskrnl();
    if (!Nt) return false;

    _LIST_ENTRY* Head = FindPiDDBCacheList(Nt);
    if (!Head) return false;

    // Pass 1: the identity source — the first benign entry on the list. All entries naming this
    // driver share its name, so one donor covers every one of them; the fit against each target's
    // own buffer is checked per copy below
    _PiDDB_CACHE_ENTRY* Donor = nullptr;
    ForEachPiDDBEntry(Head, [&](auto Entry) {
        if (!Donor && Entry->DriverName.Length && !WideNameEquals(&Entry->DriverName, &Kldr->BaseDllName))
            Donor = Entry;
    });

    if (!Donor)
    {
        print(WARN("PiDDB: no benign entry to copy an identity from, nothing cleaned"));
        return true;
    }

    // Pass 2: camouflage every entry naming this driver. A donor name that does not fit a target's
    // buffer leaves that entry in place, mentioned in the summary
    uint32_t Camouflaged = 0, Walked = 0;
    ForEachPiDDBEntry(Head, [&](auto Entry) {
        Walked++;
        if (WideNameEquals(&Entry->DriverName, &Kldr->BaseDllName) &&
            CamouflagePiDDBEntry(Entry, Donor))
        {
            Camouflaged++;
            print(INFO("PiDDB: entry %p camouflaged as %ws"), (void *) Entry, Entry->DriverName.Buffer);
        }
    });

    if (!Camouflaged)
        print(INFO("PiDDB: no entry for this driver out of %u walked (nothing to clean)"), Walked);
    else
        print(OK("PiDDB: %u of %u entries camouflaged"), Camouflaged, Walked);
    return true;
}

// Debug-only self-check of the PiDDB cleaner, run right after it inside CleanDriverTraces: walks the
// housekeeping list again and confirms the stealth property directly — no entry still names this
// driver — over a fully intact list. Non-static like VerifyMemory, so release builds compile it
// without an unused warning and --gc-sections drops it from the image
void VerifyPiDDBCache(win::DRIVER_OBJECT* DriverObject)
{
    if (!DriverObject || !DriverObject->DriverSection)
    {
        print(ERROR("VerifyPiDDB: no DriverObject or DriverSection, cannot verify"));
        return;
    }

    auto Kldr = (_KLDR_DATA_TABLE_ENTRY *) DriverObject->DriverSection;
    if (!Kldr->BaseDllName.Buffer || !Kldr->BaseDllName.Length)
    {
        print(ERROR("VerifyPiDDB: loader entry has no BaseDllName, cannot verify"));
        return;
    }

    address Nt = GetNtoskrnl();
    _LIST_ENTRY* Head = Nt ? FindPiDDBCacheList(Nt) : nullptr;
    if (!Head)
    {
        print(ERROR("VerifyPiDDB: list not found, cannot verify"));
        return;
    }

    uint32_t Walked = 0;
    const _PiDDB_CACHE_ENTRY* Leaked = nullptr;
    if (!ForEachPiDDBEntry(Head, [&](auto Entry) {
        Walked++;
        if (!Leaked && WideNameEquals(&Entry->DriverName, &Kldr->BaseDllName))
            Leaked = Entry;
    }))
    {
        print(ERROR("VerifyPiDDB: walk stopped early, list damaged?"));
        return;
    }

    if (Leaked)
        print(ERROR("VerifyPiDDB: FAILED, entry %p still names this driver after cleaning"), (void *) Leaked);
    else
        print(OK("VerifyPiDDB: all checks passed (%u entries walked, none name this driver)"), Walked);
}

// ---------------------------------------------------------------------------
// Cleaner 2: MmUnloadedDrivers / MmLastUnloadedDriver
// ---------------------------------------------------------------------------

// Every unload files an MM_UNLOADED_DRIVER record into a 50-slot array and bumps MmLastUnloadedDriver;
// "recently unloaded driver" tools read exactly this. Located by signature on both sides: the array
// pointer's rip-relative mov (stable across 1903-22H2) and the count's "cmp eax, 0x32" cap. Removal
// mirrors the reference cleaner: matching records are freed and zeroed, everything after slides down one
// slot, the count drops, and UnloadTimes are re-normalized to the kernel's own descending order
constexpr uint32_t MmUnloadedDriversSize = 0x32;

// 'TDmM' — the pool tag the name buffers were allocated with; freeing with anything else fails
constexpr uint32_t MmDtPoolTag = 0x54446D4D;

struct _MM_UNLOADED_DRIVER
{
    struct _UNICODE_STRING Name;   //0x0 image name, buffer in its own pool allocation
    VOID* ModuleStart;             //0x10
    VOID* ModuleEnd;               //0x18
    ULONGLONG UnloadTime;          //0x20 unload time, descending across the array
};

typedef void (*ExFreePoolWithTag_t)(VOID* Memory, uint32_t Tag);
typedef uint32_t (*RtlRandomEx_t)(uint32_t* Seed);

static ExAcquireResourceExclusiveLite_t MmUnloadAcquireFn = nullptr;
static ExReleaseResourceLite_t MmUnloadReleaseFn = nullptr;
static ExFreePoolWithTag_t MmUnloadFreeFn = nullptr;
static RtlRandomEx_t MmUnloadRandomFn = nullptr;
static VOID* MmUnloadResource = nullptr;

static bool ResolveMmUnloadRoutines()
{
    if (MmUnloadFreeFn) return true;

    MmUnloadAcquireFn = (ExAcquireResourceExclusiveLite_t) ResolveKernelSymbol(Decode(ExAcquireResourceName).data());
    MmUnloadReleaseFn = (ExReleaseResourceLite_t) ResolveKernelSymbol(Decode(ExReleaseResourceName).data());
    MmUnloadFreeFn = (ExFreePoolWithTag_t) ResolveKernelSymbol(Decode(ExFreePoolTagName).data());
    MmUnloadRandomFn = (RtlRandomEx_t) ResolveKernelSymbol(Decode(RtlRandomExName).data());

    bool Ok = MmUnloadAcquireFn && MmUnloadReleaseFn && MmUnloadFreeFn && MmUnloadRandomFn;
    if (!Ok)
    {
        MmUnloadAcquireFn = nullptr;
        MmUnloadReleaseFn = nullptr;
        MmUnloadFreeFn = nullptr;
        MmUnloadRandomFn = nullptr;
        print(ERROR("MmUnloaded: one or more exported routines not found"));
    }
    return Ok;
}

// The module list's ERESOURCE, held across the rewrite like the reference cleaner does. Resolving it is
// best effort: without it the shift races nothing on a quiet system, and duplicate records get caught by
// the next pass either way
static VOID* ResolveMmUnloadResource()
{
    if (MmUnloadResource) return MmUnloadResource;

    MmUnloadResource = (VOID*) ResolveKernelSymbol(Decode(PsLoadedModuleResourceName).data());
    if (!MmUnloadResource)
        print(WARN("MmUnloaded: PsLoadedModuleResource not exported, cleaning without the lock"));
    return MmUnloadResource;
}

// The array itself: the mov loads &MmUnloadedDrivers, one deref reads the array pointer out
static _MM_UNLOADED_DRIVER* FindMmUnloadedDrivers(address Nt)
{
    address Match = ScanModuleImage(Nt, Decode(MmUnloadedDriversSignature).data());
    if (!Match)
    {
        print(ERROR("MmUnloaded: array signature not found"));
        return nullptr;
    }

    auto Slot = (_MM_UNLOADED_DRIVER **) ResolveRipRelative(Match, 3, 7);
    if (!IsKernelPointer((uint64_t) Slot) || !IsKernelPointer((uint64_t) *Slot))
    {
        print(ERROR("MmUnloaded: slot %p dereferences to %p, not a kernel pointer"),
              Slot, Slot ? (void*) *Slot : nullptr);
        return nullptr;
    }

    print(INFO("MmUnloaded: array %p"), (void*) *Slot);
    return *Slot;
}

// The used-slot count, behind the "cmp eax, 0x32"
static uint32_t* FindMmLastUnloadedDriver(address Nt)
{
    address Match = ScanModuleImage(Nt, Decode(MmLastUnloadedDriverSignature).data());
    if (!Match)
    {
        print(ERROR("MmUnloaded: count signature not found"));
        return nullptr;
    }

    uint32_t* Count = (uint32_t*) ResolveRipRelative(Match, 2, 6);
    if (!IsKernelPointer((uint64_t) Count) || *Count > MmUnloadedDriversSize)
    {
        print(ERROR("MmUnloaded: count %p holds %u, not a plausible slot count"), Count, Count ? *Count : 0);
        return nullptr;
    }

    print(INFO("MmUnloaded: count %p = %u slots in use"), Count, *Count);
    return Count;
}

static bool IsUnloadEntryEmpty(_MM_UNLOADED_DRIVER* Entry)
{
    return Entry->Name.MaximumLength == 0 || Entry->Name.Length == 0 || Entry->Name.Buffer == nullptr;
}

// Whether every slot is used decides how the count is corrected after a removal
static bool IsMmUnloadedFilled(_MM_UNLOADED_DRIVER* Table)
{
    for (uint32_t Index = 0; Index < MmUnloadedDriversSize; ++Index)
        if (IsUnloadEntryEmpty(&Table[Index]))
            return false;

    return true;
}

// Letters-only case folding: every name compared here is an ASCII file name, so the 6th bit is exact
static bool WideCharEqual(wchar_t A, wchar_t B)
{
    return A == B || (A | 0x20) == (B | 0x20);
}

static bool MmUnloadNameMatches(_MM_UNLOADED_DRIVER* Entry, const wchar_t* DriverName)
{
    if (!DriverName) return false;

    size_t Target = wcslen(DriverName);
    if (!Entry->Name.Buffer || Entry->Name.Length / sizeof(wchar_t) != Target)
        return false;

    for (size_t i = 0; i < Target; ++i)
        if (!WideCharEqual(Entry->Name.Buffer[i], DriverName[i]))
            return false;

    return true;
}

// One removal pass: matching records freed + zeroed, later records slide down one slot, last slot zeroed.
// Duplicates that slide into place mid-pass are caught by the next pass
static bool RemoveMmUnloadRecords(const wchar_t* DriverName, _MM_UNLOADED_DRIVER* Table, uint32_t* Count, bool Filled)
{
    bool Modified = false;

    for (uint32_t Index = 0; Index < MmUnloadedDriversSize; ++Index)
    {
        auto Entry = &Table[Index];
        if (IsUnloadEntryEmpty(Entry)) continue;

        if (Modified)
        {
            auto Prev = &Table[Index - 1];
            *Prev = *Entry;
            if (Index == MmUnloadedDriversSize - 1)
                *Entry = {};
        }
        else if (MmUnloadNameMatches(Entry, DriverName))
        {
            VOID* Buffer = Entry->Name.Buffer;
            *Entry = {};
            MmUnloadFreeFn(Buffer, MmDtPoolTag);

            // Full array: the count sat at the cap; otherwise the record was already counted. Either way
            // one removal is one decrement
            *Count = (Filled ? MmUnloadedDriversSize : *Count) - 1;
            Modified = true;
            print(INFO("MmUnloaded: record %u removed"), Index);
        }
    }

    return Modified;
}

// Restore the descending UnloadTime order the kernel's inserts maintain
static void NormalizeMmUnloadTimes(_MM_UNLOADED_DRIVER* Table)
{
    static uint32_t Seed = 0;

    ULONGLONG PreviousTime = 0;
    for (int Index = MmUnloadedDriversSize - 2; Index >= 0; --Index)
    {
        auto Entry = &Table[Index];
        if (IsUnloadEntryEmpty(Entry)) continue;

        if (PreviousTime && Entry->UnloadTime > PreviousTime)
        {
            if (!Seed) Seed = (uint32_t) ((size_t) &Seed ^ Entry->UnloadTime);
            Entry->UnloadTime = PreviousTime - (MmUnloadRandomFn(&Seed) % 100) - 1;
        }

        PreviousTime = Entry->UnloadTime;
    }
}

// Removes this driver's records from MmUnloadedDrivers and fixes the count; up to four passes bound the
// duplicate-chasing. True when the walk completed
bool ClearMmUnloadedDrivers(win::DRIVER_OBJECT* DriverObject)
{
    if (!DriverObject || !DriverObject->DriverSection)
    {
        print(ERROR("MmUnloaded: no DriverObject or DriverSection (manual mapping?), nothing to clean"));
        return false;
    }

    auto Kldr = (_KLDR_DATA_TABLE_ENTRY *) DriverObject->DriverSection;
    if (!Kldr->BaseDllName.Buffer || !Kldr->BaseDllName.Length)
    {
        print(ERROR("MmUnloaded: loader entry has no BaseDllName"));
        return false;
    }

    address Nt = GetNtoskrnl();
    if (!Nt) return false;

    auto Table = FindMmUnloadedDrivers(Nt);
    uint32_t* Count = FindMmLastUnloadedDriver(Nt);
    if (!Table || !Count || !ResolveMmUnloadRoutines())
        return false;

    if (*Count == 0)
    {
        print(INFO("MmUnloaded: array is empty, nothing to clean"));
        return true;
    }

    VOID* Resource = ResolveMmUnloadResource();
    bool Locked = Resource && MmUnloadAcquireFn(Resource, 1);

    bool Modified = false;
    for (uint32_t Pass = 0; Pass < 4 &&
         RemoveMmUnloadRecords(Kldr->BaseDllName.Buffer, Table, Count, IsMmUnloadedFilled(Table)); ++Pass)
    {
        NormalizeMmUnloadTimes(Table);
        Modified = true;
    }

    if (Locked) MmUnloadReleaseFn(Resource);

    if (!Modified)
        print(INFO("MmUnloaded: no records for this driver"));
    else
        print(OK("MmUnloaded: records removed, count now %u"), *Count);

    return true;
}

// ---------------------------------------------------------------------------
// Cleaner 3: the CI kernel hash bucket list
// ---------------------------------------------------------------------------

// ci.dll keeps a chain of loaded kernel image hashes ("g_KernelHashBucketList") behind a rip-relative lea.
// Found by the 21H1 pattern (1903-21H1, our 19041 included), 22H2 pattern as fallback; ci.dll's base comes
// from the module walk. Entries are qword-linked (*(ULONGLONG*)Entry is the next entry), name at +0x48,
// 20-byte hash at +0x18. The reference cleaner scrambles the hash instead of unlinking: removing a node
// from CI's chain is invasive, random bytes just read as a stale cache record
constexpr uint32_t HashBucketEntryNameOffset = 0x48;
constexpr uint32_t HashBucketEntryHashOffset = 0x18;
constexpr uint32_t HashBucketEntryHashSize = 20;
constexpr uint32_t MaxHashBucketEntries = 0x800;

static RtlRandomEx_t HashBucketRandomFn = nullptr;

static bool ResolveHashBucketRoutines()
{
    if (HashBucketRandomFn) return true;

    HashBucketRandomFn = (RtlRandomEx_t) ResolveKernelSymbol(Decode(RtlRandomExName).data());
    if (!HashBucketRandomFn)
    {
        print(ERROR("HashBucket: RtlRandomEx not exported"));
        return false;
    }

    return true;
}

// ci.dll's base from the kernel module list; needs this driver's loader entry relinked, which both call
// sites guarantee
static address FindCiBase()
{
    auto Ci = Decode(CiDllName);
    return EnumerateKProcess(Ci.data());
}

// Resolves the chain head from one signature: the rip-relative lea sits at match+3 with its disp32
// at +3 within the instruction. nullptr when the pattern does not match or the anchor is not a kernel pointer
template<size_t N>
static ULONGLONG* FindBucketListByPattern(address CiBase, const std::array<char, N> &Pattern)
{
    address Match = ScanModuleImage(CiBase, Pattern.data());
    if (!Match) return nullptr;

    ULONGLONG* List = (ULONGLONG*) ResolveRipRelative(Match, 3, 7);
    if (!List || !IsKernelPointer((uint64_t) List))
    {
        print(ERROR("HashBucket: resolved list anchor %p is not a kernel pointer"), (void*) List);
        return nullptr;
    }

    print(INFO("HashBucket: list anchor %p, first entry %p"), (void*) List, (void*) *List);
    return List;
}

// The chain head: dereferenced once for the first entry, then per-entry qword links. The 21H1
// pattern (1903-21H1, our 19041 included) is tried first, the 22H2 pattern as fallback
static ULONGLONG* FindKernelHashBucketList(address CiBase)
{
    if (!CiBase)
    {
        print(ERROR("HashBucket: ci.dll not found, nothing to scan"));
        return nullptr;
    }

    print(INFO("HashBucket: ci.dll at %p"), (void*) CiBase);

    if (ULONGLONG* List = FindBucketListByPattern(CiBase, Decode(KernelHashBucketListSignature21H1)))
        return List;
    if (ULONGLONG* List = FindBucketListByPattern(CiBase, Decode(KernelHashBucketListSignature22H2)))
        return List;

    print(ERROR("HashBucket: no signature matched in ci.dll"));
    return nullptr;
}

// wcswcs-style substring search, no CRT
static const wchar_t* WideContains(const wchar_t* Haystack, const wchar_t* Needle)
{
    if (!Haystack || !Needle || !*Needle) return nullptr;

    for (const wchar_t* h = Haystack; *h; ++h)
    {
        const wchar_t* a = h;
        for (const wchar_t* b = Needle; ; ++a, ++b)
        {
            if (!*b) return h;          // needle fully matched
            if (*a != *b) break;        // mismatch: move the window
            if (!*a) break;             // haystack ended mid-needle
        }
    }

    return nullptr;
}

static void ScrambleHashBucketHash(ULONGLONG* List, const wchar_t* DriverName)
{
    static uint32_t Seed = 0;

    ULONGLONG Current = *List;
    uint32_t Removed = 0, Walked = 0;

    while (Current && Walked < MaxHashBucketEntries)
    {
        if (IsKernelPointer(Current))
        {
            auto Name = (const wchar_t*) (Current + HashBucketEntryNameOffset);
            if (WideContains(Name, DriverName))
            {
                auto Hash = (uint8_t*) (Current + HashBucketEntryHashOffset);
                for (uint32_t j = 0; j < HashBucketEntryHashSize; ++j)
                {
                    if (!Seed) Seed = (uint32_t) ((size_t) &Seed ^ Hash[j]);
                    Hash[j] = (uint8_t) (HashBucketRandomFn(&Seed) % 255);
                }

                Removed++;
            }
        }

        Current = *(ULONGLONG*) Current;
        Walked++;
    }

    if (Walked >= MaxHashBucketEntries)
        print(WARN("HashBucket: walk hit the %u entry bound"), MaxHashBucketEntries);

    if (Removed)
        print(OK("HashBucket: scrambled %u of %u entries"), Removed, Walked);
    else
        print(WARN("HashBucket: no entry matching this driver was on the list"));
}

bool ClearKernelHashBucketList(win::DRIVER_OBJECT* DriverObject)
{
    if (!DriverObject || !DriverObject->DriverSection)
    {
        print(ERROR("HashBucket: no DriverObject or DriverSection (manual mapping?), nothing to clean"));
        return false;
    }

    auto Kldr = (_KLDR_DATA_TABLE_ENTRY *) DriverObject->DriverSection;
    if (!Kldr->BaseDllName.Buffer || !Kldr->BaseDllName.Length)
    {
        print(ERROR("HashBucket: loader entry has no BaseDllName"));
        return false;
    }

    if (!ResolveHashBucketRoutines())
        return false;

    address CiBase = FindCiBase();
    if (!CiBase)
    {
        print(ERROR("HashBucket: ci.dll not reachable from the module list"));
        return false;
    }

    ULONGLONG* List = FindKernelHashBucketList(CiBase);
    if (!List) return false;

    ScrambleHashBucketHash(List, Kldr->BaseDllName.Buffer);
    return true;
}

// One pass over the three load traces, each its own small cleaner above. Runs at load (step 0, wiping what
// earlier cycles left) and at unload (dropping records from previous cycles; whatever MM adds after the
// unload callback returns is cleaned by the next load's step 0)
bool CleanDriverTraces(win::DRIVER_OBJECT* DriverObject)
{
    bool PiDDB = ClearPiDDBCache(DriverObject);

#ifdef DEBUG
    // Only when the cleaner itself ran; release builds drop the call and the function with it
    VerifyPiDDBCache(DriverObject);
#endif

    bool MmU = ClearMmUnloadedDrivers(DriverObject);
    bool Hash = ClearKernelHashBucketList(DriverObject);
    print(INFO("CleanTraces: piddb %u, mmu %u, hashbucket %u"), (uint32_t) PiDDB, (uint32_t) MmU, (uint32_t) Hash);
    return PiDDB && MmU && Hash;
}
