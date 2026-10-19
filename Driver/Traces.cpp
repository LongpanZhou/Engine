// Trace cleaning. Three cleaners, all located by runtime signature + export table, no imports, no
// hardcoded offsets beyond the record layouts. Uses ScanModuleImage, ResolveRipRelative, GetNtoskrnl,
// EnumerateKProcess and the encoded strings.
// DEBUG builds only: the whole file compiles to nothing in release, so no trace-cleaning code
// (and no driver already in place during that boot) ever touches it

#ifdef DEBUG

// Shared helpers
// ---------------------------------------------------------------------------

// Canonical kernel pointers are FFFF8.... and up; guards every dereference below against garbage hits
constexpr uint64_t KernelPointerFloor = 0xFFFF800000000000;

bool IsKernelPointer(uint64_t Value)
{
    return Value >= KernelPointerFloor;
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

// Batch variant: one walk of ntoskrnl's export table resolves every name at once — the single
// variant above re-walks the whole table per symbol. Names[i] lands in Results[i]; a name
// not exported leaves that slot null
static void ResolveKernelSymbols(const char *const *Names, address *Results, uint32_t Count)
{
    address Nt = GetNtoskrnl();
    if (!Nt)
    {
        print(ERROR("ResolveKernelSymbols: ntoskrnl not found"));
        return;
    }

    FindFuncExportsBatch(Nt, Names, Results, Count);
}

// Cached addresses of the boot-stable scan targets below, the same three-state pattern as GetNtoskrnl:
// 0 = not scanned yet, Failed = scanned and missed (deterministic, never retried), else the address.
// Each target is a data global or image base that does not move for the rest of the boot
static uint64_t CachedPiDDBCacheList = 0;
static uint64_t CachedMmUnloadedDrivers = 0;
static uint64_t CachedMmLastUnloadedDriver = 0;
static uint64_t CachedCiBase = 0;
static uint64_t CachedHashBucketList = 0;

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

// ---------------------------------------------------------------------------
// Cleaner 1: PiDDBCacheTable
// ---------------------------------------------------------------------------

// Every load attempt is filed in CI's "PiDDB process cache" (an AVL tree plus a circular housekeeping
// list, both in ntoskrnl), which cache walks still see after everything else is scrubbed. Instead of a
// hand-rolled AVL delete (one wrong balance byte corrupts the table for CI itself) the entry is
// camouflaged in place: a benign entry's name + timestamp + load status is copied over ours
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
    uint64_t Cached = __atomic_load_n(&CachedPiDDBCacheList, __ATOMIC_SEQ_CST);
    if (Cached) return Cached == Failed ? nullptr : (_LIST_ENTRY *) Cached;

    address Match = ScanModuleImage(Nt, Decode(PiDDBCacheListSignature).data());
    if (!Match)
    {
        print(ERROR("PiDDB: list signature not found"));
        __atomic_store_n(&CachedPiDDBCacheList, Failed, __ATOMIC_SEQ_CST);
        return nullptr;
    }

    // The lea sits at the match itself; its disp32 at +3, the instruction is 7 bytes
    auto List = (_LIST_ENTRY *) ResolveRipRelative((const char *) Match, 3, 7);
    if (!IsKernelPointer((uint64_t) List))
    {
        print(ERROR("PiDDB: list head %p is not a kernel pointer"), (void *) List);
        __atomic_store_n(&CachedPiDDBCacheList, Failed, __ATOMIC_SEQ_CST);
        return nullptr;
    }

    __atomic_store_n(&CachedPiDDBCacheList, (uint64_t) List, __ATOMIC_SEQ_CST);
    return List;
}

// Copies Donor's identity onto Target if the name fits Target's own buffer. Every write is small and
// aligned, so a concurrent CI reader always sees a valid record
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

// Hides this driver's records by matching name only (earlier load cycles carry different timestamps).
// True when the walk completed; false means a missing structure, not that a record existed
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

    // Pass 1: find a donor — the first benign entry. All entries naming this driver share the name, so
    // one donor covers them all. A walk that stops early means the clean is not attempted at all
    _PiDDB_CACHE_ENTRY* Donor = nullptr;
    bool ListOk = ForEachPiDDBEntry(Head, [&](auto Entry) {
        if (!Donor && Entry->DriverName.Length && !WideNameEquals(&Entry->DriverName, &Kldr->BaseDllName))
            Donor = Entry;
    });

    if (!ListOk)
    {
        print(WARN("PiDDB: donor walk stopped early (damaged list), clean not attempted"));
        return false;
    }

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

    // A clean that stopped early leaves entries past the malformed one unvisited — that is a
    // partial clean, and the caller must not read it as a complete one
    if (!ListOk)
    {
        print(WARN("PiDDB: clean walk stopped early (damaged list), result may be partial"));
        return false;
    }
    return true;
}

// Debug-only self-check of the PiDDB cleaner, run right after it inside CleanDriverTraces: walks the
// housekeeping list again and confirms the stealth property directly — no entry still names this
// driver — over a fully intact list
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
static VOID* MmUnloadResource = nullptr;

// The one RtlRandomEx resolution, shared with the hash-bucket cleaner below (both randomize
// bytes through it); resolved once, by whichever cleaner needs it first
static RtlRandomEx_t RandomFn = nullptr;

static RtlRandomEx_t ResolveRandomFn()
{
    if (RandomFn) return RandomFn;

    RandomFn = (RtlRandomEx_t) ResolveKernelSymbol(Decode(RtlRandomExName).data());
    if (!RandomFn)
        print(ERROR("RtlRandomEx not exported, randomizing cleaners will fail"));
    return RandomFn;
}

static bool ResolveMmUnloadRoutines()
{
    if (MmUnloadFreeFn) return true;

    // One walk of the export table covers all three routines; RtlRandomEx resolves separately
    // above, shared with the hash-bucket cleaner. The decoded names are kept in named locals:
    // the arrays handed to the batch resolver must outlive its call
    auto AcquireName = Decode(ExAcquireResourceName);
    auto ReleaseName = Decode(ExReleaseResourceName);
    auto FreeName = Decode(ExFreePoolTagName);
    const char *Names[3] = { AcquireName.data(), ReleaseName.data(), FreeName.data() };
    address Found[3] = {};

    ResolveKernelSymbols(Names, Found, 3);
    MmUnloadAcquireFn = (ExAcquireResourceExclusiveLite_t) Found[0];
    MmUnloadReleaseFn = (ExReleaseResourceLite_t) Found[1];
    MmUnloadFreeFn = (ExFreePoolWithTag_t) Found[2];

    bool Ok = MmUnloadAcquireFn && MmUnloadReleaseFn && MmUnloadFreeFn && ResolveRandomFn();
    if (!Ok)
    {
        MmUnloadAcquireFn = nullptr;
        MmUnloadReleaseFn = nullptr;
        MmUnloadFreeFn = nullptr;
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
    uint64_t Cached = __atomic_load_n(&CachedMmUnloadedDrivers, __ATOMIC_SEQ_CST);
    if (Cached) return Cached == Failed ? nullptr : (_MM_UNLOADED_DRIVER *) Cached;

    address Match = ScanModuleImage(Nt, Decode(MmUnloadedDriversSignature).data());
    if (!Match)
    {
        print(ERROR("MmUnloaded: array signature not found"));
        __atomic_store_n(&CachedMmUnloadedDrivers, Failed, __ATOMIC_SEQ_CST);
        return nullptr;
    }

    auto Slot = (_MM_UNLOADED_DRIVER **) ResolveRipRelative(Match, 3, 7);
    if (!IsKernelPointer((uint64_t) Slot) || !IsKernelPointer((uint64_t) *Slot))
    {
        print(ERROR("MmUnloaded: slot %p dereferences to %p, not a kernel pointer"),
              Slot, Slot ? (void*) *Slot : nullptr);
        __atomic_store_n(&CachedMmUnloadedDrivers, Failed, __ATOMIC_SEQ_CST);
        return nullptr;
    }

    // The slot holds &MmUnloadedDrivers; the array it points at is a static ntoskrnl global
    __atomic_store_n(&CachedMmUnloadedDrivers, (uint64_t) *Slot, __ATOMIC_SEQ_CST);
    print(INFO("MmUnloaded: array %p"), (void*) *Slot);
    return *Slot;
}

// The used-slot count, behind the "cmp eax, 0x32"
static uint32_t* FindMmLastUnloadedDriver(address Nt)
{
    uint64_t Cached = __atomic_load_n(&CachedMmLastUnloadedDriver, __ATOMIC_SEQ_CST);
    if (Cached) return Cached == Failed ? nullptr : (uint32_t *) Cached;

    address Match = ScanModuleImage(Nt, Decode(MmLastUnloadedDriverSignature).data());
    if (!Match)
    {
        print(ERROR("MmUnloaded: count signature not found"));
        __atomic_store_n(&CachedMmLastUnloadedDriver, Failed, __ATOMIC_SEQ_CST);
        return nullptr;
    }

    // Only the POINTER is cached; the count itself changes with every unload and is read live.
    // The value check below validates the scan-time snapshot: a sane count there means the
    // slot really is MmLastUnloadedDriver, which stays true for the rest of the boot
    uint32_t* Count = (uint32_t*) ResolveRipRelative(Match, 2, 6);
    if (!IsKernelPointer((uint64_t) Count) || *Count > MmUnloadedDriversSize)
    {
        print(ERROR("MmUnloaded: count %p holds %u, not a plausible slot count"), Count, Count ? *Count : 0);
        __atomic_store_n(&CachedMmLastUnloadedDriver, Failed, __ATOMIC_SEQ_CST);
        return nullptr;
    }

    __atomic_store_n(&CachedMmLastUnloadedDriver, (uint64_t) Count, __ATOMIC_SEQ_CST);
    print(INFO("MmUnloaded: count %p = %u slots in use"), Count, *Count);
    return Count;
}

// A slot is empty when it carries no name
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

    // Remove every matching record in one pass: survivors compact down over the holes, past-count slots
    // are zeroed. The old code removed one record per pass and chased duplicates with up to four passes
static uint32_t RemoveMmUnloadRecords(const wchar_t* DriverName, _MM_UNLOADED_DRIVER* Table, uint32_t* Count, bool Filled)
{
    uint32_t Removed = 0;
    uint32_t Out = 0;      // the next slot a surviving record takes

    for (uint32_t Index = 0; Index < MmUnloadedDriversSize; ++Index)
    {
        auto Entry = &Table[Index];

        // A matching record is freed, zeroed and dropped; everything else compacts over the holes
        if (!IsUnloadEntryEmpty(Entry) && MmUnloadNameMatches(Entry, DriverName))
        {
            VOID* Buffer = Entry->Name.Buffer;
            *Entry = {};
            MmUnloadFreeFn(Buffer, MmDtPoolTag);
            Removed++;
            print(INFO("MmUnloaded: record %u removed"), Index);
            continue;
        }

        if (Out != Index)
        {
            Table[Out] = *Entry;      // survivor (or trailing empty) slides down
            *Entry = {};             // source slot cleared
        }
        Out++;
    }

    if (Removed)
    {
        // Full array: the count sat at the cap; otherwise the records were already counted.
        // Either way the count drops by exactly the number removed
        *Count = (Filled ? MmUnloadedDriversSize : *Count) - Removed;
    }

    return Removed;
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
            Entry->UnloadTime = PreviousTime - (RandomFn(&Seed) % 100) - 1;
        }

        PreviousTime = Entry->UnloadTime;
    }
}

// Removes this driver's records from MmUnloadedDrivers and fixes the count in one pass. True
// when the walk completed
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

    // One pass removes every matching record; duplicates no longer need the old four-pass chase
    uint32_t Removed = RemoveMmUnloadRecords(Kldr->BaseDllName.Buffer, Table, Count, IsMmUnloadedFilled(Table));
    bool Modified = Removed != 0;
    if (Modified) NormalizeMmUnloadTimes(Table);

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

// ci.dll keeps a chain of loaded kernel image hashes ("g_KernelHashBucketList") behind a rip-relative
// lea. Found by the 21H1 pattern (our 19041), 22H2 as fallback; base from the module walk. The
// reference cleaner scrambles the hash instead of unlinking: random bytes read as a stale record
constexpr uint32_t HashBucketEntryNameOffset = 0x48;
constexpr uint32_t HashBucketEntryHashOffset = 0x18;
constexpr uint32_t HashBucketEntryHashSize = 20;
constexpr uint32_t MaxHashBucketEntries = 0x800;

// RtlRandomEx resolves once and is shared with the MmUnloaded cleaner above
static bool ResolveHashBucketRoutines()
{
    return ResolveRandomFn() != nullptr;
}

// ci.dll's base from the kernel module list; needs this driver's loader entry relinked, which both call
// sites guarantee
static address FindCiBase()
{
    uint64_t Cached = __atomic_load_n(&CachedCiBase, __ATOMIC_SEQ_CST);
    if (Cached) return Cached == Failed ? nullptr : (address) Cached;

    auto Ci = Decode(CiDllName);
    address Base = EnumerateKProcess(Ci.data());

    // ci.dll loads at boot and is never unloaded or moved, so a miss is as deterministic as the
    // signature misses above and is not retried either
    __atomic_store_n(&CachedCiBase, Base ? (uint64_t) Base : Failed, __ATOMIC_SEQ_CST);
    return Base;
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
    uint64_t Cached = __atomic_load_n(&CachedHashBucketList, __ATOMIC_SEQ_CST);
    if (Cached) return Cached == Failed ? nullptr : (ULONGLONG *) Cached;

    if (!CiBase)
    {
        print(ERROR("HashBucket: ci.dll not found, nothing to scan"));
        __atomic_store_n(&CachedHashBucketList, Failed, __ATOMIC_SEQ_CST);
        return nullptr;
    }

    print(INFO("HashBucket: ci.dll at %p"), (void*) CiBase);

    if (ULONGLONG* List = FindBucketListByPattern(CiBase, Decode(KernelHashBucketListSignature21H1)))
    {
        __atomic_store_n(&CachedHashBucketList, (uint64_t) List, __ATOMIC_SEQ_CST);
        return List;
    }
    if (ULONGLONG* List = FindBucketListByPattern(CiBase, Decode(KernelHashBucketListSignature22H2)))
    {
        __atomic_store_n(&CachedHashBucketList, (uint64_t) List, __ATOMIC_SEQ_CST);
        return List;
    }

    print(ERROR("HashBucket: no signature matched in ci.dll"));
    __atomic_store_n(&CachedHashBucketList, Failed, __ATOMIC_SEQ_CST);
    return nullptr;
}

// Most characters a hash-bucket name may hold before the walk treats it as garbage. Mirrors the
// 512-byte bound ForEachPiDDBEntry puts on its names; image names are tens of characters, so a
// well-formed entry never reaches it
constexpr uint32_t MaxHashBucketNameChars = 512;

// wcswcs-style substring search, no CRT. Cap bounds how much of the haystack may be read: a
// corrupt, never-terminating name reads at most Cap characters and then reads as no-match,
// instead of walking off into unmapped memory. ForEachPiDDBEntry bounds its names through the
// UNICODE_STRING length; here the cap is the only bound available
static const wchar_t* WideContains(const wchar_t* Haystack, const wchar_t* Needle, uint32_t Cap)
{
    if (!Haystack || !Needle || !*Needle) return nullptr;

    for (const wchar_t* h = Haystack; (uint32_t)(h - Haystack) < Cap && *h; ++h)
    {
        const wchar_t* a = h;
        for (const wchar_t* b = Needle; ; ++a, ++b)
        {
            if (!*b) return h;                             // needle fully matched
            if ((uint32_t)(a - Haystack) >= Cap) break;    // cap checked before the read
            if (*a != *b) break;                           // mismatch: move the window
            if (!*a) break;                                // haystack ended mid-needle
        }
    }

    return nullptr;
}

// Scrambles the hash of every entry whose name contains DriverName; entries stay on the list, the
// bytes just read as a stale record
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
            // An odd name pointer means the entry is garbage on an axis the cap below does not
            // cover; a real UNICODE_STRING buffer is always 2-byte aligned
            if (!((uint64_t) Name & 1) && WideContains(Name, DriverName, MaxHashBucketNameChars))
            {
                auto Hash = (uint8_t*) (Current + HashBucketEntryHashOffset);
                for (uint32_t j = 0; j < HashBucketEntryHashSize; ++j)
                {
                    if (!Seed) Seed = (uint32_t) ((size_t) &Seed ^ Hash[j]);
                    Hash[j] = (uint8_t) (RandomFn(&Seed) % 255);
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
    // TEMPORARY: testing one cleaner at a time — currently ClearPiDDBCache only (the camouflage clean);
    // the other two cleaners are commented out until their turn. Only-true stand-ins keep the summary
    // line and return value unchanged. (PiDDB note: a donor name longer than this driver's entry buffer
    // leaves that entry in place — that is what VerifyPiDDBCache checks)
    bool PiDDB = ClearPiDDBCache(DriverObject);
    // bool MmU = ClearMmUnloadedDrivers(DriverObject);
    // bool Hash = ClearKernelHashBucketList(DriverObject);
    bool MmU = true, Hash = true;   // not exercised in this build

#ifdef DEBUG
    // Only when the cleaner itself ran; release builds drop the call
    // VerifyPiDDBCache(DriverObject);
#endif
    print(INFO("CleanTraces: piddb %u, mmu %u, hashbucket %u"), (uint32_t) PiDDB, (uint32_t) MmU, (uint32_t) Hash);
    return PiDDB && MmU && Hash;
}

#endif // DEBUG
