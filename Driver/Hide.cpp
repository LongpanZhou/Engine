// Driver hiding: unlink the image from PsLoadedModuleList and remove the driver object's name from
// the object directory. Raw kernel structures throughout, no mapping layer in between

// Driver-object hiding is done on raw object-manager structures only: no kernel routine is called anywhere
// here, just reads/writes on the _OBJECT_* layouts in Lib/structs.h. On Win10 19041/19045 x64 the object
// manager always hands out an object body at Header + 0x30, so a body pointer minus 0x30 gets to the header
constexpr uint32_t ObjectHeaderSize = 0x30;

// The object directory hashes every insert into 37 buckets on this build, matching the _OBJECT_DIRECTORY
// layout in Lib/structs.h
constexpr uint32_t ObjectDirectoryBuckets = 37;

// OBJECT_HEADER.InfoMask bits. InfoMask selects which optional headers precede the object header; the
// name info is immediately below it unless creator info is present too, then creator info is directly
// below the header and name info is one 0x20-byte slot further back
constexpr UCHAR ObjectInfoCreator = 0x01;
constexpr UCHAR ObjectInfoName = 0x02;
constexpr uint32_t ObjectCreatorInfoSize = 0x20;

// A malformed object-directory chain must not turn a walk into an endless loop
constexpr uint32_t MaxObjectDirectoryEntries = 0x1000;

constexpr uint64_t ObjectKernelFloor = 0xFFFF800000000000ull;

static_assert(sizeof(_OBJECT_HEADER) == 0x30, "unexpected OBJECT_HEADER layout");
static_assert(sizeof(_OBJECT_HEADER_NAME_INFO) == 0x20, "unexpected OBJECT_HEADER_NAME_INFO layout");
static_assert(sizeof(_OBJECT_DIRECTORY_ENTRY) == 0x10, "unexpected OBJECT_DIRECTORY_ENTRY layout");

static bool IsObjectKernelPointer(uint64_t Value)
{
    return Value >= ObjectKernelFloor;
}

// Returns the name info only when InfoMask says it exists and the record itself looks sane. The caller
// still decides whether a missing Directory means "nothing to unlink" or a malformed object
static _OBJECT_HEADER_NAME_INFO* GetObjectNameInfo(_OBJECT_HEADER* Header)
{
    if (!Header || !(Header->InfoMask & ObjectInfoName))
        return nullptr;

    // Name info is the slot immediately below the header, or one creator-info slot further back when
    // InfoMask bit 0x1 is set (the 0x3 index into ObpInfoMaskToOffset)
    const uint32_t Offset = (Header->InfoMask & ObjectInfoCreator)
        ? ObjectCreatorInfoSize + (uint32_t) sizeof(_OBJECT_HEADER_NAME_INFO)
        : (uint32_t) sizeof(_OBJECT_HEADER_NAME_INFO);

    auto NameInfo = (_OBJECT_HEADER_NAME_INFO*) ((uint64_t) Header - Offset);
    if (!IsObjectKernelPointer((uint64_t) NameInfo))
        return nullptr;

    const auto& Name = NameInfo->Name;
    if ((Name.Length & 1) || Name.Length > 512 || Name.MaximumLength < Name.Length ||
        (Name.Length && !IsObjectKernelPointer((uint64_t) Name.Buffer)))
        return nullptr;

    return NameInfo;
}

// Result of one bounded walk over every bucket in an object directory
struct ObjectDirectoryLookup
{
    _OBJECT_DIRECTORY_ENTRY* Entry = nullptr;
    _OBJECT_DIRECTORY_ENTRY** Slot = nullptr;   // &HashBuckets[i] or &previous->ChainLink
    uint32_t Bucket = 0;
    uint32_t Walked = 0;                         // entries visited, for diagnostics
    bool WalkOk = true;                          // false: malformed link or entry bound hit
};

// Finds DriverObject in its own directory and remembers the slot that points at the entry. Raw list
// walk only: no Ob* routine, no Rtl* helper
static ObjectDirectoryLookup FindObjectDirectoryEntry(
    _OBJECT_HEADER_NAME_INFO* NameInfo,
    win::DRIVER_OBJECT* DriverObject)
{
    ObjectDirectoryLookup Result{};

    if (!NameInfo || !DriverObject || !NameInfo->Directory ||
        !IsObjectKernelPointer((uint64_t) NameInfo->Directory))
    {
        Result.WalkOk = false;
        return Result;
    }

    uint32_t Walked = 0;
    for (uint32_t i = 0; i < ObjectDirectoryBuckets; ++i)
    {
        _OBJECT_DIRECTORY_ENTRY* Previous = nullptr;
        for (_OBJECT_DIRECTORY_ENTRY* Current = NameInfo->Directory->HashBuckets[i];
             Current;
             Previous = Current, Current = Current->ChainLink)
        {
            if (++Walked > MaxObjectDirectoryEntries ||
                !IsObjectKernelPointer((uint64_t) Current))
            {
                Result.Walked = Walked;
                Result.WalkOk = false;
                return Result;
            }

            if (Current->Object == DriverObject)
            {
                Result.Entry = Current;
                Result.Slot = Previous ? &Previous->ChainLink : &NameInfo->Directory->HashBuckets[i];
                Result.Bucket = i;
                Result.Walked = Walked;
                return Result;
            }
        }
    }

    Result.Walked = Walked;
    return Result;
}

// What HideDriverObject changed when it unlinked the driver object's name, so UnhideDriverObject can restore
// it exactly. Hides and unhides are strictly paired (DriverEntry pin / Unload release), one state is enough
struct HiddenObjectState
{
    VOID* Object = nullptr;                                 // the driver object body, used to reach the header again
    _OBJECT_DIRECTORY_ENTRY** Slot = nullptr;               // &HashBuckets[i] or &prev->ChainLink, the slot pointing at the entry
    _OBJECT_DIRECTORY_ENTRY* Entry = nullptr;               // the chain node that was unlinked
    _OBJECT_HEADER_NAME_INFO* NameInfo = nullptr;           // the name info whose ReferenceCount was pinned
    uint32_t BucketIndex = 0;                               // bucket the entry was found in, prints only
    bool Saved = false;                                     // false while nothing is hidden
};

HiddenObjectState HiddenObject;

// Removes the driver object's name from the object directory, so \Driver walks (the reference tool's
// "validate driver objects" check) no longer see it. All manual: find the name info, pin object + name
// info, then splice the name's chain node out of the hash bucket
bool HideDriverObject(win::DRIVER_OBJECT *DriverObject)
{
    if (!DriverObject) return false;
    if (HiddenObject.Saved)
    {
        print(INFO("HideDriver: object %p already hidden, nothing to do"), (void*) DriverObject);
        return true;
    }

    // Body to header: the OBJECT_HEADER sits 0x30 bytes before the body pointer
    auto Header = (_OBJECT_HEADER *) ((uint64_t) DriverObject - ObjectHeaderSize);
    print(INFO("HideDriver: object %p, header %p"), (void*) DriverObject, Header);

    // A live object must have a positive pointer count. This also rejects an obviously wrong body/header
    // relationship before the InfoMask read below is trusted
    if (Header->PointerCount <= 0)
    {
        print(ERROR("HideDriver: header %p has an invalid PointerCount, layout mismatch, aborting"), Header);
        return false;
    }

    // No name bit means the object is already nameless and has no chain node anywhere: nothing to unlink
    if (!(Header->InfoMask & ObjectInfoName))
    {
        print(WARN("HideDriver: object has no name info (already nameless), nothing to unlink"));
        return true;
    }

    auto NameInfo = GetObjectNameInfo(Header);
    if (!NameInfo)
    {
        print(ERROR("HideDriver: header %p name info is implausible, layout mismatch, aborting"), Header);
        return false;
    }

    print(INFO("HideDriver: name info %p (InfoMask %02x)"), NameInfo, Header->InfoMask);

    if (!NameInfo->Directory)
    {
        print(WARN("HideDriver: name info %p has no directory, nothing to unlink"), NameInfo);
        return true;
    }

    // Locate the directory entry first; the pins below are only needed once there is something to unlink
    auto Lookup = FindObjectDirectoryEntry(NameInfo, DriverObject);
    if (!Lookup.WalkOk)
    {
        print(ERROR("HideDriver: directory walk was malformed or exceeded %u entries, aborting"),
              MaxObjectDirectoryEntries);
        return false;
    }

    if (!Lookup.Entry)
    {
        print(WARN("HideDriver: object not found in any hash bucket, nothing to unlink"));
        return false;
    }

    print(INFO("HideDriver: entry %p found in bucket %u"), Lookup.Entry, Lookup.Bucket);

    // Pin the object: one extra reference, so teardown cannot free the chain node we are about to unlink
    __atomic_fetch_add(&Header->PointerCount, 1, __ATOMIC_SEQ_CST);
    print(INFO("HideDriver: object pinned, PointerCount incremented atomically"));

    // Pin the name info, mirroring what keeps a name alive normally
    __atomic_fetch_add(&NameInfo->ReferenceCount, 1, __ATOMIC_SEQ_CST);
    print(INFO("HideDriver: name info pinned, ReferenceCount incremented atomically"));

    // Save exactly what the unlink is about to destroy, so the relink can rebuild the identical chain
    HiddenObject.Object = DriverObject;
    HiddenObject.Slot = Lookup.Slot;
    HiddenObject.Entry = Lookup.Entry;
    HiddenObject.NameInfo = NameInfo;
    HiddenObject.BucketIndex = Lookup.Bucket;
    HiddenObject.Saved = true;

    // Unlink: the slot now points at the entry's successor. Both pins keep the node and name info alive
    // while unlinked (no reference transition can free them). The object stays PERMANENT — IopDeleteDriver
    // makes it temporary itself before the final dereference, so no leak on unload either
    *HiddenObject.Slot = HiddenObject.Entry->ChainLink;
    print(OK("HideDriver: entry %p unlinked from bucket %u, object invisible to directory walks"),
          HiddenObject.Entry, HiddenObject.BucketIndex);
    return true;
}

// Inverse of HideDriverObject: puts the name's chain node back and releases both pins. Called at unload,
// after everything else; while this code runs, the saved state is the only map back into the directory.
// Returns true when a saved hide state was restored, false when there was nothing to undo
bool UnhideDriverObject()
{
    if (!HiddenObject.Saved) return false;

    if (!HiddenObject.Object || !HiddenObject.Entry || !HiddenObject.Slot || !HiddenObject.NameInfo ||
        HiddenObject.Entry->Object != HiddenObject.Object)
    {
        print(ERROR("HideDriver: saved state is incomplete, cannot unhide"));
        return false;
    }

    // Splice into the CURRENT chain: overwriting the slot instead orphaned objects inserted during the
    // hide window. Byte-identical to the old relink when nothing changed. Known narrow race: if the
    // node whose ChainLink IS the saved slot was removed during the window, this write lands in freed pool
    HiddenObject.Entry->ChainLink = *HiddenObject.Slot;
    *HiddenObject.Slot = HiddenObject.Entry;

    // Release the pins in reverse order of taking them: name info first, then the object. Both decrements
    // are atomic for the same reason the increments were
    auto Header = (_OBJECT_HEADER *) ((uint64_t) HiddenObject.Object - ObjectHeaderSize);
    __atomic_fetch_add(&HiddenObject.NameInfo->ReferenceCount, -1, __ATOMIC_SEQ_CST);
    __atomic_fetch_add(&Header->PointerCount, -1, __ATOMIC_SEQ_CST);

    print(OK("HideDriver: entry %p relinked into bucket %u, pins released"),
          HiddenObject.Entry, HiddenObject.BucketIndex);
    HiddenObject = {};
    return true;
}

#ifdef DEBUG
// Self-check for HideDriverObject/UnhideDriverObject. Raw object-directory walk only: no Ob*/Rtl* call,
// no handle or object-manager routine. ExpectedHidden checks that the driver object is unreachable from
// its own directory and that the saved state and pins are consistent; false checks the inverse after
// UnhideDriverObject
bool VerifyHideDriverObject(win::DRIVER_OBJECT* DriverObject, bool ExpectedHidden)
{
    if (!DriverObject)
    {
        print(ERROR("VerifyHide: null DriverObject"));
        return false;
    }

    auto Header = (_OBJECT_HEADER *) ((uint64_t) DriverObject - ObjectHeaderSize);
    if (Header->PointerCount <= 0)
    {
        print(ERROR("VerifyHide: header %p has an invalid PointerCount"), Header);
        return false;
    }

    if (!(Header->InfoMask & ObjectInfoName))
    {
        if (HiddenObject.Saved)
        {
            print(ERROR("VerifyHide: hidden state is saved, but the object has no name info"));
            return false;
        }

        print(INFO("VerifyHide: object is nameless, nothing to verify"));
        return true;
    }

    auto NameInfo = GetObjectNameInfo(Header);
    if (!NameInfo || !NameInfo->Directory)
    {
        print(ERROR("VerifyHide: name info %p is invalid"), (void *) NameInfo);
        return false;
    }

    if (ExpectedHidden)
    {
        if (!HiddenObject.Saved || HiddenObject.Object != DriverObject ||
            !HiddenObject.Entry || HiddenObject.Entry->Object != DriverObject ||
            HiddenObject.NameInfo != NameInfo)
        {
            print(ERROR("VerifyHide: expected hidden, but saved state does not match the object"));
            return false;
        }

        if (NameInfo->ReferenceCount == 0)
        {
            print(ERROR("VerifyHide: name info is not pinned (ReferenceCount 0)"));
            return false;
        }
    }
    else if (HiddenObject.Saved)
    {
        print(ERROR("VerifyHide: expected visible, but hide state is still saved"));
        return false;
    }

    auto Lookup = FindObjectDirectoryEntry(NameInfo, DriverObject);
    if (!Lookup.WalkOk)
    {
        print(ERROR("VerifyHide: directory walk was malformed or exceeded %u entries"),
              MaxObjectDirectoryEntries);
        return false;
    }

    if (ExpectedHidden)
    {
        if (Lookup.Entry)
        {
            print(ERROR("VerifyHide: FAILED, entry %p is still reachable in bucket %u"),
                  (void *) Lookup.Entry, Lookup.Bucket);
            return false;
        }

        print(OK("VerifyHide: hidden OK (%u directory entries walked, no match)"), Lookup.Walked);
        return true;
    }

    if (!Lookup.Entry)
    {
        print(ERROR("VerifyHide: FAILED, driver object %p is not reachable from its directory"),
              (void *) DriverObject);
        return false;
    }

    print(OK("VerifyHide: visible OK (entry %p in bucket %u, %u entries walked)"),
          (void *) Lookup.Entry, Lookup.Bucket, Lookup.Walked);
    return true;
}
#endif

// Unlinks the driver from PsLoadedModuleList, so module walks no longer report it. DriverSection is the
// loader entry the kernel created at load time; a manually mapped driver has none and is skipped
bool UnlinkDriverFromModuleList(win::DRIVER_OBJECT *DriverObject)
{
    constexpr uint64_t KernelFloor = 0xFFFF800000000000ull;

    if (!DriverObject || !DriverObject->DriverSection)
    {
        print(ERROR("UnlinkDriver: no DriverObject or DriverSection, nothing to unlink"));
        return false;
    }

    if ((uint64_t) DriverObject < KernelFloor ||
        (uint64_t) DriverObject->DriverSection < KernelFloor)
    {
        print(ERROR("UnlinkDriver: DriverObject %p or DriverSection %p is not a kernel pointer"),
              (void *) DriverObject, DriverObject->DriverSection);
        return false;
    }

    auto Entry = (_KLDR_DATA_TABLE_ENTRY *) DriverObject->DriverSection;
    ::print(INFO("UnlinkDriver: entry %p, DllBase %p, name %wZ"), (void *) Entry, Entry->DllBase,
            &Entry->BaseDllName);

    // Sanity: the loader entry must describe the driver image itself
    if ((address) Entry->DllBase != DriverObject->DriverStart)
    {
        print(ERROR("UnlinkDriver: entry DllBase %p does not match DriverStart %p"),
              Entry->DllBase, DriverObject->DriverStart);
        return false;
    }

    // Bypass the entry, then self-link its own pointers so a walk starting inside it goes nowhere.
    // Unlocked on purpose (PsLoadedModuleResource is not held): races a concurrent load/unload only on
    // a busy thread — tolerated at DriverEntry on a quiet system, and verified below
    _LIST_ENTRY *Links = &Entry->InLoadOrderLinks;
    _LIST_ENTRY *Flink = Links->Flink;
    _LIST_ENTRY *Blink = Links->Blink;

    // A malformed list must not be made worse. Besides non-null/self links, require the neighbors to
    // agree that this entry is between them; the writes below assume exactly that topology
    if ((uint64_t) Flink < KernelFloor || (uint64_t) Blink < KernelFloor ||
        Flink == Links || Blink == Links)
    {
        print(ERROR("UnlinkDriver: entry links %p/%p are not connected to the list"),
              (void *) Flink, (void *) Blink);
        return false;
    }

    if (Flink->Blink != Links || Blink->Flink != Links)
    {
        print(ERROR("UnlinkDriver: neighbor links are inconsistent (%p->Blink %p, %p->Flink %p)"),
              (void *) Flink, (void *) Flink->Blink, (void *) Blink, (void *) Blink->Flink);
        return false;
    }

    Blink->Flink = Flink;
    Flink->Blink = Blink;
    Links->Flink = Links;
    Links->Blink = Links;

    // Verify: walk the list from the head and confirm the entry is gone. The walk must terminate at
    // the head, not at a null/damaged link or the entry bound; otherwise the check is inconclusive
    _LIST_ENTRY *Head = (_LIST_ENTRY *) __imp_PsLoadedModuleList;
    if ((uint64_t) Head < KernelFloor)
    {
        print(ERROR("UnlinkDriver: PsLoadedModuleList %p is not a kernel pointer, cannot verify"),
              (void *) Head);
        return false;
    }

    constexpr uint32_t MaxWalk = 4096;
    uint32_t Count = 0;
    bool Found = false;
    bool Complete = false;
    for (_LIST_ENTRY *Current = Head->Flink; Current && Count <= MaxWalk; Current = Current->Flink)
    {
        if (Current == Head)
        {
            Complete = true;
            break;
        }

        if ((uint64_t) Current < KernelFloor)
        {
            print(ERROR("UnlinkDriver: verify walk hit non-kernel link %p after %u entries"),
                  (void *) Current, Count);
            break;
        }

        ++Count;
        if (Current == Links)
        {
            Found = true;
            break;
        }
    }

    if (Found)
    {
        print(ERROR("UnlinkDriver: VERIFY FAILED, entry still reachable from the list head"));
        return false;
    }

    if (!Complete)
    {
        print(ERROR("UnlinkDriver: VERIFY FAILED, list walk did not return to the head after %u entries"), Count);
        return false;
    }

    print(OK("UnlinkDriver: verified hidden, %u modules left"), Count);
    return true;
}

// Re-attaches the loader entry at the PsLoadedModuleList head. MUST run at unload into Mm: a detached
// entry leaves the loader-list bookkeeping inconsistent and the NEXT load bugchecks 0x1A (0x2101)
// inside MiProcessLoaderEntry, before DriverEntry even runs
bool RelinkDriverIntoModuleList(win::DRIVER_OBJECT *DriverObject)
{
    if (!DriverObject || !DriverObject->DriverSection)
    {
        print(ERROR("RelinkDriver: no DriverObject or DriverSection, nothing to relink"));
        return false;
    }

    auto Entry = (_KLDR_DATA_TABLE_ENTRY *) DriverObject->DriverSection;
    _LIST_ENTRY *Links = &Entry->InLoadOrderLinks;
    _LIST_ENTRY *Head = (_LIST_ENTRY *) __imp_PsLoadedModuleList;

    // Attached entries are never self-linked (even a one-module list wraps through the head), so one
    // compare replaces the old head walk
    if (Links->Flink != Links)
    {
        print(INFO("RelinkDriver: entry %p already attached, skipping"), (void *) Entry);
        return true;
    }

    if (!Head->Flink)
    {
        print(ERROR("RelinkDriver: list head Flink is null, list looks corrupt"));
        return false;
    }

    // Splice at the head, same spot the kernel uses for freshly loaded images. No stale-neighbor bookkeeping, so
    // the result stays valid even though the list changed while the entry was detached
    Links->Blink = Head;
    Links->Flink = Head->Flink;
    Head->Flink->Blink = Links;
    Head->Flink = Links;

    print(OK("RelinkDriver: entry %p re-attached at the list head"), (void *) Entry);
    return true;
}
