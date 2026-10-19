// Driver hiding: unlink the image from PsLoadedModuleList and remove the driver object's name from
// the object directory. Raw kernel structures throughout, no mapping layer in between

// Driver-object hiding is done on raw object-manager structures only: no kernel routine is called anywhere
// here, just reads/writes on the _OBJECT_* layouts in Lib/structs.h. On Win10 19041 x64 the object manager
// always hands out an object body at Header + 0x30, so a body pointer minus 0x30 gets to the OBJECT_HEADER
constexpr uint32_t ObjectHeaderSize = 0x30;

// The object directory hashes every insert into 37 buckets on this build, matching the _OBJECT_DIRECTORY
// layout in Lib/structs.h
constexpr uint32_t ObjectDirectoryBuckets = 37;

// What HideDriverObject changed when it unlinked the driver object's name, so UnhideDriverObject can restore
// it exactly. Hides and unhides are strictly paired (DriverEntry pin / Unload release), one state is enough
struct HiddenObjectState
{
    VOID* Object = nullptr;                                 // the driver object body, used to reach the header again
    _OBJECT_DIRECTORY_ENTRY** Slot = nullptr;               // &HashBuckets[i] or &prev->ChainLink, the slot pointing at the entry
    _OBJECT_DIRECTORY_ENTRY* Entry = nullptr;               // the chain node that was unlinked
    _OBJECT_HEADER_NAME_INFO* NameInfo = nullptr;           // the name info whose QueryReferences was pinned
    uint32_t BucketIndex = 0;                               // bucket the entry was found in, prints only
    bool Saved = false;                                     // false while nothing is hidden
};

HiddenObjectState HiddenObject;

// Removes the driver object's name from the object directory, so \Driver walks (the reference tool's
// "validate driver objects" check) no longer see it. All manual: pin object + name info, splice the
// name's chain node out of the hash bucket
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

    // Sanity: a header with a null type pointer is not an object header we understand, and touching the
    // bucket chain on the wrong layout assumption would corrupt unrelated kernel structures
    if (!Header->Type)
    {
        print(ERROR("HideDriver: header %p has a null type, layout mismatch, aborting"), Header);
        return false;
    }

    // NameInfoOffset 0 means the object carries no name info, i.e. it is already nameless and has no chain
    // node anywhere: there is nothing to unlink and nothing to save
    if (!Header->NameInfoOffset)
    {
        print(WARN("HideDriver: object has no name info (already nameless), nothing to unlink"));
        return true;
    }

    // The name info lives in memory immediately BEFORE the header, at the byte offset stored in
    // NameInfoOffset (offsets shrink going backwards: NameInfoOffset 0x20 puts it right under the header)
    auto NameInfo = (_OBJECT_HEADER_NAME_INFO *) ((uint64_t) Header - Header->NameInfoOffset);
    print(INFO("HideDriver: name info %p (NameInfoOffset %u)"), NameInfo, Header->NameInfoOffset);

    if (!NameInfo->Directory)
    {
        print(WARN("HideDriver: name info %p has no directory, nothing to unlink"), NameInfo);
        return true;
    }

    // Pin the object: one extra reference, so teardown cannot free the chain node we are about to unlink
    __atomic_fetch_add(&Header->PointerCount, 1, __ATOMIC_SEQ_CST);
    print(INFO("HideDriver: object pinned, PointerCount incremented atomically"));

    // Pin the name info, mirroring what keeps a name alive normally
    __atomic_fetch_add(&NameInfo->QueryReferences, 1, __ATOMIC_SEQ_CST);
    print(INFO("HideDriver: name info pinned, QueryReferences incremented atomically"));

    // Walk the 37 buckets for the node whose Object is the driver object; the previous node (or the
    // bucket itself for a head) is the slot that points at it
    _OBJECT_DIRECTORY_ENTRY** Slot = nullptr;
    _OBJECT_DIRECTORY_ENTRY* Entry = nullptr;
    uint32_t FoundBucket = 0;
    for (uint32_t i = 0; i < ObjectDirectoryBuckets && !Entry; ++i)
    {
        _OBJECT_DIRECTORY_ENTRY* Previous = nullptr;    // null while Current is the bucket head
        for (_OBJECT_DIRECTORY_ENTRY* Current = NameInfo->Directory->HashBuckets[i]; Current;
             Previous = Current, Current = Current->ChainLink)
        {
            if (Current->Object == DriverObject)
            {
                Entry = Current;
                Slot = Previous ? &Previous->ChainLink : &NameInfo->Directory->HashBuckets[i];
                FoundBucket = i;
                break;
            }
        }
    }

    // Not in any bucket: the object was never inserted (or was already removed by something else). Undo the
    // pins we took, nothing is unlinked and nothing needs to be kept alive
    if (!Entry)
    {
        __atomic_fetch_add(&NameInfo->QueryReferences, -1, __ATOMIC_SEQ_CST);
        __atomic_fetch_add(&Header->PointerCount, -1, __ATOMIC_SEQ_CST);
        print(WARN("HideDriver: object not found in any hash bucket, pins undone"));
        return false;
    }

    print(INFO("HideDriver: entry %p found in bucket %u"), Entry, FoundBucket);

    // Save exactly what the unlink is about to destroy, so the relink can rebuild the identical chain
    HiddenObject.Object = DriverObject;
    HiddenObject.Slot = Slot;
    HiddenObject.Entry = Entry;
    HiddenObject.NameInfo = NameInfo;
    HiddenObject.BucketIndex = FoundBucket;
    HiddenObject.Saved = true;

    // Unlink: the slot now points at the entry's successor. Both pins keep the node and name info alive
    // while unlinked (no reference transition can free them). The object stays PERMANENT — IopDeleteDriver
    // makes it temporary itself before the final dereference, so no leak on unload either
    *Slot = Entry->ChainLink;
    print(OK("HideDriver: entry %p unlinked from bucket %u, object invisible to directory walks"),
          Entry, FoundBucket);
    return true;
}

// Inverse of HideDriverObject: puts the name's chain node back and releases both pins. Called at unload,
// after everything else; while this code runs, the saved state is the only map back into the directory
void UnhideDriverObject()
{
    if (!HiddenObject.Saved) return;

    // Splice into the CURRENT chain: overwriting the slot instead orphaned objects inserted during the
    // hide window. Byte-identical to the old relink when nothing changed. Known narrow race: if the
    // node whose ChainLink IS the saved slot was removed during the window, this write lands in freed pool
    HiddenObject.Entry->ChainLink = *HiddenObject.Slot;
    *HiddenObject.Slot = HiddenObject.Entry;

    // Release the pins in reverse order of taking them: name info first, then the object. Both decrements
    // are atomic for the same reason the increments were
    auto Header = (_OBJECT_HEADER *) ((uint64_t) HiddenObject.Object - ObjectHeaderSize);
    __atomic_fetch_add(&HiddenObject.NameInfo->QueryReferences, -1, __ATOMIC_SEQ_CST);
    __atomic_fetch_add(&Header->PointerCount, -1, __ATOMIC_SEQ_CST);

    print(OK("HideDriver: entry %p relinked into bucket %u, pins released"),
          HiddenObject.Entry, HiddenObject.BucketIndex);
    HiddenObject = {};
}

// Unlinks the driver from PsLoadedModuleList, so module walks no longer report it. DriverSection is the
// loader entry the kernel created at load time; a manually mapped driver has none and is skipped
bool UnlinkDriverFromModuleList(win::DRIVER_OBJECT *DriverObject)
{
    if (!DriverObject || !DriverObject->DriverSection)
    {
        print(ERROR("UnlinkDriver: no DriverObject or DriverSection, nothing to unlink"));
        return false;
    }

    auto Entry = (_KLDR_DATA_TABLE_ENTRY *) DriverObject->DriverSection;
    print(INFO("UnlinkDriver: entry %p, DllBase %p, name %ws"), (void *) Entry, Entry->DllBase,
          Entry->BaseDllName.Length ? Entry->BaseDllName.Buffer : L"");

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
    if (!Flink || !Blink || Flink == Links || Blink == Links)
    {
        print(ERROR("UnlinkDriver: entry links are not connected to the list"));
        return false;
    }

    Blink->Flink = Flink;
    Flink->Blink = Blink;
    Links->Flink = Links;
    Links->Blink = Links;

    // Verify: walk the list from the head and confirm the entry is gone. The bound keeps a corrupt list from
    // turning this into an endless walk
    _LIST_ENTRY *Head = (_LIST_ENTRY *) __imp_PsLoadedModuleList;
    constexpr uint32_t MaxWalk = 4096;
    uint32_t Count = 0;
    bool Found = false;
    for (_LIST_ENTRY *Current = Head->Flink; Current && Current != Head && Count < MaxWalk; Current = Current->Flink)
    {
        Count++;
        if (Current == Links)
        {
            Found = true;
            break;
        }
    }

    if (Found) print(ERROR("UnlinkDriver: VERIFY FAILED, entry still reachable from the list head"));
    else if (Count < MaxWalk) print(OK("UnlinkDriver: verified hidden, %u modules left"), Count);
    else print(WARN("UnlinkDriver: verify walk did not end cleanly after %u steps"), MaxWalk);
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
