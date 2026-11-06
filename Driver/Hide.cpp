// Driver hiding: unlink the image from PsLoadedModuleList, remove the driver object's name from the
// object directory, and erase the mapped image's PE headers. Raw kernel structures throughout, no
// mapping layer in between

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

// ObjectKernelFloor / IsObjectKernelPointer live in Lib/pure.h (host-unit-tested).

static_assert(sizeof(_OBJECT_HEADER) == 0x30, "unexpected OBJECT_HEADER layout");
static_assert(sizeof(_OBJECT_HEADER_NAME_INFO) == 0x20, "unexpected OBJECT_HEADER_NAME_INFO layout");
static_assert(sizeof(_OBJECT_DIRECTORY_ENTRY) == 0x10, "unexpected OBJECT_DIRECTORY_ENTRY layout");

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
// it exactly. One hide is tracked at a time; UnhideDriverObject clears the state
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

// Removes the driver object's name from the object directory, so \Driver walks (an external
// driver-object check) no longer see it. All manual: find the name info, pin object + name
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
    // while unlinked (no reference transition can free them). The object stays PERMANENT - IopDeleteDriver
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
    // hide window. Known narrow race: if the node whose ChainLink IS the saved slot was removed during
    // the window, this write lands in freed pool
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
    print(INFO("UnlinkDriver: entry %p, DllBase %p, name %wZ"), (void *) Entry, Entry->DllBase,
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
    // a busy thread - tolerated at DriverEntry on a quiet system, and verified below
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
    // compare suffices
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

// ---------------------------------------------------------------------------
// PE header removal
//
// A scanner that knows where the driver was mapped often starts by reading MZ/PE at DllBase. This is
// only safe for a manual map: after a normal DriverEntry returns, IopLoadDriver still calls
// MiFreeDriverInitialization -> MiSnapDriverRange -> RtlImageNtHeader, so clearing the header first
// bugchecks 0x7E. Manual maps have no IopLoadDriver cleanup; if the mapper calls DriverExit, the saved
// copy is restored, otherwise the header stays erased for the lifetime of the mapping.
//
// The write goes through CR0.WP because the image header page is mapped read-only. Only the header
// bytes are touched; the first section starts at 0x1000.
// ---------------------------------------------------------------------------

extern "C" _IMAGE_DOS_HEADER __ImageBase;

constexpr uint32_t PeHeaderMaxBytes = 0x1000;
constexpr uint32_t PeDosMagic = 0x5A4D;
constexpr uint32_t PeNtSignature = 0x00004550;

static uint8_t SavedPeHeader[PeHeaderMaxBytes];
static uint32_t SavedPeHeaderSize = 0;
static address SavedPeHeaderBase = nullptr;

// Normal loads know their image base from the driver object. A manual map has no driver object, so
// use the linker-provided image base symbol (the mapper relocates it like any other image address).
static address GetOwnImageBase(win::DRIVER_OBJECT* DriverObject)
{
    if (DriverObject && DriverObject->DriverStart)
        return (address) (uint64_t) DriverObject->DriverStart;

    return (address) (uint64_t) &__ImageBase;
}

// Validates the mapped image before anything is overwritten. Size is capped to the first page so a
// malformed SizeOfHeaders cannot make the erase walk into the first section.
static bool GetPeHeaderRange(address Base, uint32_t& Size)
{
    if ((uint64_t) Base < 0xFFFF800000000000ull)
        return false;

    // kdmapper's default mapping skips the header page and reports the allocation start as image
    // base + 0x1000. Base can then point at an unrelated pool block, or at an unmapped hole. Never
    // dereference it before checking the page tables.
    if (!IsAddressValid(Base, GetSystemCr3()))
        return false;

    const auto Dos = (const _IMAGE_DOS_HEADER *) (uint64_t) Base;
    if (Dos->e_magic != PeDosMagic)
        return false;

    const uint32_t NtOffset = (uint32_t) Dos->e_lfanew;
    if (NtOffset < (uint32_t) sizeof(_IMAGE_DOS_HEADER) ||
        NtOffset > PeHeaderMaxBytes - (uint32_t) sizeof(_IMAGE_NT_HEADERS64))
        return false;

    const auto Nt = (const _IMAGE_NT_HEADERS64 *) ((uint64_t) Base + NtOffset);
    if (Nt->Signature != PeNtSignature ||
        Nt->OptionalHeader.Magic != 0x20B)
        return false;

    uint32_t HeaderBytes = Nt->OptionalHeader.SizeOfHeaders;
    if (HeaderBytes < NtOffset + (uint32_t) sizeof(_IMAGE_NT_HEADERS64))
        return false;
    if (HeaderBytes > PeHeaderMaxBytes)
        HeaderBytes = PeHeaderMaxBytes;

    Size = HeaderBytes;
    return true;
}

// Writes through the read-only image mapping. Restores the original CR0 value even when Bytes is null
// (zero fill). The size is bounded by GetPeHeaderRange before this is called.
static bool WritePeHeaderBytes(address Base, const uint8_t* Bytes, uint32_t Size)
{
    if (!Base || !Size || Size > PeHeaderMaxBytes)
        return false;

    const arch::cr0 OriginalCr0 = intrin::read_cr0();
    arch::cr0 WritableCr0 = OriginalCr0;
    WritableCr0.write_protect = 0;
    intrin::write_cr0(WritableCr0);

    auto Dest = (volatile uint8_t *) (uint64_t) Base;
    for (uint32_t i = 0; i < Size; ++i)
        Dest[i] = Bytes ? Bytes[i] : 0;

    intrin::write_cr0(OriginalCr0);
    return true;
}

// Erases the PE headers from the mapped image. Safe to call more than once for the same image; the
// saved copy is the only thing DriverExit needs to restore a normal load.
bool ErasePeHeader(win::DRIVER_OBJECT* DriverObject)
{
    const address Base = GetOwnImageBase(DriverObject);

    if (SavedPeHeaderBase)
    {
        if (SavedPeHeaderBase == Base)
            return true;

        print(WARN("PE: another image header is already saved, refusing to overwrite it"));
        return false;
    }

    if ((uint64_t) Base < 0xFFFF800000000000ull)
    {
        print(ERROR("PE: image base %p is not a kernel address"), (void *) Base);
        return false;
    }

    uint32_t Size = 0;
    if (!GetPeHeaderRange(Base, Size))
    {
        // kdmapper's default mapping does not copy the header page at all. Base can then be an
        // unmapped hole or an unrelated pool allocation; either way there is no header of ours to
        // erase. A present page that does start with MZ but has a broken PE header is an error.
        if (!IsAddressValid(Base, GetSystemCr3()) ||
            ((const _IMAGE_DOS_HEADER *) (uint64_t) Base)->e_magic != PeDosMagic)
        {
            print(INFO("PE: no header at image base %p, already absent"), (void *) Base);
            return true;
        }

        print(ERROR("PE: invalid PE header at image base %p, refusing to erase"), (void *) Base);
        return false;
    }

    auto Source = (const volatile uint8_t *) (uint64_t) Base;
    for (uint32_t i = 0; i < Size; ++i)
        SavedPeHeader[i] = Source[i];

    if (!WritePeHeaderBytes(Base, nullptr, Size))
        return false;

    SavedPeHeaderBase = Base;
    SavedPeHeaderSize = Size;
    print(OK("PE: erased %u header bytes at %p"), Size, (void *) Base);
    return true;
}

// Restores the bytes saved by ErasePeHeader. Returns true when there was nothing to restore, so
// DriverExit can call it unconditionally.
bool RestorePeHeader()
{
    if (!SavedPeHeaderBase || !SavedPeHeaderSize)
        return true;

    if (!WritePeHeaderBytes(SavedPeHeaderBase, SavedPeHeader, SavedPeHeaderSize))
        return false;

    print(OK("PE: restored %u header bytes at %p"), SavedPeHeaderSize, (void *) SavedPeHeaderBase);
    SavedPeHeaderBase = nullptr;
    SavedPeHeaderSize = 0;
    return true;
}

// Debug-only check: MZ and e_lfanew are the two fields every PE walker starts with.
bool VerifyPeHeaderRemoved(win::DRIVER_OBJECT* DriverObject)
{
    const address Base = SavedPeHeaderBase ? SavedPeHeaderBase : GetOwnImageBase(DriverObject);
    if (!Base || (uint64_t) Base < 0xFFFF800000000000ull)
        return false;

    // A mapper that omitted the header page leaves Base unmapped or pointing at other pool memory.
    // There is no DOS header there to find, so the no-MZ check below must not dereference it.
    if (!IsAddressValid(Base, GetSystemCr3()))
        return true;

    const auto Dos = (const _IMAGE_DOS_HEADER *) (uint64_t) Base;
    if (Dos->e_magic != PeDosMagic)
        return true;

    // MZ is still present: require the NT offset to be gone as well.
    return Dos->e_lfanew == 0;
}

#ifdef DEBUG
// Debug-only self-test: the driver's loader entry is in PsLoadedModuleList,
// unlink removes it, relink restores it. A manual-map build has no loader entry
// (DriverSection == null) and skips.
static bool IsDriverInModuleList(win::DRIVER_OBJECT* DriverObject)
{
    if (!DriverObject || !DriverObject->DriverSection) return false;

    auto* Entry = (_KLDR_DATA_TABLE_ENTRY*) DriverObject->DriverSection;
    auto* Head = (_LIST_ENTRY*) __imp_PsLoadedModuleList;
    if (!Head) return false;

    for (auto* Cur = Head->Flink; Cur && Cur != Head; Cur = Cur->Flink)
    {
        if (Cur == &Entry->InLoadOrderLinks) return true;
    }
    return false;
}

bool VerifyModuleListRoundTrip(win::DRIVER_OBJECT* DriverObject)
{
    if (!DriverObject || !DriverObject->DriverSection)
    {
        print(INFO("VerifyModuleList: no loader entry (manual map), skipped"));
        return true;
    }
    if (!IsDriverInModuleList(DriverObject))
    {
        print(ERROR("VerifyModuleList: driver is not in PsLoadedModuleList"));
        return false;
    }
    if (!UnlinkDriverFromModuleList(DriverObject)) return false;
    if (IsDriverInModuleList(DriverObject))
    {
        print(ERROR("VerifyModuleList: unlink left the entry reachable"));
        return false;
    }
    if (!RelinkDriverIntoModuleList(DriverObject)) return false;
    if (!IsDriverInModuleList(DriverObject))
    {
        print(ERROR("VerifyModuleList: relink did not restore the entry"));
        return false;
    }
    print(OK("VerifyModuleList: unlink/relink round trip passed"));
    return true;
}

// Debug-only self-test: erase the PE header (saving it), require MZ/PE gone,
// restore it, require the MZ and NT signature back. Manual-map builds publish
// headerless and skip.
bool VerifyPeHeaderRoundTrip(win::DRIVER_OBJECT* DriverObject)
{
    if (!DriverObject || !DriverObject->DriverStart)
    {
        print(INFO("VerifyPeHeader: no image header (manual map), skipped"));
        return true;
    }
    if (!ErasePeHeader(DriverObject)) return false;
    if (!VerifyPeHeaderRemoved(DriverObject))
    {
        print(ERROR("VerifyPeHeader: header still present after erase"));
        RestorePeHeader();
        return false;
    }
    if (!RestorePeHeader()) return false;

    const auto* Dos = (const _IMAGE_DOS_HEADER*) DriverObject->DriverStart;
    if (Dos->e_magic != PeDosMagic)
    {
        print(ERROR("VerifyPeHeader: MZ not restored"));
        return false;
    }
    uint32_t Signature = 0;
    __builtin_memcpy(&Signature,
                     (const uint8_t*) DriverObject->DriverStart + Dos->e_lfanew,
                     sizeof(Signature));
    if (Signature != 0x00004550)
    {
        print(ERROR("VerifyPeHeader: PE signature not restored"));
        return false;
    }
    print(OK("VerifyPeHeader: erase/restore round trip passed"));
    return true;
}
#endif
