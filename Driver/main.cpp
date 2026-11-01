// Unity build: the whole driver is one translation unit and main.cpp is its root. The include order below
// is the definition order, so each file may only use what the files above it provide
#include "Lib/structs.h"   // kernel struct layouts and the vendor's arch types (address, cr3, ...)
#include "Lib/utils.h"     // print() and the INFO/OK/WARN/ERROR macros

// arch and intrin names are used unqualified in every file below
using namespace arch;
using namespace intrin;

#include "Crypt.cpp"   // compile-time string crypto: Encode, Decode, EncodeBytes
#include "Scan.cpp"    // pattern parsing + PE image scanning: HexToByte, PatternToBytes, SignatureScan, SectionScan, FindFuncExports, FindFuncExportsBatch
#include "Strings.h"   // encoded runtime names + byte signatures (needs EncodeBytes + PatternToBytes above)
#include "Locate.cpp"  // locate-by-signature helpers: ScanModuleImage + ResolveRipRelative (needs Strings.h's section names, and every memory/process/hook/trace file below)

#include "MemCache.h"  // cache handoff contract between Mem.cpp and the Postbox state page
#include "Mem.cpp"     // kernel memory: CR3, page-table walk, mapping table, Access*/CopyVirtualMemory, GetNtoskrnl, GetPteBase, GetVirtualAddress
#include "Process.cpp" // process & module enumeration: EnumerateEProcess, EnumerateKProcess, EnumerateModuleBaseAddress
#ifndef MANUAL_MAP_ONLY
#include "Hide.cpp"    // driver hiding: Unlink/RelinkDriverIntoModuleList, Hide/UnhideDriverObject
#endif
#ifndef POSTBOX_CHANNEL
#include "Channel.cpp" // the shared-memory command channel (includes ../Common/Command.h itself)
#endif
#include "Postbox.cpp" // opt-in timer/work-item channel; compiles to nothing unless POSTBOX_CHANNEL
#ifdef POSTBOX_NMI
#include "PostboxNmi.cpp" // constructed-IDT NMI gate; only in POSTBOX_NMI builds
#endif
#ifndef MANUAL_MAP_ONLY
#include "Traces.cpp"  // load-trace cleaners: ClearPiDDBCache, ClearMmUnloadedDrivers, ClearKernelHashBucketList, ClearWdFilterDriverList + CleanDriverTraces / CleanExtraTraces
#endif

// The vendor's entry point walks this table to run global constructors. The driver has none that need to run,
// so the table is empty. Add an entry here if a global object with a runtime constructor is introduced
extern "C" void (*__CTOR_LIST__[2])() = {nullptr, nullptr};

#ifndef MANUAL_MAP_ONLY
win::ntstatus DriverExit(win::DRIVER_OBJECT* DriverObject)
{
#ifdef MANUAL_MAP_ONLY
    // The Postbox build is manual-map only: stop the timer/work item and unlink the
    // map table. There is no loader entry, no object to unhide, and no PE header to
    // restore; the mapper publishes the image headerless.
    PostboxStop();
    UnlinkMapTable();
    return win::ntstatus::success;
#else
    const bool ManualMapped = !DriverObject || !DriverObject->DriverSection;

    // Stop the command channel before the image is released. The default build uses the
    // shared-memory channel; the opt-in POSTBOX_CHANNEL build stops the timer/work item.
#ifdef POSTBOX_CHANNEL
    PostboxStop();
#else
    ChannelStop();
#endif

    // Rest of the teardown, both variants: an unloaded build that leaves the loader entry detached
    // makes the next load bugcheck 0x1A in MiProcessLoaderEntry
    //
    // A manual map has no loader entry and no trace records, so skip both loader-only steps.
    if (!ManualMapped)
    {
        // Re-attach the loader entry first, so Mm's unload path finds the bookkeeping consistent
        if (!RelinkDriverIntoModuleList(DriverObject))
            print(ERROR("DriverExit: relink failed, next load may bugcheck 0x1A"));

        // Second trace pass: this load cycle's own records (MmUnloadedDrivers slot, PiDDB entry, hash bucket)
        CleanDriverTraces(DriverObject);
    }
    else
    {
        print(INFO("DriverExit: manual map, skipping loader relink and trace cleaning"));
    }

    UnlinkMapTable();

    bool WasHidden = UnhideDriverObject();
#ifdef DEBUG
    // Re-check through the same raw directory walk that the name is reachable again
    if (WasHidden && !VerifyHideDriverObject(DriverObject, false))
        print(ERROR("DriverExit: unhide verification failed"));
#else
    (void) WasHidden;
#endif

    // Restore last: the unload path must see a valid PE header again
    if (!RestorePeHeader())
        print(ERROR("DriverExit: PE header restore failed"));

    // Last of all: stop the memory manager filing this unload into MmUnloadedDrivers. MiRememberUnloadedDriver
    // runs after this callback returns and skips the record when BaseDllName.Length is zero, so the slot
    // CleanDriverTraces cannot reach (it does not exist yet at this point) is never created. Only the length
    // is zeroed: Buffer and MaximumLength stay valid for anything that reads the entry on the way out
    if (!ManualMapped && DriverObject->DriverSection)
        ((_KLDR_DATA_TABLE_ENTRY*) DriverObject->DriverSection)->BaseDllName.Length = 0;

    return win::ntstatus::success;
#endif
}
#endif // MANUAL_MAP_ONLY

win::ntstatus DriverEntry(win::DRIVER_OBJECT* DriverObject, win::UNICODE_STRING* RegistryPath)
{
    print(INFO("DriverEntry: start, DriverObject %p"), (void *) DriverObject);

    // A normal SCM load has both a DriverObject and a loader-created DriverSection. A manual map has
    // neither, or only a mapper-supplied fake object. All loader-trace bookkeeping is keyed off
    // DriverSection, so cleaning is meaningless for a manual map.
    const bool ManualMapped = !DriverObject || !DriverObject->DriverSection;

#ifdef MANUAL_MAP_ONLY
    // This build is manual-map only. Refuse a normal SCM load before any mutation.
    if (!ManualMapped)
    {
        print(ERROR("DriverEntry: MANUAL_MAP_ONLY build refused a normal load"));
        return static_cast<win::ntstatus>(0xC0000001);
    }
#endif

    // The POSTBOX_CHANNEL build is manual-map only: the second entry argument is a
    // PostboxConfig instead of a provider image name.
#ifdef POSTBOX_CHANNEL
    const bool PostboxMode = ManualMapped && RegistryPath != nullptr;
#else
    const bool PostboxMode = false;
#endif

#ifdef POSTBOX_CHANNEL
    // The image is published as one RWX pool block. Apply the loader-supplied
    // section map before any channel state is initialized: .text RX, writable
    // sections RW/NX, everything else R/NX. Failure is fail-closed; the loader
    // zeroes and frees the image when the entry returns an error.
    if (PostboxMode)
    {
        print(INFO("DriverEntry: step 0.1 ProtectImageSections()"));
        if (!ProtectImageSections((const PostboxConfig*) RegistryPath))
        {
            print(ERROR("DriverEntry: ProtectImageSections failed, returning 0xC0000001"));
            return static_cast<win::ntstatus>(
                0xC0000000u | (PostboxStartFailure ? PostboxStartFailure : 20u));
        }
        print(INFO("DriverEntry: step 0.1 ProtectImageSections() ok"));
    }
#endif

#ifndef MANUAL_MAP_ONLY
    // Step 0: clean the traces of earlier cycles (PiDDB / MmUnloadedDrivers / CI hash bucket / WdFilter
    // list) before the hook, so Hook() works against pristine state. Skip entirely for a manual map.
    print(INFO("DriverEntry: step 0 CleanDriverTraces()"));
    if (!ManualMapped) CleanDriverTraces(DriverObject);

    // The loader passes the staged provider image name through the second parameter on the manual-map
    // path, so the provider's own load records can be removed while it is still resident. On the SCM
    // path that parameter is the service registry path and must not be interpreted as a name. The
    // Postbox build reuses the same argument for its config, so the name path is skipped there.
    if (ManualMapped && RegistryPath && !PostboxMode)
        CleanExtraTraces(RegistryPath);
#endif

    // Debug-only self-test: checks the PTE_BASE extraction against the kernel's own MM routines.
    // Release builds compile this out; both the call and the function are absent
#ifdef DEBUG
    print(INFO("DriverEntry: step 0.5 VerifyPteBase()"));
    if (!VerifyPteBase())
        print(ERROR("DriverEntry: VerifyPteBase() failed"));
#endif

    // Debug-only self-test: runs every hand-written memory path against the kernel's MM routines.
    // Release builds compile this out; both the call and the function are absent
#ifdef DEBUG
    print(INFO("DriverEntry: step 0.6 VerifyMemory()"));
    if (!VerifyMemory()) print(WARN("DriverEntry: VerifyMemory() reported failures (see output above)"));
#endif

    // Step 1: start the command channel. The default build uses the shared-memory section;
    // Step 1: the default shared-memory channel starts here. The POSTBOX_CHANNEL build
    // starts its timer at the end of the entry, after the image and the loader state are
    // fully set up.
#ifndef POSTBOX_CHANNEL
    print(INFO("DriverEntry: step 1 ChannelStart()"));
    if (!ChannelStart())
    {
        print(ERROR("DriverEntry: ChannelStart() failed, returning 0xC0000001"));
        return static_cast<win::ntstatus>(0xC0000001);
    }
    print(INFO("DriverEntry: step 1 ChannelStart() ok"));
#endif

    // The dedicated mapping table (compile-time switch in Mem.cpp). If linking fails at runtime the
    // table stays unlinked and mappings search the page tables as usual
    if (MapTableEnabled)
    {
        print(INFO("DriverEntry: step 2 LinkMapTable()"));
        bool Linked = LinkMapTable();
        print(INFO("DriverEntry: step 2 LinkMapTable() returned %u"), (uint32_t) Linked);
    }

#ifndef MANUAL_MAP_ONLY
    // Set before the unlink, so an unload only undoes what DriverEntry actually did. A manually mapped driver
    // (kdmapper) gets a NULL DriverObject and no unload callback, so only set it when there is one.
    // The manual-map-only build has no unload path at all; excluding it removes the dead
    // DriverExit/PostboxStop stub from the mapped image.
    if (DriverObject) DriverObject->DriverUnload = DriverExit;
#endif

#ifndef MANUAL_MAP_ONLY
    // Unlink the driver from PsLoadedModuleList, so module walks no longer report it. A manually mapped driver
    // (kdmapper) has no loader entry, so this reports and skips
    print(INFO("DriverEntry: step 3 UnlinkDriverFromModuleList()"));
    if (DriverObject && !UnlinkDriverFromModuleList(DriverObject))
        print(ERROR("DriverEntry: UnlinkDriverFromModuleList failed, driver may still be visible"));
#endif

    // Hide the driver object itself, so \Driver walks see neither the module nor the object.
    // TEMPORARY: disabled while testing SCM status. Leaving the object in \Driver lets SCM report
    // the service as RUNNING. Restore this block when object hiding is required.
    // if (DriverObject)
    // {
    //     print(INFO("DriverEntry: step 4 HideDriverObject()"));
    //     bool Hidden = HideDriverObject(DriverObject);
    //     if (!Hidden)
    //         print(ERROR("DriverEntry: HideDriverObject failed, driver object may remain visible"));
    //
    // #ifdef DEBUG
    //     if (Hidden && !VerifyHideDriverObject(DriverObject, true))
    //         print(ERROR("DriverEntry: step 4 hide verification failed"));
    // #endif
    // }

    // Step 5: remove the PE headers only for a manual map. The normal loader still parses the image
    // header after DriverEntry returns: IopLoadDriver -> MiFreeDriverInitialization -> MiSnapDriverRange
    // calls RtlImageNtHeader, and erasing the header here makes that path bugcheck 0x7E (0xC0000005).
    // A manual map has no loader entry and no IopLoadDriver cleanup, so it is safe to erase.
    // The mapper zeroes the PE headers in the local image before publishing, so the
    // mapped header page is already empty. Do not call ErasePeHeader here: it clears
    // CR0.WP to rewrite an already-zero page, which is a deterministic CR0-write VM
    // exit and a redundant artifact.
    print(INFO("DriverEntry: step 5 ErasePeHeader() skipped (mapper publishes headerless)"));

    // Step 6: arm the Postbox timer only after the image, the trace cleanup and the PEB
    // header work are done. This removes the window where a work item could run against a
    // half-initialized image (and, with MAPPED_SAFE=OFF, before LinkMapTable).
#ifdef POSTBOX_CHANNEL
    print(INFO("DriverEntry: step 6 PostboxStart()"));
    if (!PostboxMode || !PostboxStart((const PostboxConfig*) RegistryPath))
    {
        print(ERROR("DriverEntry: PostboxStart() failed, returning 0xC0000001"));
        return static_cast<win::ntstatus>(
            0xC0000000u | (PostboxStartFailure ? PostboxStartFailure : 30u));
    }
    print(INFO("DriverEntry: step 6 PostboxStart() ok"));
#endif

    print(INFO("DriverEntry: success"));
    return win::ntstatus::success;
}
