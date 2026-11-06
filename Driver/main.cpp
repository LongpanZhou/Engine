// Unity build: the whole driver is one translation unit and main.cpp is its root. The include order below
// is the definition order, so each file may only use what the files above it provide
#include "Lib/structs.h"   // kernel struct layouts and the vendor's arch types (address, cr3, ...)
#include "Lib/utils.h"     // print() and the INFO/OK/WARN/ERROR macros
#include "Lib/pure.h"      // host-testable helpers: WideEqualsIgnoreCase, IsObjectKernelPointer

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
#ifdef POSTBOX_JOB_ONLY
#include "PostboxJobShared.cpp" // job-only shared helpers; no PBOX/channel/NMI code
#else
#include "Postbox.cpp" // persistent timer/work-item channel
#endif
#ifdef POSTBOX_JOB
#include "../Common/PostboxCrypto.h"
#include "../Common/PostboxJobCrypto.h" // sealed job batch/data helpers
#include "PostboxJob.cpp" // job-only batch: one map, one entry, N jobs, one teardown
#endif
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
    const bool ManualMapped = !DriverObject || !DriverObject->DriverSection;

    // Stop the persistent Postbox channel before the image is released.
    PostboxStop();

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

    // Postbox builds are manual-map only: the second entry argument is a
    // PostboxConfig or PostboxJobConfig instead of a provider image name.
#if defined(POSTBOX_CHANNEL) || defined(POSTBOX_JOB_ONLY)
    const bool PostboxMode = ManualMapped && RegistryPath != nullptr;
#else
    const bool PostboxMode = false;
#endif

    // Job-only build: the loader passes a PostboxJobConfig instead of the
    // persistent PostboxConfig. The magic is the only mode discriminator; both
    // configs carry the image layout at offset 0x58.
#ifdef POSTBOX_JOB
    const bool JobMode = PostboxMode &&
        *reinterpret_cast<const uint32_t*>(RegistryPath) == PostboxJobConfigMagic;
#endif

#if defined(POSTBOX_CHANNEL) || defined(POSTBOX_JOB_ONLY)
    // The image is published as one RWX pool block. Apply the loader-supplied
    // section map before any channel state is initialized: .text RX, writable
    // sections RW/NX, everything else R/NX. Failure is fail-closed; the loader
    // zeroes and frees the image when the entry returns an error.
    if (PostboxMode)
    {
        print(INFO("DriverEntry: step 0.1 ProtectImageSections()"));
#ifdef POSTBOX_JOB
#ifdef POSTBOX_JOB_ONLY
        const bool Protected = JobMode &&
            ProtectImageSectionsLayout(
                &reinterpret_cast<const PostboxJobConfig*>(RegistryPath)->Layout);
#else
        const bool Protected = JobMode
            ? ProtectImageSectionsLayout(
                  &reinterpret_cast<const PostboxJobConfig*>(RegistryPath)->Layout,
                  false /* loader pre-protected; no global IPI */,
                  true  /* verify-only; do not rewrite PTEs */)
            : ProtectImageSections((const PostboxConfig*) RegistryPath);
#endif
#else
        const bool Protected = ProtectImageSections((const PostboxConfig*) RegistryPath);
#endif
        if (!Protected)
        {
            print(ERROR("DriverEntry: ProtectImageSections failed, returning 0xC0000001"));
            return static_cast<win::ntstatus>(
                0xC0000000u | (PostboxStartFailure ? PostboxStartFailure : 20u));
        }
        print(INFO("DriverEntry: step 0.1 ProtectImageSections() ok"));
    }
#endif

#ifndef MANUAL_MAP_ONLY
    // Step 0: clean traces from earlier loads (PiDDB / MmUnloadedDrivers / CI hash bucket / WdFilter
    // list) before this image unlinks itself, so each cleaner sees the loader entry. Skip entirely
    // for a manual map.
    print(INFO("DriverEntry: step 0 CleanDriverTraces()"));
    if (!ManualMapped) CleanDriverTraces(DriverObject);

    // The loader passes the staged provider image name through the second parameter on the manual-map
    // path, so the provider's own load records can be removed while it is still resident. On the SCM
    // path that parameter is the service registry path and must not be interpreted as a name. The
    // Postbox build reuses the same argument for its config, so the name path is skipped there.
    if (ManualMapped && RegistryPath && !PostboxMode)
        CleanExtraTraces(RegistryPath);
#endif

    // Debug-only self-tests. Release builds compile both the calls and the
    // verifier functions out.
#ifdef DEBUG
    print(INFO("DriverEntry: step 0.5 VerifyPteBase()"));
    if (!VerifyPteBase())
        print(ERROR("DriverEntry: VerifyPteBase() failed"));

    print(INFO("DriverEntry: step 0.6 VerifyMemory()"));
    if (!VerifyMemory())
        print(WARN("DriverEntry: VerifyMemory() reported failures (see output above)"));

    // The pre-start data-export cache must match the import slots, and the
    // SEED-XOR name decode must recover the plaintext.
    print(INFO("DriverEntry: step 0.7 VerifyMemSetPreStartNtoskrnl()"));
    if (!VerifyMemSetPreStartNtoskrnl((uint64_t) (uintptr_t) GetNtoskrnl()))
        print(ERROR("DriverEntry: VerifyMemSetPreStartNtoskrnl() failed"));

    // EPROCESS/module enumeration against the kernel anchors.
    print(INFO("DriverEntry: step 0.8 VerifyProcessEnumeration()"));
    if (!VerifyProcessEnumeration())
        print(ERROR("DriverEntry: VerifyProcessEnumeration() failed"));
#endif

#ifdef POSTBOX_CHANNEL
    // Resolve the nt data exports before VerifyProcessLayout reads the System
    // process. This keeps the product image free of the PsInitialSystemProcess
    // import slot while preserving the pre-start layout check.
    if (PostboxMode)
    {
        const auto* PostboxCfg = (const PostboxConfig*) RegistryPath;
        uint32_t ConfigError = 0;
        if (!PostboxConfigValid(*PostboxCfg, &ConfigError))
            return static_cast<win::ntstatus>(
                0xC0000000u | (ConfigError ? ConfigError : 30u));
        MemSetPreStartNtoskrnl(PostboxCfg->Layout.NtoskrnlBase);
    }
#endif

    // EPROCESS/PEB layout check; fail closed if the target build does not match
    // the pinned 19041 offsets. The job-only build performs the equivalent check
    // inside PostboxRunJobs from its PsGetCurrentProcess import.
#ifndef POSTBOX_JOB_ONLY
    print(INFO("DriverEntry: step 0.8b VerifyProcessLayout()"));
    if (!VerifyProcessLayout())
    {
        print(ERROR("DriverEntry: VerifyProcessLayout() failed"));
        return static_cast<win::ntstatus>(0xC0000001);
    }
#endif

    // Debug-only self-test: the lazy export walk against the real ntoskrnl
    // export table and the loader's import slots.
#ifdef DEBUG
    print(INFO("DriverEntry: step 0.9 VerifyFindFuncExports()"));
    if (!VerifyFindFuncExports(GetNtoskrnl()))
        print(ERROR("DriverEntry: VerifyFindFuncExports() failed"));
#endif

    // The persistent Postbox channel starts at step 6, after the image and the
    // loader state are fully set up.

    // The dedicated mapping table (compile-time switch in Mem.cpp). If linking fails at runtime the
    // table stays unlinked and mappings search the page tables as usual
    if (MapTableEnabled)
    {
        print(INFO("DriverEntry: step 2 LinkMapTable()"));
        bool Linked = LinkMapTable();
        print(INFO("DriverEntry: step 2 LinkMapTable() returned %u"), (uint32_t) Linked);
        (void) Linked;   // used by print(), which is compiled out in release
    }

#ifndef MANUAL_MAP_ONLY
#ifdef DEBUG
    // Debug-only self-tests for the SCM/default-channel profile. The manual-map
    // Postbox build excludes Hide.cpp/Traces.cpp and has no loader entry.
    if (DriverObject)
    {
        print(INFO("DriverEntry: step 2.5 VerifyModuleListRoundTrip()"));
        if (!VerifyModuleListRoundTrip(DriverObject))
            print(ERROR("DriverEntry: VerifyModuleListRoundTrip() failed"));

        print(INFO("DriverEntry: step 2.6 VerifyPeHeaderRoundTrip()"));
        if (!VerifyPeHeaderRoundTrip(DriverObject))
            print(ERROR("DriverEntry: VerifyPeHeaderRoundTrip() failed"));

        print(INFO("DriverEntry: step 2.7 VerifyEmptyTraceState()"));
        if (!VerifyEmptyTraceState(DriverObject))
            print(ERROR("DriverEntry: VerifyEmptyTraceState() failed"));
    }
#endif
#endif

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

    // Step 5: do not erase the PE header. The normal loader calls
    // RtlImageNtHeader after DriverEntry, so erasing it would bugcheck 0x7E. A
    // manual map is published headerless, so ErasePeHeader would only add a
    // redundant CR0.WP write.
    print(INFO("DriverEntry: step 5 ErasePeHeader() skipped (mapper publishes headerless)"));

    // Step 6: the job-only batch runs inline and returns. No timer, DPC, work
    // item, thread, or state page is created; the loader frees the image as soon
    // as the entry returns.
#ifdef POSTBOX_JOB
    if (JobMode)
    {
        print(INFO("DriverEntry: step 6 PostboxRunJobs()"));
        if (!PostboxRunJobs(reinterpret_cast<const PostboxJobConfig*>(RegistryPath)))
        {
            print(ERROR("DriverEntry: PostboxRunJobs() failed, returning 0xC0000001"));
            return static_cast<win::ntstatus>(
                0xC0000000u | (PostboxStartFailure ? PostboxStartFailure : 46u));
        }
        print(INFO("DriverEntry: step 6 PostboxRunJobs() ok"));
        print(INFO("DriverEntry: success"));
        return win::ntstatus::success;
    }
#endif

    // Step 6: arm the Postbox timer only after the image, trace cleanup, and PE-header
    // handling are complete. This removes the window where a work item could run
    // against a half-initialized image.
#ifdef POSTBOX_CHANNEL
    print(INFO("DriverEntry: step 6 PostboxStart()"));
    if (!PostboxMode || !PostboxStart((const PostboxConfig*) RegistryPath))
    {
        print(ERROR("DriverEntry: PostboxStart() failed, returning 0xC0000001"));
        return static_cast<win::ntstatus>(
            0xC0000000u | (PostboxStartFailure ? PostboxStartFailure : 30u));
    }
    print(INFO("DriverEntry: step 6 PostboxStart() ok"));

    // Debug-only self-test: the live state page, the request-auth path and the
    // response tag, all against the keys PostboxStart derived.
#ifdef DEBUG
    print(INFO("DriverEntry: step 6.5 VerifyPostboxSelfTest()"));
    if (!VerifyPostboxSelfTest())
        print(ERROR("DriverEntry: VerifyPostboxSelfTest() failed"));
#endif
#endif

    print(INFO("DriverEntry: success"));
    return win::ntstatus::success;
}
