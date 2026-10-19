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

#include "Mem.cpp"     // kernel memory: CR3, page-table walk, mapping table, Access*/CopyVirtualMemory, GetNtoskrnl, GetPteBase, GetVirtualAddress
#include "Process.cpp" // process & module enumeration: EnumerateEProcess, EnumerateKProcess, EnumerateModuleBaseAddress
#include "Hide.cpp"    // driver hiding: Unlink/RelinkDriverIntoModuleList, Hide/UnhideDriverObject
#include "Hooks.cpp"   // the NtCompareSigningLevels command hook (includes ../Common/Command.h itself)
#include "Traces.cpp"  // load-trace cleaners: ClearPiDDBCache, ClearMmUnloadedDrivers, ClearKernelHashBucketList + CleanDriverTraces

// The vendor's entry point walks this table to run global constructors. The driver has none that need to run,
// so the table is empty. Add an entry here if a global object with a runtime constructor is introduced
extern "C" void (*__CTOR_LIST__[2])() = {nullptr, nullptr};

win::ntstatus DriverExit(win::DRIVER_OBJECT* DriverObject)
{
    // Unhook the command channel: restoring is safe here, the image is only freed after this callback
    // returns. Release builds must unhook too — the swapped pointer would otherwise dangle into this
    // freed image after unload
    UnHook();

#ifdef DEBUG
    // Rest of the teardown, debug builds only: an unloaded release build leaves the loader entry
    // detached (next load bugchecks 0x1A) — do not unload a release build
    //
    // Re-attach the loader entry first, so Mm's unload path finds the bookkeeping consistent
    RelinkDriverIntoModuleList(DriverObject);

    // Second trace pass: this load cycle's own records (MmUnloadedDrivers slot, PiDDB entry, hash bucket)
    CleanDriverTraces(DriverObject);

    UnlinkMapTable();
    UnhideDriverObject();
#endif
    (void) DriverObject;   // used by the teardown only in debug builds
    return win::ntstatus::success;
}

win::ntstatus DriverEntry(win::DRIVER_OBJECT* DriverObject, win::UNICODE_STRING*)
{
    print(INFO("DriverEntry: start, DriverObject %p"), (void *) DriverObject);

    // Step 0: clean the traces of earlier cycles (PiDDB / MmUnloadedDrivers / CI hash bucket) before the
    // hook, so Hook() works against pristine state. A NULL DriverObject (manual mapping) skips everything
    // Debug-only while the zero-API PiDDB cleaner is being verified live; flip to unconditional once it
    // passes. print() output only exists in debug builds anyway
#ifdef DEBUG
    print(INFO("DriverEntry: step 0 CleanDriverTraces()"));
    if (DriverObject) CleanDriverTraces(DriverObject);
#endif

    // TEMPORARY: disabled; PTE_BASE extraction is proven live (randomized bases, 4 KB and 2 MB pages).
    // Restore the call to re-verify a build. Debug-only, release builds drop this with print()
    //#ifdef DEBUG
    //    print(INFO("DriverEntry: step 0.5 VerifyPteBase()"));
    //    VerifyPteBase();
    //#endif

    // TEMPORARY: disabled; VerifyMemory() passed against the live kernel (19041). Restore the call to
    // re-run on demand. Debug-only: release builds drop it (--gc-sections) and gain no imports
    //#ifdef DEBUG
    //    print(INFO("DriverEntry: step 0.6 VerifyMemory()"));
    //    if (!VerifyMemory()) print(WARN("DriverEntry: VerifyMemory() reported failures (see output above)"));
    //#endif

    // Hook (STATUS_UNSUCCESSFUL if ntoskrnl or the signature cannot be found). NO_HOOK test builds skip it: the hook
    // writes a function pointer inside ntoskrnl's SeCiCallbacks table, which PatchGuard checks (bugcheck 0x109)
#ifndef NO_HOOK
    print(INFO("DriverEntry: step 1 Hook()"));
    if (!Hook())
    {
        print(ERROR("DriverEntry: Hook() failed, returning 0xC0000001"));
        return static_cast<win::ntstatus>(0xC0000001);
    }
    print(INFO("DriverEntry: step 1 Hook() ok"));
#else
    print(INFO("DriverEntry: NO_HOOK test build, NtCompareSigningLevels not hooked"));
#endif

    // The dedicated mapping table (compile-time switch in Mem.cpp). If linking fails at runtime the
    // table stays unlinked and mappings search the page tables as usual
    if (MapTableEnabled)
    {
        print(INFO("DriverEntry: step 2 LinkMapTable()"));
        bool Linked = LinkMapTable();
        print(INFO("DriverEntry: step 2 LinkMapTable() returned %u"), (uint32_t) Linked);
    }

    // Set before the unlink, so an unload only undoes what DriverEntry actually did. A manually mapped driver
    // (kdmapper) gets a NULL DriverObject and no unload callback, so only set it when there is one
    if (DriverObject) DriverObject->DriverUnload = DriverExit;

    // Unlink the driver from PsLoadedModuleList, so module walks no longer report it. A manually mapped driver
    // (kdmapper) has no loader entry, so this reports and skips
    print(INFO("DriverEntry: step 3 UnlinkDriverFromModuleList()"));
    if (DriverObject) UnlinkDriverFromModuleList(DriverObject);

    // Hide the driver object itself, so \Driver walks see neither the module nor the object
    // TEMPORARY: disabled; on 19045 NameInfoOffset reads 1, so the bucket walk faults (bugcheck 0x7E) —
    // layout mismatch with Lib/structs.h. Restore the call once those offsets are verified
    // if (DriverObject)
    // {
    //     print(INFO("DriverEntry: step 4 HideDriverObject()"));
    //     HideDriverObject(DriverObject);
    // }

    print(INFO("DriverEntry: success"));
    return win::ntstatus::success;
}
