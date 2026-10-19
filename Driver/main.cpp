// Unity build: the whole driver is one translation unit and main.cpp is its root. The include order below
// is the definition order, so each file may only use what the files above it provide
#include "Lib/structs.h"   // kernel struct layouts and the vendor's arch types (address, cr3, ...)
#include "Lib/utils.h"     // print() and the INFO/OK/WARN/ERROR macros

// arch and intrin names are used unqualified in every file below
using namespace arch;
using namespace intrin;

#include "Crypt.cpp"   // compile-time string crypto: Encode, Decode, EncodeBytes
#include "Scan.cpp"    // pattern parsing + PE image scanning: HexToByte, PatternToBytes, SignatureScan, SectionScan, FindFuncExports
#include "Strings.h"   // encoded runtime names + byte signatures (needs EncodeBytes + PatternToBytes above)

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
    // Re-attach the loader entry before anything else: Mm's unload path removes the entry it created at load
    // time, and if the entry was left detached by UnlinkDriverFromModuleList the loader-list bookkeeping ends up
    // inconsistent, so the next load of this driver bugchecks 0x1A (0x2101) inside MiProcessLoaderEntry
    RelinkDriverIntoModuleList(DriverObject);

    // Second trace pass: this load cycle left its own records behind (previous unload's MmUnloadedDrivers
    // slot, the PiDDB entry CI filed at load). Needs the relinked loader entry above, so it runs first
    CleanDriverTraces(DriverObject);

    // Unhook the command channel and free the mapping table first. Restoring is safe this late: the
    // image is only freed after this callback returns, inside Mm's unload path
    UnHook();
    UnlinkMapTable();
    UnhideDriverObject();
    return win::ntstatus::success;
}

win::ntstatus DriverEntry(win::DRIVER_OBJECT* DriverObject, win::UNICODE_STRING*)
{
    print(INFO("DriverEntry: start, DriverObject %p"), (void *) DriverObject);

    // TEMPORARY: trace cleaning is commented out for now (the user will come back to it). The three
    // cleaners in Traces.cpp stay available; restoring the two calls below re-enables everything
    // Step 0: clean the traces of earlier cycles (PiDDB / MmUnloadedDrivers / CI hash bucket) before the
    // hook, so Hook() works against pristine state. A NULL DriverObject (manual mapping) skips everything
    // print(INFO("DriverEntry: step 0 CleanDriverTraces()"));
    // if (DriverObject) CleanDriverTraces(DriverObject);

    // TEMPORARY: verification is commented out for now (Same situation as step 0): PTE_BASE extraction has been
    // proven against the live kernel across repeated boots (four randomized bases, both 4 KB and 2 MB pages).
    // Restore the call to re-verify a build on demand; the function stays available
    // Debug-only (print() compiles out without DEBUG). Release builds run neither this step nor its scan
    //#ifdef DEBUG
    //    print(INFO("DriverEntry: step 0.5 VerifyPteBase()"));
    //    VerifyPteBase();
    //#endif

    // Memory self-test (debug builds only): our page-table walk, PA->VA translator, validity check
    // and read/write/copy paths against the kernel's own MM routines. Release builds never call it,
    // so --gc-sections drops it and no import table entries are created. Verified passing against the
    // live kernel (19041): all checks green before the hook; restore the calls to re-run on demand
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

    // The dedicated mapping table, if it is enabled (off by default)
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

    // Hide the driver object itself, so walks of the \Driver directory (the reference tool's "validate driver
    // objects" check) see neither this driver's module nor its object, and flag nothing as invalid
    // TEMPORARY: HideDriverObject is commented out for now (Same situation as step 0): on 19045 the object
    // header's NameInfoOffset reads as 1, so NameInfo lands on garbage and the bucket walk faults (bugcheck
    // 0x7E, AV at driver+0x4046) — classic _OBJECT_HEADER/_OBJECT_HEADER_NAME_INFO layout mismatch with
    // Lib/structs.h on this build. Restore the call once those offsets are verified/dified
    // if (DriverObject)
    // {
    //     print(INFO("DriverEntry: step 4 HideDriverObject()"));
    //     HideDriverObject(DriverObject);
    // }

    print(INFO("DriverEntry: success"));
    return win::ntstatus::success;
}
