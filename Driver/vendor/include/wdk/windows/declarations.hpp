// windows function declarations
#ifndef WDK_WINDOWS_DECLARATIONS_HPP
#define WDK_WINDOWS_DECLARATIONS_HPP
#include "types.hpp"

namespace win {
    // variables
    extern "C" {
    extern std::uint8_t* KeNumberProcessors;
    extern arch::address MmBadPointer;
    extern std::uint32_t NtBuildNumber;
    extern /*tmp*/ arch::address PsInitialSystemProcess;
    extern /*tmp*/ arch::address PsLoadedModuleList;
    } // extern "C"


    // functions
    extern "C" {
    // output parameters are taken by reference when they are expected, taken by a pointer when optional and defaulted
    // if applicable
    ntstatus DbgPrintEx(std::uint32_t component_id, std::uint32_t level, const char* fmt, ...);

    // The two Mm routines return the plain underlying pointer, not arch::address: an extern "C"
    // declaration cannot carry a user-defined return type (-Wreturn-type-c-linkage), and the
    // kernel export really is PVOID MmGetPhysicalAddress(PVOID). arch::address converts to void*
    // for the arguments and constructs implicitly from void* for the result, so call sites are
    // unchanged, and on x64 the underlying ABI (a 64-bit value in RAX) is identical either way.
    void* MmGetPhysicalAddress(arch::address virtual_address);

    void* MmGetVirtualForPhysical(arch::address physical_address);

    bool MmIsAddressValid(arch::address virtual_address);
    } // extern "C"
} // namespace win
#endif // WDK_WINDOWS_DECLARATIONS_HPP
