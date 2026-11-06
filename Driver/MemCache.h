#pragma once
#include <cstdint>

// Cached kernel constants used by the memory layer. The Postbox build keeps
// them on the independent state page so the mapped image's .data carries no
// ntoskrnl-base or PTE-base pointer. Mem.cpp uses a transient static cache
// until the state page exists; MemAdoptCaches() then moves the values into the
// state page and zeroes the static slots.
struct PostboxMemCaches
{
    uint64_t Ntoskrnl;
    uint64_t PteBase;
    uint64_t PfnPteAddressBase;
    // Data-export addresses resolved from the loader-provided ntoskrnl base.
    // Kept here so the mapped image has no __imp_ IAT slots for them.
    uint64_t PsInitialSystemProcess;
    uint64_t PsLoadedModuleList;
};

#ifdef POSTBOX_CHANNEL
PostboxMemCaches* PostboxGetMemCaches();
#else
inline PostboxMemCaches* PostboxGetMemCaches() { return nullptr; }
#endif

// Copies the transient cache into Dst (when non-null) and clears the statics.
void MemAdoptCaches(PostboxMemCaches* Dst);

// Postbox pre-start bootstrap: the loader supplies the ntoskrnl base before
// ProtectImageSections calls PostboxResolve. This removes the need for the
// driver's PsInitialSystemProcess/PsLoadedModuleList imports.
void MemSetPreStartNtoskrnl(uint64_t Base);

// Address of the ntoskrnl PsInitialSystemProcess data export (the pointer
// variable, not the EPROCESS). Resolved from the loader-provided base; the
// Postbox build has no __imp_PsInitialSystemProcess IAT slot.
uint64_t MemPsInitialSystemProcess();
